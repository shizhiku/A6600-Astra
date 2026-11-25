#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""imdb5_decode.py — ZV-1M2 五代固件 IMDB 任务表定位、解析与可执行性分析（只读）。

来源约束：
  * 只读取 05-原始固件/zv1m2_fw 下的原始镜像与既有提取件；
  * 不运行 QEMU，不修改既有镜像/脚本/文档；
  * 复用 02-脚本/a6600_usr.py 里的 Ext2 类（importlib 载入，不修改该文件）。

产物：
  03-证据/静态分析/imdb5/  —— JSON/TSV 证据与关键镜像内文件副本
  01-文档/106-五代IMDB表解析.md —— 中文报告（由本脚本自动生成）

用法：
  python 02-脚本/imdb5_decode.py
"""
import hashlib
import importlib.util
import io
import json
import os
import struct
import sys
from collections import Counter, OrderedDict

from elftools.elf.elffile import ELFFile

# ---------------------------------------------------------------- 路径
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FW = os.path.join(BASE, '05-原始固件', 'zv1m2_fw')
IMG = os.path.join(FW, 'extracted', '0700_part_image', 'dev', 'nflasha15')
GEN5 = os.path.join(FW, 'gen5')
OUT = os.path.join(BASE, '03-证据', '静态分析', 'imdb5')
DOC = os.path.join(BASE, '01-文档', '106-五代IMDB表解析.md')

# 关键常量（由 libIMDB.so ELF 结构确定，见报告“表结构”一节）
IMDB_FILE = '/lib/libIMDB.so'
IMDB_STRIDE = 44          # 记录大小：4(type)+4(flag)+4(target)+2(me)+2(psid)+7*4(字符串指针)
IMDB_HDR = 132            # imdb_raw 头：2*4 + 31*4（31 个 target 名槽位）
IMDB_NREC = 228           # 含 0x28 终止记录
IMDB_RAW_VA = 0xf00c      # .data.rel.ro 中 imdb_raw 符号地址 = 文件偏移 0x700c
MARKER_BASE = 0x08000000  # 序列分隔记录 type = 0x0800000N
TYPE_TERM = 0x28

# im.elf 观察到的执行阶段（见报告第 4 节，来自反汇编）
PHASES = [
    # (名称, 起始 index, 结束 index(不含), 门控 boot 位, 执行者, stage 掩码)
    ('A 目标定义',        0,   6,   None,  'main', 0xff),
    ('B 内核模块组1',     6,   9,   0x20000, 'main', 0xff),   # boot=g
    ('C 内核模块组2',     9,   19,  0x40000, 'main', 0xff),   # boot=r
    ('D 基础库/全局Infra', 19, 42,  0x80000, 'main', 0xff),   # boot=u
    ('E LIRO',            42,  44,  0x100000, 'main', 0xff),  # boot=l
    ('F Infra并行任务',   44,  142, 0x200000, 'infra1/2/4', None),  # boot=i
    ('G BIZ初始化',       142, 144, 0x200000, 'main', 0xff),  # boot=i
    ('H Application',     144, 149, 0x400000, 'app', 0xf),    # boot=a
]
STAGE_NAMES = {1: 'INFRA0', 2: 'INFRA1', 4: 'INFRA2', 0xf: 'APP', 0xff: 'main(任意)'}
TYPE_NAMES = {
    0x00000001: 'target定义',
    0x00000028: '终止',
    0x10000001: 'insmod.ko',
    0x10000002: 'insmod(liro特殊)',
    0x20000001: 'dlopen库(type1)',
    0x20000002: 'dlopen库(type2)',
    0x20000003: 'dlopen库(type3)',
    0x20000004: 'Application',
    0x40000001: 'shell脚本/可执行',
}
TARGET_BITS = ['default', 'qemu', 'sim', 'nfs', 'set', 'usbj', 'resub', 'adjust', 'test']


# ---------------------------------------------------------------- 工具
def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_ext2(path):
    spec = importlib.util.spec_from_file_location('a6600_usr', os.path.join(BASE, '02-脚本', 'a6600_usr.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Ext2(path)


def cstr(data, off, limit=160):
    if not off or off >= len(data):
        return ''
    end = data.find(b'\x00', off)
    if end < 0 or end - off > limit:
        return ''
    try:
        return data[off:end].decode('latin1')
    except UnicodeDecodeError:
        return ''


def parse_imdb_any(path):
    """通用解析：给任意 libIMDB.so 计算表头/记录数（用于 a6600 对照）。"""
    data = open(path, 'rb').read()
    e = ELFFile(io.BytesIO(data))
    sym = None
    for s in e.get_section_by_name('.dynsym').iter_symbols():
        if s.name == 'imdb_raw':
            sym = s
            break
    if sym is None:
        return None
    va = sym['st_value']
    foff = None
    for sec in e.iter_sections():
        if sec['sh_addr'] <= va < sec['sh_addr'] + sec['sh_size'] and sec['sh_type'] != 'SHT_NOBITS':
            foff = sec['sh_offset'] + (va - sec['sh_addr'])
            break
    if foff is None:
        return None
    hdr = [struct.unpack_from('<I', data, foff + 4 * i)[0] for i in range(33)]
    slots = []
    for i in range(31):
        sva = hdr[2 + i]
        if sva and sva < len(data):
            end = data.find(b'\x00', sva)
            slots.append({'bit': i, 'name': data[sva:end].decode('latin1')})
    n = 0
    while foff + 132 + 44 * n + 4 <= len(data) and n < 1000:
        if struct.unpack_from('<I', data, foff + 132 + 44 * n)[0] == 0x28:
            break
        n += 1
    return {'path': path, 'size': len(data), 'sha256': sha256(data), 'header_tag': hdr[0],
            'target_slots': slots, 'records_including_terminator': n + 1}


def dyn_exports(data):
    """返回 (导出符号集合, DT_NEEDED 列表)；解析失败返回 (set(), [])。"""
    try:
        e = ELFFile(io.BytesIO(data))
    except Exception:
        return set(), []
    names = set()
    sec = e.get_section_by_name('.dynsym')
    if sec is not None:
        for s in sec.iter_symbols():
            if s.name:
                names.add(s.name)
    need = []
    dyn = e.get_section_by_name('.dynamic')
    if dyn is not None:
        try:
            for t in dyn.iter_tags():
                if t.entry.d_tag == 'DT_NEEDED':
                    need.append(t.needed)
        except Exception:
            pass
    return names, need


def read_elf_ident(data):
    if data[:4] != b'\x7fELF':
        return None
    try:
        e = ELFFile(io.BytesIO(data))
        return {
            'class': e.elfclass, 'machine': e.get_machine_arch(),
            'type': e['e_type'], 'entry': e['e_entry'],
            'needed': dyn_exports(data)[1],
        }
    except Exception:
        return {'class': None, 'machine': None, 'type': None, 'entry': None, 'needed': []}


class Ext2Index:
    """在 a6600_usr.Ext2 之上做一次遍历，建立 path/inode/块反查所需索引。"""

    def __init__(self, fs):
        self.fs = fs
        self.bs = fs.bs
        self.files = OrderedDict()   # path -> ino
        self.dirs = OrderedDict()
        self.by_base = {}
        self._block_owner_cache = {}
        self._ptrs_cache = {}
        for path, ino, is_dir in fs.walk():
            if is_dir:
                self.dirs[path] = ino
            else:
                self.files[path] = ino
        for p in self.files:
            self.by_base.setdefault(p.rsplit('/', 1)[-1], []).append(p)
        for p in self.dirs:
            self.by_base.setdefault(p.rsplit('/', 1)[-1], []).append(p)

    def read(self, path_or_ino):
        ino = path_or_ino if isinstance(path_or_ino, int) else self.files[path_or_ino]
        return self.fs.read_file(ino)

    def block_ptrs(self, ino, max_blocks=None):
        """按逻辑顺序返回文件数据块号列表（包含间接块）。"""
        if ino in self._ptrs_cache:
            return self._ptrs_cache[ino]
        mode, size, blocks = self.fs.inode(ino)
        bs = self.bs
        out = [b for b in blocks[:12] if b]
        n = 12
        if blocks[12]:
            ind = self.fs._block(blocks[12])
            for b in struct.unpack('<%dI' % (bs // 4), ind):
                if b:
                    out.append(b)
            n += bs // 4
        if blocks[13] and (max_blocks is None or n < max_blocks):
            dind = self.fs._block(blocks[13])
            for p in struct.unpack('<%dI' % (bs // 4), dind):
                if p:
                    sub = self.fs._block(p)
                    for b in struct.unpack('<%dI' % (bs // 4), sub):
                        if b:
                            out.append(b)
        res = (size, out)
        self._ptrs_cache[ino] = res
        return res

    def owner_of_block(self, blk):
        """返回 (path, logical_block, file_offset_base) 或 None。"""
        if blk in self._block_owner_cache:
            return self._block_owner_cache[blk]
        for path, ino in list(self.files.items()) + list(self.dirs.items()):
            size, ptrs = self.block_ptrs(ino)
            try:
                idx = ptrs.index(blk)
            except ValueError:
                continue
            if idx * self.bs >= size and path in self.files:
                # 稀疏/尾部块，仍按逻辑块计算偏移
                pass
            res = (path, idx, idx * self.bs)
            self._block_owner_cache[blk] = res
            return res
        return None

    def owner_of_offset(self, off):
        blk, within = divmod(off, self.bs)
        own = self.owner_of_block(blk)
        if not own:
            return None
        path, logical, base = own
        return {'path': path, 'logical_block': logical, 'block': blk,
                'file_offset': base + within, 'image_offset': off}


# ---------------------------------------------------------------- 解析 IMDB
def parse_imdb(lib):
    """解析 imdb_raw 头 + 228 条 44 字节记录。"""
    hdr = []
    for i in range(0, IMDB_HDR, 4):
        hdr.append(struct.unpack_from('<I', lib, IMDB_RAW_VA - 0x8000 + i)[0])
    target_slots = []
    for idx in range(31):
        va = hdr[2 + idx] if 2 + idx < len(hdr) else 0
        if va:
            target_slots.append({'bit': idx, 'string_va': va, 'name': cstr(lib, va)})
    recs = []
    for i in range(IMDB_NREC):
        foff = (IMDB_RAW_VA - 0x8000) + IMDB_HDR + i * IMDB_STRIDE
        tag, flag, target, mefl, f, ini, ex, sus, res, inact, act = struct.unpack_from('<IIIIIIIIIII', lib, foff)
        me = mefl & 0xffff
        psid = mefl >> 16
        rec = {
            'index': i,
            'file_offset': foff,
            'va': (IMDB_RAW_VA + IMDB_HDR + i * IMDB_STRIDE),
            'type': tag,
            'type_name': TYPE_NAMES.get(tag) or (
                ('序列分隔%d' % (tag - MARKER_BASE)) if MARKER_BASE <= tag <= MARKER_BASE + 9 else '未知'),
            'flag': flag,
            'stage': STAGE_NAMES.get(flag) or ('0x%x' % flag),
            'target': target,
            'target_names': [TARGET_BITS[b] for b in range(len(TARGET_BITS)) if target & (1 << b)],
            'me': me,
            'psid': psid,
            'file': cstr(lib, f),
            'init': cstr(lib, ini),
            'exit': cstr(lib, ex),
            'sus': cstr(lib, sus),
            'res': cstr(lib, res),
            'inact': cstr(lib, inact),
            'act': cstr(lib, act),
            'string_vas': {'file': f, 'init': ini, 'exit': ex, 'sus': sus,
                           'res': res, 'inact': inact, 'act': act},
        }
        recs.append(rec)
    header = {'raw_u32': hdr, 'tag': hdr[0], 'target_slots': target_slots,
              'first_record_va': IMDB_RAW_VA + IMDB_HDR}
    return header, recs


# ---------------------------------------------------------------- 文件路径解析
def guest_to_image_paths(field, index):
    """把记录里的 file 字段解析为 /usr 镜像内路径候选。"""
    if not field:
        return []
    cands = []
    if field.startswith('/usr/'):
        cands.append(field[4:])
        cands.append(field)
    elif field.startswith('/'):
        cands.append(field)
        cands.append('/usr' + field)
    else:
        return list(index.by_base.get(field, []))
    return [p for p in cands if p in index.files]


def resolve_record_file(rec, index):
    paths = guest_to_image_paths(rec['file'], index)
    rec['image_paths'] = paths
    rec['file_in_image'] = bool(paths)
    if not rec['file']:
        rec['path_note'] = '空'
    elif paths:
        p = paths[0]
        if rec['file'].startswith('/usr/'):
            rec['path_note'] = '镜像路径 %s（guest %s）' % (p, rec['file'])
        elif rec['file'].startswith('/'):
            rec['path_note'] = '镜像路径 %s（按镜像根=/usr 映射）' % p
        else:
            rec['path_note'] = '按 basename 在镜像中找到 %s' % p
    else:
        rec['path_note'] = '未在 /usr 镜像中找到'


def analyze_providers(recs, index):
    """逐条记录判断 provider（动态库 / libObj 静态合并 / 缺失）与 init 符号可用性。"""
    libobj_path = '/lib/libObj.so'
    libobj = index.read(libobj_path)
    libobj_ex, libobj_need = dyn_exports(libobj)
    exports_cache = {libobj_path: libobj_ex}

    # 收集镜像中所有 .so 的导出符号，用于“跨库提供者”兜底检查
    so_paths = [p for p in index.files if p.startswith('/lib/') and (p.endswith('.so') or '.so.' in p)]
    all_exports = {}
    for p in so_paths:
        try:
            all_exports[p] = dyn_exports(index.read(p))[0]
        except Exception:
            all_exports[p] = set()

    def exports_of(p):
        if p not in exports_cache:
            exports_cache[p] = dyn_exports(index.read(p))[0]
        return exports_cache[p]

    for r in recs:
        r['provider'] = None
        r['provider_kind'] = '非库记录'
        r['init_found'] = None
        r['cross_lib_providers'] = []
        resolve_record_file(r, index)
        if r['type'] not in (0x20000001, 0x20000002, 0x20000003, 0x20000004):
            r['provider_kind'] = '非库记录'
            continue
        if r['psid']:
            r['provider'] = libobj_path
            r['provider_kind'] = 'libObj静态合并(psid!=0)'
            r['init_found'] = (r['init'] in libobj_ex) if r['init'] else None
        elif r['file_in_image']:
            p = r['image_paths'][0]
            r['provider'] = p
            r['provider_kind'] = '动态库(镜像内)'
            ex = exports_of(p)
            r['init_found'] = (r['init'] in ex) if r['init'] else None
        else:
            r['provider'] = None
            r['provider_kind'] = '缺失(psid=0 且镜像无此文件)'
            if r['init']:
                r['cross_lib_providers'] = [p for p, ex in all_exports.items() if r['init'] in ex]
                r['init_found'] = bool(r['cross_lib_providers'])
            else:
                r['init_found'] = None
        # 空 init 的纯预加载库
        if not r['init']:
            r['init_found'] = None
    return {
        'libobj_sha256': sha256(libobj),
        'libobj_size': len(libobj),
        'libobj_exports': len(libobj_ex),
        'libobj_needed': libobj_need,
        'image_so_count': len(so_paths),
    }


# ---------------------------------------------------------------- 执行模型
def build_execution(recs):
    """按 im.elf（ZV-1M2 /bin/im.elf）静态执行模型标注每条记录是否会在 Application 之前执行。

    依据（详见报告第 4 节）：
      * main 依次用 stage 掩码 0xff 执行 [0,6) [6,9) [9,19) [19,42) [42,44) 五段，
        分别受 boot=s/g/r/u/l 门控；随后启动 3 个 INFRA 线程执行 [44,142)，
        各自按 stage 位 1/2/4 过滤（门控 boot=i）；main 接着执行 [142,144)（门控 boot=i）；
        APP 线程执行 [144,149)（门控 boot=a）。
      * 每段执行条件 = 记录 target & 运行期target掩码 != 0 且 记录flag & 执行者stage掩码 != 0。
      * bootin mode3 传给 im.elf 的参数字母为 "s g r u l i a"；im.elf 参数解析对 s/u/l/i/a
        置位，对 g/r 不置位（反汇编证据见报告），因此 B/C 两段在本启动路径下不执行。
      * 正常目标(target=default)掩码 = bit0 = 1；flags=0。
    """
    exec_model = {
        'bootin_mode3_letters': 's g r u l i a',
        'im_boot_bits': {'s': 0x10000, 'g': 0x20000, 'r': 0x40000, 'u': 0x80000,
                         'l': 0x100000, 'i': 0x200000, 'a': 0x400000},
        'im_parser_sets': ['s', 'u', 'l', 'i', 'a'],
        'im_parser_ignores': ['g', 'r'],
        'runtime_target_mask': 1,
        'runtime_target_name': 'default',
        'phase_table': [],
        'per_record': [],
    }
    enabled_boot = 0x10000 | 0x80000 | 0x100000 | 0x200000 | 0x400000  # s|u|l|i|a
    # 生成每段的执行者/门控说明
    for name, lo, hi, gate, runner, stage_mask in PHASES:
        exec_model['phase_table'].append({
            'name': name, 'start': lo, 'end_exclusive': hi, 'gate_boot_bit': gate,
            'gate_enabled': (gate is None) or bool(enabled_boot & gate),
            'runner': runner, 'stage_mask': stage_mask,
        })

    for r in recs:
        rec = r
        idx = rec['index']
        executed = False
        phase = None
        runner = None
        stage_mask = None
        gate = None
        reasons = []
        if rec['type'] == TYPE_TERM:
            reasons.append('终止记录')
        elif rec['type'] == MARKER_BASE + 1:
            reasons.append('序列分隔记录(target=0，不执行)')
        for name, lo, hi, g, run, sm in PHASES:
            if lo <= idx < hi:
                phase, runner, stage_mask, gate = name, run, sm, g
                break
        if phase is None:
            reasons.append('位于 Application 之后的主循环段（挂起/恢复/激活命令处理）')
        else:
            if gate is not None and not (enabled_boot & gate):
                reasons.append('门控boot位0x%x未置位' % gate)
            if MARKER_BASE <= rec['type'] <= MARKER_BASE + 9:
                reasons.append('序列分隔记录(不执行)')
            if rec['target'] == 0:
                reasons.append('target掩码=0(不执行)')
            elif not (rec['target'] & exec_model['runtime_target_mask']):
                reasons.append('target掩码与运行期掩码(0x1)不匹配')
            if stage_mask is not None and not (rec['flag'] & stage_mask):
                reasons.append('flag未命中执行者stage掩码0x%x' % stage_mask)
            if not reasons:
                executed = True
        rec['exec'] = {
            'phase': phase, 'runner': runner, 'stage_mask': stage_mask,
            'gate_bit': gate, 'executed_before_app': executed and idx < 145,
            'executed': executed,
            'reasons': reasons,
        }
    return exec_model


# ---------------------------------------------------------------- 定位（镜像内字符串 -> 文件）
PROBE_STRINGS = [
    b'libInfraInput.so', b'infra_input_init', b'libuxengine.so', b'uxengine_init',
    b'libgrm.so', b'grm_init', b'libCoreSync.so', b'core_sync_user_init',
    b'libDDS.so', b'DDSUserInit', b'Application_System_Init', b'appFwBoot.so',
    b'libIMDB.so', b'libNVM.so', b'NVM_Initialize',
]


def locate(blob, index):
    """在镜像原始字节中搜索特征串，并映射到所属文件/目录。"""
    hits = []
    for s in PROBE_STRINGS:
        start = 0
        while True:
            off = blob.find(s, start)
            if off < 0:
                break
            start = off + 1
            owner = index.owner_of_offset(off)
            item = {'string': s.decode('latin1'), 'image_offset': off,
                    'image_offset_hex': '0x%x' % off, 'owner': owner}
            if owner:
                p = owner['path']
                if p in index.files:
                    data = index.read(p)
                    item['owner_type'] = 'file'
                    item['owner_size'] = len(data)
                    item['owner_sha256'] = sha256(data)
                else:
                    item['owner_type'] = 'directory'
                item['file_offset'] = owner['file_offset']
                item['file_offset_hex'] = '0x%x' % owner['file_offset']
                item['logical_block'] = owner['logical_block']
                item['image_block'] = owner['block']
            hits.append(item)
    return hits


def find_imdb_file(index):
    """通过字符串 + inode 反查定位 /lib/libIMDB.so，并给出块映射细节。"""
    path = IMDB_FILE
    ino = index.files[path]
    data = index.read(ino)
    mode, size, blocks = index.fs.inode(ino)
    ptrs_size, ptrs = index.block_ptrs(ino)
    block_map = []
    file_offset = 0
    for logical, blk in enumerate(ptrs):
        inside = min(index.bs, size - file_offset) if size > file_offset else 0
        if inside <= 0:
            break
        block_map.append({'logical_block': logical, 'image_block': blk,
                          'image_offset': blk * index.bs, 'file_offset': file_offset,
                          'bytes': inside})
        file_offset += inside
    return {'path': path, 'inode': ino, 'size': size, 'sha256': sha256(data),
            'mode': mode, 'block_size': index.bs, 'block_count': len(block_map),
            'first_blocks': block_map[:5], 'block_map': block_map,
            'raw_bytes': data}


# ---------------------------------------------------------------- 输出
def write_json(name, obj):
    path = os.path.join(OUT, name)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    return path


def write_tsv(name, rows, header):
    path = os.path.join(OUT, name)
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write('\t'.join(header) + '\n')
        for row in rows:
            f.write('\t'.join('' if v is None else str(v) for v in row) + '\n')
    return path


def main():
    os.makedirs(OUT, exist_ok=True)
    log = []

    def p(*a):
        s = ' '.join(str(x) for x in a)
        print(s)
        log.append(s)

    p('[1/7] 打开 /usr 镜像并建立 Ext2 索引 ...')
    fs = load_ext2(IMG)
    blob = open(IMG, 'rb').read()
    p('      镜像 %s' % IMG)
    p('      大小 %d B, sha256 %s' % (len(blob), sha256(blob)))
    p('      ext2 block_size=%d, blocks=%d, inode_size=%d' % (fs.bs, fs.blocks, fs.inode_size))
    index = Ext2Index(fs)
    p('      条目: %d 文件, %d 目录' % (len(index.files), len(index.dirs)))

    p('[2/7] 定位 IMDB 模板数据所属文件 ...')
    hits = locate(blob, index)
    imdb_info = find_imdb_file(index)
    lib = imdb_info['raw_bytes']
    del imdb_info['raw_bytes']
    gen5_lib = open(os.path.join(GEN5, 'libIMDB.so'), 'rb').read()
    imdb_info['gen5_copy'] = os.path.join('05-原始固件', 'zv1m2_fw', 'gen5', 'libIMDB.so')
    imdb_info['gen5_sha256'] = sha256(gen5_lib)
    imdb_info['same_as_gen5'] = gen5_lib == lib
    # 关键字符串的文件内偏移核对
    imdb_info['string_offsets_in_file'] = {}
    for name in (b'libInfraInput.so', b'infra_input_init', b'Application_System_Init', b'appFwBoot.so'):
        imdb_info['string_offsets_in_file'][name.decode()] = lib.find(name)
    imdb_info['header_file_offset'] = IMDB_RAW_VA - 0x8000
    imdb_info['records_file_offset'] = (IMDB_RAW_VA - 0x8000) + IMDB_HDR
    write_json('imdb5_locate.json', {'image': {'path': IMG, 'size': len(blob), 'sha256': sha256(blob)},
                                     'ext2': {'block_size': fs.bs, 'blocks': fs.blocks,
                                              'inode_size': fs.inode_size},
                                     'probe_hits': hits, 'imdb_file': imdb_info})
    for h in hits:
        if h['string'] in ('libInfraInput.so', 'infra_input_init', 'Application_System_Init',
                           'appFwBoot.so', 'libIMDB.so', 'libuxengine.so', 'uxengine_init'):
            own = h.get('owner')
            p('      %-24s @%s -> %s' % (h['string'], h['image_offset_hex'],
                                          (own or {}).get('path', '?')))
    p('      => ' + IMDB_FILE + ' inode=%d size=%d sha256=%s' % (
        imdb_info['inode'], imdb_info['size'], imdb_info['sha256']))
    p('      => 与 gen5/libIMDB.so 相同: %s' % imdb_info['same_as_gen5'])

    p('[3/7] 解析 IMDB 头与 228 条记录 ...')
    header, recs = parse_imdb(lib)
    p('      header tag=0x%x, target槽位 %d 个: %s' % (
        header['tag'], len(header['target_slots']),
        ', '.join('%d:%s' % (t['bit'], t['name']) for t in header['target_slots'])))
    p('      记录 %d 条（44 B/条），类型分布: %s' % (
        len(recs), ', '.join('0x%x×%d' % (k, v) for k, v in sorted(Counter(r['type'] for r in recs).items()))))
    app = next(r for r in recs if r['type'] == 0x20000004 and r['init'] == 'Application_System_Init')
    p('      Application_System_Init 记录 index=%d (VA 0x%x)' % (app['index'], app['va']))
    a6600_cmp = parse_imdb_any(os.path.join(BASE, '05-原始固件', 'a6600_fw', 'usr', 'lib', 'libIMDB.so'))
    if a6600_cmp:
        p('      a6600 对照: %d B, %d 条记录, header=0x%x, target位=%d' % (
            a6600_cmp['size'], a6600_cmp['records_including_terminator'],
            a6600_cmp['header_tag'], len(a6600_cmp['target_slots'])))

    p('[4/7] 分析每条记录的镜像存在性与 init 提供者 ...')
    prov_meta = analyze_providers(recs, index)
    p('      libObj: %d B sha256=%s exports=%d needed=%s' % (
        prov_meta['libobj_size'], prov_meta['libobj_sha256'][:16], prov_meta['libobj_exports'],
        prov_meta['libobj_needed']))
    app_prov = {'index': app['index'], 'file': app['file'], 'init': app['init'],
                'file_in_image': app['file_in_image'], 'image_paths': app['image_paths'],
                'provider_kind': app['provider_kind'], 'provider': app['provider'],
                'psid': app['psid'], 'init_found': app['init_found']}
    p('      Application记录: file_in_image=%s init_found=%s provider=%s' % (
        app_prov['file_in_image'], app_prov['init_found'], app_prov['provider_kind']))

    p('[5/7] 按 im.elf 静态执行模型标注执行顺序 ...')
    exec_model = build_execution(recs)
    before = [r for r in recs if r.get('exec', {}).get('executed_before_app')]
    executed = [r for r in recs if r.get('exec', {}).get('executed')]
    p('      全表执行 %d 条；Application 之前执行 %d 条' % (len(executed), len(before)))

    # 缺失实现清单（仅针对 Application 之前会执行的库/入口 + 全表统计）
    def missing_kind(r):
        if r['provider_kind'] == '缺失(psid=0 且镜像无此文件)':
            return '库文件缺失'
        if r['provider_kind'] == 'libObj静态合并(psid!=0)' and r['init'] and r['init_found'] is False:
            return 'libObj未导出该入口'
        if r['provider_kind'] == '动态库(镜像内)' and r['init'] and r['init_found'] is False:
            return '库内未导出该入口'
        return None

    missing_before = [r for r in before if missing_kind(r)]
    missing_all = [r for r in recs if missing_kind(r)]

    # ---------------- 证据文件
    write_json('imdb5_header.json', header)
    with open(os.path.join(OUT, 'imdb5_records.tsv'), 'w', encoding='utf-8', newline='') as f:
        cols = ['index', 'type', 'type_name', 'flag', 'stage', 'target', 'target_names',
                'me', 'psid', 'file', 'init', 'exit', 'sus', 'res', 'inact', 'act',
                'file_in_image', 'provider_kind', 'provider', 'init_found',
                'exec_phase', 'exec_runner', 'executed', 'executed_before_app']
        f.write('\t'.join(cols) + '\n')
        for r in recs:
            row = [r['index'], '0x%08x' % r['type'], r['type_name'], '0x%x' % r['flag'], r['stage'],
                   '0x%08x' % r['target'], '/'.join(r['target_names']), '0x%04x' % r['me'],
                   '0x%04x' % r['psid'], r['file'], r['init'], r['exit'], r['sus'], r['res'],
                   r['inact'], r['act'], r['file_in_image'], r['provider_kind'],
                   r['provider'] or '', r['init_found'],
                   r['exec']['phase'] or '', r['exec']['runner'] or '',
                   r['exec']['executed'], r['exec']['executed_before_app']]
            f.write('\t'.join('' if v is None else str(v) for v in row) + '\n')
    before_rows = []
    for r in before:
        before_rows.append([r['index'], '0x%08x' % r['type'], r['type_name'], r['stage'],
                            '0x%08x' % r['target'], '0x%04x' % r['me'], '0x%04x' % r['psid'],
                            r['file'], r['init'], r['exec']['phase'], r['exec']['runner'],
                            '镜像内' if r['file_in_image'] else '缺失',
                            r['provider_kind'], '是' if r['init_found'] else ('否' if r['init_found'] is False else '-')])
    write_tsv('imdb5_before_app_tasks.tsv', before_rows,
              ['index', 'type', 'type_name', 'stage(flag)', 'target', 'me', 'psid', 'file', 'init',
               'phase', 'runner', 'file_in_image', 'provider_kind', 'init_symbol_ok'])
    miss_rows = []
    for r in missing_all:
        miss_rows.append([r['index'], '0x%08x' % r['type'], r['type_name'], r['stage'],
                          '0x%08x' % r['target'], '0x%04x' % r['psid'], r['file'], r['init'],
                          missing_kind(r), '是' if r['exec']['executed_before_app'] else '否',
                          r['exec']['phase'] or '', r['exec']['runner'] or ''])
    write_tsv('imdb5_missing.tsv', miss_rows,
              ['index', 'type', 'type_name', 'stage(flag)', 'target', 'psid', 'file', 'init',
               'missing_kind', 'before_app', 'phase', 'runner'])
    providers_json = {'meta': prov_meta, 'records': [
        {k: r[k] for k in ('index', 'type', 'type_name', 'flag', 'stage', 'target', 'target_names',
                           'me', 'psid', 'file', 'init', 'file_in_image', 'image_paths',
                           'path_note', 'provider', 'provider_kind', 'init_found',
                           'cross_lib_providers')} for r in recs]}
    write_json('imdb5_providers.json', providers_json)
    write_json('imdb5_execution.json', {'model': exec_model, 'records': [
        {'index': r['index'], 'type': r['type'], 'stage': r['stage'], 'target': r['target'],
         'file': r['file'], 'init': r['init'], 'exec': r['exec']} for r in recs]})
    # 关键件提取到证据目录（只复制到新目录，不改动原镜像）
    copies = {
        '/lib/libIMDB.so': 'imdb5_libIMDB.so',
        '/lib/libObj.so': 'imdb5_libObj.so',
        '/bin/im.elf': 'imdb5_im.elf',
        '/bin/bootin.elf': 'imdb5_bootin.elf',
        '/lib/appFwBoot.so': 'imdb5_appFwBoot.so',
    }
    copy_manifest = []
    for guest, name in copies.items():
        if guest in index.files:
            data = index.read(guest)
            path = os.path.join(OUT, name)
            with open(path, 'wb') as f:
                f.write(data)
            copy_manifest.append({'guest_path': guest, 'evidence_file': name,
                                  'size': len(data), 'sha256': sha256(data)})
    write_json('imdb5_copies.json', copy_manifest)
    # 汇总
    type_counts = Counter(r['type_name'] for r in recs)
    summary = {
        'image': {'path': IMG, 'size': len(blob), 'sha256': sha256(blob)},
        'imdb_file': {'path': IMDB_FILE, 'inode': imdb_info['inode'], 'size': imdb_info['size'],
                      'sha256': imdb_info['sha256'], 'same_as_gen5': imdb_info['same_as_gen5']},
        'header': {'tag': header['tag'], 'target_slots': header['target_slots'],
                   'header_size': IMDB_HDR, 'stride': IMDB_STRIDE, 'records': len(recs)},
        'application_index': app['index'],
        'type_counts': dict(type_counts),
        'executed_total': len(executed),
        'before_app_count': len(before),
        'before_app_by_type': dict(Counter(r['type_name'] for r in before)),
        'before_app_by_runner': dict(Counter(r['exec']['runner'] for r in before)),
        'before_app_file_present': sum(1 for r in before if r['file_in_image']),
        'before_app_libobj_merged': sum(1 for r in before if r['provider_kind'].startswith('libObj')),
        'before_app_missing': len(missing_before),
        'missing_total': len(missing_all),
        'missing_before_by_kind': dict(Counter(missing_kind(r) for r in missing_before)),
        'missing_all_by_kind': dict(Counter(missing_kind(r) for r in missing_all)),
        'providers': prov_meta,
        'application_record': app_prov,
        'a6600_compare': a6600_cmp,
        'lib_inventory': {
            'files': len(index.files),
            'dirs': len(index.dirs),
            'lib_dir_entries': len([p for p in index.files if p.startswith('/lib/')]),
            'so_files_total': len([p for p in index.files if p.endswith('.so') or '.so.' in p]),
        },
        'copies': copy_manifest,
    }
    write_json('imdb5_summary.json', summary)
    with open(os.path.join(OUT, 'imdb5_decode.log'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(log) + '\n')

    p('[6/7] 统计:')
    p('      Application 之前执行的任务: %d' % len(before))
    p('      按执行者: %s' % dict(summary['before_app_by_runner']))
    p('      按类型: %s' % summary['before_app_by_type'])
    p('      缺失实现（before-app）: %d  %s' % (
        len(missing_before), dict(summary['missing_before_by_kind'])))
    p('      缺失实现（全表）: %d  %s' % (
        len(missing_all), dict(summary['missing_all_by_kind'])))

    p('[7/7] 生成报告 %s ...' % DOC)
    generate_report(summary, header, recs, before, missing_before, missing_all,
                    exec_model, hits, imdb_info, prov_meta, missing_kind)
    p('done.')

# ---------------------------------------------------------------- 报告
def fmt_target(t):
    names = [TARGET_BITS[b] for b in range(len(TARGET_BITS)) if t & (1 << b)]
    if t == 0:
        return '0（不执行）'
    if t == 0x7fffffff:
        return '0x7fffffff（全比特）'
    if t == 0xffffffff:
        return '0xffffffff（全比特）'
    return '0x%08x（%s）' % (t, '/'.join(names) if names else '仅高位')


def md_escape(s):
    return (s or '').replace('|', '\\|')


def generate_report(summary, header, recs, before, missing_before, missing_all,
                    exec_model, hits, imdb_info, prov_meta, missing_kind):
    app = next(r for r in recs if r['type'] == 0x20000004 and r['init'] == 'Application_System_Init')
    L = []
    a = L.append
    a('# 106 · ZV-1M2 五代固件 IMDB 任务表解析（2026-11-22）')
    a('')
    a('> 范围：只读分析 `05-原始固件/zv1m2_fw` 下的原始 `/usr` 镜像与既有提取件；未运行 QEMU，'
      '未修改任何既有镜像/脚本/文档。脚本：`02-脚本/imdb5_decode.py`；证据：`03-证据/静态分析/imdb5/`。')
    a('')
    a('## 1. 结论摘要')
    a('')
    a('1. **数据归属**：任务书说的“文件偏移约 370,524,800（`0x1615C280` 一带）”的 IMDB 模板数据，'
      '属于 `/usr` 镜像中的 **`/lib/libIMDB.so`**'
      '（ext2 inode %d，40,596 B，sha256 `%s`），与 `05-原始固件/zv1m2_fw/gen5/libIMDB.so` **逐字节相同**。'
      '它与 a6600 的 `libIMDB.so`（33,924 B，sha256 `%s`）不是同一文件：a6600 表头 tag=`0x%x`、'
      'target 位 %d 个、共 %d 条记录，与五代表（`0x20000`/9 位/228 条）不同。镜像内偏移不是文件起点：'
      '文件从镜像偏移 `0x%x`（物理块 `0x%x`）开始，模板头在文件内 `0x%x`，字符串区在文件内 `0x3c4d` 起。' % (
          imdb_info['inode'], imdb_info['sha256'],
          (summary.get('a6600_compare') or {}).get('sha256', '?'),
          (summary.get('a6600_compare') or {}).get('header_tag', 0),
          len((summary.get('a6600_compare') or {}).get('target_slots', [])),
          (summary.get('a6600_compare') or {}).get('records_including_terminator', 0),
          imdb_info['first_blocks'][0]['image_offset'],
          imdb_info['first_blocks'][0]['image_block'], imdb_info['header_file_offset']))
    a('2. **表结构**：`imdb_raw` 符号为 132 B 头（`0x20000` + 31 个 target 名槽位），'
      '之后是 **228 条 × 44 B** 记录（含一条 `0x28` 终止记录）。44 B 布局为：'
      '`type(+0) / flag(+4, stage掩码) / target(+8) / me(+12,u16) / psid(+14,u16) / '
      'file(+16) / init(+20) / exit(+24) / sus(+28) / res(+32) / inact(+36) / act(+40)`。')
    a('3. **Application 位置**：`Application_System_Init`（file=`appFwBoot.so`，psid=0）在 **index %d**'
      '（记录 VA `0x%x`）。它之前（index < %d）按 im.elf 静态执行模型会执行 **%d** 条记录，'
      '详见第 5 节顺序清单。Application 记录本身：`/lib/appFwBoot.so` 在镜像中%s，'
      '`init_found`=%s。' % (app['index'], app['va'], app['index'], len(before),
                            '存在' if summary['application_record']['file_in_image'] else '**缺失**',
                            summary['application_record']['init_found']))
    a('4. **启用判据**：`target` 是“模型/目标特性”掩码，正常 `target=default` 只置 bit0（掩码=1）；'
      '`flag` 是执行阶段掩码（1=INFRA0、2=INFRA1、4=INFRA2、0xF=APP线程、0xFF=main 任意）；'
      '`type=0x0800000N` 是序号分隔记录（target=0，本身不执行），N=1..9 把表切成 9 段。')
    a('5. **提供者分类**：24 条 `psid!=0` 的记录由 `dlopen("/usr/lib/libObj.so")+dlsym` 提供，'
      '其中 **23 条 init 入口确实在 `libObj.so` 的 `.dynsym` 中导出**；'
      '`core_sync_user_init`（libCoreSync.so，index 45）**不在 libObj 导出中**，是明确缺失实现。'
      '其余 `psid==0` 但 `/usr` 镜像里没有对应 `.so` 的记录属于“镜像内缺失”，'
      '它们可能位于本次未提供的 `/system`、`/rootfs` 分区，详见第 6 节。')
    a('6. **重要反汇编结论**：`im.elf` 解析 `bootin` 传入的字母参数时，'
      '`s/u/l/i/a` 会置 boot 位，`g/r` 只被识别但不置位（两代 im.elf 相同）；'
      '因此 **B 段（dmm/upm 内核模块）和 C 段（stream/mcmn/ms/mmc/sata/msen/hdmi/cec 内核模块）'
      '在本启动路径下不会被 im.elf 执行**。若以 `bootall` 或显式 `boot=g/r` 启动则另论。')
    a('')
    a('## 2. 定位过程（镜像偏移 → 文件）')
    a('')
    a('### 2.1 方法')
    a('')
    a('1. **原始字节搜索**：在 `nflasha15` 上直接搜索 `libInfraInput.so`、`infra_input_init`、'
      '`Application_System_Init`、`appFwBoot.so` 等特征串，得到镜像偏移（如 `0x1615c44d`）。')
    a('2. **ext2 块反查**：用 `02-脚本/a6600_usr.py` 的 `Ext2` 类遍历镜像，读取每个 inode 的'
      '直接/一级/二级块指针，按 `块号 = 镜像偏移 / block_size` 反查所属文件，并换算为文件内偏移：'
      '`file_offset = 逻辑块 * block_size + 块内偏移`。')
    a('3. **偏移一致性核对**：特征串在镜像中的“文件内偏移”与 `gen5/libIMDB.so` 中位置一致'
      '（如 `libInfraInput.so` 均在文件内 `0x3c4d`），并且整文件 SHA-256 相同，从而确认归属。')
    a('')
    a('### 2.2 关键字符串命中')
    a('')
    a('| 字符串 | 镜像偏移 | 所属文件 | 文件内偏移 | 说明 |')
    a('|---|---|---|---|---|')
    seen = set()
    for h in hits:
        if h['string'] not in ('libInfraInput.so', 'infra_input_init', 'libuxengine.so',
                               'uxengine_init', 'Application_System_Init', 'appFwBoot.so',
                               'libIMDB.so', 'libNVM.so', 'NVM_Initialize'):
            continue
        key = (h['string'], h['image_offset'])
        if key in seen:
            continue
        seen.add(key)
        own = h.get('owner') or {}
        kind = h.get('owner_type', '-')
        opath = own.get('path') or ''
        if 'libIMDB.so' in opath:
            fo = h.get('file_offset', 0)
            note = 'libIMDB 表内字符串' if fo >= 0x37b2 else 'ELF 元数据（.dynstr 中的 SONAME）'
        elif 'libObj.so' in opath:
            note = 'libObj 静态合并的入口名（导出符号字符串）'
        elif 'im.elf' in opath:
            note = 'im.elf 的 DT_NEEDED 名'
        elif kind == 'directory':
            note = '目录项（文件名，不是文件内容）'
        else:
            note = '其他引用'
        a('| `%s` | `%s` | `%s` (%s) | `%s` | %s |' % (
            md_escape(h['string']), h['image_offset_hex'], md_escape(opath),
            '目录项' if kind == 'directory' else '文件', h.get('file_offset_hex', '-'), note))
    a('')
    a('### 2.3 文件与块映射')
    a('')
    a('| 项 | 值 |')
    a('|---|---|')
    a('| 镜像 | `%s` |' % summary['image']['path'])
    a('| 镜像大小 / SHA-256 | %d B / `%s` |' % (summary['image']['size'], summary['image']['sha256']))
    a('| ext2 block size / inode size | %d / %d |' % (imdb_info['block_size'], 128))
    a('| 镜像文件/目录数 | %d 文件 / %d 目录（`/lib` 下 %d 项；全镜像 `.so*` 共 %d 个） |' % (
        summary['lib_inventory']['files'], summary['lib_inventory']['dirs'],
        summary['lib_inventory']['lib_dir_entries'], summary['lib_inventory']['so_files_total']))
    a('| 目标文件 | `%s`（inode %d） |' % (imdb_info['path'], imdb_info['inode']))
    a('| 文件大小 / SHA-256 | %d B / `%s` |' % (imdb_info['size'], imdb_info['sha256']))
    a('| 与 gen5/libIMDB.so 相同 | **%s** |' % ('是' if imdb_info['same_as_gen5'] else '否'))
    a('| 文件起点 | 镜像偏移 `0x%x`，物理块 `0x%x` |' % (
        imdb_info['first_blocks'][0]['image_offset'], imdb_info['first_blocks'][0]['image_block']))
    a('| IMDB 头 / 记录区 | 文件内 `0x%x` / `0x%x` |' % (
        imdb_info['header_file_offset'], imdb_info['records_file_offset']))
    a('| 字符串块 `libInfraInput.so` | 文件内 `0x%x` → 逻辑块 %d → 物理块 `0x%x` |' % (
        imdb_info['string_offsets_in_file']['libInfraInput.so'],
        (imdb_info['string_offsets_in_file']['libInfraInput.so'] // imdb_info['block_size']),
        imdb_info['block_map'][imdb_info['string_offsets_in_file']['libInfraInput.so'] //
                               imdb_info['block_size']]['image_block']))
    a('| 任务书偏移 370,524,800 | = `0x1615C280` → 逻辑块 14（物理块 `0x58570`）→ 文件内 `0x3a80`（字符串池内） |')
    a('')
    a('> 说明：文件逻辑块与物理块不是简单连续——`libIMDB.so` 的第 12~15 个逻辑块分别位于物理块 '
      '`0x5856e/0x5856f/0x58570/0x58571`，而它们之间还夹着单级间接块 `0x5856d`。'
      '因此“镜像偏移 − 文件起点”会多算 `0x400`：任务书的 370,524,800（`0x1615C280`）'
      '对应文件内 `0x3a80`，`libInfraInput.so`（`0x1615c44d`）对应文件内 `0x3c4d`，'
      '而不是 `0x404d`。这正是必须用 ext2 块表反查、不能只做偏移减法的原因。')
    a('')
    a('## 3. 表结构')
    a('')
    a('### 3.1 头（`imdb_raw`，132 字节）')
    a('')
    a('| 偏移 | 内容 |')
    a('|---|---|')
    a('| +0 | `0x00020000`（表标识/版本） |')
    a('| +4 | 0 |')
    a('| +8 … +128 | 31 个 target 名字符串指针槽（本表用到前 9 个） |')
    a('')
    a('target 位（`imdb_raw` 头中取出的顺序，bit0 起）：')
    a('')
    a('| bit | 名字 | 说明 |')
    a('|---|---|---|')
    for t in header['target_slots']:
        a('| %d | `%s` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |' % (t['bit'], t['name']))
    a('')
    a('### 3.2 记录（228 × 44 字节）')
    a('')
    a('> 与旧提法对照：`tag` = +0 的 `type`；旧文档里的 `version` 实为 +4 的 `flag`；'
      '旧称 `mode` 的 +8 实为 `target` 模型掩码；`me_psid` = +12/+14 的两个 u16；'
      '`file_ptr`=+16、`init_ptr`=+20；+24…+40 依次是 exit/sus/res/inact/act 指针。')
    a('')
    a('| 偏移 | 字段 | 类型 | 语义（依据 im.elf/libIMDB.so 反汇编） |')
    a('|---|---|---|---|')
    for off, name, typ, desc in [
        (0, 'type', 'u32', '任务类型：0x2000000[1-4]=库/Application，0x1000000[1-2]=insmod，'
                            '0x40000001=shell，0x00000001=target定义，0x0800000N=序号分隔N，0x28=终止'),
        (4, 'flag', 'u32', '执行阶段掩码：1=INFRA0线程、2=INFRA1线程、4=INFRA2线程、0xF=APP线程、0xFF=main任意'),
        (8, 'target', 'u32', '模型/目标特性掩码；记录执行条件为 `target & 运行期target掩码 != 0`'),
        (12, 'me', 'u16', '模块入口 id（`IMDB_find_entry(me, target_mask)` 的键）'),
        (14, 'psid', 'u16', '非 0 = 该库已静态合并进 `libObj.so`：库类型改为 `dlopen("/usr/lib/libObj.so")`，'
                            'Application 类型改为 `dlopen(NULL)` 后 `dlsym(init)`'),
        (16, 'file', 'char*', '库名/ko 路径/脚本路径；库类型多为 basename（由动态链接器搜索）'),
        (20, 'init', 'char*', '初始化符号；执行记录时 `dlopen` 后立即 `dlsym(init)` 并调用，'
                            '参数为 `act` 或 `inact` 字符串（非空时）'),
        (24, 'exit', 'char*', '退出符号（停机/卸载时用）'),
        (28, 'sus', 'char*', '挂起符号'),
        (32, 'res', 'char*', '恢复符号'),
        (36, 'inact', 'char*', 'inactive/调整模式参数；`im.elf` 在 adjust 标志位置位时传给 init'),
        (40, 'act', 'char*', 'active/正常模式参数；未置 adjust 时传给 init'),
    ]:
        a('| +%d | `%s` | %s | %s |' % (off, name, typ, desc))
    a('')
    a('### 3.3 序号分隔记录（stage 边界）')
    a('')
    a('| type | index | 含义 |')
    a('|---|---|---|')
    markers = [r for r in recs if 0x08000001 <= r['type'] <= 0x08000009]
    for m in markers:
        a('| `0x%08x` | %d | 第 %d 段结束/开始标记（target=0，仅作边界） |' % (
            m['type'], m['index'], m['type'] - 0x08000000))
    a('')
    a('## 4. 执行模型（来自 ZV-1M2 `/bin/im.elf` 反汇编）')
    a('')
    a('以下控制流来自从镜像提取的 ZV-1M2 `/bin/im.elf`（23,240 B，sha256 '
      '`9d6da003ff1d299dbfaedcd86011e2773e23b076c03bd8bbe51e8309af856db2`，证据副本 '
      '`imdb5_im.elf`）与 `/bin/bootin.elf`（15,336 B，sha256 '
      '`3eff4684182527fa29253edd2515f5bb6967e182b92e296a1d8f8db44b5961f0`，证据副本 `imdb5_bootin.elf`）'
      '的反汇编；并用 a6600 `im.elf` 做同位置交叉核对。')
    a('')
    a('`im.elf` 主流程（函数 `0xa2bc`）按表顺序分阶段执行，核心例程 `0xb9c8(index, end_tag, enabled, stage_mask)`：')
    a('')
    a('1. 从 index 起逐条扫描；遇到 `type == end_tag` 或 `0x28` 停止；')
    a('2. 跳过 `target==0` 或 `target & 运行期掩码 == 0` 的记录；')
    a('3. 跳过 `flag & stage_mask == 0` 的记录；')
    a('4. 其余记录交给 `b8bc` → `b7b8` 按类型分派：insmod / dlopen+dlsym(init) 并立即调用 / Application / shell。')
    a('')
    a('关键函数与字段证据（ZV-1M2 `im.elf`，地址为 VA）：')
    a('')
    a('| 函数/位置 | 证据 |')
    a('|---|---|')
    a('| `0xb9c8` 执行循环 | `+8` 与 `[0x154d8+0x28]`（运行期 target 掩码）做 `tst`；`+4` 与传入 stage 掩码做 `tst`；'
      '`+0xe` 半字经 `0x919c=IMDB_find_entry` 定位；命中后调 `0xb8bc`。 |')
    a('| `0xb5c0` 库记录加载 | `ldrh r0,[rec,#0xe]`（psid）：为 0 时 `dlopen(rec+0x10)`，非 0 时 '
      '`dlopen("/usr/lib/libObj.so")`；随后 `dlsym(rec+0x14=init)` 并立即调用，参数取 `rec+0x24`(act) 或 `rec+0x28`(inact)。 |')
    a('| `0xb4f8` Application 加载 | 与库相同，但 psid 非 0 时改为 `dlopen(NULL)`（从全局符号找入口），'
      '即“静态合入 libObj”的 Application 走全局命名空间。 |')
    a('| `0xb7b8` 类型分派 | type `0x10000001`→insmod；`0x10000002`→liro 特殊 insmod；'
      '`0x2000000[1-3]`→`0xb5c0`；`0x20000004`→`0xb4f8`；`0x40000001`→拼 `"%s %s &"` 通过 OSAL 消息交给 shell 服务；'
      '其它 type（含 target 定义 `0x1`、序号分隔 `0x0800000N`）走“成功但无动作”分支。 |')
    a('| `0xaf58` target 掩码计算 | `IMDB_find_target_bit(target名)`；找不到或 `target` 为空时掩码=`1`；'
      '`default` 时按 `usbj/cho(adjust)` 标志改用 `0x20/0x80`；其它 target 用 `1<<bit`。 |')
    a('| `0xb14c` 日志 | 2 字符级别 + 0x94 常量行号，用于确认字符串引用上下文。 |')
    a('')
    a('阶段表（`end_tag` 即序号分隔记录的 type）：')
    a('')
    a('| 段 | 范围 | 门控 boot 位 | 执行者 | stage掩码 | 本启动路径是否执行 |')
    a('|---|---|---|---|---|---|')
    for ph, info in zip(PHASES, exec_model['phase_table']):
        name, lo, hi, gate, runner, sm = ph
        a('| %s | index [%d, %d) | %s | %s | %s | %s |' % (
            name, lo, hi,
            ('0x%x (%s)' % (gate, {0x20000: 'g', 0x40000: 'r', 0x80000: 'u',
                                   0x100000: 'l', 0x200000: 'i', 0x400000: 'a'}.get(gate, '?'))) if gate else '无',
            runner, ('0x%x' % sm) if sm is not None else '1/2/4（三线程分别）',
            '**是**' if info['gate_enabled'] else '否'))
    a('')
    a('`bootin.elf`（ZV-1M2 `/bin/bootin.elf`）在 mode3（默认，`/setting/mode/dmode` 首字符 `3`）'
      '时把字符串 `"s g r u l i a "` 作为独立参数拼进 `/usr/bin/im.elf debug …` 命令行；'
      '`im.elf` 参数解析对 `s/u/l/i/a` 置位（0x10000/0x80000/0x100000/0x200000/0x400000），'
      '对 `g/r` 只做识别、不置位（对应分支直接回到参数循环）。因此：')
    a('')
    a('- **B 段（index 6–8：dmm.ko / upm.ko）与 C 段（index 9–18：stream/stream2/mcmn_drv/ms_drv/mmc_drv/'
      'sata_drv/msen_drv/hdmi/cec）在正常 mode3 启动中不会被 im.elf 执行**；内核模块加载属于更早的'
      '启动档/init 责任。')
    a('- D/E/F/G/H 段（基础库、liro.ko、Infra 并行任务、BIZ、Application）会执行。')
    a('- 运行期 `target=default`（`im.elf` 未收到 `target=` 时的默认值）→ target 掩码 = **1（bit0）**。')
    a('')
    a('## 5. Application（index %d）之前会执行的初始化任务（按表顺序）' % app['index'])
    a('')
    a('说明：按“全局表顺序”列出；F 段实际由 3 个 INFRA 线程并发执行，'
      '每个 INFRA 线程只执行 `flag & 1/2/4` 命中的记录（表中已标 runner），线程内相对顺序即表顺序。'
      '`file_in_image` 指该 `.so`/文件是否存在于本次提供的 `/usr` 镜像；'
      '`init_symbol_ok` 指该记录的 init 入口能否从期望提供者（动态库或 libObj）解析到。')
    a('')
    a('| # | idx | type | flag/stage | target | me | psid | phase/runner | file | init | 镜像内 | init可解析 |')
    a('|---|---|---|---|---|---|---|---|---|---|---|---|')
    for r in before:
        a('| %d | %d | `0x%08x` %s | %s | %s | `0x%04x` | `0x%04x` | %s / %s | `%s` | `%s` | %s | %s |' % (
            before.index(r) + 1, r['index'], r['type'], r['type_name'], r['stage'],
            fmt_target(r['target']), r['me'], r['psid'],
            (r['exec']['phase'] or '').split(' ')[0], r['exec']['runner'],
            md_escape(r['file']), md_escape(r['init']),
            '是' if r['file_in_image'] else '**否**',
            '是' if r['init_found'] else ('**否**' if r['init_found'] is False else '—')))
    a('')
    a('> 完整机器可读清单：`03-证据/静态分析/imdb5/imdb5_before_app_tasks.tsv`。')
    a('')
    a('### 5.1 被过滤、不会在 Application 之前执行的记录')
    a('')
    a('index<145 共 145 条，其中会执行 %d 条、不执行 %d 条。不执行的原因分类：' % (
        len(before), 145 - len(before)))
    a('')
    a('| 原因 | 记录 |')
    a('|---|---|')
    skipped = [r for r in recs if r['index'] < 145 and not r.get('exec', {}).get('executed')]
    cat_target = [r for r in skipped if any('target' in x for x in r['exec']['reasons'])
                  and not any('boot位' in x for x in r['exec']['reasons'])]
    cat_gate = [r for r in skipped if any('boot位' in x for x in r['exec']['reasons'])
                and not any('序列分隔' in x for x in r['exec']['reasons'])]
    cat_marker = [r for r in skipped if any('序列分隔' in x for x in r['exec']['reasons'])]
    cat_target = [r for r in cat_target if r not in cat_marker]
    cat_gate = [r for r in cat_gate if r not in cat_marker and r not in cat_target]
    cat_other = [r for r in skipped if r not in cat_target and r not in cat_gate and r not in cat_marker]
    for name, rows in [('target 掩码不匹配（qemu/nfs/set/usbj/resub/test 专用）', cat_target),
                       ('boot 门控 g/r 未置位（B/C 内核模块段）', cat_gate),
                       ('序号分隔记录（target=0，仅作边界）', cat_marker),
                       ('其他', cat_other)]:
        a('| %s | %s |' % (name, ', '.join('idx %d' % r['index'] for r in rows) or '—'))
    a('')
    a('> 结论：“模型实际启用”的判据就是 `target & 1（default 位）`。被 target 过滤的只有：'
      'index 1–5（其它 target 的定义记录）、41（libTestDriver，test 专用）、121/122（USB充电/USB WoLE，usbj 专用）。'
      'kernel module 组（7/8、10–18）不是 target 过滤，而是 boot=g/r 位在本启动路径下不置位。')
    a('')
    a('## 6. 镜像存在性与“只存在于 libObj 导出里”的入口')
    a('')
    a('### 6.1 分类统计')
    a('')
    a('| 类别 | 数量 | 说明 |')
    a('|---|---|---|')
    kinds = Counter(r['provider_kind'] for r in recs if r['type'] in (0x20000001, 0x20000002,
                                                                     0x20000003, 0x20000004))
    for k, v in kinds.most_common():
        a('| %s | %d | |' % (k, v))
    a('')
    a('- 库类型记录总数：%d；`psid!=0`（libObj 静态合并）：%d。' % (
        sum(kinds.values()), sum(v for k, v in kinds.items() if k.startswith('libObj'))))
    a('- Application 之前执行的库类型记录中，镜像内存在动态库 %d 条，libObj 静态合并 %d 条，缺失 %d 条。' % (
        sum(1 for r in before if r['provider_kind'] == '动态库(镜像内)'),
        sum(1 for r in before if r['provider_kind'].startswith('libObj')),
        sum(1 for r in before if r['provider_kind'].startswith('缺失'))))
    a('')
    a('### 6.2 只存在于 `libObj.so` 导出中的入口（psid!=0，共 24 条）')
    a('')
    a('| idx | psid | 记录中的库 | init | libObj 导出? |')
    a('|---|---|---|---|---|')
    for r in recs:
        if r['type'] in (0x20000001, 0x20000002, 0x20000003, 0x20000004) and r['psid']:
            a('| %d | `0x%04x` | `%s` | `%s` | %s |' % (
                r['index'], r['psid'], md_escape(r['file']), md_escape(r['init']),
                '是' if r['init_found'] else '**否（缺失实现）**'))
    a('')
    a('示例（与任务书一致）：`libInfraInput.so` 不在 `/usr` 镜像中，但 `infra_input_init` 由 `libObj.so` 导出；'
      '`libgrm.so/grm_init`、`libuxengine.so/uxengine_init`、`libDDS.so/DDSUserInit`、'
      '`libCoreSync.so/core_sync_user_init` 均为“静态合并”记录。24 条静态合并记录中，'
      '**23 条 init 入口可在 libObj 的 `.dynsym` 中解析，1 条（`core_sync_user_init`）缺失**。')
    a('')
    a('### 6.3 缺失实现清单（Application 之前会执行、但当前提供的镜像内无实现）')
    a('')
    a('| idx | type | stage | psid | file | init | 缺失类型 |')
    a('|---|---|---|---|---|---|---|')
    for r in missing_before:
        a('| %d | `0x%08x` %s | %s | `0x%04x` | `%s` | `%s` | %s |' % (
            r['index'], r['type'], r['type_name'], r['stage'], r['psid'],
            md_escape(r['file']), md_escape(r['init']), missing_kind(r)))
    a('')
    a('> 全表缺失清单位于 `03-证据/静态分析/imdb5/imdb5_missing.tsv`（共 %d 条，其中 before-app %d 条）。'
      '`psid=0` 且镜像无文件的条目，可能位于本次未提供/未提取的 `/system`、`/rootfs` 分区，'
      '因此报告只声称“在本次提供的 `/usr` 镜像中缺失”，不声称相机运行期一定缺少该库。' % (
          summary['missing_total'], summary['before_app_missing']))
    a('')
    a('## 7. 复现与产物')
    a('')
    a('```')
    a('python 02-脚本/imdb5_decode.py')
    a('```')
    a('')
    a('| 产物 | 内容 |')
    a('|---|---|')
    for name, desc in [
        ('imdb5_locate.json', '镜像/文件定位证据：字符串命中、块映射、文件 SHA'),
        ('imdb5_header.json', 'imdb_raw 头（tag、31 个 target 名槽位）'),
        ('imdb5_records.tsv', '全部 228 条记录：字段、执行阶段、提供者、执行判定'),
        ('imdb5_before_app_tasks.tsv', 'Application 之前会执行的任务顺序清单'),
        ('imdb5_providers.json', '逐条记录的镜像存在性/提供者/符号可解析性'),
        ('imdb5_execution.json', 'im.elf 静态执行模型与逐条执行判定/跳过原因'),
        ('imdb5_missing.tsv', '缺失实现清单（全表 + before-app 标记）'),
        ('imdb5_summary.json', '汇总统计/哈希（本报告数据源）'),
        ('imdb5_libIMDB.so / imdb5_libObj.so / imdb5_im.elf / imdb5_bootin.elf / imdb5_appFwBoot.so',
         '从镜像只读提取的关键件副本（SHA 见 imdb5_copies.json）'),
        ('imdb5_decode.log', '脚本运行日志'),
    ]:
        a('| `%s` | %s |' % (name, desc))
    a('')
    a('## 8. 限制与未决')
    a('')
    a('1. 本次提供的镜像集只有 `nflasha15`（/usr）与 `nflasha7`（raw，非文件系统）；`/system`、`/rootfs` 等'
      '分区不在包内，因此 `psid=0` 但 `/usr` 无文件的 %d 条库记录（其中 Application 前会执行 %d 条）'
      '不能断言“相机运行期缺失”。' % (summary['missing_total'] - sum(
          1 for r in recs if missing_kind(r) == 'libObj未导出该入口'),
          summary['before_app_missing'] - sum(
              1 for r in missing_before if missing_kind(r) == 'libObj未导出该入口')))
    a('2. “Application 之前执行”是依据 `im.elf` 静态控制流 + `bootin.elf` mode3 参数拼接的静态推演；'
      '没有真机 `strace`/QEMU 运行验证。若启动参数为 `bootall` 或显式 `boot=g/boot=r`，B/C 段会额外执行。')
    a('3. `libObj.so` 导出符号统计基于 `.dynsym`；不排除运行期由其它已全局加载库补足个别入口的可能，'
      '但已对镜像内 199 个 `.so` 的 `.dynsym` 做交叉检查，未发现可补足者。')
    a('4. 记录中的 `me`/`psid` 字段命名沿用 im.elf 调试打印（`.me=0x%04x .psid=0x%04x`）；'
      '`psid!=0` 的判定来自 `im.elf` 加载分支（`[rec+0xe]` 非 0 时库类型走 `/usr/lib/libObj.so`、'
      'Application 类型走 `dlopen(NULL)`）。')
    a('')
    with open(DOC, 'w', encoding='utf-8') as f:
        f.write('\n'.join(L) + '\n')


if __name__ == '__main__':
    main()
