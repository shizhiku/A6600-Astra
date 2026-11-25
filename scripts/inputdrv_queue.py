# -*- coding: utf-8 -*-
"""inputdrv_queue.py — OSAL/UIPC 队列语义静态分析（四代/五代 osal_uipc.ko + libosal_uipc.so）。

回答的核心问题：同一条 qid 上多个消费者/多次注册时，消息如何投递。
输出到 03-证据/静态分析/input_drv/：
  inputdrv_osal_uipc_ko_<gen>_inventory.txt     .ko 符号与节
  inputdrv_osal_uipc_ko_<gen>_<func>.dis.txt    重定位感知反汇编
  inputdrv_libosal_uipc_<gen>_<func>.dis.txt    ET_DYN 反汇编（PLT/字面量/字符串）
  inputdrv_libosal_uipc_<gen>_symbols.txt       导出符号表
只读，不执行目标代码。
"""
import io
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'
OUT.mkdir(exist_ok=True)

# 从 inputdrv_ko.py 复用 ET_REL 工具
import importlib.util
_spec = importlib.util.spec_from_file_location('ko_mod', BASE / '02-脚本/inputdrv_ko.py')
ko_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ko_mod)
RelElf = ko_mod.RelElf
R_ARM_CALL, R_ARM_JUMP24, R_ARM_ABS32 = 28, 29, 2


def dis_ko_func(elf, name):
    f = next((s for s in elf.funcs if s['name'] == name), None)
    if f is None:
        return f';; function {name} not found\n'
    lines, calls, lits = ko_mod.analyze_function(elf, f)
    return '\n'.join(lines)


def ko_inventory(elf):
    L = [f'FILE {elf.path.name}', f'SHA256 {__import__("hashlib").sha256(elf.data).hexdigest()}']
    L.append('== FUNCTIONS ==')
    for s in elf.funcs:
        L.append(f'{s["shndx"]:3d} {s["value"]:08x} size={s["size"]:6d} {s["name"]}')
    L.append('== EXPORTED (__ksymtab) ==')
    # __ksymtab 由 8 字节 {value_offset, name_offset} 组成，重定位可解析
    for tgt, m in elf.rels.items():
        if elf.secname(tgt) != '__ksymtab':
            continue
        for off, (nm, typ, si) in sorted(m.items()):
            rv = elf.resolve_reloc_value(tgt, off)
            L.append(f'  off=0x{off:x} sym={nm} -> {rv[1] if rv else "?"}')
    L.append('== .data ==')
    d = elf.secdata(17) if len(elf.secs) > 17 else b''
    for off in range(0, len(d), 4):
        w = struct.unpack_from('<I', d, off)[0]
        rv = elf.resolve_reloc_value(17, off)
        L.append(f'  +0x{off:03x}: 0x{w:08x} {("reloc " + rv[1]) if rv else ""}')
    return '\n'.join(L)


KO_FUNCS = ['osal_snd_msg', 'osal_rcv_msg_tmo', 'reg_msg_queue_cb', 'osal_snd_sync_msg',
            'osal_reg_msg_queue_cb', 'osal_reg_sync_msg_queue_cb', 'osal_unreg_msg_queue_cb',
            'unreg_msg_queue_cb', 'osal_set_msgq_broadcast_mode', 'osal_set_msgq_log_mode',
            '__k_4u_reg_msg_queue_cb', '__k_4u_unreg_msg_queue_cb', '__k_4u_rcv_msg_tmo',
            '__k_4u_snd_msg', '__k_4u_snd_sync_msg', '__k_4u_set_msgq_broadcast_mode',
            '__k_4u_set_msgq_log_mode', '__k_4u_connect', '__k_4u_valloc_msg_wait',
            '__k_4u_free_msg', '__k_4u_dynamic_id', 'finish_callback', 'delete_cbs',
            '__k_user_msg_cb', '__rcv_msg_cb', 'alloc_cb', 'free_cb', 'msgq_dump']


class Dso:
    """ET_DYN 只读反汇编：PLT 解析 + 字面量 + 字符串。"""

    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.e = ELFFile(io.BytesIO(self.data))
        self.secs = list(self.e.iter_sections())
        self.segs = [s for s in self.e.iter_segments() if s['p_type'] == 'PT_LOAD']
        self.dynsym = self.e.get_section_by_name('.dynsym')
        self.syms = []
        for s in self.dynsym.iter_symbols():
            self.syms.append((s.name, int(s['st_value']), int(s['st_size']), s['st_info']['type'],
                              s['st_shndx']))
        # PLT: ARM 12 字节三元组
        got = {}
        for sec in self.secs:
            if sec.name == '.rel.plt':
                for r in sec.iter_relocations():
                    got[int(r['r_offset'])] = self.dynsym.get_symbol(r['r_info_sym']).name
        self.plt = {}
        plt = self.e.get_section_by_name('.plt')
        if plt:
            def imm(w):
                r = ((w >> 8) & 15) * 2
                b = w & 255
                return ((b >> r) | (b << (32 - r))) & 0xffffffff if r else b
            for o in range(int(plt['sh_offset']), int(plt['sh_offset']) + int(plt['sh_size']) - 11, 4):
                a, b, c = struct.unpack_from('<III', self.data, o)
                if a & 0xfffff000 == 0xe28fc000 and b & 0xfffff000 == 0xe28cc000 and \
                        c & 0xfffff000 == 0xe5bcf000:
                    va = o - int(plt['sh_offset']) + int(plt['sh_addr'])
                    g = va + 8 + imm(a) + imm(b) + (c & 4095)
                    if g in got:
                        self.plt[va] = got[g]

    def off(self, va):
        for s in self.segs:
            if s['p_vaddr'] <= va < s['p_vaddr'] + s['p_filesz']:
                return int(s['p_offset']) + va - int(s['p_vaddr'])
        for sec in self.secs:
            if int(sec['sh_addr']) <= va < int(sec['sh_addr']) + int(sec['sh_size']) and \
                    sec['sh_type'] != 'SHT_NOBITS':
                return int(sec['sh_offset']) + va - int(sec['sh_addr'])
        return None

    def cstr(self, va, n=160):
        o = self.off(va)
        if o is None or not (0 <= o < len(self.data)):
            return None
        z = self.data.find(b'\x00', o, min(o + n, len(self.data)))
        if z < 0:
            z = min(o + n, len(self.data))
        b = self.data[o:z]
        if len(b) >= 2 and all(32 <= c < 127 or c in (9, 10, 13) for c in b):
            return b.decode('latin1')
        return None

    def r32(self, va):
        o = self.off(va)
        if o is None or o + 4 > len(self.data):
            return None
        return struct.unpack_from('<I', self.data, o)[0]

    def func_by_name(self, name):
        for n, v, sz, t, idx in self.syms:
            if n == name:
                return v
        return None

    def dis(self, start, size):
        """mixed: 用 st_value bit0 判断 Thumb（直接给 start 时按 start 奇偶）。"""
        thumb = bool(start & 1)
        va = start & ~1
        md = Cs(CS_ARCH_ARM, (CS_MODE_THUMB if thumb else CS_MODE_ARM) | CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        o = self.off(va)
        if o is None:
            return [f';; cannot map 0x{va:x}']
        code = self.data[o:o + size]
        out, pos = [], 0
        while pos < len(code) - (1 if thumb else 3):
            got = list(md.disasm(code[pos:pos + (4 if thumb else 4)], va + pos))
            if not got:
                pos += 2 if thumb else 4
                continue
            ins = got[0]
            note = []
            # 顺序扫描时跟踪字面量
            ops = ins.operands
            if ins.mnemonic.startswith('ldr') and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
                mem = ops[1].mem
                if ins.reg_name(mem.base) == 'pc':
                    if thumb:
                        la = ((ins.address + 4) & ~3) + mem.disp
                    else:
                        la = ins.address + 8 + mem.disp
                    v = self.r32(la)
                    if v is not None:
                        s = self.cstr(v)
                        note.append(f'LIT@0x{la:x}=0x{v:08x}' + (f' "{s}"' if s else ''))
            if ins.mnemonic in ('bl', 'blx', 'b', 'b.w') and ops and ops[0].type == ARM_OP_IMM:
                t = ops[0].imm & ~1
                if t in self.plt:
                    note.append('-> ' + self.plt[t])
                elif ins.mnemonic in ('bl', 'blx'):
                    note.append(f'-> 0x{t:x}')
            if ins.mnemonic in ('movw', 'movt') and ops and ops[0].type == ARM_OP_REG:
                note.append(f'{ins.mnemonic} imm16=0x{ops[1].imm:x}' if len(ops) > 1 else '')
            out.append(f'{ins.address:08x} {ins.bytes.hex():10s} {ins.mnemonic:9s} '
                       f'{ins.op_str:40s} ' + ('; ' + '; '.join(n for n in note if n) if note else ''))
            pos += ins.size
        return out

    def dump_symbols(self):
        L = [f'FILE {self.path.name}',
             f'SHA256 {__import__("hashlib").sha256(self.data).hexdigest()}',
             f'PLT entries: {len(self.plt)}']
        for n, v, sz, t, idx in self.syms:
            if n and t == 'STT_FUNC' and isinstance(idx, int):
                L.append(f'{v:08x} size={sz:5d} thumb={v & 1} {n}')
        return '\n'.join(L)


SO_FUNCS = [
    ('osal_snd_msg', 0x3c34), ('osal_rcv_msg_tmo', 0x3ed8),
    ('osal_reg_msg_queue_cb', 0x4300), ('osal_reg_sync_msg_queue_cb', 0x3ae0),
    ('osal_unreg_msg_queue_cb', 0x3b54), ('osal_snd_sync_msg', 0x3ec8),
    ('osal_snd_sync_direct', 0x4134), ('osal_valloc_msg_wait', 0x3fec),
    ('osal_free_msg', 0x4088), ('osal_set_msgq_broadcast_mode', 0x4464),
    ('u_osal_rcv_msg_tmo', 0x26f4), ('u_osal_reg_msg_queue_cb', 0x2748),
    ('u_osal_snd_msg', 0x25b8),
]


def main():
    gens = sys.argv[1:] or ['g4', 'g5']
    for gen in gens:
        ko = OUT / f'{gen}_osal_uipc.ko'
        if ko.exists():
            elf = RelElf(ko)
            (OUT / f'inputdrv_osal_uipc_ko_{gen}_inventory.txt').write_text(
                ko_inventory(elf), encoding='utf-8')
            for fn in KO_FUNCS:
                if any(s['name'] == fn for s in elf.funcs):
                    (OUT / f'inputdrv_osal_uipc_ko_{gen}_{fn}.dis.txt').write_text(
                        dis_ko_func(elf, fn), encoding='utf-8')
            print(f'[{gen}] osal_uipc.ko: {len(elf.funcs)} funcs dumped')
        so = OUT / f'{gen}_libosal_uipc.so'
        if so.exists():
            ds = Dso(so)
            (OUT / f'inputdrv_libosal_uipc_{gen}_symbols.txt').write_text(
                ds.dump_symbols(), encoding='utf-8')
            for fn, va in SO_FUNCS:
                v = ds.func_by_name(fn)
                if v is None:
                    continue
                sz = next((s for n, vv, s, t, i in ds.syms if n == fn), 0x400)
                (OUT / f'inputdrv_libosal_uipc_{gen}_{fn}.dis.txt').write_text(
                    '\n'.join(ds.dis(v, sz if sz else 0x400)), encoding='utf-8')
            print(f'[{gen}] libosal_uipc.so: {len(ds.syms)} dynsyms, {len(ds.plt)} plt dumped')


if __name__ == '__main__':
    main()
