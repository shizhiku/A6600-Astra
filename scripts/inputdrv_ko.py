# -*- coding: utf-8 -*-
"""inputdrv_ko.py — input.ko (ET_REL, ARM) 重定位感知反汇编与调用参数追踪。

输入：03-证据/静态分析/input_drv/g4_input.ko、g5_input.ko（由 inputdrv_extract.py 从镜像提取）
输出（03-证据/静态分析/input_drv/）：
  inputdrv_ko_inventory_<gen>.txt    头/节/符号/重定位/.data 初值/字符串
  inputdrv_ko_disasm_<gen>.txt       逐函数反汇编（重定位+字面量+字符串+BL 目标）
  inputdrv_ko_calls_<gen>.tsv        每个外部调用点的 r0..r3 参数（常量/字面量/全局）
  inputdrv_ko_qids_<gen>.json        候选 qid 及使用上下文
只读分析，不执行任何目标代码。
"""
import io
import json
import re
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'

R_ARM_ABS32 = 2
R_ARM_TARGET1 = 38
R_ARM_PREL31 = 42
R_ARM_MOVW_ABS_NC = 43
R_ARM_MOVT_ABS = 44
R_ARM_CALL = 28
R_ARM_JUMP24 = 29
R_ARM_ABS32_NAMES = {R_ARM_ABS32, R_ARM_TARGET1}

REG_NAMES = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'sb', 'sl', 'fp', 'ip', 'sp', 'lr', 'pc']


class RelElf:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.e = ELFFile(io.BytesIO(self.data))
        self.secs = list(self.e.iter_sections())
        self.symtab = self.e.get_section_by_name('.symtab')
        # target section idx -> {offset: (symname, type, symidx)}
        self.rels = {}
        for si, sec in enumerate(self.secs):
            if sec['sh_type'] == 'SHT_REL':
                tgt = int(sec['sh_info'])
                m = {}
                for r in sec.iter_relocations():
                    sym = self.symtab.get_symbol(r['r_info_sym'])
                    m[int(r['r_offset'])] = (sym.name, int(r['r_info_type']), int(r['r_info_sym']))
                self.rels[tgt] = m
        self.syms = []
        for s in self.symtab.iter_symbols():
            self.syms.append(dict(name=s.name, value=int(s['st_value']), size=int(s['st_size']),
                                  type=s['st_info']['type'], shndx=s['st_shndx']))
        self.funcs = [s for s in self.syms if s['type'] == 'STT_FUNC' and isinstance(s['shndx'], int)]
        self.funcs.sort(key=lambda z: (z['shndx'], z['value']))
        self.objs = [s for s in self.syms if s['type'] == 'STT_OBJECT' and isinstance(s['shndx'], int)]
        self.by_sec_val = {}
        for s in self.funcs:
            self.by_sec_val.setdefault(s['shndx'], {})[s['value']] = s

    # ---------------- helpers ----------------
    def secdata(self, idx):
        sec = self.secs[idx]
        if sec['sh_type'] == 'SHT_NOBITS':
            return b'\x00' * int(sec['sh_size'])
        return sec.data()

    def secname(self, idx):
        if isinstance(idx, int) and 0 <= idx < len(self.secs):
            return self.secs[idx].name
        return str(idx)

    def sec_at_va(self, idx, off):
        """section idx + offset -> (secname, off)"""
        return self.secname(idx), off

    def read_word(self, sec_idx, off):
        d = self.secdata(sec_idx)
        if 0 <= off <= len(d) - 4:
            return struct.unpack_from('<I', d, off)[0]
        return None

    def resolve_reloc_value(self, sec_idx, off):
        """Return (kind, text, value) for relocation at (sec_idx, off)."""
        rel = self.rels.get(sec_idx, {}).get(off)
        if rel is None:
            return None
        name, typ, si = rel
        sym = self.symtab.get_symbol(si)
        addend = self.read_word(sec_idx, off) or 0
        shndx = sym['st_shndx']
        if isinstance(shndx, int):
            target_sec = self.secname(shndx)
            val = int(sym['st_value']) + addend
            label = name or target_sec
            if not name or name.startswith('$'):
                return ('sec', f'{target_sec}+0x{addend:x} (0x{val:x})', val, target_sec, addend)
            return ('sym', f'{name}+0x{addend:x}' if addend else name, val, target_sec, addend)
        return ('ext', name, None, None, addend)

    def literal_addr(self, insn):
        """ARM: ldr rX,[pc,#imm] -> literal address; ldr{r}? handled by caller."""
        ops = insn.operands
        if len(ops) >= 2 and ops[1].type == ARM_OP_MEM and insn.reg_name(ops[1].mem.base) == 'pc':
            return insn.address + 8 + ops[1].mem.disp
        return None

    def text_va_to_off(self, va):
        """text-section-relative address (kernel module: all code secs loaded separately).
        Validate against known code sections; return (sec_idx, off) or None."""
        for idx, sec in enumerate(self.secs):
            if sec['sh_type'] != 'SHT_PROGBITS' or not (int(sec['sh_flags']) & 0x4):
                continue  # not executable
            if sec['sh_addr'] == 0 and 0 <= va < int(sec['sh_size']):
                return idx, va
        return None

    def func_name_at(self, sec_idx, off):
        tbl = self.by_sec_val.get(sec_idx, {})
        if off in tbl:
            return tbl[off]['name']
        starts = getattr(self, 'region_starts', {}).get(sec_idx, [])
        best = None
        for s in starts:
            if s <= off:
                best = s
        if best is not None:
            return f'static_{self.secname(sec_idx)}_{best:04x}+0x{off - best:x}'
        best2 = None
        for v, s in tbl.items():
            if v <= off < v + max(s['size'], 1):
                if best2 is None or v > best2[0]:
                    best2 = (v, s)
        if best2:
            return f'{best2[1]["name"]}+0x{off - best2[0]:x}'
        return f'sec+0x{off:x}'

    def cstr_in_sec(self, sec_idx, off, maxlen=200):
        d = self.secdata(sec_idx)
        if not (0 <= off < len(d)):
            return None
        z = d.find(b'\x00', off, min(off + maxlen, len(d)))
        if z < 0:
            z = min(off + maxlen, len(d))
        b = d[off:z]
        if len(b) >= 2 and all(32 <= c < 127 or c in (9, 10, 13) for c in b):
            return b.decode('latin1')
        return None

    def insn_relocs(self, sec_idx, insn):
        m = self.rels.get(sec_idx, {})
        return [(o, m[o]) for o in range(insn.address, insn.address + len(insn.bytes)) if o in m]

    def describe_literal(self, sec_idx, lit_addr):
        """Read literal word in code section + relocation annotation/string."""
        v = self.read_word(sec_idx, lit_addr)
        if v is None:
            return None
        rv = self.resolve_reloc_value(sec_idx, lit_addr)
        s = self.cstr_in_sec(sec_idx, lit_addr)
        return v, rv, s


def is_branch(mn):
    return mn.startswith('b') and mn not in ('bic', 'bics', 'bfc', 'bfi', 'bkpt', 'blx', 'bl')


def arg_value(state, reg):
    v = state.get(reg)
    if v is None:
        return None
    return v


def regions(elf):
    """Yield (name, sec_idx, start, size) covering every executable byte.

    函数边界 = 符号表函数 ∪ 字节模式检测到的 APCS 序言
      mov ip, sp ; push {..., fp, ip, lr, pc} ; sub fp, ip, #4
    这能把 input.ko 里没有符号的静态函数（front/vgrip/liro_adc 消息助手等）还原出来。
    """
    starts_by_sec = {}
    for sec_idx, sec in enumerate(elf.secs):
        if sec['sh_type'] != 'SHT_PROGBITS' or not (int(sec['sh_flags']) & 0x4):
            continue
        size = int(sec['sh_size'])
        d = elf.secdata(sec_idx)
        starts = {s['value']: s['name'] for s in elf.funcs if s['shndx'] == sec_idx}
        for a in range(0, size - 12, 4):
            w0, w1, w2 = struct.unpack_from('<III', d, a)
            if w0 == 0xE1A0C00D and (w1 & 0xFFFF0000) == 0xE92D0000 and (w1 & 0xD800) == 0xD800 \
                    and (w2 & 0xFFFFFF00) == 0xE24CB000:
                starts.setdefault(a, f'static_{sec.name}_{a:04x}')
        starts_by_sec[sec_idx] = (sorted(starts.items()), size)
    elf.region_starts = {idx: [a for a, _ in v[0]] for idx, v in starts_by_sec.items()}
    for sec_idx, (starts, size) in starts_by_sec.items():
        for i, (start, name) in enumerate(starts):
            end = starts[i + 1][0] if i + 1 < len(starts) else size
            yield (name, sec_idx, start, end - start)


def analyze_function(elf, func):
    sec_idx = func['shndx']
    sec = elf.secs[sec_idx]
    start = func['value']
    size = func['size']
    code = elf.secdata(sec_idx)[start:start + size]
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = []
    off = 0
    while off < len(code):
        got = list(md.disasm(code[off:off + 4], start + off))
        if got:
            insns.append(got[0])
        off += 4
    # ---- basic blocks ----
    leaders = {start}
    for ins in insns:
        ops = ins.operands
        has_rel = bool(elf.insn_relocs(sec_idx, ins))
        if ins.mnemonic in ('b', 'bl', 'blx', 'bx') or is_branch(ins.mnemonic):
            if (not has_rel) and ops and ops[0].type == ARM_OP_IMM:
                leaders.add(ops[0].imm)
            leaders.add(ins.address + len(ins.bytes))
        if ins.mnemonic.startswith('pop') and 'pc' in ins.op_str:
            leaders.add(ins.address + len(ins.bytes))
        if ins.mnemonic.startswith('ldm') and 'pc' in ins.op_str:
            leaders.add(ins.address + len(ins.bytes))
    leaders = sorted(a for a in leaders if start <= a < start + size)
    # ---- forward abstract interpretation per block ----
    state = {}
    annotations = {}
    calls = []
    lit_values = []
    blocks_of = sorted(leaders)
    for bi, bstart in enumerate(blocks_of):
        bend = blocks_of[bi + 1] if bi + 1 < len(blocks_of) else start + size
        state = {}
        for ins in insns:
            if not (bstart <= ins.address < bend):
                continue
            notes = []
            mn = ins.mnemonic
            ops = ins.operands
            # ---- relocation annotation (call / movw / movt / data) ----
            has_reloc_call = False
            for o, (rname, rtyp, rsi) in elf.insn_relocs(sec_idx, ins):
                rv = elf.resolve_reloc_value(sec_idx, o)
                if rv:
                    notes.append(f'RELOC {rv[0]}:{rv[1]} type={rtyp}')
                    if rtyp in (R_ARM_CALL, R_ARM_JUMP24):
                        has_reloc_call = True
                        calls.append(dict(addr=ins.address, callee=rv[1], kind='call',
                                          args={r: state.get(r) for r in ('r0', 'r1', 'r2', 'r3')}))
                    elif rtyp in (R_ARM_MOVW_ABS_NC, R_ARM_MOVT_ABS):
                        state[REG_NAMES[ops[0].reg]] = ('reloc', rv[1], None, None)
            # ---- literal load ----
            if mn.startswith('ldr') and len(ops) >= 2 and ops[1].type == ARM_OP_MEM and \
                    ins.reg_name(ops[1].mem.base) == 'pc':
                la = ins.address + 8 + ops[1].mem.disp
                desc = elf.describe_literal(sec_idx, la)
                if desc:
                    v, rv, s = desc
                    notes.append(f'LIT@{la:#x}=0x{v:08x}' + (f' {rv[0]}:{rv[1]}' if rv else '') +
                                 (f' "{s}"' if s else ''))
                    lit_values.append(dict(addr=ins.address, lit_va=la, value=v,
                                           reloc=(rv[1] if rv else None), string=s,
                                           dst=ins.reg_name(ops[0].reg)))
                    if rv is not None:
                        state[ins.reg_name(ops[0].reg)] = ('lit_reloc', v, rv, s)
                    elif s:
                        state[ins.reg_name(ops[0].reg)] = ('lit_str', v, s, None)
                    else:
                        state[ins.reg_name(ops[0].reg)] = ('imm', v, None, None)
                annotations[ins.address] = notes
                continue
            # ---- add rD, pc, #imm (position-independent str / table) ----
            if mn in ('add', 'adds', 'add.w') and len(ops) >= 3 and ops[0].type == ARM_OP_REG:
                if ops[1].type == ARM_OP_REG and ins.reg_name(ops[1].reg) == 'pc' and \
                        ops[2].type == ARM_OP_IMM:
                    v = (ins.address + 8 + ops[2].imm) & 0xffffffff
                    s = elf.cstr_in_sec(sec_idx, v)
                    notes.append(f'PCREL=0x{v:x}' + (f' "{s}"' if s else ''))
                    state[ins.reg_name(ops[0].reg)] = ('pcrel', v, s, None)
                    annotations[ins.address] = notes
                    continue
                # add rD, rS, #imm
                if ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                    src = state.get(ins.reg_name(ops[1].reg))
                    if src and src[0] in ('imm', 'pcrel'):
                        state[ins.reg_name(ops[0].reg)] = ('imm', (src[1] + ops[2].imm) & 0xffffffff, None, None)
                        continue
            # ---- mov / movw / movt / mvn ----
            if mn in ('mov', 'movs', 'mov.w', 'movw', 'movt', 'mvn', 'mvns') and \
                    len(ops) >= 2 and ops[0].type == ARM_OP_REG:
                if ops[1].type == ARM_OP_IMM:
                    v = ops[1].imm & 0xffffffff
                    if mn in ('movt',):
                        old = state.get(ins.reg_name(ops[0].reg))
                        if old and old[0] in ('imm', 'movw'):
                            v = (old[1] & 0xffff) | (v << 16)
                    if mn in ('mvn', 'mvns'):
                        v = (~v) & 0xffffffff
                    state[ins.reg_name(ops[0].reg)] = ('imm', v, None, None)
                    continue
                if ops[1].type == ARM_OP_REG:
                    state[ins.reg_name(ops[0].reg)] = state.get(ins.reg_name(ops[1].reg))
                    continue
            # ---- ldr rD, [rS, #imm] (global variable load) ----
            if mn == 'ldr' and len(ops) == 2 and ops[1].type == ARM_OP_MEM and \
                    ops[1].mem.base != 0 and ins.reg_name(ops[1].mem.base) != 'pc':
                base = state.get(ins.reg_name(ops[1].mem.base)) if ops[1].mem.base else None
                if base and base[0] == 'lit_reloc':
                    rv = base[2]
                    notes.append(f'[GLOBAL {rv[1]}+0x{ops[1].mem.disp:x}]')
                    state[ins.reg_name(ops[0].reg)] = ('global', ops[1].mem.disp, rv[1], None)
                    continue
            # ---- keep state valid: any other write to tracked reg invalidates ----
            if ops and ops[0].type == ARM_OP_REG:
                dst = ins.reg_name(ops[0].reg)
                if dst in ('r0', 'r1', 'r2', 'r3'):
                    if mn not in ('cmp', 'cmn', 'tst', 'teq'):
                        state[dst] = None
            if mn in ('bl', 'blx'):
                # direct call not annotated by reloc (local): resolve section-relative target
                if (not has_reloc_call) and ops and ops[0].type == ARM_OP_IMM:
                    tgt = ops[0].imm
                    name = elf.func_name_at(sec_idx, tgt)
                    calls.append(dict(addr=ins.address, callee=name, kind='call_local',
                                      args={r: state.get(r) for r in ('r0', 'r1', 'r2', 'r3')}))
            if mn in ('b', 'bl', 'blx', 'bx') or is_branch(mn):
                state = {} if mn != 'bl' and mn != 'blx' else {}
            annotations[ins.address] = notes
    # ---- render ----
    lines = [f'FUNCTION {func["name"]} sec={elf.secname(sec_idx)} start=0x{start:x} size=0x{size:x}']
    for ins in insns:
        note = '; '.join(annotations.get(ins.address, []))
        lines.append(f'{ins.address:08x} off={ins.address:08x} {ins.bytes.hex():10s} '
                     f'{ins.mnemonic:9s} {ins.op_str:36s} {("; " + note) if note else ""}')
    return lines, calls, lit_values


def inventory(elf, gen):
    L = [f'FILE {elf.path.name}',
         f'SHA256 {__import__("hashlib").sha256(elf.data).hexdigest()}',
         f'ELF {elf.e.header["e_type"]} {elf.e.header["e_machine"]}',
         '', '== SECTIONS ==']
    for i, sec in enumerate(elf.secs):
        L.append(f'[{i:2d}] {sec.name:24s} type={sec["sh_type"]:14s} flags=0x{int(sec["sh_flags"]):x} '
                 f'addr=0x{int(sec["sh_addr"]):x} off=0x{int(sec["sh_offset"]):x} size=0x{int(sec["sh_size"]):x}')
    L += ['', '== SYMBOLS (FUNC/OBJECT) ==']
    for s in elf.syms:
        if s['type'] in ('STT_FUNC', 'STT_OBJECT') or (s['name'] and s['shndx'] == 'SHN_UNDEF'):
            L.append(f'{str(s["shndx"]):>14s} {s["value"]:08x} size={s["size"]:5d} {s["type"]:10s} {s["name"]}')
    L += ['', '== RELOCATIONS ==']
    for tgt, m in sorted(elf.rels.items()):
        L.append(f'-- target section [{tgt}] {elf.secname(tgt)} : {len(m)} relocs')
        for off, (name, typ, si) in sorted(m.items()):
            rv = elf.resolve_reloc_value(tgt, off)
            L.append(f'   off=0x{off:05x} type={typ:3d} sym={name:36s} -> {rv[1] if rv else "?"}')
    L += ['', '== .data / .rodata initial contents ==']
    for i, sec in enumerate(elf.secs):
        if sec.name not in ('.data', '.rodata'):
            continue
        d = elf.secdata(i)
        L.append(f'-- {sec.name} ({len(d)} bytes)')
        for off in range(0, len(d), 4):
            w = struct.unpack_from('<I', d, off)[0] if off + 4 <= len(d) else None
            rv = elf.resolve_reloc_value(i, off)
            s = elf.cstr_in_sec(i, off)
            L.append(f'   +0x{off:03x}: 0x{w:08x} {("reloc " + rv[1]) if rv else ""} {("str " + repr(s)) if s else ""}')
    L += ['', '== STRINGS ==']
    for i, sec in enumerate(elf.secs):
        if sec.name != '.rodata.str1.1':
            continue
        d = elf.secdata(i)
        for m in re.finditer(rb'[\x20-\x7e]{3,}', d):
            L.append(f'   off=0x{m.start():04x} {m.group().decode("latin1")}')
    return L


QID_LO, QID_HI = 0x600000, 0x9FFFFF


def looks_like_qid(v):
    return isinstance(v, int) and QID_LO <= v <= QID_HI


def main():
    gens = sys.argv[1:] or ['g4', 'g5']
    qid_report = {}
    for gen in gens:
        ko = OUT / f'{gen}_input.ko'
        if not ko.exists():
            print('[missing]', ko)
            continue
        elf = RelElf(ko)
        print(f'[{gen}] {ko.name}: {len(elf.funcs)} funcs, {len(elf.objs)} objects')
        (OUT / f'inputdrv_ko_inventory_{gen}.txt').write_text(
            '\n'.join(inventory(elf, gen)), encoding='utf-8')
        dis_lines, call_lines = [], []
        qids = {}
        for reg in regions(elf):
            f = dict(name=reg[0], shndx=reg[1], value=reg[2], size=reg[3])
            if f['size'] == 0:
                continue
            lines, calls, lits = analyze_function(elf, f)
            dis_lines.extend(lines)
            dis_lines.append('')
            for c in calls:
                a = c['args']
                def fmt(r):
                    v = a.get(r)
                    if v is None:
                        return ''
                    if v[0] in ('imm', 'movw'):
                        return f'0x{v[1]:x}'
                    if v[0] == 'lit_reloc':
                        extra = ''
                        if isinstance(v[2], tuple) and len(v[2]) > 1:
                            extra = v[2][1]
                        return f'LIT:{extra}'
                    if v[0] == 'pcrel':
                        return f'PCREL:"{v[2]}"'
                    return f'{v[0]}:{v[1]}'
                call_lines.append('\t'.join([hex(c['addr']), f['name'], c['callee'],
                                             fmt('r0'), fmt('r1'), fmt('r2'), fmt('r3')]))
                for r in ('r0', 'r1', 'r2', 'r3'):
                    v = a.get(r)
                    if v and v[0] in ('imm', 'movw') and looks_like_qid(v[1]):
                        key = f'0x{v[1]:08x}'
                        qids.setdefault(key, []).append(dict(func=f['name'], call=hex(c['addr']),
                                                             callee=c['callee'], reg=r))
            for lit in lits:
                if looks_like_qid(lit['value']):
                    key = f'0x{lit["value"]:08x}'
                    qids.setdefault(key, []).append(dict(func=f['name'], insn=hex(lit['addr']),
                                                         lit_va=hex(lit['lit_va']), how='literal'))
        (OUT / f'inputdrv_ko_disasm_{gen}.txt').write_text('\n'.join(dis_lines), encoding='utf-8')
        (OUT / f'inputdrv_ko_calls_{gen}.tsv').write_text(
            'site\tfunc\tcallee\tr0\tr1\tr2\tr3\n' + '\n'.join(call_lines), encoding='utf-8')
        (OUT / f'inputdrv_ko_qids_{gen}.json').write_text(json.dumps(qids, indent=2), encoding='utf-8')
        qid_report[gen] = qids
        print(f'  qid candidates: {len(qids)}')
    # cross-image diff of strings / qids
    if all(g in qid_report for g in ('g4', 'g5')):
        cmp = {'g4': sorted(qid_report['g4'].keys()), 'g5': sorted(qid_report['g5'].keys()),
               'only_g4': sorted(set(qid_report['g4']) - set(qid_report['g5'])),
               'only_g5': sorted(set(qid_report['g5']) - set(qid_report['g4']))}
        (OUT / 'inputdrv_ko_qid_diff.json').write_text(json.dumps(cmp, indent=2), encoding='utf-8')
        print(json.dumps(cmp, indent=2))


if __name__ == '__main__':
    main()
