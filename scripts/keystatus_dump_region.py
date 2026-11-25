#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_dump_region.py -- 通用区间反汇编：解析 PC 字面量/字符串/命名函数调用。

用法:
    python 02-脚本/keystatus_dump_region.py <elf> <hex_start> <hex_len> [thumb|arm] [输出名]

只读。用于 libObj / upm.ko / appFw 的定点分析。
"""
from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / '03-证据/静态分析/keystatus'


def main() -> int:
    elf_path = Path(sys.argv[1])
    start = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0
    length = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x400
    mode = sys.argv[4] if len(sys.argv) > 4 else 'thumb'
    name = sys.argv[5] if len(sys.argv) > 5 else 'region'
    if not elf_path.is_absolute():
        elf_path = ROOT / elf_path

    data = elf_path.read_bytes()
    elf = ELFFile(io.BytesIO(data))
    secs = [(s['sh_addr'], s['sh_addr'] + s['sh_size'], s['sh_offset'], s.name)
            for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS' and s['sh_size']]

    def off(va):
        for a, b, o, _ in secs:
            if a <= va < b:
                return o + (va - a)
        return None

    def u32(va):
        return struct.unpack_from('<I', data, off(va))[0]

    def cstr(va, mx=200):
        o = off(va)
        if o is None:
            return None
        j = data.find(b'\0', o, o + mx)
        if j < 0:
            return None
        try:
            return data[o:j].decode('utf-8')
        except UnicodeDecodeError:
            return None

    # 符号
    syms, objs = {}, {}
    for sn in ('.symtab', '.dynsym'):
        st = elf.get_section_by_name(sn)
        if st is None:
            continue
        for s in st.iter_symbols():
            v = s['st_value']
            if not v or s['st_info']['type'] not in ('STT_FUNC', 'STT_OBJECT'):
                continue
            d = syms if s['st_info']['type'] == 'STT_FUNC' else objs
            d.setdefault(v & ~1, s.name)
    # PLT / veneer 解析
    pltmap, relmap = {}, {}
    plts = []
    rel = elf.get_section_by_name('.rel.plt')
    ds = elf.get_section_by_name('.dynsym')
    if rel is not None and ds is not None:
        rd = rel.data()
        for k in range(0, len(rd) - 7, 8):
            ro, ri = struct.unpack_from('<II', rd, k)
            relmap[ro] = ri >> 8
    plt = elf.get_section_by_name('.plt')
    if plt is not None and ds is not None:
        md0 = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        md0.detail = True
        pb, pbase = plt.data(), plt['sh_addr']
        for k in range(0, len(pb) - 3, 4):
            w = struct.unpack_from('<I', pb, k)[0]
            if (w >> 16) != 0xE28F or ((w >> 12) & 0xF) != 0xC:
                continue
            st = pbase + k
            ins = list(md0.disasm(data[st:st + 12], st))
            try:
                def imm(i):
                    im = [o.imm for o in i.operands if o.type == 2]
                    if not im:
                        return None
                    if len(im) >= 2:
                        return ((im[0] >> im[1]) | (im[0] << (32 - im[1]))) & 0xFFFFFFFF
                    return im[0]
                slot = (ins[0].address + 8 + imm(ins[0]) + imm(ins[1])
                        + ins[2].operands[1].mem.disp) & 0xFFFFFFFF
            except Exception:
                continue
            if slot in relmap:
                nm = ds.get_symbol(relmap[slot]).name
                if nm:
                    pltmap[st] = nm
                    plts.append(st)
    for i, st in enumerate(plts):
        pass
    # 有的 ELF 不用 ARM 长跳，用 Thumb 2 指令；这里只处理 ARM 形 + 直接 bl 到 plt
    veneers = {}
    pat = bytes.fromhex('00c09fe50cf08fe0')
    i = data.find(pat)
    while i >= 0:
        try:
            tgt = (struct.unpack_from('<I', data, i + 8)[0] + i + 12) & 0xFFFFFFFF
        except struct.error:
            tgt = None
        if tgt in pltmap:
            veneers[i] = pltmap[tgt]
        i = data.find(pat, i + 1)

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if mode == 'thumb' else CS_MODE_ARM)
    md.detail = False
    reglit = {}
    lines = []
    blob = data[off(start):off(start) + length]
    for ins in md.disasm(blob, start):
        ann = ''
        op = ins.op_str
        if ins.mnemonic.startswith('ldr') and '[pc' in op:
            j = op.rfind('#')
            if j >= 0:
                immv = int(op[j + 1:].rstrip(']'), 0)
                base = (ins.address + 4) & ~3 if mode == 'thumb' else ins.address + 8
                lva = base + immv
                try:
                    val = u32(lva)
                except Exception:
                    val = None
                if val is not None:
                    ann = f'   ; [0x{lva:08x}]=0x{val:08x}'
                    s = cstr(val)
                    if s and len(s) > 1 and all(32 <= ord(c) < 127 for c in s):
                        ann += f' "{s[:90]}"'
                    elif (val & ~1) in syms:
                        ann += f' <{syms[val & ~1]}>'
                    elif (val & ~1) in objs:
                        ann += f' obj<{objs[val & ~1]}>'
                    elif val in veneers:
                        ann += f' veneer<{veneers[val]}>'
                    elif val in pltmap:
                        ann += f' plt<{pltmap[val]}>'
                    reglit[op.split(',')[0].strip()] = val
        elif ins.mnemonic in ('add', 'add.w') and ', pc' in op:
            toks = [t.strip() for t in op.split(',')]
            if len(toks) == 2 and toks[0] in reglit:
                tgt = (((ins.address + 4) & ~3) + reglit[toks[0]]) & 0xFFFFFFFF
                ann = f'   ; -> 0x{tgt:08x}'
                s = cstr(tgt)
                if s and len(s) > 1 and all(32 <= ord(c) < 127 for c in s):
                    ann += f' "{s[:90]}"'
        elif ins.mnemonic in ('bl', 'blx', 'b') and op.startswith('#'):
            tgt = int(op[1:], 0)
            nm = veneers.get(tgt) or pltmap.get(tgt) or syms.get(tgt & ~1)
            ann = f'   ; -> 0x{tgt:08x}'
            if nm:
                ann += f' <{nm}>'
        lines.append(f'{ins.address:08x}  {ins.bytes.hex():<10} {ins.mnemonic:<8} {ins.op_str}{ann}')

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    outp = OUT_DIR / f'{name}.txt'
    with open(outp, 'w', encoding='utf-8') as f:
        f.write(f'# {elf_path}  range 0x{start:x}+0x{length:x} mode={mode}\n')
        for ln in lines:
            f.write(ln + '\n')
    print('written', outp, len(lines), 'insns')
    return 0


if __name__ == '__main__':
    sys.exit(main())
