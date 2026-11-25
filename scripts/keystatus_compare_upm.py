#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_compare_upm.py -- 对比四代/五代 upm.ko 的 boot-factor 消息 ABI。

产出:
  * 符号表大小 (g_bf / 关键函数)
  * 两个版本 k_upm_notify_boot_factor / k_upm_framework_boot_factor 的反汇编
  * 两个版本 .text 里所有 0x92xxxx 常量（uipc id / message id）清单
"""
from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / '03-证据/静态分析/keystatus'


def load(p: Path):
    d = p.read_bytes()
    e = ELFFile(io.BytesIO(d))
    secs = [(s['sh_addr'], s['sh_addr'] + s['sh_size'], s['sh_offset'], s.name)
            for s in e.iter_sections() if s['sh_type'] != 'SHT_NOBITS' and s['sh_size']]
    return d, e, secs


def main() -> int:
    files = {'g4': OUT / 'g4_upm.ko', 'g5': OUT / 'g5_upm.ko'}
    OUT.mkdir(parents=True, exist_ok=True)
    out = open(OUT / '05_upm_g4_vs_g5.txt', 'w', encoding='utf-8')

    for gen, p in files.items():
        if not p.exists():
            print('missing', p)
            continue
        d, e, secs = load(p)

        def off(va):
            for a, b, o, _ in secs:
                if a <= va < b:
                    return o + (va - a)
            return None

        def u32(va):
            return struct.unpack_from('<I', d, off(va))[0]

        st = e.get_section_by_name('.symtab')
        syms = {}
        for s in st.iter_symbols():
            if s.name:
                syms.setdefault(s.name, []).append((s['st_value'], s['st_size'], s['st_info']['type']))
        out.write(f'===== {gen}  {p.name}  size={len(d)}\n')
        for name in ('g_bf', 'k_upm_notify_boot_factor', 'k_upm_framework_boot_factor',
                     'upm_notify_wrapper_async', 'upm_notify_wrapper_sync',
                     'k_upm_set_boot_factor_for_oriks', 'k_upm_setup_boot_factor',
                     'k_upm_init_boot_factor', 'k_upm_exit_boot_factor',
                     'k_upm_setup_boot_factor_default', 'upm_framework_attach',
                     'upm_task_call_req', 'upm_c3p_msg_async', 'upm_c3p_msg_sync'):
            for v, sz, t in syms.get(name, []):
                out.write(f'  {name:34s} VA=0x{v:06x} size={sz} type={t}\n')

        # .text 中的 0x92xxxx 常量 (按 literal pool 找)
        text = e.get_section_by_name('.text')
        tb, td = text['sh_addr'], text.data()
        vals = {}
        for k in range(0, len(td) - 3, 4):
            v = struct.unpack_from('<I', td, k)[0]
            if 0x920000 <= v <= 0x92FFFF:
                vals.setdefault(v, []).append(tb + k)
        out.write(f'  -- .text 中 0x92xxxx 常量: {len(vals)} 个不同值\n')
        for v in sorted(vals):
            out.write(f'     0x{v:08x}  x{len(vals[v])}  @{",".join(hex(x) for x in vals[v][:6])}\n')

        # 关键函数反汇编
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

        def dump(name, maxlen=0x200):
            got = syms.get(name)
            if not got:
                return
            va, sz, _ = got[0]
            out.write(f'  ----- {name} @0x{va:06x} (size {sz}) -----\n')
            blob = d[off(va):off(va) + min(sz or maxlen, maxlen)]
            for ins in md.disasm(blob, va):
                extra = ''
                if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
                    j = ins.op_str.rfind('#')
                    imm = int(ins.op_str[j + 1:].rstrip(']'), 0)
                    lit = ins.address + 8 + imm
                    try:
                        v = u32(lit)
                    except Exception:
                        v = None
                    if v is not None:
                        extra = f'   ; [0x{lit:06x}] = 0x{v:08x}'
                out.write(f'      {ins.address:06x}  {ins.bytes.hex():<10} {ins.mnemonic:<8} {ins.op_str}{extra}\n')

        dump('k_upm_notify_boot_factor')
        dump('k_upm_framework_boot_factor', 0x1c0)
        dump('upm_notify_wrapper_async')
        out.write('\n')

    out.close()
    print('written', OUT / '05_upm_g4_vs_g5.txt')
    return 0


if __name__ == '__main__':
    sys.exit(main())
