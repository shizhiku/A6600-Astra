# -*- coding: utf-8 -*-
"""
92_keylist_args.py : 反汇编 13 个 SetEventKeyList 调用点前的参数准备, 解析传入的静态表地址
"""
import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import libobj92_tools as T
from capstone import *
from capstone.arm import ARM_REG_PC

SITES = [0x3D3A5E, 0x3D4644, 0x660DBA, 0x85E846, 0x86231C, 0x86609A,
         0x8691E8, 0x8692CA, 0x9D0D86, 0xA0B70A, 0xA0BB0A, 0xD7A69A, 0xDBBDB4]

def show_prefix(site, back=0x34):
    start = site - back
    o = T.va2off(start)
    lastlit = {}
    lines = []
    for ins in T.MD.disasm(T.DATA[o:o + back + 4], start):
        note = ''
        if ins.mnemonic.startswith('ldr') and len(ins.operands) >= 2 \
           and ins.operands[1].type == CS_OP_MEM and ins.operands[1].mem.base == ARM_REG_PC:
            lt = ((ins.address + 4) & ~3) + ins.operands[1].mem.disp
            v = T.r32(lt)
            rd = ins.operands[0].reg
            if v is not None:
                lastlit[rd] = v
                s = T.cstr(v, 40) if T.RO_A <= v < T.RO_E else None
                note = ' ; =0x%X %s' % (v, ('"%s"' % s) if s else '')
        if ins.mnemonic in ('add', 'add.w') and len(ins.operands) == 2 \
           and ins.operands[1].type == CS_OP_REG and ins.operands[1].reg == ARM_REG_PC:
            rd = ins.operands[0].reg
            if rd in lastlit:
                t = (ins.address + 4) + lastlit[rd]
                s = T.cstr(t, 40) if T.RO_A <= t < T.RO_E else None
                note = ' => 0x%X %s' % (t, ('"%s"' % s) if s else '')
        lines.append('%08X  %-9s %-34s%s' % (ins.address, ins.mnemonic, ins.op_str, note))
    return lines

print('==== SetEventKeyList 调用点参数准备 ====')
for s in SITES:
    print('\n--- call site 0x%08X  (func 0x%08X) ---' % (s, T.func_of(s)))
    for ln in show_prefix(s):
        print('   ' + ln)
