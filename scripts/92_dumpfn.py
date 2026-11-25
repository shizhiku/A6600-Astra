# -*- coding: utf-8 -*-
"""
92_dumpfn.py : 反汇编并解析函数内全部 PC 相对字面量, 打印对应字符串
用法: python -X utf8 92_dumpfn.py <hex_va> <hex_size>
"""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import libobj92_tools as T
from capstone import *
from capstone.arm import ARM_REG_PC

va = int(sys.argv[1], 16)
sz = int(sys.argv[2], 16)

o = T.va2off(va)
print('===== 0x%X size=0x%X =====' % (va, sz))
lastlit = {}
for ins in T.MD.disasm(T.DATA[o:o + sz], va):
    line = '%08X  %-9s %s' % (ins.address, ins.mnemonic, ins.op_str)
    notes = []
    # 记录 ldr 字面量
    if ins.mnemonic.startswith('ldr') and len(ins.operands) >= 2 \
       and ins.operands[1].type == CS_OP_MEM and ins.operands[1].mem.base == ARM_REG_PC:
        lt = ((ins.address + 4) & ~3) + ins.operands[1].mem.disp
        v = T.r32(lt)
        rd = ins.operands[0].reg
        notes.append('lit 0x%X=0x%X' % (lt, v if v is not None else 0))
        if v is not None:
            lastlit[rd] = v
            s = T.cstr(v, 90) if T.RO_A <= v < T.RO_E else None
            if s and s.isprintable():
                notes.append('"%s"' % s)
            else:
                notes.append('#%d' % v)
    # 记录 add rD, pc 的解析结果
    if ins.mnemonic in ('add', 'add.w') and len(ins.operands) == 2 \
       and ins.operands[1].type == CS_OP_REG and ins.operands[1].reg == ARM_REG_PC:
        rd = ins.operands[0].reg
        if rd in lastlit:
            t = ((ins.address + 4) & ~3) + lastlit[rd]
            s = T.cstr(t, 90) if T.RO_A <= t < T.RO_E else None
            notes.append('=> 0x%X "%s"' % (t, s if s else ''))
    print(line + ('   ; ' + ' | '.join(notes) if notes else ''))
