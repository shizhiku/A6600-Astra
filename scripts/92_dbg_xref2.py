# -*- coding: utf-8 -*-
"""
92_dbg_xref2.py : 修正 detail + 在每条字符串前 1.2KB 内暴力搜 PC 相对引用
"""
import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

LIB = r'<WORKSPACE>\03-证据\静态分析\libObj.so'
data = open(LIB, 'rb').read()
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.arm import ARM_REG_PC
elf = ELFFile(open(LIB, 'rb'))
segs = []
for sec in elf.iter_sections():
    if sec['sh_type'] == 'SHT_NOBITS' or sec['sh_size'] == 0:
        continue
    segs.append((sec['sh_addr'], sec['sh_offset'], sec['sh_size'], sec.name))

def va2off(va):
    for a, o, s, n in segs:
        if a <= va < a + s:
            return o + (va - a)
    return None

TEXT_A, TEXT_SZ = 0x104A30, 0xD3A6F0
MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
MD.detail = True
MDA = Cs(CS_ARCH_ARM, CS_MODE_ARM)
MDA.detail = True

def insn_at(va):
    o = va2off(va)
    if o is None:
        return []
    return list(MD.disasm(data[o:o + 4], va))

def thumb_refs(lva, span=0x600):
    out = []
    lo = lva - span
    a = lo + (lo & 1)
    while a <= lva - 2:
        for ins in insn_at(a):
            if ins.address != a:
                continue
            mn = ins.mnemonic
            if mn in ('ldr', 'ldr.w') and len(ins.operands) >= 2:
                mem = ins.operands[1]
                if mem.type == CS_OP_MEM and mem.mem.base == ARM_REG_PC:
                    base = (a + 4) & ~3
                    if base + mem.mem.disp == lva:
                        out.append((a, mn, ins.op_str, 'ldr'))
            elif mn in ('add', 'add.w', 'adr', 'addw') and len(ins.operands) == 3:
                if ins.operands[1].type == CS_OP_REG and ins.operands[1].reg == ARM_REG_PC:
                    base = (a + 4) & ~3
                    try:
                        if base + ins.operands[2].imm == lva:
                            out.append((a, mn, ins.op_str, 'addpc'))
                    except Exception:
                        pass
        a += 2
    return out

TARGETS = {
    0x1012D8D: 'InputEventList {',
    0x1012DAB: 'InfraInputKeyList event {',
    0x1012DD3: 'key_code=',
    0x1012DFD: 'event_code=',
    0x1012E27: 'status=',
    0x1012FB2: 'LINE key_code,event_code',
    0x1012E6F: 'phy_data {',
    0x1012D55: 'unknown key_code',
    0x1012CEB: '%s(cb_id,list_no)',
    0x1012D1A: 'new callback_table',
    0x1012C27: 'ChangeEventStatus',
    0x1012C51: 'max_on/off/invalid',
    0x101302C: 'event inh',
    0x1012FF9: 'no group',
    0x1013002: 'do not',
    0x1013009: 'repeat key',
    0x1013014: 'keep_unknown',
    0x1013021: 'same event',
    0x1013036: 'no_send',
    0x101303E: 'chg/rep/inh/flags',
    0x10130AF: 'KeyConfigInfraInput {',
    0x101307B: 'display config_tableI',
    0x1012FF2: 'set key_list',
    0x10132FD: 'received InputPhyKeyInternal',
    0x10132F4: 'rep over',
    0x1012E51: 'config_pos = %d',
    0x1012F50: 'config_pos word',
    0x1012F7D: 'internal_flag',
    0x10132D6: 'EV I %08x',
    0x1012C00: 'l_errUpm',
    0x1012E9C: 'phy key_code',
}
print('=== thumb pc-relative refs (window 0x600 before string) ===')
for va in sorted(TARGETS):
    refs = thumb_refs(va)
    print('0x%08X %-28s n=%d %s' % (va, TARGETS[va], len(refs),
          ' '.join('%s@0x%X[%s]' % (k, a, o) for a, mn, o, k in refs[:6])))
