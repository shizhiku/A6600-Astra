# -*- coding: utf-8 -*-
"""
92_dbg_infra.py : 反汇编 InfraInput 关键函数, 观察其字面量池与日志如何构造
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
def r32(va):
    o = va2off(va)
    return struct.unpack_from('<I', data, o)[0] if o is not None and o + 4 <= len(data) else None
def cstr(va, n=200):
    o = va2off(va)
    if o is None: return None
    z = data.find(b'\x00', o, o + n)
    return data[o:(z if z > 0 else o + n)].decode('utf-8', 'replace')

MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB); MD.detail = True

def dis(va, size, title=''):
    print('\n===== %s  VA=0x%X size=%d =====' % (title, va, size))
    o = va2off(va)
    blob = data[o:o + size]
    lits = []
    for i, ins in enumerate(MD.disasm(blob, va)):
        line = '%08X  %-9s %s' % (ins.address, ins.mnemonic, ins.op_str)
        note = ''
        if len(ins.operands) >= 2 and ins.operands[-1].type == CS_OP_MEM:
            m = ins.operands[-1].mem
            if m.base == ARM_REG_PC:
                tgt = ((ins.address + 4) & ~3) + m.disp
                v = r32(tgt)
                note = '   ; lit@0x%X = 0x%X' % (tgt, v)
                if v is not None and 0xE3F128 <= v < 0x11958CA:
                    s = cstr(v)
                    if s and s.isprintable():
                        note += ' -> "%s"' % s[:70]
                lits.append((tgt, v))
        print(line + note)

dis(0x0860FD4, 296, 'InfraInput::GetEventStatus')
dis(0x08610FC, 304, 'InfraInput::SendEventInitData')
dis(0x08612E2, 32, 'InfraInput::GetKeyInh')
dis(0x08613FC, 268, 'InfraInput::SetKeyInh')
