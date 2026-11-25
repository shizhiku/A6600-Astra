# -*- coding: utf-8 -*-
"""
92_infra_key_map_scan3.py
libObj.so: 修正后的字面量 xref + 候选表上下文 dump
只读。
"""
import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

LIB = r'<WORKSPACE>\03-证据\静态分析\libObj.so'
data = open(LIB, 'rb').read()

from elftools.elf.elffile import ELFFile
from capstone import *

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

def off2va(off):
    for a, o, s, n in segs:
        if o <= off < o + s:
            return a + (off - o)
    return None

def r32(va):
    o = va2off(va)
    if o is None or o + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, o)[0]

def cstr(va, maxlen=400):
    o = va2off(va)
    if o is None:
        return None
    z = data.find(b'\x00', o, min(o + maxlen, len(data)))
    if z < 0:
        z = o + maxlen
    return data[o:z].decode('utf-8', 'replace')

TEXT_A, TEXT_SZ = 0x104A30, 0xD3A6F0
TEXT_E = TEXT_A + TEXT_SZ

MD_T = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
MD_A = Cs(CS_ARCH_ARM, CS_MODE_ARM)

def dec(md, va, n=4):
    o = va2off(va)
    if o is None:
        return []
    return list(md.disasm(data[o:o + n], va))

def find_refs(lva, span=0x500):
    """找把 lva 这个字面量加载进寄存器的指令 (Thumb T1/T2, ARM), 以及 add rX,pc。"""
    res = []
    lo = lva - span
    # Thumb 候选: 2 字节对齐
    a = lo if lo % 2 == 0 else lo + 1
    while a <= lva - 2:
        for ins in dec(MD_T, a, 4):
            if ins.address != a:
                continue
            target = None
            if ins.mnemonic in ('ldr', 'ldr.w'):
                try:
                    mem = ins.operands[1].mem
                    if mem.base == ARM_REG_PC:
                        base = (a + 4) & ~3
                        target = base + mem.disp
                        if target == lva:
                            res.append((a, 'T', ins.mnemonic, ins.op_str))
                except Exception:
                    pass
            elif ins.mnemonic in ('add', 'add.w'):
                try:
                    if ins.operands[1].type == ARM_OP_REG and ins.operands[1].reg == ARM_REG_PC:
                        base = (a + 4) & ~3
                        imm = ins.operands[2].imm
                        if base + imm == lva:
                            res.append((a, 'T', ins.mnemonic, ins.op_str))
                except Exception:
                    pass
            elif ins.mnemonic in ('addw',):
                pass
        a += 2
    # ARM 候选: 4 字节对齐, PC = a+8
    a = lva - 0x1100
    a -= a % 4
    while a <= lva - 8:
        for ins in dec(MD_A, a, 4):
            if ins.address != a:
                continue
            if ins.mnemonic == 'ldr':
                try:
                    mem = ins.operands[1].mem
                    if mem.base == ARM_REG_PC and a + 8 + mem.disp == lva:
                        res.append((a, 'A', ins.mnemonic, ins.op_str))
                except Exception:
                    pass
            elif ins.mnemonic == 'add':
                try:
                    if ins.operands[1].type == ARM_OP_REG and ins.operands[1].reg == ARM_REG_PC:
                        if a + 8 + ins.operands[2].imm == lva:
                            res.append((a, 'A', ins.mnemonic, ins.op_str))
                except Exception:
                    pass
        a += 4
    return res

STR_TARGETS = {
    0x1012D8D: 'InputEventList {',
    0x1012DAB: 'InfraInputKeyList event {',
    0x1012DD3: 'key_code=',
    0x1012DFD: 'event_code=',
    0x1012E27: 'status=',
    0x1012FB2: 'key_code,event_code LINE',
    0x1012E6F: 'InputPhyKeyInternal phy_data {',
    0x1012D55: 'unknown key_code',
    0x1012CEB: '%s(cb_id,list_no)',
    0x1012D1A: 'new callback_table',
    0x1012C27: 'ChangeEventStatus',
    0x1012C51: 'max_on/max_off/max_invalid',
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
}
print('=== literal xrefs (fixed) ===')
for va in sorted(STR_TARGETS):
    refs = find_refs(va)
    print('0x%08X %-30s refs=%d' % (va, STR_TARGETS[va], len(refs)))
    for a, mode, mn, ops in refs[:8]:
        print('        %s 0x%08X  %s %s' % (mode, a, mn, ops))

def dump_words(va, n, label):
    print('\n=== %s @0x%08X (%d words) ===' % (label, va, n))
    for i in range(n):
        v = r32(va + 4 * i)
        print('  +%03X 0x%08X : 0x%08X  %d' % (i * 4, va + 4 * i, v,
              v - (1 << 32) if v > 0x7FFFFFFF else v))

dump_words(0x00F9B210, 80, 'rodata descending key list neighbourhood')
dump_words(0x01383280, 96, '.data 4-byte {k,ev} pairs neighbourhood')
dump_words(0x013F08C0, 60, '.data key->ptr table')
print('\n--- strings near 0x01014500 ---')
for va in range(0x01014480, 0x01014680, 0x10):
    s = cstr(va, 40)
    print('  0x%08X %r' % (va, s))
dump_words(0x0134B440, 60, '.data.rel.ro around 0x134B480')
dump_words(0x0134B540, 40, '.data.rel.ro around 0x134B568')
dump_words(0x01383300, 20, '.data before 0x1383322')
