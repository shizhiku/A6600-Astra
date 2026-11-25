# -*- coding: utf-8 -*-
"""
92_dbg_xref.py : 诊断字符串地址在文件里的出现位置(作为数据字), 以及附近 PC 相对 ldr 的行为
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

def off2va(off):
    for a, o, s, n in segs:
        if o <= off < o + s:
            return a + (off - o), n
    return None, None
def va2off(va):
    for a, o, s, n in segs:
        if a <= va < a + s:
            return o + (va - a)
    return None

TARGETS = [0x1012D8D, 0x1012DAB, 0x1012DD3, 0x1012DFD, 0x1012E27, 0x1012FB2,
           0x101303E, 0x1012C27]
print('=== where do these string VAs appear as data words? ===')
for t in TARGETS:
    pat = struct.pack('<I', t)
    offs = []
    i = 0
    while True:
        i = data.find(pat, i)
        if i < 0:
            break
        offs.append(i); i += 1
    desc = []
    for o in offs:
        va, n = off2va(o)
        desc.append('0x%X[%s]' % (va, n))
    print('0x%08X : %d  %s' % (t, len(offs), ' '.join(desc[:12])))

# ---- test capstone on a known-ish code area: are there pc-relative ldrs at all?
MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
print('\n=== sample: pc-relative ldr count in first 64KB of .text ===')
cnt = 0
samples = []
o = va2off(0x104A30)
blob = data[o:o + 0x10000]
for ins in MD.disasm(blob, 0x104A30):
    if ins.mnemonic.startswith('ldr') and 'pc' in ins.op_str:
        cnt += 1
        if len(samples) < 8:
            samples.append((ins.address, ins.mnemonic, ins.op_str,
                            ins.operands[1].mem.base if len(ins.operands) > 1 else None,
                            ins.operands[1].mem.disp if len(ins.operands) > 1 else None))
print('count(linear sweep from 0x104A30):', cnt)
for s in samples:
    print('  0x%X %s %s base=%s disp=0x%X' % (s[0], s[1], s[2], s[3], s[4] if s[4] is not None else -1))

print('\n=== ARM_REG_PC value =', ARM_REG_PC)

# ---- brute force: scan whole .text at 2-byte granularity for pc-relative loads
#      whose target equals any target string; report all.
tset = set(TARGETS)
print('\n=== brute-force thumb sweep over .text (2-byte step) ===')
hits = []
n = 0
text_off = va2off(0x104A30)
text_blob = data[text_off:text_off + 0xD3A6F0]
addr = 0x104A30
while addr < 0x104A30 + 0xD3A6F0 - 4:
    rel = addr - text_off
    for ins in MD.disasm(text_blob[rel:rel + 4], addr):
        if ins.mnemonic.startswith('ldr') and 'pc' in ins.op_str:
            try:
                mem = ins.operands[1].mem
                if mem.base == ARM_REG_PC:
                    base = (addr + 4) & ~3
                    tgt = base + mem.disp
                    if tgt in tset:
                        hits.append((addr, tgt, ins.op_str))
            except Exception:
                pass
        elif ins.mnemonic.startswith('add') and len(ins.operands) == 3:
            try:
                if ins.operands[1].type == ARM_OP_REG and ins.operands[1].reg == ARM_REG_PC:
                    tgt = ((addr + 4) & ~3) + ins.operands[2].imm
                    if tgt in tset:
                        hits.append((addr, tgt, ins.op_str))
            except Exception:
                pass
    addr += 2
print('hits:', len(hits))
for h in hits:
    print('  insn 0x%X -> str 0x%X  (%s)' % h)
