"""Enumerate ALL sched_lock wrappers in the 0x2B1Bxxx region by decoding each
function that calls 0x2C2E46C, then reading the group/id immediates.

This avoids the fragile backward-window scan: instead we locate every
`bl 0x2C2E46C` site and then walk backwards through the enclosing straight-line
prologue to read `movs r0,#g` and `movs r1,#i`.
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

LO, HI = 0x2B1B000, 0x2B1C000      # region containing 0x2B1B470 / 0x2B1B524
print('=== scanning %#x..%#x for bl 0x2C2E46C sites ===' % (LO, HI))

insns = list(md.disasm(td[LO - tb:HI - tb], LO))
print('instructions in region:', len(insns))

# build index
idx_of = {ins.address: i for i, ins in enumerate(insns)}

hits = []
for i, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.op_str == '#0x2c2e46c':
        hits.append(i)

print('bl LOCK sites:', len(hits))
for i in hits:
    lock_ins = insns[i]
    grp = lid = None
    # walk back up to 8 instructions for movs r0/r1
    for j in range(i - 1, max(-1, i - 10), -1):
        w = insns[j]
        if w.mnemonic == 'movs' and w.op_str.startswith('r0') and grp is None:
            try:
                grp = int(w.op_str.split('#')[-1].rstrip(']'), 0)
            except ValueError:
                pass
        if w.mnemonic == 'movs' and w.op_str.startswith('r1') and lid is None:
            try:
                lid = int(w.op_str.split('#')[-1].rstrip(']'), 0)
            except ValueError:
                pass
        if grp is not None and lid is not None:
            break
    # business call after the lock
    biz = None
    for j in range(i + 1, min(len(insns), i + 8)):
        w = insns[j]
        if w.mnemonic in ('bl', 'blx') and w.op_str.startswith('#'):
            biz = w.op_str
            break
    print('  lock site %#010x  group=%s id=%s  next_call=%s'
          % (lock_ins.address,
             ('%#x' % grp) if grp is not None else '?',
             ('%#x' % lid) if lid is not None else '?', biz or '?'))
