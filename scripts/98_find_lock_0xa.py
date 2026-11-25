"""Find who owns sched lock (group=0xf, id=0xa).

Strategy:
  1. Scan the whole .text for the lock-wrapper prologue pattern
       push {r4,r5,r7,lr} / mov r5,r0 / add r7,sp,#0 / mov r4,r1 /
       movs r0,#GROUP / movs r1,#ID / bl <lock primitive>
  2. For each wrapper, report (group,id, entry, business function).
  3. Group by id so we can see all id=0xa users and where they live.
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io
import struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

LOCK = 0x2C2E46C
UNLOCK = 0x2C2E3C0

results = []
# Disassemble the whole text once.  ~42 MB of code; capstone is fast enough but
# we only look at instructions that could start a wrapper.
print('scanning .text ...', flush=True)
count = 0
for ins in md.disasm(td, tb):
    if ins.mnemonic != 'movs' or not ins.op_str.startswith('r1'):
        continue
    try:
        lid = int(ins.op_str.split('#')[-1], 0)
    except ValueError:
        continue
    if lid != 0xa:
        continue
    # Check backwards: previous instruction should set r0 to the group.
    # Simpler: decode a small window starting a bit before and look for the
    # `bl LOCK` a few instructions later.
    start = ins.address - 10
    if start < tb:
        continue
    win = list(md.disasm(td[start - tb:start - tb + 0x1c], start))
    seq = [f'{w.mnemonic} {w.op_str}' for w in win]
    joined = ' | '.join(seq)
    if 'bl #0x2c2e46c' not in joined:
        continue
    # locate the movs r0 (group) just before
    grp = None
    for w in reversed(win):
        if w.mnemonic == 'movs' and w.op_str.startswith('r0'):
            try:
                grp = int(w.op_str.split('#')[-1], 0)
            except ValueError:
                grp = None
            break
    # business call right after the lock bl
    biz = None
    idx = None
    for i, w in enumerate(win):
        if w.mnemonic == 'bl' and w.op_str == '#0x2c2e46c':
            idx = i
            break
    if idx is not None:
        for w in win[idx + 1:idx + 6]:
            if w.mnemonic in ('bl', 'blx') and w.op_str.startswith('#'):
                try:
                    biz = int(w.op_str[1:], 16)
                except ValueError:
                    biz = None
                break
    results.append((ins.address, grp, lid, biz))
    count += 1
    if count > 400:
        break

print('found %d wrappers with id=0xa' % len(results))
for site, grp, lid, biz in results[:80]:
    print('  movs r1,#%#x at %#010x  group=%s business=%s'
          % (lid, site, ('%#x' % grp) if grp is not None else '?',
             ('%#010x' % biz) if biz else '?'))
