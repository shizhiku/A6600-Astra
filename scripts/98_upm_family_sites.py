"""Locate the remaining upm2model converters that call
notify_model_system_error and show their field-check code.

The stack return addresses seen at the abort were:
  0x2B359F7, 0x2B20821, 0x2B20DA9
For each we print the containing function and the instructions around the
BL to 0x2BC3174, plus any ldr of the local message struct that feeds the
0x1C/0x20/0x24 checks.
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io, struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

ex = e.get_section_by_name('.ARM.exidx')
ed, eb = ex.data(), ex['sh_addr']
starts = []
for k in range(0, len(ed), 8):
    w = struct.unpack_from('<I', ed, k)[0]
    pre = (w & 0x7fffffff)
    pre = pre if pre < 0x40000000 else pre - 0x80000000
    starts.append((eb + k + pre) & 0xffffffff)
starts = sorted(set(starts))

for st in starts:
    if st & 1:
        continue
    if st <= 0x2B359F7 and (0x2B359F7 - st) > 0x2000:
        continue
    if st > 0x2B359F7:
        print('function containing 0x2B359F7 =', hex(st), 'delta',
              hex(0x2B359F7 - st))
        cand = st
        break
else:
    cand = None
print('cand', hex(cand) if cand else None)

for start, ra in ((cand, 0x2B359F7),):
    if not start:
        continue
    print('==== function', hex(start), 'RA', hex(ra))
    off = start - tb
    insns = list(md.disasm(td[off:off + 0x180], start))
    for i in insns:
        mark = '  <-- RA' if (i.address + i.size) == ra else ''
        print(f'{i.address:08x} {i.mnemonic:8} {i.op_str}{mark}')

print('==== search all BL to 0x2BC3174 in range 0x2B00000-0x2BC0000')
count = 0
for ins in md.disasm(td[0x2B00000 - tb:0x2BC0000 - tb], 0x2B00000):
    if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
        try:
            v = int(ins.op_str[1:], 16)
        except ValueError:
            continue
        if (v & ~1) == 0x2BC3174:
            print(hex(ins.address))
            count += 1
            if count > 40:
                break
