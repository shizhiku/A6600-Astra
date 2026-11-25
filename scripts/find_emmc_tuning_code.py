"""Locate the eMMC tuning warning string and the code that references it in the kernel image."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/nflasha3-Image'
d = IMG.read_bytes()

for term in (b'Software Tuning is forbiden', b'debug_quirks', b'sdhci', b'HS200'):
    idx, n = d.find(term), 0
    pos = []
    while idx >= 0 and n < 5:
        pos.append(idx)
        n += 1
        idx = d.find(term, idx + 1)
    print(f'{term.decode():32s} -> {[hex(p) for p in pos]}')

i = d.find(b'Software Tuning is forbiden')
if i < 0:
    raise SystemExit('warning string not found')
print('\ncontext around warning string:')
seg = d[max(0, i - 120): i + 200]
print(''.join(chr(c) if 32 <= c < 127 else '.' for c in seg))

# find code referencing it: literal V with target = i, using add rX,pc pattern
TARGET = i
cands = []
for A in range(0, len(d) - 4, 4):
    V = struct.unpack_from('<I', d, A)[0]
    if V == 0 or V > 0x4000000:
        continue
    # ARM: add rX, pc, #imm at B -> B+8+V == TARGET
    B = TARGET - V - 8
    if 0 <= B < len(d) - 8 and (B % 4 == 0):
        w = struct.unpack_from('<I', d, B)[0]
        if ((w >> 28) == 0xE and ((w >> 25) & 7) == 1 and ((w >> 21) & 0xF) == 4):
            cands.append((B, A, V))
print(f'\nARM add-pc candidates: {len(cands)}')
for B, A, V in cands[:10]:
    print(f'  add@{B:#x} literal@{A:#x} V={V:#x}')

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.skipdata = True
for B, A, V in cands[:2]:
    start = max(0, B - 0x60)
    print(f'\n=== code around {B:#x} ===')
    for x in md.disasm(d[start:B + 0x40], start):
        mark = '   <== ref' if x.address == B else ''
        print(f'{x.address:08x} {x.bytes.hex():8} {x.mnemonic:8} {x.op_str}{mark}')
