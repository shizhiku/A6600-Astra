"""Locate code that builds or parses 0x39-prefixed SIO frames."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/av-cam-live.bin'
VA0 = 0x635C6000
d = IMG.read_bytes()

# Thumb 16-bit: movs rX,#0x39  -> 0x2039 | (Rd<<8)
patterns = {}
for rd in range(8):
    patterns[0x2000 | (rd << 8) | 0x39] = f'movs r{rd},#0x39'

hits = []
for off in range(0, len(d) - 2, 2):
    hw = struct.unpack_from('<H', d, off)[0]
    if hw in patterns:
        hits.append((off, patterns[hw]))

print('movs rX,#0x39 occurrences:', len(hits))
for off, desc in hits[:40]:
    print(f'  file {off:#08x}  VA {VA0 + off:#010x}  {desc}')

# also look for cmp rX,#0x39 (0x2939 | Rd<<8)
cmp_hits = []
for off in range(0, len(d) - 2, 2):
    hw = struct.unpack_from('<H', d, off)[0]
    if (hw & 0xFF00) == 0x2900 and (hw & 0xFF) == 0x39:
        cmp_hits.append(off)
print('\ncmp rX,#0x39 occurrences:', len(cmp_hits))
for off in cmp_hits[:20]:
    print(f'  file {off:#08x}  VA {VA0 + off:#010x}')
