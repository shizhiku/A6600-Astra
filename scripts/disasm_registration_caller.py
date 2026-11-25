"""Disassemble the function that calls the font registration (call site 0x54F42C)."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'
d = LIB.read_bytes()
SITE = 0x54F42C

start = None
for va in range(SITE, SITE - 0x600, -2):
    hw = struct.unpack_from('<H', d, va)[0]
    if (hw & 0xFF00) == 0xB500 or (hw & 0xFFE0) == 0xB080 or (hw & 0xFFF0) == 0xE92D:
        start = va
        break
print('function start candidate:', hex(start) if start else None)

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
begin = start if start else SITE - 0x80
for x in md.disasm(d[begin: SITE + 0x30], begin):
    mark = '   <== calls registration' if x.address == SITE else ''
    print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:9} {x.op_str}{mark}')

# look for literal references to printable strings near this function
print('\n--- printable strings referenced within +/-0x400 ---')
for off in range(begin, SITE + 0x100, 2):
    if off + 4 > len(d):
        break
    v = struct.unpack_from('<I', d, off)[0]
    if 0 < v < len(d) - 32:
        seg = d[v:v + 48]
        if seg[0] and all(32 <= c < 127 or c == 0 for c in seg[:16]):
            txt = seg.split(b'\x00')[0].decode('latin1', 'replace')
            if len(txt) >= 4:
                print(f'  literal@{off:#x} -> {v:#x}: {txt!r}')
