"""Extract the device path opened by libsencore's packet sender (function at 0x15120)."""
from pathlib import Path
import struct

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libsencore.so'
d = LIB.read_bytes()

# ldr r0,[pc,#0x8c] at 0x1512C  -> literal at align(0x15130)+0x8c
lit_addr = (0x1512C + 4) + 0x8C
V = struct.unpack_from('<I', d, lit_addr)[0]
print(f'literal @ {lit_addr:#x} = {V:#x}')

# add r0, pc at 0x15134 -> PC = 0x15138
add_pc = 0x15134 + 4
target = add_pc + V
print(f'path VA = {add_pc:#x} + {V:#x} = {target:#x}')

seg = d[target:target + 96]
txt = seg.split(b'\x00')[0]
print('path bytes:', seg[:64].hex(' '))
print('path text :', txt.decode('latin1', 'replace'))

# also list all device-like strings in .rodata
print('\n--- device-ish strings in the library ---')
import re
for m in re.finditer(rb'/dev/[ -~]{2,60}', d):
    print('   ', m.group(0).decode('latin1'))
