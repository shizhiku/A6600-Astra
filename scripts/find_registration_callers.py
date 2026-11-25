"""Find the font-registration function boundaries and its callers in libObj."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'
d = LIB.read_bytes()

# locate prologue before 0x54EA46
start = None
for va in range(0x54EA46, 0x54E800, -2):
    hw = struct.unpack_from('<H', d, va)[0]
    if (hw & 0xFF00) == 0xB500 or (hw & 0xFFE0) == 0xB080:  # push {..,lr} variants
        start = va
        break
print('registration function candidate start:', hex(start) if start else None)

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
if start:
    print('\n--- prologue ---')
    for x in md.disasm(d[start:start + 40], start):
        print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:9} {x.op_str}')

# scan for bl targets into the candidate function
print('\n--- callers (bl to the function) ---')
hits = []
if start:
    for ins in md.disasm(d, 0):
        if ins.mnemonic == 'bl' and ins.op_str.startswith('#'):
            try:
                tgt = int(ins.op_str[1:], 16)
            except ValueError:
                continue
            if tgt == start:
                hits.append(ins.address)
print('calls:', [hex(a) for a in hits][:20], 'total', len(hits))
