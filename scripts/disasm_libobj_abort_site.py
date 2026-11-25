"""Disassemble libObj around the abort call site with correct alignment."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'
LR = 0x64191F              # return address offset (thumb bit set)
CALL = (LR & ~1) - 4       # 0x64191A
data = LIB.read_bytes()
print(f'file size {len(data):#x}; call site {CALL:#x}')

# find a plausible function prologue before the call
start = None
for va in range(CALL - 2, CALL - 0x400, -2):
    hw = struct.unpack_from('<H', data, va)[0]
    if (hw & 0xFF00) == 0xB500:      # push {.., lr}
        start = va
        break
print('prologue candidate:', hex(start) if start else None)

begin = start if start is not None else CALL - 0x80
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
print('--- disassembly ---')
for ins in md.disasm(data[begin: CALL + 0x40], begin):
    mark = ''
    if ins.address == CALL:
        mark = '   <== bl abort'
    print(f'  {ins.address:06x} {ins.bytes.hex():10} {ins.mnemonic:9} {ins.op_str}{mark}')

# scan the following literal pool for pointers into .rodata that look like strings
print('\n--- literal pool scan (next 0x60 bytes) ---')
for off in range(CALL + 4, CALL + 0x60, 4):
    v = struct.unpack_from('<I', data, off)[0]
    if 0 < v < len(data):
        seg = data[v:v + 48]
        if all(32 <= c < 127 or c in (0,) for c in seg[:24]):
            txt = seg.split(b'\x00')[0].decode('latin1', 'replace')
            print(f'  literal@{off:#x} -> {v:#x}: {txt!r}')
