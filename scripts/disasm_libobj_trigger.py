"""Disassemble libObj around the real abort trigger (offset 0x64795F)."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'
LR = 0x64795F
CALL = (LR & ~1) - 4        # presumed bl return
data = LIB.read_bytes()

start = None
for va in range(CALL - 2, CALL - 0x300, -2):
    hw = struct.unpack_from('<H', data, va)[0]
    if (hw & 0xFF00) == 0xB500:
        start = va
        break
print(f'call ~{CALL:#x}; prologue candidate {hex(start) if start else None}')

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
begin = start if start is not None else CALL - 0x60
for ins in md.disasm(data[begin: CALL + 0x30], begin):
    mark = '   <== call thunk' if ins.address in (CALL, CALL - 2) else ''
    print(f'  {ins.address:06x} {ins.bytes.hex():10} {ins.mnemonic:9} {ins.op_str}{mark}')

# strings referenced from the literal pool right after the function
print('\n--- nearby literals pointing at printable data ---')
for off in range(CALL, CALL + 0x120, 4):
    if off + 4 > len(data):
        break
    v = struct.unpack_from('<I', data, off)[0]
    if 0 < v < len(data) - 32:
        seg = data[v:v + 60]
        if seg[0] != 0 and all(32 <= c < 127 or c == 0 for c in seg[:20]):
            txt = seg.split(b'\x00')[0].decode('latin1', 'replace')
            if len(txt) >= 6:
                print(f'  literal@{off:#x} -> {v:#x}: {txt!r}')
