"""Redirect the 4th-gen InfraInput queues to dummy qids so the 4th-gen
instance stops consuming the real input events (Agent 112 / input-driver
analysis, plan A2).

Patches three literal dwords in 4th-gen /lib/libObj.so:
  0x86270C  0x007A804C -> 0x007A8060
  0x86301C  0x007A0020 -> 0x007A0030
  0x863150  0x007A804C -> 0x007A8060
"""
from pathlib import Path
import struct

src = Path('03-证据/静态分析/97_abi/a6_libObj.so')
out = Path('03-证据/静态分析/97_abi/libObj4_inputq.so')
d = bytearray(src.read_bytes())

sites = [
    (0x86270C, 0x007A804C, 0x007A8060),
    (0x86301C, 0x007A0020, 0x007A0030),
    (0x863150, 0x007A804C, 0x007A8060),
]
for off, old, new in sites:
    cur = struct.unpack_from('<I', d, off)[0]
    print(hex(off), hex(cur), '->', hex(new))
    assert cur == old, f'mismatch at {off:#x}: {cur:#x} != {old:#x}'
    struct.pack_into('<I', d, off, new)

out.write_bytes(bytes(d))
print('wrote', out, len(d))
