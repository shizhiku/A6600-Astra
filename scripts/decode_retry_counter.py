"""Decode the retry counter routine and its shared predicate checks."""
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
root=Path(__file__).resolve().parent
d=(root/'qemu_in/av-cam.bin').read_bytes();base=0x635c6000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.skipdata=True
lines=[]
for start,end,label in [(0x638529c4,0x638529e0,'predicate-3 gate'),(0x63852a20,0x63852a60,'30-retry counter and error publish')]:
 lines.append(f'=== {label} ===')
 for x in md.disasm(d[start-base:end-base],start):
  lines.append(f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:9} {x.op_str}')
# resolve the pc-relative counter literal used at 0x63852a28
pc=(0x63852a28+4)&~3
import struct
raw=struct.unpack_from('<H',d[0x63852a28-base:0x63852a2a-base])[0]
lines.append(f'counter literal instruction raw=0x{raw:04x}')
p=root/'a6600_port/analysis/liro-fault-static/retry-counter.txt'
p.write_text('\n'.join(lines),encoding='utf-8');print('\n'.join(lines))
