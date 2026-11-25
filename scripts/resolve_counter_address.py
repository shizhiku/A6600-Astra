"""Resolve the retry counter's runtime address from original Thumb code."""
from pathlib import Path
import struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
root=Path(__file__).resolve().parent
d=(root/'qemu_in/av-cam.bin').read_bytes();base=0x635c6000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
rows=[]
for x in md.disasm(d[0x63852a20-base:0x63852a50-base],0x63852a20):
 rows.append((x.address,x.mnemonic,x.op_str,x.bytes.hex()))
for a,m,o,h in rows:print(f'{a:08x} {h:10} {m:9} {o}')
# literal load at 0x63852a28 is ldr r3,[pc,#0x4c]; add r3,pc
ldr=0x63852a28; add=0x63852a2a
lit=(ldr+4)&~3
lit=(lit & ~3)+0
alt=(ldr & ~3)+4+0x4c
print('candidate literal addresses',hex(alt))
val=struct.unpack_from('<H',d[alt-base:alt-base+2])[0]
print('literal value',hex(val))
addpc=(add+4)&~3
print('counter runtime',hex(addpc+val))
