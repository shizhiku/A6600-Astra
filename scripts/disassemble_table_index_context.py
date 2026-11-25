"""Disassemble bounded av-cam windows around uses of table index 0x3824."""
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
root=Path(__file__).resolve().parent;d=(root/'qemu_in/av-cam.bin').read_bytes();base=0x635c6000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.skipdata=True
out=[]
for start,end in [(0x638528c0,0x63852970),(0x63852970,0x63852aa0),(0x63852cc0,0x63852da0)]:
 out.append(f'=== {start:#x}-{end:#x} ===')
 for x in md.disasm(d[start-base:end-base],start):out.append(f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:9} {x.op_str}')
p=root/'a6600_port/analysis/liro-fault-static/table-index-context.txt';p.write_text('\n'.join(out),encoding='utf-8');print('\n'.join(out))
