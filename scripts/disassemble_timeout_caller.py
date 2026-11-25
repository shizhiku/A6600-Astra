"""Decode the captured indirect-callback caller of the timeout routine."""
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
import json
root=Path(__file__).resolve().parent;d=(root/'qemu_in/av-cam.bin').read_bytes();base=0x635c6000
start=0x63cefc70;end=0x63cefd40
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.skipdata=True
lines=[f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:9} {x.op_str}' for x in md.disasm(d[start-base:end-base],start)]
out=root/'a6600_port/analysis/liro-fault-static/timeout-caller-context.txt';out.write_text('\n'.join(lines),encoding='utf-8');print('\n'.join(lines))
