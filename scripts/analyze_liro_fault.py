"""Bounded static inspection of the original av-cam instructions at an observed QEMU fault."""
from pathlib import Path
import hashlib,json,struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
root=Path(__file__).resolve().parent
src=root/'qemu_in/av-cam.bin'; data=src.read_bytes()
base=0x635c6000; pc=0x63849f30; off=pc-base
out=root/'a6600_port/analysis/liro-fault-static'; out.mkdir(parents=True,exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True;md.skipdata=True
lines=[]
for x in md.disasm(data[off-0x80:off+0x120],pc-0x80):
 lines.append(f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:9} {x.op_str}'+('  <-- OBSERVED PC' if x.address==pc else ''))
report={'input':str(src),'sha256':hashlib.sha256(data).hexdigest(),'mapping_assumption':'Raw av-cam address 0x635c6000; confirm fault bytes against kernel dump','runtime_pc':hex(pc),'file_offset':hex(off),'bytes_at_pc':data[off:off+8].hex(),'preceding_halfwords':data[off-8:off+2].hex(),'instructions':lines}
(out/'instructions.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
(out/'instructions.txt').write_text('\n'.join(lines),encoding='utf-8')
print('SHA256',report['sha256']);print('file offset',hex(off));print('\n'.join(lines))
