"""Compare the observed state with file-backed av-cam data and inspect bounded helper windows."""
from pathlib import Path
import json,struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
root=Path(__file__).resolve().parent;data=(root/'qemu_in/av-cam.bin').read_bytes();base=0x635c6000
out=root/'a6600_port/analysis/liro-fault-static/helpers.txt'
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.skipdata=True
lines=[]
for addr in [0x64437e98,0x644ad325]:
 off=addr-base;lines.append(f'FILE_STATE {addr:#x} offset={off:#x} bytes={data[off:off+64].hex()}')
for addr,n in [(0x63d2aaf2,160),(0x6384cc94,64),(0x638516c8,64),(0x6384f4f4,48),(0x63849a00,96)]:
 lines.append(f'\nWINDOW {addr:#x}')
 for x in md.disasm(data[addr-base:addr-base+n],addr):lines.append(f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:9} {x.op_str}')
out.write_text('\n'.join(lines),encoding='utf-8');print('\n'.join(lines))
