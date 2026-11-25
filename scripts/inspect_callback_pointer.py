"""Inspect the local function-pointer table containing the callback trampoline."""
from pathlib import Path
import struct,json
root=Path(__file__).resolve().parent;d=(root/'qemu_in/av-cam.bin').read_bytes();off=0x1009950
rows=[]
for i in range(-16,32):
 p=off+i*4
 if 0<=p<=len(d)-4:
  v=struct.unpack_from('<I',d,p)[0]
  rows.append({'offset':hex(p),'relative_to_match':i,'value':hex(v),'runtime_pointer_likely':0x635c6000<=v<0x645c6000})
out={'match_offset':hex(off),'match_value':hex(struct.unpack_from('<I',d,off)[0]),'words':rows}
(root/'a6600_port/analysis/liro-fault-static/callback-pointer-context.json').write_text(json.dumps(out,indent=2),encoding='utf-8');print(json.dumps(out,indent=2))
