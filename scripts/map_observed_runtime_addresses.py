"""Map QEMU-observed LIRO addresses back into a6600 av-cam.bin bytes."""
from pathlib import Path
import struct,json,hashlib
root=Path(__file__).resolve().parent
p=root/'qemu_in/av-cam.bin';d=p.read_bytes();base=0x635c6000
addrs={'getter_table_slot':0x645ca930,'getter_target':0x6431f3c0,'fault_state':0x64437e98,'global_a':0x644ae302,'global_b':0x644ae326}
out={'base':hex(base),'file_bytes':len(d),'file_sha256':hashlib.sha256(d).hexdigest(),'mapped':{}}
for name,a in addrs.items():
 off=a-base;rec={'runtime':hex(a),'relative_offset':hex(off),'in_file_range':0<=off<len(d)}
 if 0<=off<len(d):rec['bytes']=d[off:off+64].hex();rec['words']=[hex(x) for x in struct.unpack_from('<8I',d,off)]
 out['mapped'][name]=rec
needle=struct.pack('<I',0x6431f3c0)
hits=[];i=0
while (i:=d.find(needle,i))>=0:hits.append(hex(i));i+=1
out['literal_pointer_file_offsets']=hits[:100];out['literal_pointer_count']=len(hits)
(root/'a6600_port/analysis/liro-fault-static/runtime-map.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
print(json.dumps(out,indent=2))
