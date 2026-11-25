"""Survey immediate loads of backup unit 0x170000 in the original Thumb image."""
from pathlib import Path
import struct,json
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
root=Path(__file__).resolve().parent;data=(root/'qemu_in/av-cam.bin').read_bytes();base=0x635c6000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.skipdata=True
forms=[]
for imm in range(4096):
 h1=0xf04f|((imm>>11)<<10);h2=((imm>>8)&7)<<12|(imm&255)
 raw=struct.pack('<HH',h1,h2)
 ins=next(md.disasm(raw,0),None)
 if ins and ins.mnemonic in ('mov.w','mov') and ins.op_str=='r0, #0x170000':forms.append((h1,h2))
hits=[]
for h1,h2 in forms:
 for reg in range(13):
  raw=struct.pack('<HH',h1,h2|(reg<<8));start=0
  while True:
   p=data.find(raw,start)
   if p<0:break
   start=p+2
   if p%2 or p>0xc00000:continue
   context=[f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:8} {x.op_str}' for x in md.disasm(data[p-16:p+40],base+p-16)]
   hits.append({'offset':hex(p),'address':hex(base+p),'register':reg,'context':context})
out=root/'a6600_port/analysis/liro-fault-static/unit-immediate-references.json';out.write_text(json.dumps(hits,indent=2),encoding='utf-8')
print('immediate forms',[(hex(a),hex(b)) for a,b in forms],'hits',len(hits))
for h in hits[:15]:print('\n'.join(h['context'])+'\n')
