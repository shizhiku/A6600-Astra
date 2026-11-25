from pathlib import Path
from elftools.elf.elffile import ELFFile
import struct,sys,json
r=Path(__file__).resolve().parents[1];p=r/sys.argv[1];targets={int(x,0) for x in sys.argv[2:]}
with p.open('rb') as f:
 e=ELFFile(f);hits=[]
 for s in e.iter_sections():
  if not s['sh_flags']&4:continue
  d=s.data();base=s['sh_addr']
  for o in range(0,len(d)-3,2):
   a,b=struct.unpack_from('<HH',d,o)
   if a&0xf800!=0xf000:continue
   if b&0xd000 not in (0xd000,0x9000,0xc000):continue
   S=(a>>10)&1;J1=(b>>13)&1;J2=(b>>11)&1;I1=1^(J1^S);I2=1^(J2^S)
   v=(S<<24)|(I1<<23)|(I2<<22)|((a&0x3ff)<<12)|((b&0x7ff)<<1)
   if S:v-=1<<25
   pc=base+o+4
   if b&0xd000==0xc000:pc&=~3
   dst=(pc+v)&0xffffffff
   if dst in targets:hits.append({'va':hex(base+o),'file':hex(s['sh_offset']+o),'target':hex(dst),'kind':hex(b&0xd000)})
 print(json.dumps(hits,indent=2))
 # pointer references (including thumb)
 for s in e.iter_sections():
  if s['sh_type']=='SHT_NOBITS':continue
  d=s.data()
  for dst in targets:
   for ptr in (dst,dst|1):
    needle=struct.pack('<I',ptr);i=d.find(needle)
    while i>=0:
     print('PTR',s.name,hex(s['sh_addr']+i),hex(ptr));i=d.find(needle,i+1)
