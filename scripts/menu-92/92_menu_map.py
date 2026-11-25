"""Offline MENU key mapping evidence; never starts QEMU or changes shared files."""
from pathlib import Path
import sys,struct,json,hashlib,bisect
sys.path.insert(0,str(Path(__file__).resolve().parent))
from input_sen_analyze import Elf
B=Path(__file__).resolve().parents[1]; E=Elf(B/'03-证据/静态分析/libObj.so'); D=E.data
O=B/'03-证据/静态分析/92_menu_map'; O.mkdir(exist_ok=True)
starts=[]
s=E.e.get_section_by_name('.ARM.exidx')
for o in range(s['sh_offset'],s['sh_offset']+s['sh_size'],8):
 w=struct.unpack_from('<I',D,o)[0]&0x7fffffff; w=w-(1<<31) if w&(1<<30) else w; starts.append((s['sh_addr']+o-s['sh_offset']+w)&0xffffffff)
starts.sort()
def owner(a):return starts[bisect.bisect_right(starts,a)-1]
def calls(target):
 out=[]; t=E.e.get_section_by_name('.text')
 for o in range(t['sh_offset'],t['sh_offset']+t['sh_size']-3,2):
  a,b=struct.unpack_from('<HH',D,o)
  if a&0xf800!=0xf000 or b&0xc000!=0xc000:continue
  S=(a>>10)&1; j1=(b>>13)&1;j2=(b>>11)&1;i1=1^(j1^S);i2=1^(j2^S)
  v=(S<<24)|(i1<<23)|(i2<<22)|((a&1023)<<12)|((b&2047)<<1)
  if S:v-=1<<25
  va=o-t['sh_offset']+t['sh_addr']
  dest=va+4+v
  if not b&0x1000:dest=(va+4&~3)+v
  if dest&~1==target&~1:out.append((va,owner(va),E.name(owner(va))))
 return out
mode=sys.argv[1] if len(sys.argv)>1 else 'scan'
if mode=='summary':
 V=Elf(O/'viewUnified2.so')
 def words(e,a,n):return list(struct.unpack_from('<'+'I'*n,e.data,e.off(a)))
 result={'libObj_sha256':hashlib.sha256(D).hexdigest(),'viewUnified2_sha256':hashlib.sha256(V.data).hexdigest(),'physical_name_table':[{'va':hex(a),'key':hex(words(E,a,2)[0]),'name':E.string(words(E,a,2)[1])} for a in [0x13f0924,0x13f092c]],'config_table_va':'0x95fa5c','config_entry_size':'0x14','config_entries':[],'mapping_rows':[]}
 for index in [0,2]:
  a=0x95fa5c+index*20;ws=words(V,a,5);result['config_entries'].append({'index':index,'va':hex(a),'list_va':hex(ws[0]),'callback_thumb':hex(ws[1]),'count':ws[2],'init_flag':ws[3],'predicate':hex(ws[4])})
 for key,a,base in [(0x1ab,0x9600fc,0x96009c),(0x1ac,0x95ffa0,0x95ff94)]:
  result['mapping_rows'].append({'key':hex(key),'va':hex(a),'file_offset':hex(V.off(a)),'index':(a-base)//12,'words':[hex(x) for x in words(V,a,3)],'raw':V.data[V.off(a):V.off(a)+12].hex()})
 text=json.dumps(result,ensure_ascii=False,indent=2);(O/'mapping_evidence.json').write_text(text,encoding='utf-8');print(text)
elif mode=='vdis':
 E=Elf(O/'viewUnified2.so'); a=int(sys.argv[2],0); n=int(sys.argv[3],0); text=E.dis(a,n);(O/f'view_dis_{a:08x}.txt').write_text(text,encoding='utf-8');print(text)
elif mode=='dis':
 a=int(sys.argv[2],0); n=int(sys.argv[3],0); text=E.dis(a,n); (O/f'dis_{a:08x}.txt').write_text(text,encoding='utf-8');print(text)
elif mode=='firmware':
 from a6600_usr import Ext2
 fs=Ext2(str(B/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15')); lines=[]
 for p,ino,isdir in fs.walk():
  if isdir or not p.startswith('/lib/'):continue
  data=fs.read_file(ino)
  if not data.startswith(b'\x7fELF'):continue
  hits=[]
  for key in [0x1ab,0x1ac]:
   needle=struct.pack('<I',key);pos=0
   while True:
    pos=data.find(needle,pos)
    if pos<0:break
    if pos%4==0 and pos+12<=len(data):
     ws=struct.unpack_from('<III',data,pos)
     if ws[1]>=0x10000000 and ws[1]<0x20000000:hits.append((hex(pos),[hex(w) for w in ws]))
    pos+=1
  if hits or b'InputServiceConfig' in data or b'getInputKey' in data:
   dest=O/Path(p).name
   if not dest.exists():dest.write_bytes(data)
   lines.append((p,hits))
 text=json.dumps(lines,indent=2);(O/'firmware_scan.json').write_text(text);print(text)
elif mode=='call':
 a=int(sys.argv[2],0);r=calls(a);print(json.dumps(r,indent=2));(O/f'calls_{a:08x}.json').write_text(json.dumps(r,indent=2))
else:
 lines=['SHA256 '+hashlib.sha256(D).hexdigest()]
 for o in range(0,len(D)-12,4):
  if struct.unpack_from('<I',D,o)[0]==0x1ac:
   lines.append(f'{o:08x}: '+' '.join(f'{x:08x}' for x in struct.unpack_from('<'+'I'*min(16,(len(D)-o)//4),D,o)))
 lines+=['SetEventKeyList direct calls: '+json.dumps(calls(0x861aa8))]
 text='\n'.join(lines);(O/'scan.txt').write_text(text,encoding='utf-8'); print(text)
