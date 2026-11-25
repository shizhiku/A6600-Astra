"""Search original gen5 images for remaining ABI providers, including static/kernel tables.
No execution. Raw matches are candidates, not callable user-space providers.
"""
from pathlib import Path
import io,json,hashlib,struct,importlib.util,tarfile
from elftools.elf.elffile import ELFFile
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_abi'
s=importlib.util.spec_from_file_location('u',B/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
u=json.loads((O/'union_missing.json').read_text(encoding='utf8')); targets={n for x in u.values() for n in x['strong'] if n!='stm_system'}
short=[b'arch_phys_to_cache',b'adf_ext_type',b'set_user_matrix',b'SetAllInvalidDefStrGpsInfo',b'_M_compile',b'regex_search']
results=[];coverage=[]
def inspect(data,source):
 found={x.decode():[hex(i) for i in range(len(data)) if False] for x in []}
 for needle in short:
  off=data.find(needle)
  if off>=0:found[needle.decode()]={'first_offset':hex(off),'count':data.count(needle)}
 if not found:return
 rec={'source':source,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'raw_matches':found,'exact_symbols':[]}
 if data[:4]==b'\x7fELF':
  try:
   e=ELFFile(io.BytesIO(data));e._section_name_map={e._get_section_name(e._get_section_header(i)):i for i in range(e.num_sections())}
   for tab in ('.dynsym','.symtab'):
    sec=e.get_section_by_name(tab)
    if not sec:continue
    for sym in sec.iter_symbols():
     if sym.name in targets:rec['exact_symbols'].append({'table':tab,'name':sym.name,'section':str(sym['st_shndx']),'value':hex(sym['st_value']),'size':sym['st_size'],'bind':sym['st_info']['bind'],'visibility':sym['st_other']['visibility']})
  except Exception as exc:rec['parse_error']=str(exc)
 results.append(rec)
for img in ('nflasha15','nflasha7'):
 p=B/'05-原始固件/zv1m2_fw/extracted/0700_part_image/dev'/img;fs=m.Ext2(str(p));count=0
 for name,ino,d in fs.walk():
  if d:continue
  mode,size,_=fs.inode(ino)
  if mode&0xf000!=0x8000:continue
  data=fs.read_file(ino);count+=1
  inspect(data,img+':'+name)
 coverage.append({'image':img,'regular_files_scanned':count})
# Inspect the system FAT's original root and nested regular files, especially AV-CAM.BIN.
p=B/'05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha3'
if p.exists():blob=p.read_bytes()
else:
 with tarfile.open(B/'05-原始固件/zv1m2_fw/firmware.tar') as archive:blob=archive.extractfile('0700_part_image/dev/nflasha3').read()
coverage.append({'image':'nflasha3','sha256':hashlib.sha256(blob).hexdigest(),'bytes':len(blob),'source':'firmware.tar:0700_part_image/dev/nflasha3' if not p.exists() else str(p)})
if blob:
 bps=struct.unpack_from('<H',blob,11)[0];spc=blob[13];reserved=struct.unpack_from('<H',blob,14)[0];nf=blob[16];nroot=struct.unpack_from('<H',blob,17)[0];spf=struct.unpack_from('<H',blob,22)[0] or struct.unpack_from('<I',blob,36)[0]
 if bps in (512,1024,2048,4096) and spc and reserved:
  rootsecs=(nroot*32+bps-1)//bps;firstdata=reserved+nf*spf+rootsecs;tot=struct.unpack_from('<H',blob,19)[0] or struct.unpack_from('<I',blob,32)[0];clusters=(tot-firstdata)//spc;fatbits=12 if clusters<4085 else 16 if clusters<65525 else 32
  fat=blob[reserved*bps:(reserved+spf)*bps]
  def chain(c):
   seen=set();out=bytearray()
   while c>=2 and c not in seen and c<({12:0xff8,16:0xfff8,32:0xffffff8}[fatbits]):
    seen.add(c);off=(firstdata+(c-2)*spc)*bps;out+=blob[off:off+spc*bps]
    if fatbits==12:
     v=struct.unpack_from('<H',fat,c+c//2)[0];c=(v>>4 if c&1 else v&0xfff)
    else:c=struct.unpack_from('<H' if fatbits==16 else '<I',fat,c*(2 if fatbits==16 else 4))[0]&(0xffff if fatbits==16 else 0xfffffff)
   return bytes(out)
  files=[]
  def walk(d,prefix):
   for pos in range(0,len(d)-31,32):
    en=d[pos:pos+32]
    if en[0]==0:break
    if en[0]==229 or en[11]&0x0f==0x0f or en[11]&8:continue
    name=en[:8].decode('latin1').rstrip();ext=en[8:11].decode('latin1').rstrip();name+=('.'+ext if ext else '')
    if name in ('.','..'):continue
    c=struct.unpack_from('<H',en,26)[0]|(struct.unpack_from('<H',en,20)[0]<<16);size=struct.unpack_from('<I',en,28)[0];full=prefix+'/'+name
    if en[11]&16:walk(chain(c),full)
    else:
     data=chain(c)[:size];files.append({'path':full,'bytes':size,'sha256':hashlib.sha256(data).hexdigest()});inspect(data,'nflasha3:'+full)
     if 'AV-CAM' in name.upper() or 'VMLINUX' in name.upper():(O/('zv_system_'+name)).write_bytes(data)
  if fatbits in (12,16,32):
   root=blob[(reserved+nf*spf)*bps:(reserved+nf*spf)*bps+nroot*32] if fatbits in (12,16) else chain(struct.unpack_from('<I',blob,44)[0]);walk(root,'')
   coverage.append({'image':'nflasha3','fatbits':fatbits,'files':files})
  else:coverage.append({'image':'nflasha3','unsupported_fatbits':fatbits})
 else:coverage.append({'image':'nflasha3','error':'not recognized FAT BPB','bps':bps})
(O/'provider_search.json').write_text(json.dumps({'targets':sorted(targets),'coverage':coverage,'matches':results},ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'coverage':coverage,'candidate_files':len(results),'exact_defined_symbols':[{'source':r['source'],'symbols':[s for s in r['exact_symbols'] if s['section']!='SHN_UNDEF']} for r in results if any(s['section']!='SHN_UNDEF' for s in r['exact_symbols'])],'non_elf_raw_matches':[r for r in results if not r['exact_symbols']]},ensure_ascii=False,indent=2))
