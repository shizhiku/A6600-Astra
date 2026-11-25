"""Decode IMDB fixed-size records and string evidence without target execution."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
import io,struct,json,re
BASE=Path(__file__).resolve().parents[1]; OUT=BASE/'03-证据/静态分析/97_abi'
results={}
for prefix in ('a6usr','zvusr'):
 p=OUT/(prefix+'_libIMDB.so'); data=p.read_bytes(); e=ELFFile(io.BytesIO(data))
 def read(va,n):
  for s in e.iter_segments():
   if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz']:
    off=s['p_offset']+va-s['p_vaddr']; return data[off:off+n]
  return b''
 def string(va):
  raw=read(va,256).split(b'\0')[0]
  try: return raw.decode('ascii') if raw and all(32<=b<127 for b in raw) else None
  except UnicodeDecodeError:return None
 raw=next(s['st_value'] for s in e.get_section_by_name('.dynsym').iter_symbols() if s.name=='imdb_raw')
 hdr=list(struct.unpack('<33I',read(raw,132))); records=[]
 for i in range(1000):
  va=raw+132+44*i; b=read(va,44)
  if len(b)<44:break
  w=list(struct.unpack('<11I',b)); strings={str(j*4):string(v) for j,v in enumerate(w) if string(v)}
  rec={'index':i,'va':hex(va),'words':[hex(v) for v in w],'strings':strings,'u16_offset8':struct.unpack_from('<H',b,8)[0],'u16_offset10':struct.unpack_from('<H',b,10)[0],'u16_offset12':struct.unpack_from('<H',b,12)[0],'u16_offset14':struct.unpack_from('<H',b,14)[0]}
  records.append(rec)
  if w[0]==40: break
 results[prefix]={'imdb_raw':hex(raw),'header_words':[hex(v) for v in hdr],'header_strings':{str(j*4):string(v) for j,v in enumerate(hdr) if string(v)},'entries':records}
(OUT/'imdb_entries.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf8')
for k,v in results.items():
 print(k,'header',v['header_strings'],'records',len(v['entries']))
 for r in v['entries']: print(r['index'],r['va'],r['words'][:4],r['strings'])
# Addresses for every printable string in the im executable; used to resolve Thumb literal loads.
for prefix in ('a6usr','zvusr'):
 p=OUT/(prefix+'_im.elf'); data=p.read_bytes(); e=ELFFile(io.BytesIO(data)); lines=[]
 for seg in e.iter_segments():
  if seg['p_type']!='PT_LOAD':continue
  blob=seg.data()
  for mat in re.finditer(rb'[\x20-\x7e]{4,}',blob):
   lines.append(f'{seg["p_vaddr"]+mat.start():08x} {mat.group().decode()}')
 (OUT/(prefix+'_im_strings.txt')).write_text('\n'.join(lines),encoding='utf8')
