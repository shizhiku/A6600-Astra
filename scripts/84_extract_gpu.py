from pathlib import Path
import importlib.util,hashlib,json,io
from elftools.elf.elffile import ELFFile
ROOT=Path(__file__).resolve().parents[1];out=ROOT/'03-证据/静态分析/probe84';out.mkdir(exist_ok=True)
spec=importlib.util.spec_from_file_location('usr',ROOT/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);fs=m.Ext2(str(ROOT/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'))
for p,ino,dr in fs.walk():
 if not dr and ('grm_gles' in p or 'grm_2d' in p):
  d=fs.read_file(ino);target=out/Path(p).name
  if not target.exists():target.write_bytes(d)
  e=ELFFile(io.BytesIO(d));ss=e.get_section_by_name('.symtab');lines=[]
  if ss:
   for s in ss.iter_symbols():
    if s['st_info']['type']=='STT_FUNC':lines.append((s.name,s['st_shndx'],hex(s['st_value']),hex(s['st_size'])))
  (out/(target.name+'.symbols.json')).write_text(json.dumps(lines,indent=2))
  print(p,len(d),hashlib.sha256(d).hexdigest())
