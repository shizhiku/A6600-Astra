from pathlib import Path
from elftools.elf.elffile import ELFFile
import re,json,sys
ROOT=Path(__file__).resolve().parents[1]
pat=re.compile(r'registerFont|TextRM|FontFace|fontlist|draw|render|Input|KeyEvent|sen',re.I)
paths=list((ROOT/'05-原始固件/a6600_fw/usr').rglob('*'))
for p in paths:
 if not p.is_file() or p.suffix not in ('.so','.elf'): continue
 try:
  with p.open('rb') as f:
   e=ELFFile(f); out=[]
   for sn in ('.dynsym','.symtab'):
    s=e.get_section_by_name(sn)
    if s:
     for x in s.iter_symbols():
      if ('registerFont' in x.name or 'FontFace' in x.name or 'TextRM' in x.name):out.append((x.name,hex(x['st_value']),x['st_size'],x['st_shndx']))
   if out:print(str(p.relative_to(ROOT)),json.dumps(out,ensure_ascii=False))
 except Exception: pass
