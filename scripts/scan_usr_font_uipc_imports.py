"""Scan every ELF in stock a6600 /usr directly from ext2 for font/UIPC/input imports."""
from pathlib import Path
import importlib.util,io,json,hashlib
from elftools.elf.elffile import ELFFile
ROOT=Path(__file__).resolve().parents[1]; IMG=ROOT/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec=importlib.util.spec_from_file_location('usr',ROOT/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
need=['registerFontFaceFile','TextRM_loadFont','osal_reg_sync_msg_queue_cb','osal_snd_sync_msg','osal_snd_msg','InfraInput','InputService']
fs=m.Ext2(str(IMG));out=[]
for path,ino,isdir in fs.walk():
 if isdir:continue
 b=fs.read_file(ino)
 if not b.startswith(b'\x7fELF'):continue
 row={'path':path,'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'imports':[],'exports':[]}
 try:
  e=ELFFile(io.BytesIO(b))
  for sn in ('.dynsym','.symtab'):
   s=e.get_section_by_name(sn)
   if not s:continue
   for x in s.iter_symbols():
    if any(k in x.name for k in need):
     (row['imports'] if x['st_shndx']=='SHN_UNDEF' else row['exports']).append(x.name)
 except Exception as ex: row['error']=str(ex)
 if row['imports'] or row['exports']:out.append(row)
p=ROOT/'03-证据/静态分析/usr_font_uipc_imports.json';p.write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8');print(len(out),p)
