"""Read init/launch_shell source bytes and ELF strings; no firmware execution."""
from pathlib import Path
import importlib.util,re,io,json
from elftools.elf.elffile import ELFFile
BASE=Path(__file__).resolve().parents[1];OUT=BASE/'03-证据/静态分析/97_abi'
s=importlib.util.spec_from_file_location('u',BASE/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for label,img,paths in [('a6root','a6600_fw/extracted/0700_part_image/dev/nflasha7',['/sbin/init']),('a6usr','a6600_fw/extracted/0700_part_image/dev/nflasha15',['/bin/launch_shell.elf','/bin/bootin.elf']),('zvusr','zv1m2_fw/extracted/0700_part_image/dev/nflasha15',['/bin/launch_shell.elf','/bin/bootin.elf'])]:
 fs=m.Ext2(str(BASE/'05-原始固件'/img)); entries={p:i for p,i,d in fs.walk() if not d}
 for path in paths:
  if path not in entries:continue
  data=fs.read_file(entries[path]); name=label+'_'+Path(path).name; (OUT/name).write_bytes(data)
  if data[:4]!=b'\x7fELF':
   (OUT/(name+'.txt')).write_text(data.decode('utf8',errors='replace'),encoding='utf8');continue
  e=ELFFile(io.BytesIO(data)); lines=[]
  for seg in e.iter_segments():
   if seg['p_type']!='PT_LOAD':continue
   for mat in re.finditer(rb'[\x20-\x7e]{4,}',seg.data()):lines.append(f'{seg["p_vaddr"]+mat.start():08x} {mat.group().decode()}')
  (OUT/(name+'_strings.txt')).write_text('\n'.join(lines),encoding='utf8')
  print(name,len(data))
