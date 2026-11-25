"""Extract selected original files offline for audit; no execution of target code."""
from pathlib import Path
import hashlib,struct,re,json,importlib.util
BASE=Path(__file__).resolve().parents[1]; OUT=BASE/'03-证据/静态分析/97_flash'; lines=[]
def say(x):lines.append(str(x));print(x)
def save(n,b):
 p=OUT/('97_flash_'+n)
 if p.exists():raise FileExistsError(p)
 p.write_bytes(b)
s=importlib.util.spec_from_file_location('ext2_reader',BASE/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
say('command: python 02-脚本/97_flash_extract.py')
for label,path in [('rootfs',BASE/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha7'),('initrd',BASE/'05-原始固件/qemu_in/nflasha3-initrd'),('usr',BASE/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15')]:
 b=path.read_bytes();say(f'{label} sha256={hashlib.sha256(b).hexdigest()} magic={b[1080:1082].hex()}')
 if b[1080:1082]!=b'\x53\xef':continue
 fs=m.Ext2(path); found=[]
 for p,ino,isdir in fs.walk():
  if isdir:continue
  if any(x in p.lower() for x in ['updat','crypter','emmc.ko','sdm','fwup','nflasha','boot','rcs']) or p=='/sbin/init':
   d=fs.read_file(ino);found.append({'path':p,'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()})
   save(label+p.replace('/','_'),d)
   strings=[{'offset':x.start(),'text':x.group().decode('ascii')} for x in re.finditer(rb'[ -~]{5,}',d) if re.search(rb'(?i)crc|sum|sig|rsa|sha|part|nflash|SDM|8246|updat|check|verif|reject|fail',x.group())]
   save(label+p.replace('/','_')+'.strings.json',json.dumps(strings,indent=2).encode())
 say(found)
 save(label+'_selected_manifest.json',json.dumps(found,indent=2).encode())
save('extract.log',('\n'.join(lines)+'\n').encode())
