"""Read-only SDM / ext2 geometry audit, no device connection or mutation."""
from pathlib import Path
import hashlib,struct,re,json
BASE=Path(__file__).resolve().parents[1]; OUT=BASE/'03-证据/静态分析/97_flash'; p=Path(r'\\wsl.localhost\Ubuntu\root\qemu_in\emmc.img')
lines=[]
def say(s): lines.append(str(s)); print(s)
say('command: python 02-脚本/97_flash_geometry.py')
say('input: '+str(p)); say('size='+str(p.stat().st_size))
with p.open('rb') as f:
 h=hashlib.file_digest(f,'sha256').hexdigest()
say('sha256='+h)
with p.open('rb') as f:
 head=f.read(65536)
 say('head magic='+repr(head[:64])); say('SDM 8246 offsets='+repr([m.start() for m in re.finditer(b'8246',head)])); say('MBR signature='+head[510:512].hex())
 for i in range(0,2048,16):
  x=head[i:i+16]
  if any(x): say(f'{i:08x} {x.hex(" ")} '+''.join(chr(a) if 32<=a<127 else '.' for a in x))
 for off in (763363328,771751936,1077936128):
  f.seek(off+1024); sb=f.read(1024)
  say(f'candidate[{off:#x}] superblock magic@+1080={sb[56:58].hex()} blocks={struct.unpack_from("<I",sb,4)[0]} logblock={struct.unpack_from("<I",sb,24)[0]}')
for name,b in [('97_flash_emmc_head_64k.bin',head),('97_flash_geometry.log',('\n'.join(lines)+'\n').encode())]:
 out=OUT/name
 if out.exists(): raise FileExistsError(out)
 out.write_bytes(b)
