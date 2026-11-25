"""Read-only actual SDM table and embedded original kernel strings."""
from pathlib import Path
import struct,hashlib,re,json
BASE=Path(__file__).resolve().parents[1]; OUT=BASE/'03-证据/静态分析/97_flash'; D=Path(r'\\wsl.localhost\Ubuntu\root\qemu_in'); L=[]
def say(x): L.append(str(x));print(x)
say('command: python 02-脚本/97_flash_sdm.py')
b=(D/'sdm.bin').read_bytes(); say('sdm.bin size='+str(len(b))+' sha256='+hashlib.sha256(b).hexdigest())
for i in range(0,len(b),16):say(f'{i:04x} {b[i:i+16].hex(" ")} '+''.join(chr(a) if 32<=a<127 else '.' for a in b[i:i+16]))
with (D/'emmc.img').open('rb') as f:
 f.seek(8*1024*1024); h=f.read(65536)
say('emmc 8MiB first512 eq sdm='+str(h[:512]==b));say('8246 offsets near8MiB='+repr([m.start()+8*1024*1024 for m in re.finditer(b'8246',h)]))
for name in ['97_flash_actual_sdm.bin','97_flash_sdm.log']:
 p=OUT/name
 if p.exists():raise FileExistsError(p)
 p.write_bytes(b if name.endswith('.bin') else ('\n'.join(L)+'\n').encode())
