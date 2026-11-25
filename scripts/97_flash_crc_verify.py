"""Independent repeat of CRC checks; creates only evidence, never a firmware package."""
from pathlib import Path
import struct,zlib,tarfile,hashlib,json
BASE=Path(__file__).resolve().parents[1];OUT=BASE/'03-证据/静态分析/97_flash';L=[]
def say(x):L.append(str(x));print(x)
def save(n,b):
 p=OUT/('97_flash_'+n)
 if p.exists():raise FileExistsError(p)
 p.write_bytes(b)
say('command: python 02-脚本/97_flash_crc_verify.py')
# Independently build IEEE reflected CRC lookup table and search native tool bytes.
tab=[]
for x in range(256):
 c=x
 for _ in range(8):c=(c>>1)^ (0xedb88320 if c&1 else 0)
 tab.append(c)
pat=struct.pack('<256I',*tab);native=(OUT/'97_flash_updaterimg_bin_uc_crc32sum.elf').read_bytes();say('native uc_crc32sum.elf sha256='+hashlib.sha256(native).hexdigest());say('IEEE CRC table byte offset='+str(native.find(pat)))
for model in ['a6600','zv1m2']:
 with tarfile.open(BASE/f'05-原始固件/{model}_fw/firmware.tar') as tf:
  sumdata=tf.extractfile('0701_part_image_sum/part_image.sum').read()
  for row in sumdata.decode().splitlines():
   x=row.split(',')
   if x[0]!='0':continue
   m=tf.getmember('0700_part_image/'+x[10]);crc=0;n=0
   with tf.extractfile(m) as f:
    while True:
     b=f.read(65521)
     if not b:break
     crc=zlib.crc32(b,crc);n+=len(b)
   say({'model':model,'path':x[10],'manifest_size':int(x[2],16),'actual_size':n,'manifest_crc':x[1],'actual_crc':f'{crc&0xffffffff:08x}','match':int(x[1],16)==crc&0xffffffff and n==int(x[2],16)})
  if model=='a6600':original_sum=sumdata
p=BASE/'04-产物/nflasha15_patched.bin'
with p.open('rb') as f:
 crc=0
 while True:
  b=f.read(65521)
  if not b:break
  crc=zlib.crc32(b,crc)
rebuilt=original_sum.replace(b'0,520fff36,0cd88800,',f'0,{crc&0xffffffff:08x},{p.stat().st_size:08x},'.encode())
say('patched recomputed CRC='+f'{crc&0xffffffff:08x}');say('recomputed sum sha256='+hashlib.sha256(rebuilt).hexdigest());say('ONLY self-consistent checksum evidence, not signed image / guard / hardware acceptance')
save('part_image.recomputed.sum',rebuilt)
save('crc_verify.log',('\n'.join(L)+'\n').encode())
