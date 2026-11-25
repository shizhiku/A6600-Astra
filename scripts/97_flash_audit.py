"""Offline read-only firmware audit; creates only new 97_flash evidence files.
No camera/device/process-network APIs. Never executes inspected firmware/scripts.
Usage: python 02-脚本/97_flash_audit.py
"""
from pathlib import Path
import hashlib, zlib, struct, tarfile, json, sys, re, datetime
BASE=Path(__file__).resolve().parents[1]
OUT=BASE/'03-证据/静态分析/97_flash'
OUT.mkdir(parents=True,exist_ok=True)
log=[]; manifest={}
def say(s=''): log.append(str(s)); print(s)
def sha(b): return hashlib.sha256(b).hexdigest()
def get(p):
 p=BASE/p; b=p.read_bytes(); manifest[str(p.relative_to(BASE))]={'bytes':len(b),'sha256':sha(b)}; return b
def save(n,b):
 p=OUT/('97_flash_'+n)
 if p.exists(): raise FileExistsError(p)
 p.write_bytes(b)
def dump(b):
 return '\n'.join(f'{i:08x}  {b[i:i+16].hex(" "):<47}  '+''.join(chr(x) if 32<=x<127 else '.' for x in b[i:i+16]) for i in range(0,len(b),16))
say('command: python 02-脚本/97_flash_audit.py')
say('python: '+sys.version)
say('utc: '+datetime.datetime.now(datetime.timezone.utc).isoformat())
results={}
for model in ('a6600','zv1m2'):
 fw=Path('05-原始固件')/(model+'_fw')
 tar=get(fw/'firmware.tar'); plain=get(fw/'fdat_plain.bin')
 say('\n=== '+model+' ==='); say('TAR sha256 '+sha(tar)); say('FDAT plain sha256 '+sha(plain))
 header=plain[:512]; save(model+'_fdat_header.bin',header); save(model+'_fdat_header.txt',dump(header).encode())
 expected=struct.unpack_from('<I',plain,8)[0]; actual=zlib.crc32(plain[12:512])&0xffffffff
 say(f'FDAT header CRC stored={expected:08x} zlib[12:512]={actual:08x} match={expected==actual}')
 off,size,nfs=struct.unpack_from('<III',plain,48)
 say(f'FDAT firmware offset={off} size={size} numfs={nfs}; exact_tar_equal={plain[off:off+size]==tar}; tail_bytes={len(plain)-(off+size)}')
 rows=[]
 with tarfile.open(BASE/fw/'firmware.tar') as tf:
  members=tf.getmembers()
  save(model+'_tar_inventory.json',json.dumps([{'name':m.name,'size':m.size,'offset':m.offset,'offset_data':m.offset_data,'type':m.type.decode('ascii','replace')} for m in members],ensure_ascii=False,indent=2).encode())
  for m in members:
   if not m.isfile(): continue
   if 'part_image.sum' in m.name or 'partinf' in m.name or 'mount.conf' in m.name or 'config' in m.name or 'updater' in m.name:
    b=tf.extractfile(m).read(); name=model+'_'+m.name.replace('/','_')
    save(name,b); say(f'member {m.name} size={len(b)} sha256={sha(b)}')
    if len(b)<65536:
     save(name+'.txt',dump(b).encode())
     say('strings '+repr(re.findall(rb'[ -~]{4,}',b)[:100]))
   if m.name.startswith('0700_part_image/'):
    b=tf.extractfile(m).read(); c=zlib.crc32(b)&0xffffffff
    row={'name':m.name,'size':len(b),'sha256':sha(b),'crc32_ieee_full':f'{c:08x}'}
    rows.append(row); say(row)
  s=[m for m in members if 'part_image.sum' in m.name]
  if s:
   sb=tf.extractfile(s[0]).read()
   say('SUM hex\n'+dump(sb))
 results[model]={'partitions':rows,'header_crc_expected':f'{expected:08x}','header_crc_actual':f'{actual:08x}','fw_offset':off,'fw_size':size,'numfs':nfs}
# Existing modified artifacts: read only; do not generate a flash package.
new=get(Path('04-产物/nflasha15_patched.bin')); old=get(Path('05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'))
say('\n=== modified partition actual ===')
say(f'old size={len(old)} crc={zlib.crc32(old)&0xffffffff:08x}; new size={len(new)} crc={zlib.crc32(new)&0xffffffff:08x}')
say(f'new sha256={sha(new)}')
for name,b in [('original',old),('patched',new)]:
 for start,end in [(0,len(b)),(0,len(b)-1),(1,len(b)),(1024,len(b)),(0,min(215517184,len(b)))]:
  say(f'{name} CRC32 range [{start},{end}) length={end-start}: {zlib.crc32(b[start:end])&0xffffffff:08x}')
# In-memory one-bit intervention demonstrates recomputability without producing an image.
mut=bytearray(old); mut[0]^=1
say(f'in-memory byte[0]^=1 crc={zlib.crc32(mut)&0xffffffff:08x}; no modified image written')
say(f'CRC known vector 123456789={zlib.crc32(b"123456789")&0xffffffff:08x}')
with tarfile.open(BASE/'04-产物/firmware_patched.tar') as tf:
 p=BASE/'04-产物/firmware_patched.tar'; manifest[str(p.relative_to(BASE))]={'bytes':p.stat().st_size,'sha256':hashlib.file_digest(p.open('rb'),'sha256').hexdigest()}
 for m in tf.getmembers():
  if m.isfile() and ('part_image.sum' in m.name or 'partinf.conf' in m.name):
   b=tf.extractfile(m).read(); say(f'PATCHED TAR {m.name} size={len(b)} sha256={sha(b)}'); save('patched_'+m.name.replace('/','_'),b)
# DAT container inventory and DEND verification.
dat=get(Path('04-产物/nflasha15_astra.dat')); pos=8; chunks=[]
say('\n=== existing modified DAT ==='); say('magic '+repr(dat[:8]))
while pos+8<=len(dat):
 size,tag=struct.unpack_from('>I4s',dat,pos); chunks.append({'tag':tag.decode('ascii','replace'),'header_offset':pos,'data_offset':pos+8,'size':size})
 if tag==b'FDAT':
  save('patched_dat_fdat_trailer.bin',dat[pos+8+size-272:pos+8+size]); say('FDAT last 272 bytes\n'+dump(dat[pos+8+size-272:pos+8+size]))
 if tag==b'DEND':
  stored=struct.unpack_from('>I',dat,pos+8)[0]; calculated=zlib.crc32(dat[:pos])&0xffffffff
  say(f'DEND CRC stored={stored:08x} calculated[0:{pos}]={calculated:08x} match={stored==calculated}'); break
 pos+=8+size
say(chunks)
results['modified']={'size':len(new),'sha256':sha(new),'crc32_ieee_full':f'{zlib.crc32(new)&0xffffffff:08x}','dat_chunks':chunks}
for f in ['02-脚本/build_full_image.py','02-脚本/repack_a6600.py','02-脚本/f1_partimage_sum.py','01-文档/96-ASTRA移植任务书.md']:
 get(Path(f))
save('input_manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2).encode())
save('results.json',json.dumps(results,ensure_ascii=False,indent=2).encode())
save('audit.log',('\n'.join(log)+'\n').encode('utf-8'))
