"""Audit local firmware artifacts without touching any connected device."""
from pathlib import Path
import tarfile,zlib,json,hashlib
root=Path(__file__).resolve().parent
report={'boot_input_headers':{},'partition_checksum_manifests':[]}
for name in ['nflasha3-Image','nflasha3-initrd','av-cam.bin']:
 p=root/'qemu_in'/name
 with p.open('rb') as f: head=f.read(64)
 report['boot_input_headers'][name]={'bytes':p.stat().st_size,'first64':head.hex()}
part=root/'a6600_port/nflasha15_patched.bin'
crc=0
with part.open('rb') as f:
 for b in iter(lambda:f.read(1<<20),b''): crc=zlib.crc32(b,crc)
report['modified_partition_crc32']=f'{crc & 0xffffffff:08x}'
for rel in ['a6600_fw/firmware.tar','a6600_port/firmware_patched.tar']:
 with tarfile.open(root/rel) as tf:
  for m in tf.getmembers():
   if m.isfile() and m.name.endswith('.sum'):
    data=tf.extractfile(m).read().decode('utf-8','replace')
    for line in data.splitlines():
     if 'nflasha15' in line:
      report['partition_checksum_manifests'].append({'archive':rel,'member':m.name,'record':line})
(root/'a6600_port/input-audit.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
