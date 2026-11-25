"""Bounded literal and string survey for backup subsystem 0x17 (offline only)."""
from pathlib import Path
import re,struct,json
root=Path(__file__).resolve().parent
files=[root/'qemu_in/av-cam.bin',root/'a6600_fw/usr/lib/libObj.so']
res=[]
for p in files:
 d=p.read_bytes();matches=[]
 for m in re.finditer(re.escape(struct.pack('<I',0x170000)),d):
  o=m.start()
  if o%4: continue
  matches.append({'offset':hex(o),'words':[hex(x) for x in struct.unpack_from('<12I',d,max(0,o-16))]})
 strings=[]
 for m in re.finditer(rb'[ -~]{5,}',d):
  s=m.group().decode('ascii')
  if 'BKID' in s and any(k in s.lower() for k in ['liro','af','camera','config','sensor','mode']):strings.append({'offset':hex(m.start()),'string':s[:160]})
 res.append({'file':str(p),'unit_literals':matches[:80],'literal_count':len(matches),'related_bkid_strings':strings[:80]})
 print(p.name,'literal_count',len(matches));print(json.dumps(matches[:20],indent=2));print(json.dumps(strings[:20],indent=2))
out=root/'a6600_port/analysis/liro-fault-static/property-references.json';out.write_text(json.dumps(res,indent=2),encoding='utf-8')
