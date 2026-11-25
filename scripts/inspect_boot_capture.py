"""Validate local capture hashes and inspect basic backup header facts."""
from pathlib import Path
import hashlib,json,struct
root=Path(__file__).resolve().parent
cap=root/'a6600_port/captures/boot-20261120T151656Z-26869'
r=json.loads((cap/'receipt.json').read_text())
for x in r['files']:
 if x['status']=='read':
  data=(cap/x['local']).read_bytes()
  if hashlib.sha256(data).hexdigest()!=x['sha256']: raise RuntimeError('Capture digest mismatch')
backup=(cap/'05-setting__Backup.bin').read_bytes()
kemco=(cap/'06-setting__kemco.txt').read_bytes()
original=(root/'qemu_in/kemco.txt').read_bytes()
facts={'capture':cap.name,'all_receipt_hashes_match':True,'backup_bytes':len(backup),'backup_first_eight_words':[hex(x) for x in struct.unpack_from('<8I',backup)],'kemco_matches_update':kemco==original,'proc_reads':'zero-length; not validated observations','preload_still_present':(cap/'09-etc__ld.so.preload').read_text(errors='replace').strip(),'nonempty_files':[x['remote'] for x in r['files'] if x.get('bytes',0)]}
(cap/'inspection.json').write_text(json.dumps(facts,indent=2),encoding='utf-8')
print(json.dumps(facts,indent=2))
