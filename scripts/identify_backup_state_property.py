"""Read-only parsing of the captured backup to locate a state-copy source property."""
from pathlib import Path
import sys,json,io
root=Path(__file__).resolve().parent
sys.path.insert(0,str(root/'repo/tools/flash/camtool/vendor'))
from pmca.backup import BackupFile
p=root/'a6600_port/captures/boot-20261120T151656Z-26869/05-setting__Backup.bin'
b=BackupFile(io.BytesIO(p.read_bytes()))
target=0x67f56
r={'backup_checksum':'validated by PMCA BackupFile','revision':b.revision,'subsystems':b.header.numSubsystems,'properties':b.header.numProperties,'candidate_file_offset':hex(target),'matches':[]}
for subid in range(b.header.numSubsystems):
 sub=b._readSubsystemTable(subid)
 for low in range(sub.numProperties):
  id=(subid<<16)|low
  try: prop=b._readProperty(id)
  except Exception: continue
  if prop.ptr<=target<prop.ptr+prop.maxSize:
   r['matches'].append({'id':hex(id),'start':hex(prop.ptr),'size':prop.size,'max_size':prop.maxSize,'attr':hex(prop.attr),'target_index':target-prop.ptr})
(root/'a6600_port/analysis/liro-fault-static/backup-property.json').write_text(json.dumps(r,indent=2),encoding='utf-8')
print(json.dumps(r,indent=2))
