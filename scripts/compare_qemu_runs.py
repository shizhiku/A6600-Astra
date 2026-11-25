"""Compare explicit local original/patched boot observations."""
from pathlib import Path
import json,re
r=Path(__file__).resolve().parent/'a6600_port/emulation'
names=['20261120T150021Z-25296','stock-20261120T150342Z-25683']
summary={}
for name in names:
 p=r/name; text=(p/'serial.log').read_text(errors='replace')
 facts={}
 for label,needle in [('root_mount','VFS: Mounted root'),('backup_failure','backup_init() error'),('busybox','BusyBox v'),('fixed_area','FixedAreaTop'),('mmap_failure','ERROR : Failed to mmap'),('im_fault','program: im.elf'),('fault_address','address: 00000000')]:
  facts[label]=[{'line':i,'text':line} for i,line in enumerate(text.splitlines(),1) if needle in line][:3]
 facts['shim_name_occurs']='appFwBoot' in text
 facts['exit_code']=(p/'exit-code.txt').read_text().strip()
 facts['stderr']=(p/'stderr.log').read_text(errors='replace')
 summary[name]=facts
out=r/'comparison.json'; out.write_text(json.dumps(summary,indent=2),encoding='utf-8')
print(json.dumps(summary,indent=2))
