"""Add BACKUP_IMG and CMDLINE_EXTRA support to the observer."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')

changed = []

old_append = "'-append', (CONTROL/'cmdline.txt').read_text(),"
new_append = "'-append', (CONTROL/'cmdline.txt').read_text() + os.environ.get('CMDLINE_EXTRA', ''),"
if old_append in s:
    s = s.replace(old_append, new_append)
    changed.append('cmdline')

old_backup = "loader,file={CONTROL}/Backup.bin,addr=0x02E80000,force-raw=on"
new_backup = "loader,file={os.environ.get('BACKUP_IMG', str(CONTROL / 'Backup.bin'))},addr=0x02E80000,force-raw=on"
if old_backup in s:
    s = s.replace(old_backup, new_backup)
    changed.append('backup')

if not changed:
    print('nothing patched (already?)')
else:
    ast.parse(s)
    p.write_text(s, encoding='utf-8')
    print('patched:', changed)
