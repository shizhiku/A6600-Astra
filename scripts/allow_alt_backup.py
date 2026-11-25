"""Let the boot script take an alternate Backup.bin via BACKUP_IMG."""
from pathlib import Path

p = Path(r'<WORKSPACE>\02-脚本\boot_strip_exception.sh')
s = p.read_text(encoding='utf-8', newline='')
old = 'cp "$CAP/05-setting__Backup.bin" "$R/Backup.bin"'
if old not in s:
    raise SystemExit('anchor not found')
if 'BACKUP_IMG' in s:
    print('already patched')
else:
    s = s.replace(old, 'cp "${BACKUP_IMG:-$CAP/05-setting__Backup.bin}" "$R/Backup.bin"')
    p.write_text(s, encoding='utf-8', newline='')
    print('patched')
print([l for l in s.splitlines() if 'BACKUP_IMG' in l])
