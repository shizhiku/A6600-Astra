"""Enumerate the properties in Backup.bin and check whether 0x810000 exists."""
from pathlib import Path
import sys, io

BASE = Path(r'<WORKSPACE>')
VENDOR = Path(r'<LEGACY_WORKSPACE>\repo\tools\flash\camtool\vendor')
SRC = BASE / '03-证据/相机采集/boot-20261120T151656Z-26869/05-setting__Backup.bin'

sys.path.insert(0, str(VENDOR))
from pmca.backup import BackupFile

raw = SRC.read_bytes()
bf = BackupFile(io.BytesIO(raw))
print('header:', bf.header)
print('dataOffset=%#x dataSize=%#x total=%d' % (bf.header.dataOffset, bf.header.dataSize, len(raw)))

print('\nBackupFile methods:', [m for m in dir(bf) if not m.startswith('__')])

# try to enumerate: pmca may expose _properties or a table
for attr in ('_properties', 'properties', '_table', 'table', '_props'):
    if hasattr(bf, attr):
        val = getattr(bf, attr)
        print(f'\n{attr}: type={type(val)}')
        try:
            items = list(val.items()) if hasattr(val, 'items') else list(val)
            for k, v in items[:40]:
                size = len(v.data) if hasattr(v, 'data') else '?'
                print(f'  {k:#010x} size={size}')
        except Exception as exc:
            print('  iterate failed:', exc)

# probe specific ids
for pid in (0x810000, 0x00170000, 0x810001):
    try:
        p = bf.getProperty(pid)
        d = bytes(p.data)
        print(f'\nid {pid:#010x}: size={len(d) if d else 0} preview={d[:64].hex(" ")}')
    except Exception as exc:
        print(f'\nid {pid:#010x}: {type(exc).__name__}: {exc}')
