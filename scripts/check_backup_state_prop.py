"""Inspect Backup properties that may initialise the av-cam state structure."""
from pathlib import Path
import importlib.util, io, struct

BASE = Path(r'<WORKSPACE>')
VENDOR = Path(r'<LEGACY_WORKSPACE>\repo\tools\flash\camtool\vendor')
BACKUP = BASE / '03-证据/相机采集/boot-20261120T151656Z-26869/05-setting__Backup.bin'

import sys
sys.path.insert(0, str(VENDOR))
from pmca.backup import BackupFile

bf = BackupFile(io.BytesIO(BACKUP.read_bytes()))
print('revision', bf.revision, 'props', bf.header.numProperties)

CANDIDATES = [0x00170000, 0x00170001, 0x00170002, 0x00000102, 0x00000203]
for pid in CANDIDATES:
    try:
        ptr = bf._readProperty(pid)
        p = bf.getProperty(pid)
        data = p.data
        words = [hex(w) for w in struct.unpack_from('<%dI' % (len(data) // 4), data)] if len(data) >= 4 else []
        print(f'{pid:#010x} attr={p.attr:#x} size={ptr.size} hex={data[:16].hex()} words={words[:4]}')
    except Exception as exc:
        print(f'{pid:#010x} ERR {type(exc).__name__}: {exc}')

# scan for any property whose first 4 bytes equal 00 00 03 02
target = bytes.fromhex('00000302')
hits = []
for pid in range(0x00000000, 0x01000000):
    pass  # full scan too slow; rely on the enumerator below

print('\nscanning property table for value 00 00 03 02 ...')
count = 0
for pid, attr in []:
    pass
