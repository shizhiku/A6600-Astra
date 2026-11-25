"""Read the av-cam load-address property from the captured Backup.bin (offline)."""
from pathlib import Path
import sys, json, struct

BASE = Path(r'<WORKSPACE>')
sys.path.insert(0, str(BASE / '02-脚本'))
import io

vendor = r'<LEGACY_WORKSPACE>\repo\tools\flash\camtool\vendor'
sys.path.insert(0, vendor)
from pmca.backup import BackupFile

BACKUP = BASE / '03-证据/相机采集/boot-20261120T151656Z-26869/05-setting__Backup.bin'
CANDIDATES = [0x00FA007C, 0x00FA0080, 0x00FA0078]

data = BACKUP.read_bytes()
bf = BackupFile(io.BytesIO(data))
print('revision', bf.revision, 'subsystems', bf.header.numSubsystems,
      'properties', bf.header.numProperties)

out = {}
for pid in CANDIDATES:
    try:
        p = bf.getProperty(pid)
        raw = p.data
        words = [hex(w) for w in struct.unpack_from('<%dI' % (len(raw) // 4), raw)] if len(raw) >= 4 else []
        entry = {'id': hex(pid), 'attr': hex(p.attr), 'size': p.size,
                 'hex': raw.hex(), 'words': words}
        out[hex(pid)] = entry
        print(hex(pid), 'attr', hex(p.attr), 'size', p.size, 'raw', raw.hex(), 'words', words)
    except Exception as exc:
        out[hex(pid)] = {'error': f'{type(exc).__name__}: {exc}'}
        print(hex(pid), 'ERR', exc)

(BASE / '03-证据/静态分析/backup-avcam-address.json').write_text(
    json.dumps(out, indent=2), encoding='utf-8')
