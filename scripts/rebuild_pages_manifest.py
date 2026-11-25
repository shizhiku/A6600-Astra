"""Regenerate a provenance manifest for the captured live pages (receipt was truncated)."""
from pathlib import Path
import json, hashlib, datetime

BASE = Path(r'<WORKSPACE>')
PAGES = BASE / '03-证据/相机采集/live-avcam-pages-20261121'
PA0 = 0x035C6000

rows = []
for p in sorted(PAGES.glob('page-*.bin')):
    off = int(p.stem.split('-')[1], 16)
    data = p.read_bytes()
    rows.append({'file_offset': hex(off), 'physical': hex(PA0 + off),
                 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})

manifest = {
    'regenerated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'note': 'Original receipt.json was truncated to 0 bytes by a process timeout; '
            'this manifest is derived from the saved page files.',
    'load_address': hex(PA0),
    'scope': 'Read-only page capture; no device writes',
    'pages': rows,
}
(PAGES / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
print(f'wrote manifest for {len(rows)} pages')
