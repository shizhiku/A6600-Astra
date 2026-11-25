"""Locate each captured live page inside the local av-cam image.

For every live page, several 32-byte windows are searched in the local file.
A consistent shift across pages means layout/relocation; no hit means a
different build.
"""
from pathlib import Path
import json, hashlib

BASE = Path(r'<WORKSPACE>')
PAGES = BASE / '03-证据/相机采集/live-avcam-pages-20261121'
LOCAL = BASE / '05-原始固件/qemu_in/av-cam.bin'

local = LOCAL.read_bytes()
results = {'local_bytes': len(local), 'local_sha256': hashlib.sha256(local).hexdigest(), 'pages': []}

for page in sorted(PAGES.glob('page-*.bin')):
    off = int(page.stem.split('-')[1], 16)
    data = page.read_bytes()
    hits = []
    for win in (0x000, 0x100, 0x400, 0x800, 0xC00, 0xF00):
        chunk = data[win:win + 32]
        if chunk.count(0) > 24:
            continue
        pos = local.find(chunk)
        if pos >= 0:
            hits.append({'window': hex(win), 'local_offset': hex(pos),
                         'local_offset_minus_page': hex(pos - off - win)})
    results['pages'].append({
        'page': page.name, 'live_offset': hex(off),
        'sha256': hashlib.sha256(data).hexdigest(),
        'windows_found': len(hits), 'hits': hits,
    })
    print(page.name, 'windows found:', len(hits),
          'shifts:', sorted({h['local_offset_minus_page'] for h in hits})[:5])

(BASE / '03-证据/静态分析/live-page-locate.json').write_text(
    json.dumps(results, indent=2), encoding='utf-8')
