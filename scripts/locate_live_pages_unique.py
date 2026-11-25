"""Locate live pages in the local image using long, uniqueness-checked windows."""
from pathlib import Path
import json, hashlib

BASE = Path(r'<WORKSPACE>')
PAGES = BASE / '03-证据/相机采集/live-avcam-pages-20261121'
LOCAL = BASE / '05-原始固件/qemu_in/av-cam.bin'

local = LOCAL.read_bytes()
out = {'local_bytes': len(local), 'pages': []}

for page in sorted(PAGES.glob('page-*.bin')):
    off = int(page.stem.split('-')[1], 16)
    data = page.read_bytes()
    best = None
    for win in range(0x100, 0xF00, 0x40):
        chunk = data[win:win + 128]
        if len(chunk) < 128:
            break
        if chunk.count(0) > 64:
            continue
        first = local.find(chunk)
        if first < 0:
            continue
        second = local.find(chunk, first + 1)
        if second >= 0:
            continue  # ambiguous
        delta = first - (off + win)
        best = {'window': hex(win), 'local_offset': hex(first), 'delta': delta}
        break
    out['pages'].append({'page': page.name, 'live_offset': hex(off),
                         'unique_match': best})
    if best:
        print(f"{page.name} offset={off:#010x} unique local={best['local_offset']} "
              f"delta={best['delta']:+#x}")
    else:
        print(f'{page.name} offset={off:#010x} no unique 128-byte match')

(BASE / '03-证据/静态分析/live-page-locate-unique.json').write_text(
    json.dumps(out, indent=2), encoding='utf-8')
