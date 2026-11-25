"""Estimate per-page offset delta using within-page consistency filtering."""
from pathlib import Path
import json
from collections import Counter

BASE = Path(r'<WORKSPACE>')
PAGES = BASE / '03-证据/相机采集/live-avcam-pages-20261121'
LOCAL = BASE / '05-原始固件/qemu_in/av-cam.bin'

local = LOCAL.read_bytes()
rows = []
for pg in sorted(PAGES.glob('page-*.bin')):
    off = int(pg.stem.split('-')[1], 16)
    data = pg.read_bytes()
    deltas = Counter()
    for win in range(0, 4096 - 256, 64):
        chunk = data[win:win + 256]
        if chunk.count(0) > 128:
            continue
        pos = local.find(chunk)
        if pos < 0:
            continue
        if local.find(chunk, pos + 1) >= 0:
            continue
        deltas[pos - (off + win)] += 1
    if not deltas:
        rows.append({'page': pg.name, 'live_offset': hex(off), 'delta': None, 'note': 'no unique match'})
        continue
    delta, count = deltas.most_common(1)[0]
    total = sum(deltas.values())
    rows.append({'page': pg.name, 'live_offset': hex(off), 'delta': delta,
                 'delta_hex': f'{delta:+#x}', 'consistent': count, 'total': total,
                 'ratio': round(count / total, 2),
                 'distinct_deltas': len(deltas)})
    print(f'{pg.name} off={off:#010x} delta={delta:+#x} '
          f'consistency={count}/{total} distinct={len(deltas)}')

(BASE / '03-证据/静态分析/live-page-delta-consistent.json').write_text(
    json.dumps(rows, indent=2), encoding='utf-8')
