"""Resolve which module contains the caller address, from the printed memory map."""
from pathlib import Path
import re

LOG = Path(r'<WORKSPACE>\03-证据\模拟器运行\cmdline-20261120T201519Z-45704\serial.log')
TARGETS = [0x04262D8E, 0x04253796]

txt = LOG.read_text(errors='replace')
rows = []
for line in txt.splitlines():
    m = re.match(r'^([0-9a-f]{8})-([0-9a-f]{8})\s+(\S+)\s+0x([0-9a-f]{8})\s*(.*)$', line.strip())
    if m:
        rows.append({'lo': int(m.group(1), 16), 'hi': int(m.group(2), 16),
                     'perm': m.group(3), 'fileoff': int(m.group(4), 16),
                     'name': m.group(5).strip()})

print('map entries:', len(rows))
for t in TARGETS:
    hit = [r for r in rows if r['lo'] <= t < r['hi']]
    if hit:
        r = hit[-1]
        delta = t - r['lo']
        print(f'{t:#010x} -> {r["name"] or "(anon)"} perm={r["perm"]} '
              f'base={r["lo"]:#010x} delta={delta:#x} fileoff={r["fileoff"]:#x}')
    else:
        print(f'{t:#010x} -> not found in printed maps')
