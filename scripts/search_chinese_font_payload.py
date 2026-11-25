"""Search all firmware partitions for the Chinese font payload."""
from pathlib import Path

BASE = Path(r'<WORKSPACE>')
PART = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev'
TERMS = [b'MYingHeiC-GB18030', b'MYingHeiC-Big5', b'MYingHeiC', b'GB18030', b'Sony_DI_Icons']

targets = []
for name in ('nflasha15', 'nflasha7', 'nflasha5'):
    p = PART / name
    if p.exists():
        targets.append((name, p))

for name, path in targets:
    data = path.read_bytes()
    print(f'--- {name} ({len(data):#x}) ---')
    for t in TERMS:
        i = data.find(t)
        n = 0
        j = i
        while j >= 0 and n < 3:
            n += 1
            j = data.find(t, j + 1)
        print(f'  {t.decode():18s} first={hex(i) if i >= 0 else "none"} n(<=3)={n}')
        if i >= 0:
            seg = data[max(0, i - 24): i + 48]
            print('      ctx:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg))
