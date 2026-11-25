"""Inspect nflasha3 for an embedded FAT (/system) region and check /usr for UI resources."""
from pathlib import Path

BASE = Path(r'<WORKSPACE>')
P3 = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha3'
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'

d3 = P3.read_bytes()
print('nflasha3 size:', len(d3))
for sig, name in ((b'FAT12', 'FAT12'), (b'FAT16', 'FAT16'), (b'FAT32', 'FAT32'),
                  (b'\x55\xaa', 'boot-sig')):
    i = d3.find(sig, 0x1000)
    print(f'  {name:9s} first={hex(i) if i >= 0 else "none"}')

us = USR.read_bytes()
for term in (b'image_cmn_169.uxc', b'TextRM', b'libTextRM', b'.uxc'):
    i = us.find(term)
    n = 0
    j = i
    while j >= 0 and n < 5:
        n += 1
        j = us.find(term, j + 1)
    print(f'  /usr {term.decode():20s} first={hex(i) if i >= 0 else "none"} n(<=5)={n}')
