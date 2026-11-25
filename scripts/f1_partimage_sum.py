"""Extract part_image.sum from firmware.tar and analyse its structure vs actual CRC32s."""
from pathlib import Path
import tarfile, struct, zlib, hashlib

BASE = Path('<WORKSPACE>')
FW = BASE / '05-原始固件/a6600_fw'
TAR = FW / 'firmware.tar'
OUT = BASE / '03-证据/静态分析'
OUT.mkdir(parents=True, exist_ok=True)

with tarfile.open(TAR) as tf:
    m = tf.getmember('0701_part_image_sum/part_image.sum')
    data = tf.extractfile(m).read()
(OUT / 'part_image.sum').write_bytes(data)
print(f'part_image.sum: {len(data)} B  sha256={hashlib.sha256(data).hexdigest()[:16]}')

print('\nfirst 256 bytes:')
for off in range(0, min(len(data), 256), 16):
    chunk = data[off:off + 16]
    hexs = ' '.join(f'{b:02x}' for b in chunk)
    text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f'  {off:04x}  {hexs:<48} {text}')

# print printable strings for orientation
print('\nstrings:')
cur = b''
for b in data:
    if 32 <= b < 127:
        cur += bytes([b])
    else:
        if len(cur) >= 3:
            print('  ', cur.decode())
        cur = b''
if len(cur) >= 3:
    print('  ', cur.decode())

# CRC32 of the original partitions
print('\nactual CRC32 of partitions:')
for name in ('nflasha7', 'nflasha15', 'nflasha3', 'nflasha5'):
    p = FW / 'extracted/0700_part_image/dev' / name
    if not p.exists():
        print(f'  {name:10} missing')
        continue
    crc = 0
    size = 0
    with open(p, 'rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            size += len(b)
            crc = zlib.crc32(b, crc)
    print(f'  {name:10} size={size:>12,}  crc32={crc & 0xFFFFFFFF:08x}')
