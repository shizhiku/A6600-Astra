from pathlib import Path
import struct

raw = Path('/tmp/ov_init5.raw')
print('raw size', raw.stat().st_size)
data = raw.read_bytes()
print('ext2 magics at 1024+off:')
found = []
i = data.find(b'\x53\xef')
while i >= 0 and len(found) < 10:
    found.append(i - 56)
    i = data.find(b'\x53\xef', i + 1)
print(found[:10])
# check superblock sanity at 771751936
for off in found[:5]:
    if off < 0 or off + 2048 > len(data):
        continue
    sb = data[off + 1024: off + 2048]
    blocks, log = struct.unpack_from('<I', sb, 4)[0], struct.unpack_from('<I', sb, 24)[0]
    print(hex(off), 'bs', 1024 << log, 'blocks', blocks,
          'bytes', (1024 << log) * blocks, 'magic', hex(struct.unpack_from('<H', sb, 56)[0]))
print('expected 771751936:', data[771751936 + 1024 + 56: 771751936 + 1024 + 58].hex())
print('bytes at 771751936+1080:', data[771751936 + 1024 + 24: 771751936 + 1024 + 28].hex())
