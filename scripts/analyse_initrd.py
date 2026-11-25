"""Analyse the initrd layout to find the embedded root filesystem."""
from pathlib import Path
import struct

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/nflasha3-initrd'
d = IMG.read_bytes()
print('size', len(d))
print('head', d[:64].hex())
for sig, name in ((b'\x1f\x8b', 'gzip'), (b'\xfd7zXZ', 'xz'), (b'070701', 'cpio-newc'),
                  (b'070702', 'cpio-crc'), (b'BZh', 'bzip2'), (b'\x28\xb5\x2f\xfd', 'zstd')):
    i = d.find(sig)
    print(f'{name:9s} signature at {i}')

# embedded ext2: superblock magic 0xEF53 at block_start + 1024 + 0x38
hits = []
for base in range(0, len(d) - 2048, 1024):
    magic_off = base + 1024 + 0x38
    if magic_off + 2 > len(d):
        break
    if struct.unpack_from('<H', d, magic_off)[0] == 0xEF53:
        hits.append(base)
print('ext2 superblock candidates:', [hex(h) for h in hits[:8]])

for h in hits[:3]:
    # log block size and counts
    log_bs = struct.unpack_from('<I', d, h + 1024 + 24)[0]
    blocks = struct.unpack_from('<I', d, h + 1024 + 4)[0]
    print(f'  base {h:#x}: log_block_size={log_bs} blocks={blocks} => fs size ~{blocks * (1024 << log_bs)} bytes')

# also look for the string '/lib/libc-2.11.2.so' to locate the fs data region
i = d.find(b'libc-2.11.2.so')
print('"libc-2.11.2.so" string at', hex(i) if i >= 0 else 'none')
