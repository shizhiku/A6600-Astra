"""Report ext2 free space for the a6600 and ZV-1M2 /usr images."""
from pathlib import Path
import struct

BASE = Path(r'<WORKSPACE>')
IMGS = {
    'a6600  /usr (nflasha15)': BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15',
    'ZV-1M2 /usr (nflasha15)': BASE / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15',
}

for name, p in IMGS.items():
    with open(p, 'rb') as f:
        f.seek(1024)
        sb = f.read(1024)
    inodes = struct.unpack_from('<I', sb, 0x00)[0]
    blocks = struct.unpack_from('<I', sb, 0x04)[0]
    rblocks = struct.unpack_from('<I', sb, 0x08)[0]
    free_blocks = struct.unpack_from('<I', sb, 0x0C)[0]
    free_inodes = struct.unpack_from('<I', sb, 0x10)[0]
    log_bs = struct.unpack_from('<I', sb, 0x18)[0]
    bs = 1024 << log_bs
    print(f'{name}')
    print(f'  size={p.stat().st_size:,} B  block={bs} B')
    print(f'  blocks={blocks:,}  free_blocks={free_blocks:,} '
          f'({free_blocks * bs / 1048576:.1f} MB free)')
    print(f'  inodes={inodes:,}  free_inodes={free_inodes:,}')
