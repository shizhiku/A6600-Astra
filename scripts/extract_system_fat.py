"""Locate and extract the FAT32 (/system) region inside nflasha3."""
from pathlib import Path
import struct

BASE = Path(r'<WORKSPACE>')
P3 = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha3'
OUT = BASE / '05-原始固件/qemu_in/system_fat.img'
d = P3.read_bytes()
print('nflasha3 size:', hex(len(d)))

# find sector-aligned boot sectors whose FS type field says FAT32
cands = []
for off in range(0, len(d) - 512, 512):
    if d[off + 0x52:off + 0x57] == b'FAT32' and d[off + 510:off + 512] == b'\x55\xaa':
        cands.append(off)
print('FAT32 boot sector candidates:', [hex(c) for c in cands[:5]])

if not cands:
    raise SystemExit('no FAT32 boot sector found')

off = cands[0]
bs = d[off:off + 512]
bytes_per_sec = struct.unpack_from('<H', bs, 0x0B)[0]
sec_per_clus = bs[0x0D]
reserved = struct.unpack_from('<H', bs, 0x0E)[0]
num_fats = bs[0x10]
fat_size32 = struct.unpack_from('<I', bs, 0x24)[0]
total32 = struct.unpack_from('<I', bs, 0x20)[0]
print(f'boot sector at {off:#x}: bytes/sector={bytes_per_sec} sec/clus={sec_per_clus} '
      f'reserved={reserved} fats={num_fats} fat_size={fat_size32} total_sectors={total32}')
fs_bytes = total32 * bytes_per_sec
print('filesystem bytes:', fs_bytes, hex(fs_bytes))
print('nflasha3 bytes   :', len(d), 'fits:', off + fs_bytes <= len(d))

region = d[off: off + fs_bytes] if off + fs_bytes <= len(d) else d[off:]
OUT.write_bytes(region)
print('wrote', OUT, len(region))
