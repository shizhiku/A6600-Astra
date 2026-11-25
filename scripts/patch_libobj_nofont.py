"""Diagnostic patch: make libObj::TextRM_loadFont return 0 immediately (inside a /usr copy)."""
from pathlib import Path
import struct, shutil, importlib.util

BASE = Path('<WORKSPACE>')
SRC = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
DST = BASE / '05-原始固件/qemu_in/nflasha15-nofont'
LIBOBJ_OFF = 0x54ED58
PATCH = bytes.fromhex('00207047')     # movs r0,#0 ; bx lr

spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

if not DST.exists():
    print('copying image ...', flush=True)
    shutil.copyfile(SRC, DST)

data = bytearray(DST.read_bytes())

# --- ext2 structures ---
sb = 1024
u32 = lambda o: struct.unpack_from('<I', data, o)[0]
bs = 1024 << u32(sb + 24)
first_data = u32(sb + 20)
bpg = u32(sb + 32)
ipg = u32(sb + 40)
inode_size = struct.unpack_from('<H', data, sb + 88)[0] or 128
inode_tables = []
gd = (first_data + 1) * bs
for g in range((u32(sb + 4) + bpg - 1) // bpg):
    inode_tables.append(u32(gd + g * 32 + 8))

def inode_off(ino):
    g, idx = divmod(ino - 1, ipg)
    return inode_tables[g] * bs + idx * inode_size

def inode_blocks(ino):
    o = inode_off(ino)
    size = u32(o + 4)
    blocks = [u32(o + 40 + 4 * k) for k in range(15)]
    per = bs // 4
    ptrs = list(blocks[:12])
    if blocks[12]:
        for i in range(per):
            ptrs.append(u32(blocks[12] * bs + i * 4))
    if blocks[13]:
        for i in range(per):
            sub = u32(blocks[13] * bs + i * 4)
            if not sub:
                continue
            for j in range(per):
                ptrs.append(u32(sub * bs + j * 4))
    return size, [p for p in ptrs if p]

# --- find libObj inode via the helper's walk ---
fs = m.Ext2(str(DST))
ino = None
for path, i2, is_dir in fs.walk():
    if not is_dir and path == '/lib/libObj.so':
        ino = i2
        break
if ino is None:
    raise SystemExit('libObj.so not found')

size, ptrs = inode_blocks(ino)
print(f'libObj inode={ino} size={size} blocks={len(ptrs)}')

idx, off_in_block = divmod(LIBOBJ_OFF, bs)
blk = ptrs[idx]
abs_off = blk * bs + off_in_block
print(f'patch target: block {blk}, image offset {abs_off:#x}')
print('old:', bytes(data[abs_off:abs_off + 4]).hex(' '))
data[abs_off:abs_off + 4] = PATCH
DST.write_bytes(bytes(data))
print('new:', bytes(data[abs_off:abs_off + 4]).hex(' '))

# verify through the ext2 reader
fs2 = m.Ext2(str(DST))
for path, i3, is_dir in fs2.walk():
    if not is_dir and path == '/lib/libObj.so':
        blob = fs2.read_file(i3)
        print('verify:', blob[LIBOBJ_OFF:LIBOBJ_OFF + 4].hex(' '))
        break
