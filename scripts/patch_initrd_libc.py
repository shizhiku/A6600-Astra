"""Patch the initrd ext2 image: replace /lib/libc-2.11.2.so with the camera's copy.

Writes a NEW file (initrd-live-libc.img); the original is untouched.
"""
from pathlib import Path
import struct, hashlib

BASE = Path(r'<WORKSPACE>')
SRC_IMG = BASE / '05-原始固件/qemu_in/nflasha3-initrd'
DST_IMG = BASE / '05-原始固件/qemu_in/nflasha3-initrd-live-libc'
NEW_LIBC = BASE / '03-证据/相机采集/live-libc-20261121/system_libc-2.11.2.so'

data = bytearray(SRC_IMG.read_bytes())
new = NEW_LIBC.read_bytes()

# --- superblock ---
sb = 1024
u32 = lambda o: struct.unpack_from('<I', data, sb + o)[0]
bs = 1024 << u32(24)
first_data = u32(20)
bpg = u32(32)
ipg = u32(40)
inode_size = struct.unpack_from('<H', data, sb + 88)[0] or 128
inode_tables = []
gd = (first_data + 1) * bs
for g in range((u32(4) + bpg - 1) // bpg):
    inode_tables.append(struct.unpack_from('<I', data, gd + g * 32 + 8)[0])

def inode_off(ino):
    g, idx = divmod(ino - 1, ipg)
    return inode_tables[g] * bs + idx * inode_size

def read_inode(ino):
    o = inode_off(ino)
    mode = struct.unpack_from('<H', data, o)[0]
    size = struct.unpack_from('<I', data, o + 4)[0]
    blocks = [struct.unpack_from('<I', data, o + 40 + 4 * k)[0] for k in range(15)]
    return mode, size, blocks

def read_dir(ino):
    mode, size, blocks = read_inode(ino)
    out = []
    for b in blocks[:12]:
        if not b:
            continue
        base = b * bs
        off = 0
        while off + 8 <= bs:
            e_ino, rec, nl, ft = struct.unpack_from('<IHBB', data, base + off)
            if rec == 0:
                break
            if e_ino:
                name = data[base + off + 8: base + off + 8 + nl].decode('latin1')
                out.append((name, e_ino))
            off += rec
    return out

def lookup(path):
    ino = 2
    for part in [p for p in path.split('/') if p]:
        found = None
        for name, child in read_dir(ino):
            if name == part:
                found = child
                break
        if found is None:
            return None
        ino = found
    return ino

target = '/lib/libc-2.11.2.so'
ino = lookup(target)
print('inode for', target, '=', ino)
mode, size, blocks = read_inode(ino)
print(f'inode: mode={mode:#o} size={size} blocks[0..3]={blocks[:4]}')
print('new libc size:', len(new))

# gather data blocks (direct + single + double indirect)
nblk = (max(size, len(new)) + bs - 1) // bs
per = bs // 4
ptrs = list(blocks[:12])
if nblk > 12 and blocks[12]:
    ind = blocks[12] * bs
    for i in range(per):
        ptrs.append(struct.unpack_from('<I', data, ind + i * 4)[0])
if nblk > 12 + per and blocks[13]:
    dind = blocks[13] * bs
    for i in range(per):
        sub = struct.unpack_from('<I', data, dind + i * 4)[0]
        if not sub:
            continue
        base = sub * bs
        for j in range(per):
            ptrs.append(struct.unpack_from('<I', data, base + j * 4)[0])
ptrs = [p for p in ptrs if p]
print('data blocks available:', len(ptrs), 'needed:', nblk)
if len(ptrs) < nblk:
    raise SystemExit('not enough blocks in the file')

# write data
for i in range(nblk):
    chunk = new[i * bs:(i + 1) * bs]
    base = ptrs[i] * bs
    data[base:base + len(chunk)] = chunk
    if len(chunk) < bs:
        # zero the tail of the last block
        data[base + len(chunk):base + bs] = b'\x00' * (bs - len(chunk))

# update inode size
o = inode_off(ino)
struct.pack_into('<I', data, o + 4, len(new))
# high size (dir_acl) for large files: clear it since < 4 GiB
struct.pack_into('<I', data, o + 108, 0)

DST_IMG.write_bytes(bytes(data))
print('wrote', DST_IMG, len(data))
print('sha256', hashlib.sha256(bytes(data)).hexdigest())

# verify by reading back
check = bytearray(DST_IMG.read_bytes())
mode2, size2, blocks2 = None, None, None
o2 = inode_off(ino)
print('inode size now:', struct.unpack_from('<I', check, o2 + 4)[0])
first = struct.unpack_from('<I', data, o2 + 40)[0] * bs
print('head of new file:', bytes(check[first:first + 16]).hex(), '...')
print('expected       :', new[:16].hex())
