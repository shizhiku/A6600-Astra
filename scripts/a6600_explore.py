"""Explore nflasha15 (a6600 /usr ext2) with the ext4 package."""
import hashlib, os

from ext4 import Volume

BASE = os.path.dirname(os.path.abspath(__file__))
IMG = os.path.join(BASE, "a6600_fw", "extracted", "0700_part_image", "dev", "nflasha15")

v = Volume(open(IMG, "rb"))
root = v.root
print("volume block_size:", v.block_size, "root inode:", root.i_no, "flags:", hex(root.i_flags))

ents = list(root.opendir())
print("root entries:", len(ents))
e0 = ents[0]
print("entry attrs:", [a for a in dir(e0) if not a.startswith("_")][:40])
for e in ents[:8]:
    print("  %-10s dir=%-5s size=%s" % (e.name, getattr(e, "is_dir", "?"), getattr(e, "size", "?")))

lib = [e for e in ents if e.name == "lib"][0]
libents = list(lib.opendir())
print("lib entries:", len(libents))


def sha_of(entry):
    h = hashlib.sha256()
    f = entry.open()
    try:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    finally:
        f.close()
    return h.hexdigest()


for name in ("libObj.so", "libmpr.so", "libAK8975.so", "libIMDB.so"):
    for e in libents:
        if e.name == name:
            print("%-14s %10d  %s" % (name, e.size, sha_of(e)))
            break
    else:
        print("%-14s MISSING" % name)
