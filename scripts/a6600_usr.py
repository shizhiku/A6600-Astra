"""Minimal ext2 reader + a6600 /usr inventory/analysis (Windows, no WSL)."""
import hashlib, os, struct, sys

BASE = os.path.dirname(os.path.abspath(__file__))
IMG = os.path.join(BASE, "a6600_fw", "extracted", "0700_part_image", "dev", "nflasha15")
OUTDIR = os.path.join(BASE, "a6600_fw", "usr")


class Ext2:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.f.seek(1024)
        sb = self.f.read(1024)
        u32 = lambda o: struct.unpack_from("<I", sb, o)[0]
        u16 = lambda o: struct.unpack_from("<H", sb, o)[0]
        self.bs = 1024 << u32(24)
        self.first_data = u32(20)
        self.bpg = u32(32)
        self.ipg = u32(40)
        self.inode_size = u16(88) or 128
        self.blocks = u32(4)
        self.rev = u32(76)
        self.ngroups = (self.blocks + self.bpg - 1) // self.bpg
        gd_start = (self.first_data + 1) * self.bs
        self.f.seek(gd_start)
        gd = self.f.read(self.ngroups * 32)
        self.inode_tables = [struct.unpack_from("<I", gd, i * 32 + 8)[0] for i in range(self.ngroups)]

    def inode(self, n):
        g, idx = divmod(n - 1, self.ipg)
        off = self.inode_tables[g] * self.bs + idx * self.inode_size
        self.f.seek(off)
        d = self.f.read(self.inode_size)
        mode = struct.unpack_from("<H", d, 0)[0]
        size = struct.unpack_from("<I", d, 4)[0]
        if mode & 0xF000 == 0x8000 and size >= 0x80000000:  # regular file, high size
            size |= struct.unpack_from("<I", d, 108)[0] << 32
        blocks = [struct.unpack_from("<I", d, 40 + 4 * k)[0] for k in range(15)]
        return mode, size, blocks

    def _block(self, b):
        self.f.seek(b * self.bs)
        return self.f.read(self.bs)

    def read_file(self, ino):
        mode, size, blocks = self.inode(ino)
        out = bytearray()
        ptrs = list(blocks[:12])
        if size > 12 * self.bs and blocks[12]:
            ind = self._block(blocks[12])
            ptrs += list(struct.unpack("<%dI" % (self.bs // 4), ind))
        if size > (12 + self.bs // 4) * self.bs and blocks[13]:
            dind = self._block(blocks[13])
            for p in struct.unpack("<%dI" % (self.bs // 4), dind):
                if p:
                    ptrs += list(struct.unpack("<%dI" % (self.bs // 4), self._block(p)))
        for p in ptrs:
            if len(out) >= size:
                break
            if p:
                out += self._block(p)
        return bytes(out[:size])

    def listdir(self, ino):
        mode, size, blocks = self.inode(ino)
        data = self.read_file(ino)
        out, off = [], 0
        while off + 8 <= len(data):
            e_ino, rec, nl, ft = struct.unpack_from("<IHBB", data, off)
            if rec == 0:
                break
            if e_ino:
                out.append((data[off + 8:off + 8 + nl].decode("latin1"), e_ino, ft))
            off += rec
        return out

    def walk(self, ino=2, prefix=""):
        for name, child, ft in self.listdir(ino):
            if name in (".", ".."):
                continue
            path = prefix + "/" + name
            is_dir = ft == 2 or (ft == 0 and self.inode(child)[0] & 0xF000 == 0x4000)
            yield path, child, is_dir
            if is_dir:
                yield from self.walk(child, path)


def main():
    fs = Ext2(IMG)
    print("ext2: bs=%d blocks=%d groups=%d inode_size=%d" % (fs.bs, fs.blocks, fs.ngroups, fs.inode_size))
    files, dirs = 0, 0
    listing = []
    for path, ino, is_dir in fs.walk():
        if is_dir:
            dirs += 1
            listing.append(("d", path, 0, ino))
        else:
            mode, size, _ = fs.inode(ino)
            files += 1
            listing.append(("f", path, size, ino))
    print("entries: %d files, %d dirs" % (files, dirs))

    os.makedirs(OUTDIR, exist_ok=True)
    with open(os.path.join(OUTDIR, "..", "usr_filelist.txt"), "w", encoding="utf-8") as o:
        for kind, path, size, ino in sorted(listing, key=lambda x: x[1]):
            o.write("%s %10d %s\n" % (kind, size, path))

    key = ["/bin/bootin.elf", "/bin/change_mode.sh", "/lib/libObj.so", "/lib/libmpr.so",
           "/lib/libAK8975.so", "/lib/libIMDB.so", "/tool/LeakTracer.so"]
    by_path = {p: (s, i) for k, p, s, i in listing}
    for p in key:
        if p not in by_path:
            print("%-24s MISSING" % p)
            continue
        size, ino = by_path[p]
        data = fs.read_file(ino)
        dst = os.path.join(OUTDIR, p.lstrip("/").replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        open(dst, "wb").write(data)
        print("%-24s %10d  sha256=%s" % (p, size, hashlib.sha256(data).hexdigest()))

    views = [p for k, p, s, i in listing if "/viewUnified" in p]
    print("viewUnified*: %s" % ", ".join(sorted(os.path.basename(v) for v in views)))
    for p in sorted(views):
        s, i = by_path[p]
        print("   %-28s %10d" % (p, s))

    print("appFw/libuxengine/libgrm present:",
          [p for k, p, s, i in listing if os.path.basename(p) in ("appFw.so", "libuxengine.so", "libgrm.so", "libOb5.so")])


if __name__ == "__main__":
    main()
