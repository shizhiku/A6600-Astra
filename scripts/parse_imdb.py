"""S2-1: 解析 libIMDB.so 的模块表（a6600 vs ZV-1M2）。"""
import os
import struct
import sys

ROOT = r"<LEGACY_WORKSPACE>"
A = os.path.join(ROOT, "a6600_fw", "usr", "lib", "libIMDB.so")
B = os.path.join(ROOT, "zv1m2_fw", "extracted", "0700_part_image", "dev", "nflasha15")

ENTRY = 24  # 6 x u32


def extract_zv1m2_imdb():
    import importlib.util
    spec = importlib.util.spec_from_file_location("usr", os.path.join(ROOT, "a6600_usr.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    fs = m.Ext2(B)
    for path, ino, isdir in fs.walk():
        if path == "/lib/libIMDB.so":
            data = fs.read_file(ino)
            out = os.path.join(ROOT, "zv1m2_fw", "gen5", "libIMDB.so")
            open(out, "wb").write(data)
            print(f"extracted ZV-1M2 libIMDB.so {len(data):,} B")
            return out
    raise SystemExit("not found")


def cstr(data, off):
    if off >= len(data):
        return None
    end = data.find(b"\x00", off)
    if end < 0 or end - off > 120:
        return None
    s = data[off:end]
    if not s or any(c < 32 or c > 126 for c in s):
        return None
    return s.decode("ascii", "replace")


def scan(path, label):
    data = open(path, "rb").read()
    print(f"\n=== {label}  ({len(data):,} B) ===")
    hits = []
    needle = struct.pack("<I", 0x20000004)
    i = 0
    while True:
        i = data.find(needle, i)
        if i < 0:
            break
        # 条目对齐：24 字节步进的表里，tag 一般在 entry 起点
        hits.append(i)
        i += 1
    print(f"0x20000004 出现 {len(hits)} 次")
    for h in hits[:20]:
        vals = struct.unpack_from("<6I", data, h)
        tag, ver, mode, psid, fptr, iptr = vals
        s = cstr(data, fptr) if fptr < len(data) else None
        print(f"  @{h:#06x} tag={tag:#010x} ver={ver:#x} mode={mode:#010x} "
              f"psid={psid:#010x} file={fptr:#x}({s!r}) init={iptr:#x}")


if __name__ == "__main__":
    print("a6600 :", A)
    scan(A, "a6600 libIMDB")
    b = os.path.join(ROOT, "zv1m2_fw", "gen5", "libIMDB.so")
    if not os.path.exists(b):
        b = extract_zv1m2_imdb()
    scan(b, "ZV-1M2 libIMDB")
