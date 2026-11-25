"""S2-1d: 按条目形状扫描两张 libIMDB 的完整模块表。"""
import os
import struct

ROOT = r"<LEGACY_WORKSPACE>"
A = os.path.join(ROOT, "a6600_fw", "usr", "lib", "libIMDB.so")
B = os.path.join(ROOT, "zv1m2_fw", "gen5", "libIMDB.so")


def cstr(data, off, maxlen=100):
    if off <= 0 or off >= len(data):
        return None
    end = data.find(b"\x00", off)
    if end < 0 or end - off > maxlen or end == off:
        return None
    s = data[off:end]
    if any(c < 32 or c > 126 for c in s):
        return None
    return s.decode("ascii", "replace")


def scan(path, label):
    data = open(path, "rb").read()
    print(f"\n{'='*80}\n{label}  {len(data):,} B")
    rows = []
    for o in range(0, len(data) - 24, 4):
        psid, fptr, iptr = struct.unpack_from("<III", data, o + 12)
        s = cstr(data, fptr)
        t = cstr(data, iptr)
        if not s or not t:
            continue
        if not (s.endswith(".so") or "/" in s or s.endswith(".ko")):
            continue
        rows.append((o, psid, fptr, iptr, s, t))

    # 按 stride 聚类
    offs = [r[0] for r in rows]
    stride = {}
    for a, b in zip(offs, offs[1:]):
        stride[b - a] = stride.get(b - a, 0) + 1
    print("条目间距分布:", sorted(stride.items(), key=lambda x: -x[1])[:5])
    print(f"命中 {len(rows)} 条\n")
    print(f"{'off':>8} {'psid':>10}  {'file':<34} init")
    for o, psid, fptr, iptr, s, t in rows:
        print(f"{o:#8x} {psid:#10x}  {s:<34} {t}")


if __name__ == "__main__":
    scan(A, "a6600")
    scan(B, "ZV-1M2")
