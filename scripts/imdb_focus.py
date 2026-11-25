"""S2-1e: 按 44 字节步长解析模块表，定位 appFw / testcmd 条目，输出改造方案。"""
import os
import struct

ROOT = r"<LEGACY_WORKSPACE>"
A = os.path.join(ROOT, "a6600_fw", "usr", "lib", "libIMDB.so")
B = os.path.join(ROOT, "zv1m2_fw", "gen5", "libIMDB.so")
STRIDE = 44


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


def entries(data):
    out = []
    for o in range(0, len(data) - STRIDE, STRIDE):
        psid, fptr, iptr = struct.unpack_from("<III", data, o + 12)
        s = cstr(data, fptr)
        t = cstr(data, iptr)
        if s and t:
            out.append((o, psid, fptr, iptr, s, t))
    return out


def report(path, label, targets):
    data = open(path, "rb").read()
    print(f"\n{'='*80}\n{label}  {len(data):,} B")
    ent = entries(data)
    print(f"44 步长解析到 {len(ent)} 条")
    for o, psid, fptr, iptr, s, t in ent:
        if s in targets or any(k in s for k in targets):
            print(f"\n  条目 @{o:#06x}  ({o//STRIDE} 号)")
            print(f"    原始 44 字节: {data[o:o+STRIDE].hex(' ')}")
            print(f"    +12 psid = {psid:#010x}")
            print(f"    +16 file = {fptr:#06x} -> {s!r}")
            print(f"    +20 init = {iptr:#06x} -> {t!r}")


if __name__ == "__main__":
    report(A, "a6600", {"appFw.so", "testcmd_scn.so"})
    report(B, "ZV-1M2", {"appFwBoot.so", "testcmd_scn.so"})
