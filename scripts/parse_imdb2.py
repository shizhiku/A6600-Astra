"""S2-1b: 完整解析两张 libIMDB 模块表，并找出可借用的字符串槽位。"""
import os
import struct
import sys

ROOT = r"<LEGACY_WORKSPACE>"
A = os.path.join(ROOT, "a6600_fw", "usr", "lib", "libIMDB.so")
B = os.path.join(ROOT, "zv1m2_fw", "gen5", "libIMDB.so")
ENTRY = 24


def cstr(data, off, maxlen=120):
    if off >= len(data):
        return None
    end = data.find(b"\x00", off)
    if end < 0 or end - off > maxlen:
        return None
    s = data[off:end]
    if not s or any(c < 32 or c > 126 for c in s):
        return None
    return s.decode("ascii", "replace")


def looks_like_entry(data, off):
    if off + ENTRY > len(data):
        return None
    tag, ver, mode, psid, fptr, iptr = struct.unpack_from("<6I", data, off)
    if ver not in (0, 1):
        return None
    s = cstr(data, fptr)
    t = cstr(data, iptr)
    if not s or not t:
        return None
    return tag, ver, mode, psid, fptr, iptr, s, t


def table(data, anchor):
    # 从 anchor 向前后扩展，直到条目不再合法
    lo = anchor
    while looks_like_entry(data, lo - ENTRY):
        lo -= ENTRY
    hi = anchor
    while looks_like_entry(data, hi + ENTRY):
        hi += ENTRY
    return lo, hi


def dump(path, label):
    data = open(path, "rb").read()
    print(f"\n{'='*78}\n{label}  {len(data):,} B")
    needle = struct.pack("<I", 0x20000004)
    anchors = []
    i = 0
    while True:
        i = data.find(needle, i)
        if i < 0:
            break
        anchors.append(i)
        i += 4
    lo, hi = table(data, anchors[0])
    print(f"模块表: {lo:#x} .. {hi + ENTRY:#x}  共 {(hi - lo)//ENTRY + 1} 条\n")
    print(f"{'off':>8} {'tag':>10} {'mode':>10} {'psid':>10}  {'file':<34} init")
    for off in range(lo, hi + ENTRY, ENTRY):
        e = looks_like_entry(data, off)
        if not e:
            continue
        tag, ver, mode, psid, fptr, iptr, s, t = e
        print(f"{off:#8x} {tag:#10x} {mode:#10x} {psid:#10x}  {s:<34} {t}")

    # 可借用的字符串槽位：长度 >= 12 且属于"可禁用模块"的
    print("\n候选字符串槽位（长度 >= 12）:")
    for kw in ("testcmd", "gps", "fan", "sata", "Ethernet", "Vss", "appFw"):
        idx = 0
        while True:
            idx = data.find(kw.encode(), idx)
            if idx < 0:
                break
            s = cstr(data, idx)
            if s and len(s) >= 12:
                print(f"  {idx:#06x}  {s!r}  ({len(s)} 字符)")
            idx += 1


if __name__ == "__main__":
    dump(A, "a6600 libIMDB")
    dump(B, "ZV-1M2 libIMDB")
