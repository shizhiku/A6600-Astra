"""S2-2: 冲突去重 —— 区分"同名且同码"（可豁免）与"同名不同码"（必须改名）。"""
import os
import struct

from elftools.elf.elffile import ELFFile

ROOT = r"<LEGACY_WORKSPACE>"
A = os.path.join(ROOT, "a6600_fw", "usr", "lib")
B = os.path.join(ROOT, "zv1m2_fw", "gen5")
PAIRS = [("libObj.so", "libObj.so", "libObj → libOb5"),
         ("libmpr.so", "libmpr.so", "libmpr → libmp5")]


def load(path):
    """返回 {name: (bytes, type, size)} 只含已定义全局符号。"""
    f = open(path, "rb")
    e = ELFFile(f)
    text = e.get_section_by_name(".text")
    taddr, toff, tsize = text["sh_addr"], text["sh_offset"], text["sh_size"]
    out = {}
    for s in e.get_section_by_name(".dynsym").iter_symbols():
        if not s.name or s["st_shndx"] == "SHN_UNDEF":
            continue
        if s["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK"):
            continue
        val, size = s["st_value"], s["st_size"]
        if not size or not (taddr <= val < taddr + tsize):
            out[s.name] = (None, s["st_info"]["type"], size)
            continue
        off = toff + (val - taddr)
        f.seek(off)
        out[s.name] = (f.read(min(size, 1 << 20)), s["st_info"]["type"], size)
    f.close()
    return out


def main():
    for fa, fb, label in PAIRS:
        pa, pb = os.path.join(A, fa), os.path.join(B, fb)
        if not (os.path.exists(pa) and os.path.exists(pb)):
            print(f"{label}: 缺文件")
            continue
        da, db = load(pa), load(pb)
        common = set(da) & set(db)
        same = [n for n in common if da[n][0] is not None and da[n][0] == db[n][0]]
        diff = [n for n in common if n not in same]
        print(f"\n=== {label} ===")
        print(f"  同名符号        {len(common):,}")
        print(f"  其中同码（可豁免）{len(same):,}")
        print(f"  需要改名        {len(diff):,}")
        print("  同码示例:", ", ".join(sorted(same)[:5]) if same else "—")
        print("  必改示例:", ", ".join(sorted(diff)[:5]) if diff else "—")


if __name__ == "__main__":
    main()
