"""S2 第一步：扫描 a6600 与 ZV-1M2 之间的同名导出符号（跨代冲突候选）。"""
import os
import sys

from elftools.elf.elffile import ELFFile

A = r"<LEGACY_WORKSPACE>\a6600_fw\usr"
B = r"<LEGACY_WORKSPACE>\zv1m2_fw\gen5"


def exports(path):
    with open(path, "rb") as f:
        e = ELFFile(f)
        dyn = e.get_section_by_name(".dynsym")
        out = set()
        for s in dyn.iter_symbols():
            if not s.name:
                continue
            if s["st_shndx"] == "SHN_UNDEF":
                continue
            if s["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK"):
                continue
            out.add(s.name)
        return out


def main():
    pairs = [
        (os.path.join(A, "lib", "libObj.so"), os.path.join(B, "libObj.so"), "libObj → libOb5"),
        (os.path.join(A, "lib", "libmpr.so"), os.path.join(B, "libmpr.so"), "libmpr → libmp5"),
    ]
    for pa, pb, label in pairs:
        if not (os.path.exists(pa) and os.path.exists(pb)):
            print(f"{label}: 文件缺失")
            continue
        ea, eb = exports(pa), exports(pb)
        common = ea & eb
        print(f"\n=== {label} ===")
        print(f"  a6600   导出 {len(ea):,}")
        print(f"  ZV-1M2  导出 {len(eb):,}")
        print(f"  同名冲突 {len(common):,}")
        sample = sorted(common)[:12]
        for s in sample:
            print(f"    {s}")


if __name__ == "__main__":
    main()
