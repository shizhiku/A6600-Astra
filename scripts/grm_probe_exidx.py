"""临时探针: 检查 libObj.so 的 .ARM.exidx 函数起始编码 与 dynsym Thumb 位."""
import struct
from elftools.elf.elffile import ELFFile

SO = r"03-证据\静态分析\grm\lib\libObj.so"
with open(SO, "rb") as f:
    elf = ELFFile(f)
    ex = elf.get_section_by_name(".ARM.exidx")
    data = ex.data()
    base = ex["sh_addr"]
    print("exidx addr=0x%x size=0x%x entries=%d" % (base, len(data), len(data) // 8))
    starts = []
    for i in range(0, len(data), 8):
        w0, w1 = struct.unpack_from("<II", data, i)
        off = w0 & 0x7FFFFFFF
        if off & 0x40000000:
            off -= 0x80000000
        starts.append(((base + i + off) & 0xFFFFFFFF, w0, w1))
    n_odd = sum(1 for s, _, _ in starts if s & 1)
    print("odd-bit0 entries: %d / %d" % (n_odd, len(starts)))
    for s, w0, w1 in starts:
        if 0x116a00 < (s & ~1) < 0x116d00:
            print("  exidx: start=0x%x w0=0x%08x w1=0x%08x" % (s, w0, w1))
    syms = elf.get_section_by_name(".dynsym")
    for i in range(syms.num_symbols()):
        sym = syms.get_symbol(i)
        if sym.name in ("grm_init", "GRM_gpermRectblit", "uiresp_init"):
            print("  dynsym %-20s value=0x%x size=%d shndx=%s"
                  % (sym.name, sym["st_value"], sym["st_size"], sym["st_shndx"]))
