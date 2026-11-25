"""临时探针: 统计 libObj.so 函数首指令, 估计 ARM/Thumb 比例."""
import struct
from elftools.elf.elffile import ELFFile

SO = r"03-证据\静态分析\grm\lib\libObj.so"
with open(SO, "rb") as f:
    elf = ELFFile(f)
    ex = elf.get_section_by_name(".ARM.exidx")
    data = ex.data()
    base = ex["sh_addr"]
    starts = []
    for i in range(0, len(data), 8):
        w0 = struct.unpack_from("<I", data, i)[0]
        off = w0 & 0x7FFFFFFF
        if off & 0x40000000:
            off -= 0x80000000
        starts.append((base + i + off) & ~1)
    starts = sorted(set(starts))
    print("exidx funcs:", len(starts))
    # 读节数据
    text = elf.get_section_by_name(".text")
    tb = text.data()
    taddr = text["sh_addr"]

    def word(a):
        o = a - taddr
        return struct.unpack_from("<I", tb, o)[0] if 0 <= o < len(tb) - 3 else 0

    from collections import Counter
    c = Counter()
    amb = 0
    for a in starts:
        w = word(a)
        hi = w >> 28
        hw = w & 0xFFFF
        if (hw & 0xFF00) in (0xB400, 0xB500):
            c["thumb_push16"] += 1
        elif hi == 0xE or hi == 0xF:
            c["ambig_arm_or_thumb32"] += 1
            amb += 1
        else:
            c["thumb_cond_arm"] += 1
    print(c)
    # dynsym 已定义函数 thumb 位比例
    syms = elf.get_section_by_name(".dynsym")
    odd = even = 0
    for i in range(syms.num_symbols()):
        s = syms.get_symbol(i)
        if s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] != "SHN_UNDEF" and s["st_value"]:
            if s["st_value"] & 1:
                odd += 1
            else:
                even += 1
    print("defined FUNC dynsym: thumb(odd)=%d arm(even)=%d" % (odd, even))
    # 前 10 个 ambig 函数看首 3 条 thumb/arm 对照
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    th = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    shown = 0
    for a in starts:
        w = word(a)
        hi = w >> 28
        if hi in (0xE, 0xF) and (w & 0xFFFF) not in (0xB400, 0xB500):
            o = a - taddr
            code = tb[o:o + 12]
            print("ambig 0x%x thumb=%s | arm=%s"
                  % (a,
                     [(i.mnemonic, i.op_str) for i in th.disasm(code, a)][:3],
                     [(i.mnemonic, i.op_str) for i in arm.disasm(code, a)][:3]))
            shown += 1
            if shown >= 5:
                break
