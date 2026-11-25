"""S2-4: 在 a6600 的 libMWF.so 里定位 "overlap generation" 断言与对应的 cbz 补丁点。"""
import os
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

P = r"<LEGACY_WORKSPACE>\a6600_fw\usr\lib\libMWF.so"


def main():
    f = open(P, "rb")
    e = ELFFile(f)
    raw = open(P, "rb").read()

    def va_of(off):
        for s in e.iter_sections():
            if s["sh_offset"] <= off < s["sh_offset"] + s["sh_size"] and s["sh_addr"]:
                return s["sh_addr"] + (off - s["sh_offset"])
        return None

    str_off = 0x33A3C
    s = raw[str_off:raw.index(b"\x00", str_off)].decode()
    va = va_of(str_off)
    print(f"字符串 {s!r} @file {str_off:#x} -> VA {va:#x}")

    text = e.get_section_by_name(".text")
    body = raw[text["sh_offset"]:text["sh_offset"] + text["sh_size"]]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.skipdata = True
    insns = list(md.disasm(body, text["sh_addr"]))
    print(f".text {text['sh_addr']:#x}..{text['sh_addr']+text['sh_size']:#x}  {len(insns)} 条")

    # 找引用该字符串的 ldr 字面量
    for i, ins in enumerate(insns):
        if ins.mnemonic != "ldr" or "[pc" not in ins.op_str:
            continue
        try:
            imm = int(ins.op_str.split("#")[1].split("]")[0], 0)
        except Exception:
            continue
        pc = (ins.address + 4) & ~3
        lit = pc + imm
        off = lit - text["sh_addr"] + text["sh_offset"] if text["sh_addr"] <= lit < text["sh_addr"] + text["sh_size"] else None
        if off is None or off + 4 > len(raw):
            continue
        val = struct.unpack_from("<I", raw, off)[0]
        if val == va:
            print(f"\n引用点 {ins.address:#06x}: {ins.mnemonic} {ins.op_str}")
            for j in range(max(0, i - 10), min(len(insns), i + 12)):
                y = insns[j]
                mark = "  <<<" if j == i else ""
                print(f"   {y.address:#06x}  {y.mnemonic:9s} {y.op_str}{mark}")
            return
    print("未找到字符串引用（可能在别的节或用了 GOT）")


if __name__ == "__main__":
    main()
