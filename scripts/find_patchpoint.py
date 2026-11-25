"""S2-3: 在 a6600 的 im.elf 里定位 ZV-E10 0x175e 对应的补丁点。"""
import os
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

P = r"<LEGACY_WORKSPACE>\a6600_fw\usr\bin\im.elf"


def main():
    f = open(P, "rb")
    e = ELFFile(f)
    text = e.get_section_by_name(".text")
    taddr, toff, tsize = text["sh_addr"], text["sh_offset"], text["sh_size"]
    raw = open(P, "rb").read()
    body = raw[toff:toff + tsize]
    print(f".text addr={taddr:#x} off={toff:#x} size={tsize:#x}")

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = False
    insns = list(md.disasm(body, taddr))
    print(f"反汇编 {len(insns)} 条")

    # 找 mov r2, r0（Thumb: 0x4602）
    targets = []
    for i, ins in enumerate(insns):
        if ins.mnemonic == "mov" and ins.op_str.replace(" ", "") == "r2,r0":
            targets.append(i)
    print(f"mov r2, r0 命中 {len(targets)} 处\n")

    for idx in targets:
        lo = max(0, idx - 4)
        hi = min(len(insns), idx + 4)
        print(f"--- @{insns[idx].address:#06x} ---")
        for j in range(lo, hi):
            mark = "  <<<" if j == idx else ""
            ins = insns[j]
            print(f"  {ins.address:#06x}  {ins.mnemonic:8s} {ins.op_str}{mark}")
        print()


if __name__ == "__main__":
    main()
