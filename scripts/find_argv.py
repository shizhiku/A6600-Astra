"""S2-3b: 通过 PLT 映射定位 im.elf 里 argv 检查函数与模块加载调用。"""
import os

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

P = r"<LEGACY_WORKSPACE>\a6600_fw\usr\bin\im.elf"


def main():
    f = open(P, "rb")
    e = ELFFile(f)
    raw = open(P, "rb").read()

    # .rel.plt -> 符号顺序 == PLT stub 顺序
    plt = e.get_section_by_name(".plt")
    plt_addr = plt["sh_addr"]
    plt_ent = 4
    syms = []
    for sec in e.iter_sections():
        if isinstance(sec, RelocationSection) and "plt" in sec.name:
            for r in sec.iter_relocations():
                s = e.get_section_by_name(".dynsym").get_symbol(r["r_info_sym"])
                syms.append(s.name)
    print(f".plt @{plt_addr:#x}, 重定位 {len(syms)} 个")
    plt_map = {}
    for i, name in enumerate(syms):
        # Thumb PLT: 每个 stub 4 字节，前两个是保留
        plt_map[plt_addr + 8 + i * plt_ent] = name
    for a, n in list(plt_map.items())[:8]:
        print(f"  plt {a:#x} -> {n}")

    text = e.get_section_by_name(".text")
    body = raw[text["sh_offset"]:text["sh_offset"] + text["sh_size"]]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.skipdata = True
    insns = list(md.disasm(body, text["sh_addr"]))

    print("\n调用 strchr/strcmp/strncmp 的位置:")
    for i, ins in enumerate(insns):
        if ins.mnemonic not in ("bl", "blx"):
            continue
        tgt = None
        try:
            tgt = int(ins.op_str.lstrip("#"), 16)
        except Exception:
            continue
        name = plt_map.get(tgt)
        if name in ("strchr", "strcmp", "strncmp", "putenv", "system"):
            print(f"  {ins.address:#06x}  -> {name}")
            for j in range(max(0, i - 6), min(len(insns), i + 6)):
                y = insns[j]
                mark = "  <<<" if j == i else ""
                print(f"      {y.address:#06x}  {y.mnemonic:8s} {y.op_str}{mark}")
            print()


if __name__ == "__main__":
    main()
