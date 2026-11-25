"""取 ZV-E10 的 im.elf，反汇编 0x975e 附近，作为 a6600 的对照样板。"""
import os
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

ROOT = r"<LEGACY_WORKSPACE>"
IMG = os.path.join(ROOT, "zve10_fw", "extracted", "0700_part_image", "dev", "nflasha15")
DST = os.path.join(ROOT, "zve10_fw", "usr", "bin", "im.elf")


def extract():
    import importlib.util
    spec = importlib.util.spec_from_file_location("usr", os.path.join(ROOT, "a6600_usr.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    fs = m.Ext2(IMG)
    for path, ino, isdir in fs.walk():
        if path == "/bin/im.elf":
            data = fs.read_file(ino)
            os.makedirs(os.path.dirname(DST), exist_ok=True)
            open(DST, "wb").write(data)
            print(f"extracted {DST} {len(data):,} B")
            return
    raise SystemExit("not found")


def main():
    if not os.path.exists(DST):
        extract()
    raw = open(DST, "rb").read()
    e = ELFFile(open(DST, "rb"))
    text = e.get_section_by_name(".text")
    print(f"size={len(raw):,} e_entry={e['e_entry']:#x} "
          f".text off={text['sh_offset']:#x} addr={text['sh_addr']:#x} size={text['sh_size']:#x}")

    off = 0x175E
    print(f"@0x{off:x} bytes: {raw[off:off+8].hex(' ')}")

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.skipdata = True
    body = raw[text["sh_offset"]:text["sh_offset"] + text["sh_size"]]
    insns = list(md.disasm(body, text["sh_addr"]))

    target_va = text["sh_addr"] + (off - text["sh_offset"])
    print(f"\n目标 VA = {target_va:#x}，上下文：")
    for i, ins in enumerate(insns):
        if abs(ins.address - target_va) <= 0x18:
            mark = "  <<< PATCH" if ins.address == target_va else ""
            print(f"  {ins.address:#06x}  {ins.mnemonic:8s} {ins.op_str}{mark}")

    # 统计
    hits = [i for i, x in enumerate(insns)
            if x.mnemonic == "mov" and x.op_str.replace(" ", "") == "r2,r0"]
    print(f"\nZV-E10 im.elf 中 mov r2,r0 共 {len(hits)} 处")


if __name__ == "__main__":
    main()
