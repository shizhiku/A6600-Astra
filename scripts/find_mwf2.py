"""S2-4b: 用 ZV-E10 的 libMWF 做对照，定位 a6600 的影子继承补丁点。"""
import os
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

ROOT = r"<LEGACY_WORKSPACE>"
Z_IMG = os.path.join(ROOT, "zve10_fw", "extracted", "0700_part_image", "dev", "nflasha15")
Z_OUT = os.path.join(ROOT, "zve10_fw", "usr", "lib", "libMWF.so")
A = os.path.join(ROOT, "a6600_fw", "usr", "lib", "libMWF.so")
ZVE10_PATCH_VA = 0x2D2AC


def extract_zve10():
    import importlib.util
    spec = importlib.util.spec_from_file_location("usr", os.path.join(ROOT, "a6600_usr.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    fs = m.Ext2(Z_IMG)
    for path, ino, isdir in fs.walk():
        if path == "/lib/libMWF.so":
            data = fs.read_file(ino)
            os.makedirs(os.path.dirname(Z_OUT), exist_ok=True)
            open(Z_OUT, "wb").write(data)
            print(f"ZV-E10 libMWF.so {len(data):,} B")
            return
    raise SystemExit("not found")


def dis(path, va, before=10, after=12):
    raw = open(path, "rb").read()
    e = ELFFile(open(path, "rb"))
    t = e.get_section_by_name(".text")
    body = raw[t["sh_offset"]:t["sh_offset"] + t["sh_size"]]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.skipdata = True
    ins = list(md.disasm(body, t["sh_addr"]))
    out = []
    idx = next((i for i, x in enumerate(ins) if x.address == va), None)
    if idx is None:
        return None
    for j in range(max(0, idx - before), min(len(ins), idx + after)):
        out.append(ins[j])
    return out


def main():
    if not os.path.exists(Z_OUT):
        extract_zve10()
    print("=== ZV-E10 libMWF @0x2D2AC 上下文 ===")
    ctx = dis(Z_OUT, ZVE10_PATCH_VA)
    for x in ctx:
        print(f"  {x.address:#06x}  {x.mnemonic:9s} {x.op_str}")
    # 打印 12 字节机器码作为特征
    raw = open(Z_OUT, "rb").read()
    e = ELFFile(open(Z_OUT, "rb"))
    t = e.get_section_by_name(".text")
    off = t["sh_offset"] + (ZVE10_PATCH_VA - t["sh_addr"])
    print(f"\n特征字节 @{off:#x}: {raw[off-8:off+16].hex(' ')}")

    # 在 a6600 里找同样的指令序列（用周围 3 条指令的机器码做锚）
    print("\n=== a6600 中匹配 ===")
    araw = open(A, "rb").read()
    ae = ELFFile(open(A, "rb"))
    at = ae.get_section_by_name(".text")
    abody = araw[at["sh_offset"]:at["sh_offset"] + at["sh_size"]]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.skipdata = True
    ains = list(md.disasm(abody, at["sh_addr"]))

    # 用 ZV-E10 补丁点前 3 条 + 后 3 条的"助记符形状"做模糊匹配
    def shape(lst):
        return [(x.mnemonic, x.op_str) for x in lst]
    target = shape(ctx)
    key = target[9:15] if len(target) >= 15 else target
    hits = []
    for i in range(len(ains) - len(key)):
        seg = [(x.mnemonic, x.op_str) for x in ains[i:i + len(key)]]
        if seg == key:
            hits.append(ains[i].address)
    print(f"完全匹配 {len(hits)} 处: {[hex(h) for h in hits]}")
    for h in hits[:3]:
        c = dis(A, h, 6, len(key) + 4)
        for x in c:
            mark = "  <<<" if x.address == h + (ZVE10_PATCH_VA - ctx[9].address) else ""
            print(f"  {x.address:#06x}  {x.mnemonic:9s} {x.op_str}{mark}")
        print()


if __name__ == "__main__":
    main()
