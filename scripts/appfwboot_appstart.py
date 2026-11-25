"""appfwboot_appstart.py — 反汇编 appFw.so 的 Application_Start (入口, 72 B)、
gen5 libMWF.so 的 MWF_Init，以及检查它们引用的符号/字符串。

只读分析，不执行目标代码。
输出: 03-证据/静态分析/boot5/appstart_mwf_disasm.txt
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import appfwboot_libobj_probe as P  # noqa: E402
from capstone.arm import ARM_REG_PC  # noqa: E402

ROOT = HERE.parent
APL = ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "appFw.so"
MWF = ROOT / "03-证据" / "静态分析" / "97_abi" / "zv_libMWF.so"
OUT = ROOT / "03-证据" / "静态分析" / "boot5"

TARGETS = [
    (APL, "Application_Start"),
    (MWF, "MWF_Init"),
]


def main():
    lines = []
    for path, name in TARGETS:
        lib = P.Lib(path)
        plt = P.build_plt(lib)
        md = P.Cs(P.CS_ARCH_ARM, P.CS_MODE_THUMB)
        md.detail = True
        sym = lib.syms.get(name)
        lines.append(f"# {path.name} :: {name}")
        if not sym:
            lines.append("  symbol not found")
            continue
        val = sym["value"]; size = sym["size"]; shndx = sym["shndx"]
        start = val & ~1
        text = lib.secs.get(".text")
        code = text["data"][start - text["addr"]:start - text["addr"] + (size or 128)]
        for ins in md.disasm(code, start):
            note = ""
            if ins.mnemonic in ("bl", "blx") and ins.operands and ins.operands[0].type == P.ARM_OP_IMM:
                tgt = ins.operands[0].imm & 0xFFFFFFFF
                nm = plt.get(tgt) or plt.get(tgt | 1)
                if not nm:
                    nm = lib.by_value.get(tgt & ~1)
                note = "  ; -> " + (nm or ("sub_%x" % (tgt & ~1)))
            if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1:
                m = ins.operands[1]
                if m.type == P.ARM_OP_MEM and m.mem.base == ARM_REG_PC:
                    lit = ((ins.address + 4) & ~3) + m.mem.disp
                    v = lib.read_u32(lit)
                    if v is not None:
                        cs = lib.read_cstr(v)
                        note = "  ; =%#x%s" % (v, (' "%s"' % cs) if cs else "")
            lines.append(f"  {ins.address:08x}: {ins.bytes.hex():>10s} {ins.mnemonic:8s} {ins.op_str}{note}")
            if ins.address + ins.size >= start + (size or 128):
                break
        lines.append("")
    (OUT / "appstart_mwf_disasm.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
