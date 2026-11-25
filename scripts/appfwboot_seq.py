"""appfwboot_seq.py — 从 appFwBoot.so 中按地址顺序提取 Application_System_Init / Main /
initializeArena 的调用序列与字符串引用，作为“调用顺序”证据。

只读分析，不执行目标代码。
输出: 03-证据/静态分析/boot5/call_sequence.txt
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import appfwboot_libobj_probe as P  # noqa: E402
from capstone.arm import ARM_OP_MEM, ARM_REG_PC  # noqa: E402

ROOT = HERE.parent
BOOT = ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "appFwBoot.so"
OUT = ROOT / "03-证据" / "静态分析" / "boot5"

FUNCS = ["Application_System_Init", "_Z4MainPv", "_Z15initializeArenav"]


def main():
    lib = P.Lib(BOOT)
    plt = P.build_plt(lib)
    md = P.Cs(P.CS_ARCH_ARM, P.CS_MODE_THUMB)
    md.detail = True
    text = lib.secs[".text"]
    lines = ["# appFwBoot.so 调用序列（按指令地址）", ""]
    for name in FUNCS:
        sym = lib.syms.get(name)
        if not sym:
            lines.append(f"## {name}: NOT FOUND")
            continue
        val = sym["value"]
        size = sym["size"]
        start = val & ~1
        lines.append(f"## {name} @ {start:#x} size={size}")
        code = text["data"][start - text["addr"]:start - text["addr"] + size]
        seq = []
        for ins in md.disasm(code, start):
            if ins.mnemonic in ("bl", "blx") and ins.operands and ins.operands[0].type == P.ARM_OP_IMM:
                tgt = ins.operands[0].imm & 0xFFFFFFFF
                nm = plt.get(tgt) or plt.get(tgt | 1) or lib.by_value.get(tgt & ~1) or ("sub_%x" % (tgt & ~1))
                seq.append((ins.address, "call", nm, ""))
            if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1:
                m = ins.operands[1]
                if m.type == ARM_OP_MEM and m.mem.base == ARM_REG_PC:
                    lit = ((ins.address + 4) & ~3) + m.mem.disp
                    v = lib.read_u32(lit)
                    if v is not None:
                        cs = lib.read_cstr(v)
                        seq.append((ins.address, "lit", "%#x" % v, cs or ""))
                        if cs:
                            seq.append((ins.address, "str", cs, ""))
            if ins.address + ins.size >= start + size:
                break
        # 只保留 call 与“看起来是字符串地址”的字面量(用于 add-pc 解引用)
        last_lit = None
        for addr, kind, val, extra in seq:
            if kind == "call":
                lines.append(f"  {addr:08x}  call  {val}")
                last_lit = None
            elif kind == "lit":
                last_lit = val
            elif kind == "str" and last_lit:
                lines.append(f"  {addr:08x}  str   {val}      (取自字面量 {last_lit})")
                last_lit = None
        lines.append("")
    (OUT / "call_sequence.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
