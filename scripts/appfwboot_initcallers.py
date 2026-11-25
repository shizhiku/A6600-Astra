"""appfwboot_initcallers.py — 在 libObj.so 内查找初始化入口的内部调用点（含 PLT 间接）
并反汇编调用者上下文，判断这些入口在库内部被谁、以什么顺序调用。

只读分析，不执行目标代码。
输出: 03-证据/静态分析/boot5/libobj_initcallers_<gen>.txt
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import appfwboot_libobj_probe as P  # noqa: E402
from capstone.arm import ARM_REG_PC  # noqa: E402

OUTDIR = P.OUTDIR

TARGETS = [
    "uxengine_init",
    "uxengine_init2",
    "uxengine_app_fw_init",
    "DDSUserInit",
    "grm_init",
    "infra_input_init",
    "dmp_allocator_lib_init",
    "dmp_allocator_mmap_init",
    "_ZN2ux6wgtlay14WidgetLayouter14sys_initializeEv",
]


def func_range(lib, starts, text, va):
    import bisect

    i = bisect.bisect_right(starts, va) - 1
    if i < 0:
        return va, va
    end = starts[i + 1] if i + 1 < len(starts) else text["addr"] + text["size"]
    return starts[i], end


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "gen5"
    path = P.GEN5_OBJ if which == "gen5" else P.GEN4_OBJ
    lib = P.Lib(path)
    plt = P.build_plt(lib)
    exidx = P.collect_func_starts(lib)
    starts = [s & ~1 for s in exidx]
    text = lib.secs[".text"]
    lines = [f"# internal callers of init entry points in {path.name} ({which})"]
    for name in TARGETS:
        sym = lib.syms.get(name)
        if not sym:
            lines.append(f"## {name}: not exported")
            continue
        hits, nfunc = P.xref_scan(lib, [name], plt)
        lines.append(f"## {name} @ {sym['value'] & ~1:#x} size={sym['size']}  callsites={len(hits)}")
        for h in hits:
            va = int(h["site"], 16)
            caller_lo, caller_hi = func_range(lib, starts, text, int(h["caller_start"], 16))
            
            caller_name = lib.by_value.get(caller_lo, f"sub_{caller_lo:x}")
            lines.append(f"  callsite {h['site']} in {caller_name} [{caller_lo:#x},{caller_hi:#x})")
            md = P.Cs(P.CS_ARCH_ARM, P.CS_MODE_THUMB)
            md.detail = True
            code = text["data"][caller_lo - text["addr"]:caller_hi - text["addr"]]
            for ins in md.disasm(code, caller_lo):
                if ins.address < va - 0x140 or ins.address > va + 0x40:
                    continue
                note = ""
                if ins.mnemonic in ("bl", "blx") and ins.operands and ins.operands[0].type == P.ARM_OP_IMM:
                    tgt = ins.operands[0].imm & 0xFFFFFFFF
                    nm = plt.get(tgt) or plt.get(tgt | 1)
                    if not nm:
                        nm = lib.by_value.get(tgt & ~1, "sub_%x" % (tgt & ~1))
                    note = " ; -> " + nm
                if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1:
                    m = ins.operands[1]
                    if m.type == P.ARM_OP_MEM and m.mem.base == ARM_REG_PC:
                        lit = ((ins.address + 4) & ~3) + m.mem.disp
                        val = lib.read_u32(lit)
                        if val is not None:
                            cs = lib.read_cstr(val)
                            note = " ; =%#x%s" % (val, (' "%s"' % cs) if cs else "")
                lines.append(f"    {ins.address:08x}: {ins.bytes.hex():>10s} {ins.mnemonic:8s} {ins.op_str}{note}")
            lines.append("")
    (OUTDIR / f"libobj_initcallers_{which}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("wrote", OUTDIR / f"libobj_initcallers_{which}.txt")


if __name__ == "__main__":
    main()
