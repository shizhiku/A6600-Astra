"""grm_xref.py -- 全库函数级字符串引用 / 直接调用图, 用于定位 grm_init 阻塞点.

在 03-证据/静态分析/grm/lib/libObj.so 上:
  * 扫描全部 .ARM.exidx 函数, 解析 PIC 字符串加载(ldr@pc + add Rd,pc);
  * 建立直接调用图(bl/blx 立即数目标, 含 PLT 导入);
  * 回答: 哪些函数打印 "GPE HW: PSC dummywrite"、打开 /dev/dmpgles2、
    等待 sugilite 信号; 它们能否从 grm_init / 0x115078 / DMP2D 处理器直接到达.
输出: 03-证据/静态分析/grm/grm_string_xrefs.json / grm_dep_paths.txt
"""
from __future__ import annotations

import json
import os
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import grm_disasm as G  # noqa: E402

OUT = G.OUT
KEY_STRINGS = {
    0x2A1D58: "grm_ma ",
    0x2A1DA8: "/dev/dmpgles2",
    0x2A1DB8: "failed to open sugilite device",
    0x2A1E64: "!!! GPE HW: PSC dummywrite %s.",
    0x2A1E84: "GPE HW dummywrite buf",
    0x2A1EB4: "mmap register area failed",
    0x2A1FBC: "failed to wait signal from sugilite device",
    0x2A1FE8: "failed to send signal with sugilite device",
    0x29CA16: "grm_gpe",
    0x2A1E24: "",  # 占位: 若存在打印 GPE 初始化标志的字符串
}
ROOTS = {
    "grm_init": 0x116AE4,
    "sub_115078": 0x115078,
    "dmp2d_handler": 0x1814F0,
    "dmp2d_init": 0x1819B0,
    "gpe_worker": 0x181890,
}


def scan_all(img, funcs, plt) -> dict:
    """扫描全部函数: 直接调用目标 / 字符串(经 ldr-pc + add-pc 解析)."""
    starts = sorted(funcs)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    result = {}
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else \
            img.text["sh_addr"] + img.text["sh_size"]
        code = img.read(start, min(end - start, 0x10000))
        regvals: dict[str, int] = {}
        calls = []
        strings = []
        imports = []
        for insn in md.disasm(code, start):
            if insn.address >= end:
                break
            mn = insn.mnemonic
            ops = insn.operands
            if mn in ("ldr", "ldr.w") and ops and \
                    ops[0].type == ARM_OP_REG:
                rd = insn.reg_name(ops[0].reg)
                for op in ops[1:]:
                    if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                        la = (G.align4(insn.address + 4) + op.mem.disp) \
                            & 0xFFFFFFFF
                        v = img.u32(la)
                        if v is not None:
                            if img.in_rodata(v):
                                regvals.pop(rd, None)
                                if v in KEY_STRINGS:
                                    strings.append({"at": "0x%x" % insn.address,
                                                    "va": "0x%x" % v,
                                                    "text": KEY_STRINGS[v]})
                            else:
                                regvals[rd] = v
                        break
            elif mn in ("add", "adds", "add.w") and len(ops) >= 2 and \
                    ops[0].type == ARM_OP_REG and ops[1].type == ARM_OP_REG \
                    and ops[1].reg == ARM_REG_PC:
                rd = insn.reg_name(ops[0].reg)
                base = (insn.address + 4) & 0xFFFFFFFF
                if rd in regvals:
                    v = (regvals[rd] + base) & 0xFFFFFFFF
                    if v in KEY_STRINGS:
                        strings.append({"at": "0x%x" % insn.address,
                                        "va": "0x%x" % v,
                                        "text": KEY_STRINGS[v]})
                    if img.in_rodata(v):
                        regvals.pop(rd, None)
                    else:
                        regvals[rd] = v
            elif mn in ("movw", "movt", "mov") and ops and \
                    ops[0].type == ARM_OP_REG:
                imm = G._imm(insn)
                rd = insn.reg_name(ops[0].reg)
                if imm is not None:
                    regvals[rd] = imm
            if mn in ("bl", "blx") and ops:
                if ops[0].type == ARM_OP_IMM:
                    t = ops[0].imm & 0xFFFFFFFF
                    if t in plt:
                        imports.append(plt[t])
                    elif (t & ~1) in funcs:
                        calls.append(t & ~1)
                for r in list(G.VOLATILE):
                    regvals.pop(r, None)
        result[start] = {"calls": calls, "strings": strings,
                         "imports": imports}
        if (i + 1) % 3000 == 0:
            print("  scanned %d/%d" % (i + 1, len(starts)))
    return result


def reverse_edges(scan: dict) -> dict:
    rev: dict[int, list] = {}
    for f, info in scan.items():
        for t in info["calls"]:
            rev.setdefault(t, []).append(f)
    return rev


def bfs(scan: dict, start: int, targets: set, max_depth: int = 12):
    """从 start 沿直接调用边 BFS 到 targets, 返回最短路径. 间接调用不可见."""
    if start in targets:
        return [start]
    seen = {start}
    layer = [(start, [start])]
    for _ in range(max_depth):
        nxt = []
        for node, path in layer:
            for t in scan.get(node, {}).get("calls", []):
                if t in seen:
                    continue
                np = path + [t]
                if t in targets:
                    return np
                seen.add(t)
                nxt.append((t, np))
        layer = nxt
        if not layer:
            break
    return None


def main() -> int:
    img = G.Image(G.SO)
    funcs = G.build_functions(img)
    plt = G.build_plt_map(img)
    print("functions: %d, plt: %d" % (len(funcs), len(plt)))
    scan = scan_all(img, funcs, plt)
    rev = reverse_edges(scan)

    # 找到引用关键字符串的函数
    refs = {}
    for f, info in scan.items():
        for s in info["strings"]:
            refs.setdefault(s["va"], []).append(f)
    print("string refs:")
    for va, text in sorted(KEY_STRINGS.items()):
        fl = refs.get("%s" % ("0x%x" % va), [])
        print("  0x%x %-40s -> %s" % (va, text, [hex(x) for x in fl]))

    targets = set()
    for fl in refs.values():
        targets.update(fl)

    # 从关键根沿直接调用能否到达这些函数
    paths = {}
    for name, root in ROOTS.items():
        for t in sorted(targets):
            p = bfs(scan, root, {t})
            if p:
                paths.setdefault(name, []).append({
                    "target": "0x%x" % t,
                    "target_strings": scan[t]["strings"],
                    "path": ["0x%x" % x for x in p],
                })

    # 每个字符串引用函数的直接调用者(两级)
    callers = {}
    for t in sorted(targets):
        direct = [c for c in rev.get(t, [])]
        callers["0x%x" % t] = {
            "strings": scan[t]["strings"],
            "imports": scan[t]["imports"][:20],
            "direct_callers": ["0x%x" % c for c in direct[:20]],
        }

    # 找到调用 rm_reg_init / rm_reg_exit@plt 的函数, 并检查从各根的可达性
    reg_funcs = set()
    for f, info in scan.items():
        for name in info["imports"]:
            if name in ("rm_reg_init", "rm_reg_exit"):
                reg_funcs.add(f)
    print("rm_reg_init/exit callers:", [hex(x) for x in sorted(reg_funcs)])
    reg_paths = {}
    for name, root in ROOTS.items():
        for t in sorted(reg_funcs):
            p = bfs(scan, root, {t})
            if p:
                reg_paths.setdefault(name, []).append(
                    {"target": "0x%x" % t,
                     "path": ["0x%x" % x for x in p]})

    out = {
        "so": os.path.relpath(G.SO, G.WS),
        "functions": len(funcs),
        "rm_reg_init_callers": ["0x%x" % x for x in sorted(reg_funcs)],
        "rm_reg_reachable_from_roots": reg_paths,
        "key_strings": {"0x%x" % k: v for k, v in KEY_STRINGS.items()},
        "string_ref_functions": {k: ["0x%x" % x for x in v]
                                 for k, v in refs.items()},
        "reachable_from_roots": paths,
        "callers": callers,
    }
    with open(os.path.join(OUT, "grm_string_xrefs.json"), "w",
              encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    with open(os.path.join(OUT, "grm_dep_paths.txt"), "w",
              encoding="utf-8") as f:
        f.write("== 关键字符串引用函数 ==\n")
        for k, v in out["string_ref_functions"].items():
            f.write("%s (%s): %s\n" % (k, KEY_STRINGS[int(k, 16)],
                                       " ".join(v)))
        f.write("\n== 从关键根的直接调用可达路径 ==\n")
        for name, pl in paths.items():
            f.write("\n-- root %s (0x%x)\n" % (name, ROOTS[name]))
            for rec in pl:
                f.write("  target %s %s\n    %s\n"
                        % (rec["target"], rec["target_strings"],
                           " -> ".join(rec["path"])))
        f.write("\n== 字符串引用函数的直接调用者 ==\n")
        for k, rec in callers.items():
            f.write("%s %s\n  imports=%s\n  callers=%s\n"
                    % (k, rec["strings"], rec["imports"],
                       rec["direct_callers"]))
        f.write("\n== rm_reg_init/rm_reg_exit 的调用者 ==\n")
        f.write(" ".join(out["rm_reg_init_callers"]) + "\n")
        f.write("\n== 从关键根到 rm_reg_init 调用者的路径 ==\n")
        for name, pl in reg_paths.items():
            f.write("\n-- root %s (0x%x)\n" % (name, ROOTS[name]))
            for rec in pl:
                f.write("  target %s\n    %s\n"
                        % (rec["target"], " -> ".join(rec["path"])))
    print("done ->", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
