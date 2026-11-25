"""grm_probe_funcs.py -- 快速查看指定函数的导入/调用/字符串/前若干指令.

只读; 供 grm_init 阻塞链的中间函数核对用.
用法: python 02-脚本/grm_probe_funcs.py 0x12c670 0x138610 ...
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import grm_disasm as G
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


def main() -> int:
    addrs = [int(a, 0) for a in sys.argv[1:]]
    img = G.Image(G.SO)
    funcs = G.build_functions(img)
    plt = G.build_plt_map(img)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    for a in addrs:
        if a not in funcs:
            print("0x%x NOT a function start (nearest: %s)"
                  % (a, hex(max(k for k in funcs if k <= a))))
            continue
        info = G.scan_function(img, md, funcs, plt, a)
        print("\n=== 0x%x <%s> insns=%d mode=%s"
              % (a, G._sym_name(img, a), info["insn_count"], info["mode"]))
        print(" imports:", [i["name"] for i in info["imports"]])
        print(" calls  :", [c["target"] for c in info["calls"]])
        print(" strings:", [s["text"][:70] for s in info["strings"]])
        print(" indirect:", len(info["indirect_calls"]))
        for insn, note in list(zip(info["insns"], info["notes"]))[:40]:
            print("   0x%08x %-8s %-34s %s"
                  % (insn.address, insn.mnemonic, insn.op_str, note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
