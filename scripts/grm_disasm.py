"""grm_disasm.py -- 五代 libObj.so 的 grm_init 静态调用链与阻塞点扫描.

只读分析 03-证据/静态分析/grm/lib/libObj.so (由 grm_extract_libobj.py 提取),
用 pyelftools + capstone:
  * .ARM.exidx 还原内部函数边界(该 so 无 .symtab);
  * 解析 .plt / .rel.plt 把 PLT 槽映射回导入符号;
  * 从 grm_init 起做有界调用图 BFS, 标记 osal_*/ioctl/poll/sem_wait 等阻塞原语;
  * 跟踪 ldr@pc / add Rd,pc 的 PIC 字符串加载, 解出函数引用的字符串.
输出只写 03-证据/静态分析/grm/.

用法:
  python 02-脚本/grm_disasm.py                 # 默认根 0x116ae4, 深度 6
  python 02-脚本/grm_disasm.py --depth 8
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import (ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC)
from elftools.elf.elffile import ELFFile

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SO = os.path.join(WS, "03-证据", "静态分析", "grm", "lib", "libObj.so")
OUT = os.path.join(WS, "03-证据", "静态分析", "grm")
ROOT = 0x116AE4  # grm_init, Thumb (st_value=0x116ae5, bit0 为 Thumb 标志)

BLOCKING_IMPORTS = {
    "osal_rcv_msg_tmo": "OSAL 收消息(超时=-1 时永久阻塞)",
    "osal_wai_sem_tmo": "OSAL 等信号量(超时=-1 时永久阻塞)",
    "osal_snd_sync_msg": "OSAL 同步消息(等对端应答)",
    "osal_snd_sync_direct": "OSAL 同步直发(等对端应答)",
    "osal_wait_thread_exit": "等待线程退出",
    "osal_valloc_msg_wait": "等消息内存",
    "pthread_cond_wait": "条件变量永久等待",
    "pthread_cond_timedwait": "条件变量定时等待",
    "pthread_join": "等待线程结束",
    "sem_wait": "信号量永久等待",
    "sem_timedwait": "信号量定时等待",
    "poll": "poll 等 fd 事件",
    "select": "select 等 fd 事件",
    "ioctl": "ioctl(驱动未实现时可能阻塞)",
    "read": "read(设备/FIFO 无数据则阻塞)",
    "recv": "recv 等数据",
    "usleep": "睡眠",
    "nanosleep": "睡眠",
    "sleep": "睡眠",
    "sigsuspend": "等信号",
    "waitpid": "等子进程",
    "mmap": "mmap",
}

VOLATILE = {"r0", "r1", "r2", "r3", "r12", "ip", "lr"}


def align4(x: int) -> int:
    return x & ~3


class Image:
    """按 PT_LOAD 把 ELF 虚拟地址映射到文件字节."""

    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.segments = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            self.segments.append((seg["p_vaddr"],
                                  seg["p_vaddr"] + seg["p_filesz"],
                                  seg["p_offset"], seg["p_memsz"]))
        self.segments.sort()
        self.sections = {}
        for sec in self.elf.iter_sections():
            self.sections[sec.name] = sec
        self.text = self.sections[".text"]
        self.plt = self.sections[".plt"]
        self.rodata = self.sections[".rodata"]
        self.dynsym = self.elf.get_section_by_name(".dynsym")

    def read(self, va: int, n: int) -> bytes:
        for lo, hi, off, memsz in self.segments:
            if lo <= va < hi:
                self.f.seek(off + (va - lo))
                return self.f.read(min(n, hi - va))
            if hi <= va < lo + memsz:
                return b"\x00" * min(n, lo + memsz - va)
        return b""

    def u32(self, va: int) -> int | None:
        b = self.read(va, 4)
        if len(b) < 4:
            return None
        return struct.unpack("<I", b)[0]

    def cstr(self, va: int, maxlen: int = 240) -> str | None:
        b = self.read(va, maxlen)
        out = bytearray()
        for ch in b:
            if 0x20 <= ch < 0x7F or ch == 0x09:
                out.append(ch)
            else:
                break
        if len(out) < 2:
            return None
        return out.decode("ascii", "replace")

    def in_rodata(self, va: int) -> bool:
        lo = self.rodata["sh_addr"]
        return lo <= va < lo + self.rodata["sh_size"]


def prel31(addr: int, val: int) -> int:
    off = val & 0x7FFFFFFF
    if off & 0x40000000:
        off -= 0x80000000
    return (addr + off) & 0xFFFFFFFF


def build_functions(img: Image) -> dict[int, str]:
    """用 .ARM.exidx 得到函数起始(偶数地址). 本 so 内全部为 Thumb 代码:
    dynsym 中已定义 FUNC 的 st_value 全部带 bit0; 17605 个 exidx 起始里
    11430 个以 16-bit push 开头、6005 个首字高 4 位非 E/F, 其余 170 个按
    Thumb 解码同样是合法 push => 统一按 Thumb 处理."""
    funcs: dict[int, str] = {}
    sec = img.sections.get(".ARM.exidx")
    if sec is not None:
        data = sec.data()
        base = sec["sh_addr"]
        for i in range(0, len(data) - 7, 8):
            word0 = struct.unpack_from("<I", data, i)[0]
            if word0 in (0, 1):
                continue
            start = prel31(base + i, word0) & ~1
            funcs.setdefault(start, "thumb")
    for sym in img.dynsym.iter_symbols():
        if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"]:
            funcs[sym["st_value"] & ~1] = "thumb"
    return funcs


def build_plt_map(img: Image) -> dict[int, str]:
    """解 ARM/Thumb-interworking PLT 条目 -> 导入符号名."""
    plt = img.plt
    base, size = plt["sh_addr"], plt["sh_size"]
    data = img.read(base, size)
    got2sym: dict[int, str] = {}
    rel = img.elf.get_section_by_name(".rel.plt")
    dynsym = img.dynsym
    if rel is not None:
        for r in rel.iter_relocations():
            name = dynsym.get_symbol(r["r_info_sym"]).name
            got2sym[r["r_offset"]] = name
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    out: dict[int, str] = {}
    pos = 0
    while pos + 12 <= size:
        va = base + pos
        half = struct.unpack_from("<H", data, pos)[0]
        arm_off = pos
        if half == 0x4778:  # Thumb: bx pc; nop; 之后是 ARM 序列
            arm_off = pos + 4
        if arm_off + 12 > size:
            break
        insns = list(md.disasm(data[arm_off:arm_off + 12], base + arm_off))
        if len(insns) == 3:
            a, b, c = insns
            if (a.mnemonic.startswith("add") and "ip" in a.op_str
                    and "pc" in a.op_str and b.mnemonic.startswith("add")
                    and "ip" in b.op_str and c.mnemonic.startswith("ldr")
                    and "pc" in c.op_str):
                ok = True
                try:
                    simm0 = int(a.op_str.split("#")[1].split("]")[0], 0)
                    simm1 = int(b.op_str.split("#")[1].split("]")[0], 0)
                    simm2 = int(c.op_str.split("#")[1].strip("!]"), 0)
                except Exception:  # noqa: BLE001
                    ok = False
                if ok:
                    got = ((base + arm_off + 8) + simm0 + simm1 + simm2) \
                        & 0xFFFFFFFF
                    sym = got2sym.get(got)
                    if sym:
                        # Thumb 调用者 BLX 落在 ARM 序列起点; 若 ARM 调用者
                        # 存在则落在 va. 两个地址都登记.
                        out[base + arm_off] = sym
                        out[va] = sym
                        pos = arm_off + 12
                        continue
        pos += 4
    return out


def _imm(insn) -> int | None:
    for op in insn.operands:
        if op.type == ARM_OP_IMM:
            return op.imm
    return None


def scan_function(img: Image, md: Cs, funcs: dict[int, str],
                  plt: dict[int, str], start: int) -> dict:
    """反汇编一个函数, 解析调用/导入/字符串/阻塞原语."""
    starts = sorted(funcs)
    idx = starts.index(start) if start in funcs else -1
    end = starts[idx + 1] if 0 <= idx + 1 < len(starts) else \
        img.text["sh_addr"] + img.text["sh_size"]
    code = img.read(start, min(end - start, 0x10000))
    insns = []
    regvals: dict[str, int] = {}
    notes: list[str] = []
    calls, imports, indirect, strings, lits = [], [], [], [], []
    busy_loop = False
    loop_target = None
    last_call = None

    def note(i: int, txt: str) -> None:
        while len(notes) <= i:
            notes.append("")
        notes[i] = (notes[i] + "  ; " + txt) if notes[i] else ("; " + txt)

    def maybe_string(i: int, val: int) -> None:
        if img.in_rodata(val):
            s = img.cstr(val)
            if s:
                strings.append({"at": "0x%x" % insns[i].address,
                                "va": "0x%x" % val, "text": s})
                note(i, 'str 0x%x "%s"' % (val, s))

    for i, insn in enumerate(md.disasm(code, start)):
        if insn.address >= end:
            break
        if len(insns) >= 4000:
            break
        insns.append(insn)
        notes.append("")
        mn = insn.mnemonic
        # ---- 1) 字面量加载: ldr Rd, [pc, #imm]
        if mn in ("ldr", "ldr.w", "ldrb") and insn.operands:
            ops = insn.operands
            if ops[0].type == ARM_OP_REG:
                rd = insn.reg_name(ops[0].reg)
                for op in ops[1:]:
                    if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                        lit = (align4(insn.address + 4) + op.mem.disp) \
                            & 0xFFFFFFFF
                        val = img.u32(lit)
                        if val is not None:
                            lits.append({"at": "0x%x" % insn.address,
                                         "lit": "0x%x" % lit,
                                         "value": "0x%x" % val})
                            if img.in_rodata(val):
                                regvals.pop(rd, None)
                                maybe_string(i, val)
                            else:
                                regvals[rd] = val
                        break
        # ---- 2) add Rd, pc (T1, 无立即数): Rd = Rd + Align(PC,4)
        elif mn in ("add", "adds", "add.w") and len(insn.operands) >= 2:
            ops = insn.operands
            if (ops[0].type == ARM_OP_REG and ops[1].type == ARM_OP_REG
                    and ops[1].reg == ARM_REG_PC):
                rd = insn.reg_name(ops[0].reg)
                # 实测(0x116b3a -> 0x29cb74)这里 PC = 指令地址+4, 不做 4 对齐
                base = (insn.address + 4) & 0xFFFFFFFF
                if rd in regvals:
                    val = (regvals[rd] + base) & 0xFFFFFFFF
                    maybe_string(i, val)
                    regvals[rd] = val
                else:
                    regvals[rd] = base
            elif (len(ops) == 3 and ops[2].type == ARM_OP_IMM
                  and ops[1].type == ARM_OP_REG):
                rd = insn.reg_name(ops[0].reg)
                rs = insn.reg_name(ops[1].reg)
                if rs == "pc":
                    val = (align4(insn.address + 4) + ops[2].imm) \
                        & 0xFFFFFFFF
                    regvals[rd] = val
                    maybe_string(i, val)
                elif rs in regvals:
                    val = (regvals[rs] + ops[2].imm) & 0xFFFFFFFF
                    maybe_string(i, val)
                    regvals[rd] = val
        elif mn == "adr" and insn.operands:
            imm = _imm(insn)
            rd = insn.reg_name(insn.operands[0].reg)
            if imm is not None:
                val = (align4(insn.address + 4) + imm) & 0xFFFFFFFF
                regvals[rd] = val
                maybe_string(i, val)
        elif mn in ("movw", "mov") and insn.operands:
            imm = _imm(insn)
            rd = insn.reg_name(insn.operands[0].reg)
            if imm is not None:
                if mn == "movw":
                    regvals[rd] = (regvals.get(rd, 0) & 0xFFFF0000) | \
                        (imm & 0xFFFF)
                else:
                    regvals[rd] = imm
        elif mn == "movt" and insn.operands:
            imm = _imm(insn)
            if imm is not None:
                rd = insn.reg_name(insn.operands[0].reg)
                regvals[rd] = (regvals.get(rd, 0) & 0xFFFF) | \
                    ((imm & 0xFFFF) << 16)
        # ---- 3) 分支/调用
        if mn in ("bl", "blx") and insn.operands:
            op = insn.operands[0]
            if op.type == ARM_OP_IMM:
                tgt = op.imm & 0xFFFFFFFF
                if tgt in plt:
                    name = plt[tgt]
                    imports.append({"at": "0x%x" % insn.address,
                                    "target": "0x%x" % tgt,
                                    "name": name})
                    hint = {r: "0x%x" % regvals[r] for r in
                            ("r0", "r1", "r2", "r3") if r in regvals}
                    if hint:
                        imports[-1]["args_hint"] = hint
                    note(i, "-> %s@plt" % name)
                    if name in BLOCKING_IMPORTS:
                        note(i, "BLOCKING[%s]" % name)
                elif (tgt & ~1) in funcs:
                    calls.append({"at": "0x%x" % insn.address,
                                  "target": "0x%x" % (tgt & ~1)})
                    note(i, "-> 0x%x <%s>" % (tgt & ~1,
                                              _sym_name(img, tgt & ~1)))
                else:
                    lits.append({"at": "0x%x" % insn.address,
                                 "kind": "call-unresolved",
                                 "target": "0x%x" % tgt})
            elif op.type == ARM_OP_REG:
                indirect.append({"at": "0x%x" % insn.address,
                                 "insn": "%s %s" % (mn, insn.op_str)})
                note(i, "indirect")
            last_call = insn.address
            for r in list(VOLATILE):
                regvals.pop(r, None)
        elif mn.startswith("b") and mn not in (
                "bic", "bfi", "bfc", "bl", "blx") and insn.operands:
            op = insn.operands[0]
            if op.type == ARM_OP_IMM:
                tgt = op.imm & 0xFFFFFFFF
                if (tgt & ~1) in funcs and (tgt & ~1) != start:
                    calls.append({"at": "0x%x" % insn.address,
                                  "target": "0x%x" % (tgt & ~1),
                                  "tail": True})
                    note(i, "tail -> 0x%x <%s>"
                         % (tgt & ~1, _sym_name(img, tgt & ~1)))
                if tgt < insn.address:
                    busy_loop = True
                    loop_target = "0x%x" % tgt
    blocking = [imp for imp in imports if imp["name"] in BLOCKING_IMPORTS]
    return {
        "start": "0x%x" % start,
        "mode": funcs.get(start, "thumb"),
        "insn_count": len(insns),
        "calls": calls,
        "imports": imports,
        "blocking_imports": blocking,
        "indirect_calls": indirect,
        "strings": strings,
        "lits": lits,
        "busy_loop": busy_loop,
        "loop_target": loop_target,
        "notes": notes,
        "insns": insns,
        "last_call": "0x%x" % last_call if last_call else None,
    }


def _sym_name(img: Image, addr: int) -> str:
    for sym in img.dynsym.iter_symbols():
        if sym["st_value"] and (sym["st_value"] & ~1) == addr:
            return sym.name
    return "sub_%x" % addr


def _depth(parent, node):
    d = 0
    while parent.get(node) is not None:
        node = parent[node]
        d += 1
    return d


def _dump_disasm(img: Image, info: dict, f) -> None:
    f.write("\n0x%x <%s> mode=%s  (next func boundary, insns=%d)\n"
            % (int(info["start"], 16), _sym_name(img, int(info["start"], 16)),
               info["mode"], info["insn_count"]))
    for insn, note in zip(info["insns"], info["notes"]):
        f.write("  0x%08x  %-22s %-10s %s%s\n"
                % (insn.address, insn.bytes.hex(), insn.mnemonic,
                   insn.op_str, ("  " + note) if note else ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="0x%x" % ROOT)
    ap.add_argument("--depth", type=int, default=6)
    ap.add_argument("--max-functions", type=int, default=500)
    ap.add_argument("--so", default=SO)
    ap.add_argument("--dump", default="",
                    help="逗号分隔的函数地址, 额外导出完整反汇编")
    args = ap.parse_args()
    root = int(args.root, 0)
    os.makedirs(OUT, exist_ok=True)

    img = Image(args.so)
    global _IMG_FOR_NAME
    _IMG_FOR_NAME = img
    funcs = build_functions(img)
    plt = build_plt_map(img)
    print("functions(exidx): %d, plt entries: %d, dynsym: %d"
          % (len(funcs), len(plt), img.dynsym.num_symbols()))
    if root not in funcs:
        print("root 0x%x not in exidx; 手工加入" % root)
        funcs[root] = "thumb"
    print("root 0x%x mode=%s" % (root, funcs[root]))

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True

    nodes: dict[int, dict] = {}
    parent: dict[int, int | None] = {root: None}
    order = [root]
    i = 0
    while i < len(order) and len(nodes) < args.max_functions:
        cur = order[i]
        i += 1
        info = scan_function(img, md, funcs, plt, cur)
        info["depth"] = _depth(parent, cur)
        nodes[cur] = info
        if info["depth"] >= args.depth:
            continue
        for c in info["calls"]:
            tgt = int(c["target"], 16)
            if tgt not in parent and tgt in funcs:
                parent[tgt] = cur
                order.append(tgt)
    print("analyzed functions: %d" % len(nodes))

    blocking = []
    for addr, info in nodes.items():
        if not info["blocking_imports"]:
            continue
        path = []
        p = addr
        while p is not None:
            path.append("0x%x" % p)
            p = parent.get(p)
        path.reverse()
        for imp in info["blocking_imports"]:
            blocking.append({
                "import": imp["name"],
                "import_at": imp["at"],
                "category": BLOCKING_IMPORTS[imp["name"]],
                "args_hint": imp.get("args_hint", {}),
                "function": "0x%x" % addr,
                "function_name": _sym_name(img, addr),
                "depth": info["depth"],
                "path": path,
            })
    blocking.sort(key=lambda x: (x["depth"], x["import"], x["function"]))

    graph = {
        "so": os.path.relpath(args.so, WS),
        "so_sha256": _sha256_file(args.so),
        "root": "0x%x" % root,
        "depth_limit": args.depth,
        "functions_analyzed": len(nodes),
        "exidx_functions": len(funcs),
        "plt_entries": len(plt),
        "nodes": {},
        "blocking_imports": blocking,
    }
    for addr, info in nodes.items():
        graph["nodes"]["0x%x" % addr] = {
            k: info[k] for k in ("start", "mode", "insn_count", "depth",
                                 "calls", "imports", "blocking_imports",
                                 "indirect_calls", "strings", "lits",
                                 "busy_loop", "loop_target")}
    with open(os.path.join(OUT, "grm_callgraph.json"), "w",
              encoding="utf-8") as f:
        json.dump(graph, f, ensure_ascii=False, indent=1)

    with open(os.path.join(OUT, "grm_init_disasm.txt"), "w",
              encoding="utf-8") as f:
        _dump_disasm(img, nodes[root], f)
    with open(os.path.join(OUT, "grm_blocking_funcs_disasm.txt"), "w",
              encoding="utf-8") as f:
        seen = set()
        for b in blocking:
            a = int(b["function"], 16)
            if a in seen or a not in nodes:
                continue
            seen.add(a)
            f.write("\n" + "=" * 78 + "\n// %s (blocking: %s)\n"
                    % (b["function"], b["import"]))
            _dump_disasm(img, nodes[a], f)

    with open(os.path.join(OUT, "grm_blocking_paths.txt"), "w",
              encoding="utf-8") as f:
        for b in blocking:
            f.write("%-22s %-30s depth=%d in %s(%s) args=%s\n     path=%s\n"
                    % (b["import"], b["category"], b["depth"],
                       b["function"], b["function_name"],
                       b.get("args_hint", {}), " -> ".join(b["path"])))

    # 根函数调用树(短)
    with open(os.path.join(OUT, "grm_init_calltree.txt"), "w",
              encoding="utf-8") as f:
        _tree(f, nodes, parent, root, 0)
    print("blocking imports found: %d" % len(blocking))
    for b in blocking[:50]:
        print("  %-22s depth=%d in %s(%s) args=%s path=%s"
              % (b["import"], b["depth"], b["function"],
                 b["function_name"], b.get("args_hint", {}),
                 " -> ".join(b["path"])))
    print("root strings:")
    for s in nodes[root]["strings"][:30]:
        print("  0x%s %r" % (s["va"], s["text"]))

    # 额外指定函数的完整反汇编
    if args.dump:
        for t in args.dump.split(","):
            a = int(t.strip(), 0)
            if a not in funcs:
                print("dump 0x%x: not a function start" % a)
                continue
            info = nodes.get(a) or scan_function(img, md, funcs, plt, a)
            path = os.path.join(OUT, "grm_dump_0x%x.txt" % a)
            with open(path, "w", encoding="utf-8") as f:
                _dump_disasm(img, info, f)
            print("dumped 0x%x -> %s" % (a, os.path.relpath(path, WS)))
    return 0


def _tree(f, nodes, parent, node, depth) -> None:
    global _TREE_LINES
    if depth > 6 or _TREE_LINES > 3000:
        return
    info = nodes.get(node)
    if info is None:
        return
    _TREE_LINES += 1
    pad = "  " * depth
    f.write("%s0x%x <%s> strings=%s\n"
            % (pad, node, _sym_name_global(node),
               [s["text"][:48] for s in info["strings"]][:4]))
    for c in info["calls"]:
        t = int(c["target"], 16)
        _tree(f, nodes, parent, t, depth + 1)


_IMG_FOR_NAME = None
_TREE_LINES = 0


def _sym_name_global(addr):
    if _IMG_FOR_NAME is None:
        return "sub_%x" % addr
    return _sym_name(_IMG_FOR_NAME, addr)


def _sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    sys.exit(main())
