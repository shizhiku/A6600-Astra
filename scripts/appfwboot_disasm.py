"""appfwboot_disasm.py — 五代 appFwBoot.so 的 Thumb 反汇编 + 调用图 + 导入引用解析.

只读分析，不执行目标代码。输入 05-原始固件/zv1m2_fw/gen5/appFwBoot.so，
输出到 03-证据/静态分析/boot5/:
  disasm_text.txt       带符号注释的完整 .text 反汇编
  plt_map.txt           PLT 桩 -> 导入符号 映射
  callgraph.json        每个内部函数的调用/引用(站点、目标、符号)
  data_relro.txt        .data.rel.ro / .got / .init_array 指针内容
  imports_used.txt      每个导入符号被哪些内部函数引用
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from pathlib import Path
import io
import json
import struct

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "appFwBoot.so"
OUTDIR = ROOT / "03-证据" / "静态分析" / "boot5"

TEXT_SECTION = ".text"


def vhex(x):
    return f"0x{x:x}"


def read_u32(raw, va, secs):
    for s in secs:
        if s["sh_type"] == "SHT_NOBITS":
            continue
        a = s["sh_addr"]
        if a <= va < a + s["sh_size"]:
            off = s["sh_offset"] + (va - a)
            if off + 4 <= len(raw):
                return struct.unpack_from("<I", raw, off)[0]
    return None


def read_cstr(raw, va, secs, maxlen=96):
    for s in secs:
        if s["sh_type"] == "SHT_NOBITS":
            continue
        a = s["sh_addr"]
        if a <= va < a + s["sh_size"]:
            off = s["sh_offset"] + (va - a)
            end = raw.find(b"\x00", off, min(len(raw), off + maxlen))
            if end < 0:
                end = min(len(raw), off + maxlen)
            try:
                return raw[off:end].decode("ascii")
            except UnicodeDecodeError:
                return None
    return None


class Target:
    def __init__(self, raw, elf):
        self.raw = raw
        self.elf = elf
        self.secs = []
        for s in elf.iter_sections():
            self.secs.append(
                {
                    "name": s.name,
                    "sh_type": s["sh_type"],
                    "sh_addr": s["sh_addr"],
                    "sh_offset": s["sh_offset"],
                    "sh_size": s["sh_size"],
                    "data": None if s["sh_type"] == "SHT_NOBITS" else s.data(),
                }
            )
        self.by_name = {s["name"]: s for s in self.secs}
        self.sec_objs = {s.name: s for s in elf.iter_sections()}
        self.syms = {}
        dynsym = elf.get_section_by_name(".dynsym")
        self.dynsym = dynsym
        if dynsym is not None:
            for i in range(dynsym.num_symbols()):
                sym = dynsym.get_symbol(i)
                if sym.name:
                    self.syms[sym.name] = {
                        "value": sym["st_value"],
                        "size": sym["st_size"],
                        "shndx": sym["st_shndx"],
                    }

    def sec_of(self, va):
        for s in self.secs:
            if s["sh_type"] == "SHT_NOBITS":
                continue
            if s["sh_addr"] and s["sh_addr"] <= va < s["sh_addr"] + s["sh_size"]:
                return s
        return None


def arm_imm(op):
    """Effective immediate for an ARM data-processing immediate operand.

    Capstone yields (#imm8, #rotate) for rotated immediates; apply ROR.
    """
    if len(op) > 1 and isinstance(op, (list, tuple)):
        pass
    return None


def _eff_imm(ins, idx):
    """Compute ROR(imm8, rotate) for `add r,r,#imm8,#rot` style operands."""
    ops = ins.operands
    if idx >= len(ops) or ops[idx].type != ARM_OP_IMM:
        return None
    imm = ops[idx].imm
    if idx + 1 < len(ops) and ops[idx + 1].type == ARM_OP_IMM:
        imm = ((imm >> ops[idx + 1].imm) | (imm << (32 - ops[idx + 1].imm))) & 0xFFFFFFFF
    return imm


def build_plt_map(t):
    """Decode .plt (ARM PLT) stubs -> imported symbol names."""
    plt = t.by_name.get(".plt")
    gotplt = t.by_name.get(".got.plt")
    relplt_obj = t.sec_objs.get(".rel.plt")
    if plt is None or relplt_obj is None:
        return {}
    # GOT slot -> symbol from .rel.plt
    slot2sym = {}
    for r in relplt_obj.iter_relocations():
        idx = r["r_info_sym"]
        name = ""
        if t.dynsym is not None and idx < t.dynsym.num_symbols():
            name = t.dynsym.get_symbol(idx).name
        slot2sym[r["r_offset"]] = name
    data = plt["data"]
    base = plt["sh_addr"]
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    ins_list = list(md.disasm(data, base))
    out = {}
    i = 0
    n = len(ins_list)
    while i + 2 < n:
        a, b, c = ins_list[i], ins_list[i + 1], ins_list[i + 2]
        ok = (
            a.mnemonic == "add" and a.op_str.startswith("ip, pc")
            and b.mnemonic == "add" and b.op_str.startswith("ip, ip")
            and c.mnemonic == "ldr" and c.op_str.startswith("pc, [ip")
        )
        if not ok:
            i += 1
            continue
        i1 = _eff_imm(a, 2)
        i2 = _eff_imm(b, 2)
        disp = c.operands[1].mem.disp
        target = (a.address + 8) + i1 + i2 + disp
        sym = slot2sym.get(target, "")
        out[a.address] = {"got": target, "sym": sym, "entry": a.address}
        i += 3
    return out


def function_starts(t):
    exidx = t.by_name.get(".ARM.exidx")
    starts = set()
    if exidx is not None:
        data = exidx["data"]
        base = exidx["sh_addr"]
        for k in range(0, len(data), 8):
            w = struct.unpack_from("<I", data, k)[0]
            pre = w & 0x7FFFFFFF
            if pre & 0x40000000:
                pre -= 0x80000000
            starts.add(((base + k + pre) & 0xFFFFFFFF) | 1)  # Thumb
    # internal functions from dynsym (defined in .text)
    text = t.by_name[TEXT_SECTION]
    lo, hi = text["sh_addr"], text["sh_addr"] + text["sh_size"]
    for name, s in t.syms.items():
        if s["value"] and s["shndx"] == text["sh_index"] if False else True:
            pass
    for name, s in t.syms.items():
        if s["shndx"] == 10 and s["value"] and lo <= s["value"] < hi:
            starts.add(s["value"] | 1)
    # _init / _fini etc. in .init/.fini
    for secname in (".init", ".fini"):
        sec = t.by_name.get(secname)
        if sec is not None and sec["sh_addr"]:
            starts.add(sec["sh_addr"] | 1)
    # 构造/析构数组里的函数也算函数起点（R_ARM_RELATIVE 就地存放指针值）
    for secname in (".init_array", ".fini_array"):
        sec = t.by_name.get(secname)
        if sec is None or sec["sh_type"] == "SHT_NOBITS":
            continue
        data = sec["data"]
        for off in range(0, len(data) - 3, 4):
            val = struct.unpack_from("<I", data, off)[0]
            if val:
                starts.add(val | 1)
    return sorted(starts)


def sym_name_at(t, va):
    for name, s in t.syms.items():
        if (s["value"] & ~1) == (va & ~1) and s["shndx"] in (10, 8, 11):
            return name
    return None


def analyze_function(t, start_thumb, end, plt_map, func_starts_set):
    """Disassemble one Thumb function and resolve calls/literals."""
    text = t.by_name[TEXT_SECTION]
    base_off = text["sh_offset"] + (start_thumb & ~1) - text["sh_addr"]
    n = end - (start_thumb & ~1)
    code = t.raw[base_off:base_off + n]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    insns = list(md.disasm(code, start_thumb & ~1))
    calls = []
    refs = []
    movw = {}
    movt = {}
    for ins in insns:
        addr = ins.address
        # --- calls / branches ---
        if ins.mnemonic in ("bl", "blx", "b", "bx", "b.w"):
            if ins.operands and ins.operands[0].type == ARM_OP_IMM:
                tgt = ins.operands[0].imm & 0xFFFFFFFF
                name = None
                kind = None
                if tgt in plt_map:
                    name = plt_map[tgt]["sym"]
                    kind = "import"
                elif tgt in func_starts_set:
                    name = sym_name_at(t, tgt) or f"sub_{tgt:x}"
                    kind = "internal"
                elif tgt & 1 and (tgt & ~1) in (start_thumb & ~1,):
                    kind = "self"
                if ins.mnemonic in ("b", "b.w"):
                    calls.append({"site": vhex(addr), "kind": "branch", "target": vhex(tgt), "sym": name})
                else:
                    calls.append(
                        {
                            "site": vhex(addr),
                            "kind": "call",
                            "target": vhex(tgt),
                            "sym": name or (f"unknown_{tgt:x}" if kind is None else name),
                            "target_kind": kind or "unknown",
                        }
                    )
        # --- literal pool loads ---
        if ins.mnemonic.startswith("ldr") and len(ins.operands) >= 2:
            m = ins.operands[1]
            if m.type == ARM_OP_MEM and m.mem.base == ARM_REG_PC_thumb(ins):
                lit = ((addr + 4) & ~3) + m.mem.disp
                val = read_u32(t.raw, lit, t.secs)
                rec = {"site": vhex(addr), "lit": vhex(lit), "value": vhex(val) if val is not None else None}
                if val is not None:
                    cs = read_cstr(t.raw, val, t.secs)
                    if cs and len(cs) >= 3:
                        rec["string"] = cs
                refs.append(rec)
        # --- movw/movt tracking for address materialization ---
        if ins.mnemonic in ("movw", "movw.w") and len(ins.operands) == 2 and ins.operands[1].type == ARM_OP_IMM:
            movw[ins.operands[0].reg] = ins.operands[1].imm
        if ins.mnemonic in ("movt", "movt.w") and len(ins.operands) == 2 and ins.operands[1].type == ARM_OP_IMM:
            movt[ins.operands[0].reg] = ins.operands[1].imm
        if ins.mnemonic == "bl" and len(ins.operands) == 1 and ins.operands[0].type == ARM_OP_IMM:
            pass
    # post: movw+movt combos
    for reg, hi in movt.items():
        if reg in movw:
            val = ((hi & 0xFFFF) << 16) | (movw[reg] & 0xFFFF)
            refs.append({"site": "movw/movt", "const": vhex(val)})
    return insns, calls, refs


def ARM_REG_PC_thumb(ins):
    from capstone.arm import ARM_REG_PC
    return ARM_REG_PC


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    raw = SRC.read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    t = Target(raw, elf)
    plt_map = build_plt_map(t)
    starts = function_starts(t)
    start_set = set(starts)
    # build display names / ranges
    ranges = []
    text = t.by_name[TEXT_SECTION]
    text_lo = text["sh_addr"]
    text_hi = text["sh_addr"] + text["sh_size"]
    for i, st in enumerate(starts):
        nxt = starts[i + 1] if i + 1 < len(starts) else text_hi + 0x40
        if st & ~1 < text_lo or (st & ~1) >= text_hi:
            # .init / .fini sections: use section end
            sec = t.sec_of(st & ~1)
            nxt = sec["sh_addr"] + sec["sh_size"]
        ranges.append((st, nxt))

    # ---- PLT map output ----
    with (OUTDIR / "plt_map.txt").open("w", encoding="utf-8") as f:
        f.write("PLT stub (ARM) -> GOT slot -> import symbol\n")
        for stub in sorted(plt_map):
            e = plt_map[stub]
            f.write(f"{vhex(stub):>10s} -> got {vhex(e['got']):>10s}  {e['sym']}\n")
    # NOTE: code calls PLT stubs with Thumb BL, target address has bit0 set.
    plt_thumb = {}
    for k, v in plt_map.items():
        plt_thumb[k] = v
        plt_thumb[k | 1] = v

    # ---- disassembly ----
    funcs_json = []
    all_calls = []
    imports_used = {}
    lines = []
    for st, nxt in ranges:
        name = sym_name_at(t, st & ~1) or f"sub_{st & ~1:x}"
        if (st & ~1) < text_lo or (st & ~1) >= text_hi:
            sec = t.sec_of(st & ~1)
            name = f"{sec['name']}@{vhex(st & ~1)}"
        lines.append("")
        lines.append(f"===== {name} @ {vhex(st & ~1)} .. {vhex(nxt)} =====")
        insns, calls, refs = analyze_function(t, st, nxt, plt_thumb, start_set)
        rec = {"name": name, "start": vhex(st & ~1), "end": vhex(nxt), "calls": calls, "literal_refs": refs}
        funcs_json.append(rec)
        all_calls.extend([dict(c, func=name) for c in calls])
        for c in calls:
            if c.get("target_kind") == "import":
                imports_used.setdefault(c["sym"], []).append({"func": name, "site": c["site"]})
        if refs:
            rec["literal_refs"] = refs
        for ins in insns:
            note = ""
            for c in calls:
                if c["site"] == vhex(ins.address):
                    note = f"  ; -> {c['target']} {c.get('sym') or ''}".rstrip()
            for r in refs:
                if r["site"] == vhex(ins.address):
                    if "string" in r:
                        note += f'  ; "{r["string"]}" @ {r["value"]}'
                    elif r.get("value"):
                        note += f"  ; ={r['value']}"
            lines.append(f"{vhex(ins.address):>10s}: {ins.bytes.hex():>12s}  {ins.mnemonic:8s} {ins.op_str}{note}")
        lines.append("")

    (OUTDIR / "disasm_text.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUTDIR / "callgraph.json").write_text(
        json.dumps({"plt": {vhex(k): v for k, v in plt_thumb.items()}, "functions": funcs_json}, indent=1, ensure_ascii=False),
        encoding="utf-8",
    )

    # ---- imports used map ----
    with (OUTDIR / "imports_used.txt").open("w", encoding="utf-8") as f:
        for sym in sorted(imports_used):
            f.write(f"{sym}\n")
            for u in imports_used[sym]:
                f.write(f"    from {u['func']} @ {u['site']}\n")

    # ---- data structures ----
    dlines = []
    for secname in (".init_array", ".fini_array", ".data.rel.ro", ".got", ".data"):
        sec = t.by_name.get(secname)
        if sec is None or sec["sh_type"] == "SHT_NOBITS":
            continue
        dlines.append(f"--- {secname} @ {vhex(sec['sh_addr'])} size {sec['sh_size']} ---")
        data = sec["data"]
        for off in range(0, len(data) - 3, 4):
            val = struct.unpack_from("<I", data, off)[0]
            va = sec["sh_addr"] + off
            sname = sym_name_at(t, val) or ""
            txt = ""
            if val:
                cs = read_cstr(t.raw, val, t.secs)
                if cs:
                    txt = f'  "{cs}"'
            dlines.append(f"  {vhex(va):>10s}: {vhex(val):>10s} {sname}{txt}")
        dlines.append("")
    (OUTDIR / "data_relro.txt").write_text("\n".join(dlines) + "\n", encoding="utf-8")

    print("PLT stubs:", len(plt_map))
    print("functions:", len(ranges))
    for st, nxt in ranges:
        print(" ", vhex(st & ~1), "..", vhex(nxt), sym_name_at(t, st & ~1))
    print("imports used:", len(imports_used))


if __name__ == "__main__":
    main()
