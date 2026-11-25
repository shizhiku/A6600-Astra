"""appfwboot_libobj_probe.py — 在 libObj.so（五代 / 四代）中反汇编关键初始化函数，
解析其调用、字面量字符串、init_array 构造器，并扫描全 .text 的调用点(xref)。

只读分析，不执行目标代码。
用法:
  python appfwboot_libobj_probe.py gen5
  python appfwboot_libobj_probe.py gen4
输出到 03-证据/静态分析/boot5/。
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM
from pathlib import Path
import io
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
GEN5_OBJ = ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "libObj.so"
GEN4_OBJ = ROOT / "05-原始固件" / "a6600_fw" / "usr" / "lib" / "libObj.so"
OUTDIR = ROOT / "03-证据" / "静态分析" / "boot5"

GEN5_TARGETS = [
    "uxengine_init",
    "uxengine_init2",
    "uxengine_app_fw_init",
    "uxengine_sus",
    "uxengine_res",
    "uxengine_exit",
    "DDSUserInit",
    "grm_init",
    "infra_input_init",
    "dmp_allocator_lib_init",
    "dmp_allocator_mmap_init",
    "_ZN2ux6wgtlay14WidgetLayouter14sys_initializeEv",
    "stella_print_log",
    "_ZN8UXEngine6gfxengEv",
    "_ZN8UXEngine6resmgrEv",
    "_ZN8UXEngine6wgtsysEv",
]
GEN4_TARGETS = [
    "Application_System_Init",
    "DDSUserInit",
    "grm_init",
    "infra_input_init",
    "dmp_allocator_lib_init",
    "dmp_allocator_mmap_init",
    "uxengine_init",
    "uxengine_init2",
    "_ZN2ux6wgtlay14WidgetLayouter14sys_initializeEv",
]

XREF_TARGETS_GEN5 = [
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
XREF_TARGETS_GEN4 = [
    "DDSUserInit",
    "grm_init",
    "infra_input_init",
    "dmp_allocator_lib_init",
    "dmp_allocator_mmap_init",
    "uxengine_init",
    "_ZN2ux6wgtlay14WidgetLayouter14sys_initializeEv",
    "Application_System_Init",
]


def vhex(x):
    return f"0x{x:x}"


class Lib:
    def __init__(self, path):
        self.path = path
        self.raw = path.read_bytes()
        self.elf = ELFFile(io.BytesIO(self.raw))
        self.secs = {}
        self.sec_objs = {}
        for s in self.elf.iter_sections():
            self.sec_objs[s.name] = s
            self.secs[s.name] = {
                "name": s.name,
                "type": s["sh_type"],
                "addr": s["sh_addr"],
                "off": s["sh_offset"],
                "size": s["sh_size"],
                "data": None if s["sh_type"] == "SHT_NOBITS" else s.data(),
            }
        dynsym = self.sec_objs.get(".dynsym")
        self.syms = {}
        self.by_value = {}
        if dynsym is not None:
            for i in range(dynsym.num_symbols()):
                sym = dynsym.get_symbol(i)
                if not sym.name:
                    continue
                rec = {
                    "value": sym["st_value"],
                    "size": sym["st_size"],
                    "shndx": sym["st_shndx"],
                    "type": sym["st_info"]["type"],
                }
                self.syms[sym.name] = rec
                if sym["st_shndx"] not in ("SHN_UNDEF",) and sym["st_value"]:
                    self.by_value.setdefault(sym["st_value"] & ~1, sym.name)
        self.sorted_vals = sorted(self.by_value)

    def contains(self, va):
        for s in self.secs.values():
            if s["data"] is None:
                continue
            if s["addr"] and s["addr"] <= va < s["addr"] + s["size"]:
                return s
        return None

    def read_u32(self, va):
        s = self.contains(va)
        if s is None or va + 4 > s["addr"] + s["size"]:
            return None
        off = va - s["addr"]
        return struct.unpack_from("<I", s["data"], off)[0]

    def read_cstr(self, va, maxlen=120):
        s = self.contains(va)
        if s is None:
            return None
        off = va - s["addr"]
        data = s["data"][off:off + maxlen]
        z = data.find(b"\x00")
        if z < 0:
            return None
        try:
            return data[:z].decode("ascii")
        except UnicodeDecodeError:
            return None

    def name_near(self, va):
        """Closest defined symbol at or below va."""
        lo, hi = 0, len(self.sorted_vals) - 1
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            v = self.sorted_vals[mid]
            if v <= va:
                best = v
                lo = mid + 1
            else:
                hi = mid - 1
        return self.by_value.get(best) if best is not None else None


def build_plt(lib):
    plt = lib.secs.get(".plt")
    relplt = lib.sec_objs.get(".rel.plt")
    dynsym = lib.sec_objs.get(".dynsym")
    if plt is None or relplt is None or dynsym is None:
        return {}
    slot2sym = {}
    for r in relplt.iter_relocations():
        idx = r["r_info_sym"]
        if idx < dynsym.num_symbols():
            slot2sym[r["r_offset"]] = dynsym.get_symbol(idx).name
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    ins_list = list(md.disasm(plt["data"], plt["addr"]))
    out = {}
    i = 0
    while i + 2 < len(ins_list):
        a, b, c = ins_list[i], ins_list[i + 1], ins_list[i + 2]
        if not (
            a.mnemonic == "add" and a.op_str.startswith("ip, pc")
            and b.mnemonic == "add" and b.op_str.startswith("ip, ip")
            and c.mnemonic == "ldr" and c.op_str.startswith("pc, [ip")
        ):
            i += 1
            continue
        import operator as _op

        def eff(ins, idx):
            ops = ins.operands
            if idx >= len(ops) or ops[idx].type != ARM_OP_IMM:
                return 0
            imm = ops[idx].imm
            if idx + 1 < len(ops) and ops[idx + 1].type == ARM_OP_IMM:
                rot = ops[idx + 1].imm
                imm = ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF
            return imm

        target = (a.address + 8) + eff(a, 2) + eff(b, 2) + c.operands[1].mem.disp
        out[a.address] = slot2sym.get(target, "")
        out[a.address | 1] = slot2sym.get(target, "")
        i += 3
    return out


def disasm_func(lib, name, plt, md_thumb):
    sym = lib.syms.get(name)
    if sym is None:
        return {"name": name, "error": "symbol not found"}
    start = sym["value"] & ~1
    size = sym["size"] or 0
    sec = lib.contains(start)
    if sec is None:
        return {"name": name, "error": "outside sections"}
    data = sec["data"][start - sec["addr"]: start - sec["addr"] + (size or 64)]
    lines = []
    calls = []
    refs = []
    consts = []
    movw = {}
    movt = {}
    ldr_pc_reg = {}
    for ins in md_thumb.disasm(data, start):
        note = ""
        if ins.mnemonic in ("bl", "blx", "b", "b.w") and ins.operands and ins.operands[0].type == ARM_OP_IMM:
            tgt = ins.operands[0].imm & 0xFFFFFFFF
            tname = plt.get(tgt)
            kind = "import" if tname else ""
            if not tname:
                tname = lib.name_near(tgt) if (tgt in lib.by_value) else None
                if tgt in lib.by_value:
                    kind = "local-export"
                else:
                    nm = lib.name_near(tgt)
                    tname = f"{nm}+{tgt - lib.by_value.get(nm, tgt):#x}" if nm else None
                    kind = "internal" if nm else "unknown"
            calls.append({"site": vhex(ins.address), "target": vhex(tgt), "sym": tname, "kind": kind})
            note = f"  ; {kind} {tname}"
        if ins.mnemonic.startswith("ldr") and len(ins.operands) >= 2:
            m = ins.operands[1]
            if m.type == ARM_OP_MEM:
                from capstone.arm import ARM_REG_PC
                if m.mem.base == ARM_REG_PC:
                    lit = ((ins.address + 4) & ~3) + m.mem.disp
                    val = lib.read_u32(lit)
                    refs.append({"site": vhex(ins.address), "lit": vhex(lit), "value": vhex(val) if val is not None else None})
                    if val is not None:
                        cs = lib.read_cstr(val)
                        if cs:
                            refs[-1]["string"] = cs
                            note = f'  ; ={vhex(val)} "{cs}"'
                        else:
                            note = f"  ; ={vhex(val)}"
        if ins.mnemonic in ("movw", "movw.w") and len(ins.operands) == 2 and ins.operands[1].type == ARM_OP_IMM:
            movw[ins.operands[0].reg] = ins.operands[1].imm
        if ins.mnemonic in ("movt", "movt.w") and len(ins.operands) == 2 and ins.operands[1].type == ARM_OP_IMM:
            movt[ins.operands[0].reg] = ins.operands[1].imm
        if ins.mnemonic == "add" and len(ins.operands) == 3 and ins.op_str.endswith(", pc"):
            # add rX, pc, #imm  -> immediate from operands[2]
            if ins.operands[0].reg in ldr_pc_reg:
                base = ldr_pc_reg.pop(ins.operands[0].reg)
                ptr = ((ins.address + 4) & ~3) + ins.operands[2].imm + base
                cs = lib.read_cstr(ptr)
                if cs:
                    consts.append({"site": vhex(ins.address), "ptr": vhex(ptr), "string": cs})
                    note += f'  ; -> {vhex(ptr)} "{cs}"'
        if ins.mnemonic == "add" and len(ins.operands) == 2 and ins.operands[1].type == ARM_OP_IMM:
            pass
        if ins.mnemonic.startswith("ldr") and len(ins.operands) >= 2 and ins.operands[1].type == ARM_OP_IMM:
            # ldr rX, [pc, #imm] is mem, not imm; skip
            pass
        lines.append(f"{vhex(ins.address):>10s}: {ins.bytes.hex():>10s}  {ins.mnemonic:8s} {ins.op_str}{note}")
        if ins.address + ins.size >= start + size:
            break
    return {
        "name": name,
        "start": vhex(start),
        "size": size,
        "disasm": lines,
        "calls": calls,
        "literal_refs": refs,
        "string_adds": consts,
    }


def dump_init_array(lib):
    sec = lib.sec_objs.get(".init_array")
    relsec = lib.sec_objs.get(".rel.dyn")
    relmap = {}
    if relsec is not None:
        for r in relsec.iter_relocations():
            relmap[r["r_offset"]] = (r["r_info_type"], r["r_info_sym"])
    out = []
    if sec is None:
        return out
    data = sec.data()
    base = sec["sh_addr"]
    for i in range(0, len(data) - 3, 4):
        va = base + i
        val = struct.unpack_from("<I", data, i)[0]
        out.append({"slot": vhex(va), "value": vhex(val), "reloc": relmap.get(va), "sym": lib.name_near(val) if val else None})
    return out


def collect_func_starts(lib):
    exidx = lib.sec_objs.get(".ARM.exidx")
    starts = set()
    if exidx is not None:
        data = exidx.data()
        base = exidx["sh_addr"]
        for k in range(0, len(data), 8):
            w = struct.unpack_from("<I", data, k)[0]
            pre = w & 0x7FFFFFFF
            if pre & 0x40000000:
                pre -= 0x80000000
            starts.add(((base + k + pre) & 0xFFFFFFFF) | 1)
    text = lib.sec_objs.get(".text")
    if text is not None:
        lo = text["sh_addr"]
        hi = lo + text["sh_size"]
        for nm, s in lib.syms.items():
            if s["shndx"] == text["sh_index"] if False else True:
                pass
        for nm, s in lib.syms.items():
            if s["value"] and lo <= (s["value"] & ~1) < hi:
                starts.add(s["value"] | 1)
    return sorted(starts)


def xref_scan(lib, target_names, plt=None, max_report=200):
    """Sweep .text per exidx function and record BL targets of interest.

    Calls to exported symbols inside the same lib go through PLT stubs, so the
    PLT map must be consulted in addition to defined symbol values.
    """
    starts = collect_func_starts(lib)
    text = lib.sec_objs.get(".text")
    lo, hi = text["sh_addr"], text["sh_addr"] + text["sh_size"]
    ranges = []
    for i, st in enumerate(starts):
        nxt = starts[i + 1] if i + 1 < len(starts) else hi
        if (st & ~1) < lo or (st & ~1) >= hi:
            continue
        ranges.append((st & ~1, min(nxt & ~1, hi)))
    target_vas = {}
    for nm in target_names:
        s = lib.syms.get(nm)
        if s and s["value"]:
            target_vas[s["value"] & ~1] = nm
    plt = plt or {}
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = False
    hits = []
    for start, end in ranges:
        code = text.data()[start - lo:end - lo]
        try:
            for ins in md.disasm(code, start):
                if ins.mnemonic in ("bl", "blx") and ins.op_str.startswith("#"):
                    try:
                        tgt = int(ins.op_str[1:], 0)
                    except ValueError:
                        continue
                    tgt &= ~1
                    nm = plt.get(tgt) or plt.get(tgt | 1)
                    if nm is None and tgt in target_vas:
                        nm = target_vas[tgt]
                    if nm in target_names:
                        hits.append(
                            {
                                "target": nm,
                                "site": vhex(ins.address),
                                "caller_start": vhex(start),
                                "caller_sym": lib.name_near(start) if start in lib.by_value else None,
                            }
                        )
        except Exception:
            continue
    return hits[:max_report], len(ranges)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "gen5"
    path = GEN5_OBJ if which == "gen5" else GEN4_OBJ
    targets = GEN5_TARGETS if which == "gen5" else GEN4_TARGETS
    OUTDIR.mkdir(parents=True, exist_ok=True)
    lib = Lib(path)
    plt = build_plt(lib)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    result = {
        "lib": str(path),
        "sections": {k: {"addr": vhex(v["addr"]), "size": v["size"]} for k, v in lib.secs.items()},
        "needed": [],
        "targets": [],
        "init_array": [],
    }
    dyn = lib.sec_objs.get(".dynamic")
    if dyn is not None:
        for t in dyn.iter_tags():
            if t.entry.d_tag == "DT_NEEDED":
                result["needed"].append(t.needed)
    result["init_array"] = dump_init_array(lib)
    out_lines = []
    out_lines.append(f"# {path.name} ({which})")
    out_lines.append("DT_NEEDED: " + ", ".join(result["needed"]))
    out_lines.append("")
    out_lines.append(f".init_array ({len(result['init_array'])} entries):")
    for e in result["init_array"]:
        out_lines.append(f"  {e['slot']}: {e['value']} {e['sym'] or ''} reloc={e['reloc']}")
    out_lines.append("")
    missing = []
    for nm in targets:
        rec = disasm_func(lib, nm, plt, md)
        result["targets"].append(rec)
        if "error" in rec:
            missing.append(nm)
            out_lines.append(f"## {nm}: {rec['error']}")
            continue
        out_lines.append(f"## {nm} @ {rec['start']} size {rec['size']}")
        out_lines.extend(rec["disasm"])
        out_lines.append("  calls:")
        for c in rec["calls"]:
            out_lines.append(f"    {c['site']} -> {c['target']} {c['kind']} {c['sym']}")
        out_lines.append("")
    if which == "gen5":
        hits, nfunc = xref_scan(lib, XREF_TARGETS_GEN5)
        result["xref_hits"] = hits
        result["xref_func_count"] = nfunc
        out_lines.append(f"## xref scan over {nfunc} exidx functions")
        for h in hits:
            out_lines.append(f"  {h['target']} <- {h['site']} in func {h['caller_start']} {h['caller_sym']}")
        out_lines.append("")
    else:
        hits, nfunc = xref_scan(lib, XREF_TARGETS_GEN4)
        result["xref_hits"] = hits
        result["xref_func_count"] = nfunc
        out_lines.append(f"## xref scan over {nfunc} exidx functions")
        for h in hits:
            out_lines.append(f"  {h['target']} <- {h['site']} in func {h['caller_start']} {h['caller_sym']}")
        out_lines.append("")
    name = "libobj_probe_gen5.txt" if which == "gen5" else "libobj_probe_gen4.txt"
    (OUTDIR / name).write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    (OUTDIR / name.replace(".txt", ".json")).write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", OUTDIR / name)
    print("missing:", missing)
    for rec in result["targets"]:
        if "error" not in rec:
            print(f"{rec['name']:60s} @ {rec['start']} size={rec['size']}")


if __name__ == "__main__":
    main()
