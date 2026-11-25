"""appfwboot_imelf.py — 反汇编五代 im.elf（ZV-1M2 /bin/im.elf），定位它如何遍历
libIMDB 模块表并调用各库的 init 入口。

只读分析，不执行目标代码。
输出:
  imelf_info.txt         ELF 事实 + DT_NEEDED + dynsym
  imelf_disasm.txt       全部函数(按 .ARM.exidx 边界)的反汇编
  imelf_focus.txt        引用 IMDB_*/dlopen/dlsym/strncmp/entry 名字的函数及上下文
  imelf_strings.txt      .rodata 字符串
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
from pathlib import Path
import io
import struct
import json
import re

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "03-证据" / "静态分析" / "boot5" / "image" / "bin" / "im.elf"
OUTDIR = ROOT / "03-证据" / "静态分析" / "boot5"

FOCUS_SYMS = ("IMDB_", "dlopen", "dlsym", "strncmp", "strcmp", "getenv", "msgsnd",
              "msgget", "open", "fopen", "osal_", "putenv", "system", "exec")


def vhex(x):
    return f"0x{x:x}"


class ELF:
    def __init__(self, path):
        self.raw = path.read_bytes()
        self.elf = ELFFile(io.BytesIO(self.raw))
        self.secs = {}
        for s in self.elf.iter_sections():
            self.secs[s.name] = {
                "name": s.name, "type": s["sh_type"], "addr": s["sh_addr"],
                "off": s["sh_offset"], "size": s["sh_size"],
                "data": None if s["sh_type"] == "SHT_NOBITS" else s.data(),
            }
        dynsym = self.elf.get_section_by_name(".dynsym")
        self.dynsym = dynsym
        self.syms = {}
        self.by_value = {}
        if dynsym:
            for i in range(dynsym.num_symbols()):
                s = dynsym.get_symbol(i)
                if not s.name:
                    continue
                self.syms[s.name] = (s["st_value"], s["st_size"], s["st_shndx"])
                if s["st_shndx"] != "SHN_UNDEF" and s["st_value"]:
                    self.by_value.setdefault(s["st_value"] & ~1, s.name)

    def section_of(self, va):
        for s in self.secs.values():
            if s["data"] is None:
                continue
            if s["addr"] and s["addr"] <= va < s["addr"] + s["size"]:
                return s
        return None

    def read_u32(self, va):
        s = self.section_of(va)
        if s is None or va + 4 > s["addr"] + s["size"]:
            return None
        return struct.unpack_from("<I", s["data"], va - s["addr"])[0]

    def cstr(self, va, maxlen=160):
        s = self.section_of(va)
        if s is None:
            return None
        off = va - s["addr"]
        d = s["data"][off:off + maxlen]
        z = d.find(b"\x00")
        if z < 0:
            return None
        try:
            return d[:z].decode("ascii")
        except UnicodeDecodeError:
            return None


def build_plt(e):
    plt = e.secs.get(".plt")
    relplt = e.elf.get_section_by_name(".rel.plt")
    dynsym = e.dynsym
    if plt is None or relplt is None or dynsym is None:
        return {}
    slot2sym = {}
    for r in relplt.iter_relocations():
        idx = r["r_info_sym"]
        if idx < dynsym.num_symbols():
            slot2sym[r["r_offset"]] = dynsym.get_symbol(idx).name
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    ins = list(md.disasm(plt["data"], plt["addr"]))
    out = {}

    def eff(i, idx):
        ops = i.operands
        if idx >= len(ops) or ops[idx].type != ARM_OP_IMM:
            return 0
        imm = ops[idx].imm
        if idx + 1 < len(ops) and ops[idx + 1].type == ARM_OP_IMM:
            rot = ops[idx + 1].imm
            imm = ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF
        return imm

    i = 0
    while i + 2 < len(ins):
        a, b, c = ins[i], ins[i + 1], ins[i + 2]
        if not (a.mnemonic == "add" and a.op_str.startswith("ip, pc")
                and b.mnemonic == "add" and b.op_str.startswith("ip, ip")
                and c.mnemonic == "ldr" and c.op_str.startswith("pc, [ip")):
            i += 1
            continue
        tgt = (a.address + 8) + eff(a, 2) + eff(b, 2) + c.operands[1].mem.disp
        name = slot2sym.get(tgt, "")
        out[a.address] = name
        out[a.address | 1] = name
        i += 3
    return out


def func_starts(e):
    starts = set()
    ex = e.secs.get(".ARM.exidx")
    if ex:
        data = ex["data"]
        base = ex["addr"]
        for k in range(0, len(data), 8):
            w = struct.unpack_from("<I", data, k)[0]
            pre = w & 0x7FFFFFFF
            if pre & 0x40000000:
                pre -= 0x80000000
            starts.add(((base + k + pre) & 0xFFFFFFFF) | 1)
    text = e.secs.get(".text")
    if text:
        for nm, (val, size, shndx) in e.syms.items():
            if shndx == text.get("shndx") if False else True:
                pass
        lo = text["addr"]
        hi = lo + text["size"]
        for nm, (val, size, shndx) in e.syms.items():
            if shndx == "SHN_UNDEF":
                continue
            # only symbols located within .text
            if val and lo <= (val & ~1) < hi:
                starts.add(val | 1)
    return sorted(starts)


def name_for(e, plt, target):
    tn = plt.get(target)
    if tn:
        return tn, "import"
    if target in e.by_value:
        return e.by_value[target], "local-export"
    return None, "internal"


def main():
    e = ELF(SRC)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    plt = build_plt(e)
    text = e.secs[".text"]
    starts = func_starts(e)
    start_set = set(starts)
    ranges = []
    for i, st in enumerate(starts):
        nxt = starts[i + 1] if i + 1 < len(starts) else text["addr"] + text["size"]
        if (st & ~1) < text["addr"] or (st & ~1) >= text["addr"] + text["size"]:
            continue
        ranges.append((st & ~1, min(nxt & ~1, text["addr"] + text["size"])))

    # ---- info ----
    info = ["# im.elf facts"]
    for s in e.secs.values():
        info.append("%-14s %-18s addr=%08x off=%06x size=%7d" %
                    (s["name"], s["type"], s["addr"], s["off"], s["size"]))
    info.append("")
    dyn = e.elf.get_section_by_name(".dynamic")
    if dyn:
        for t in dyn.iter_tags():
            if t.entry.d_tag in ("DT_NEEDED",):
                info.append("DT_NEEDED " + t.needed)
            elif t.entry.d_tag == "DT_SONAME":
                info.append("DT_SONAME " + str(t.soname))
    info.append("")
    info.append("# dynsym")
    for nm, (val, size, shndx) in sorted(e.syms.items()):
        info.append("%-46s %08x size=%-6d %s" % (nm, val, size, shndx))
    (OUTDIR / "imelf_info.txt").write_text("\n".join(info) + "\n", encoding="utf-8")

    # ---- strings ----
    lines = []
    for va, txt in scan_strings(e):
        lines.append("%08x  %s" % (va, txt))
    (OUTDIR / "imelf_strings.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # ---- disassembly ----
    dis = []
    focus = []
    for start, end in ranges:
        code = text["data"][start - text["addr"]:end - text["addr"]]
        ins_list = list(md.disasm(code, start))
        fname = e.by_value.get(start, "sub_%x" % start)
        func_lines = []
        focus_hits = []
        for ins in ins_list:
            note = ""
            if ins.mnemonic in ("bl", "blx", "b", "b.w") and ins.operands and \
                    ins.operands[0].type == ARM_OP_IMM:
                tgt = ins.operands[0].imm & 0xFFFFFFFF
                tn, kind = name_for(e, plt, tgt)
                if tn:
                    note = "  ; %s %s" % (kind, tn)
                elif tgt in start_set:
                    note = "  ; local sub_%x" % tgt
                if tn and any(k in tn for k in FOCUS_SYMS):
                    focus_hits.append((ins.address, ins.mnemonic, tn))
            if ins.mnemonic.startswith("ldr") and len(ins.operands) >= 2:
                m = ins.operands[1]
                from capstone.arm import ARM_OP_MEM, ARM_REG_PC
                if m.type == ARM_OP_MEM and m.mem.base == ARM_REG_PC:
                    lit = ((ins.address + 4) & ~3) + m.mem.disp
                    val = e.read_u32(lit)
                    if val:
                        cs = e.cstr(val)
                        note = "  ; =%08x%s" % (val, (' "%s"' % cs) if cs else "")
            func_lines.append("%08x: %-10s %-8s %s%s" %
                              (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, note))
        dis.append("")
        dis.append("===== %s @ %08x .. %08x =====" % (fname, start, end))
        dis.extend(func_lines)
        if focus_hits:
            focus.append("===== %s @ %08x =====" % (fname, start))
            for a, m, tn in focus_hits:
                focus.append("  %08x: %s %s" % (a, m, tn))
            focus.extend("    " + x for x in func_lines)
            focus.append("")
    (OUTDIR / "imelf_disasm.txt").write_text("\n".join(dis) + "\n", encoding="utf-8")
    (OUTDIR / "imelf_focus.txt").write_text("\n".join(focus) + "\n", encoding="utf-8")
    print("functions:", len(ranges), "focus funcs:", len([x for x in focus if x.startswith("=====")]))
    print("wrote", OUTDIR)


def scan_strings(e):
    out = []
    for s in e.secs.values():
        if s["data"] is None or s["type"] == "SHT_STRTAB":
            continue
        data = s["data"]
        for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
            va = s["addr"] + m.start()
            out.append((va, m.group().decode("ascii")))
    return out


if __name__ == "__main__":
    main()
