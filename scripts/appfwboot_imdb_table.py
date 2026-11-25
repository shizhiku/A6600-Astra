"""appfwboot_imdb_table.py — 解码 libIMDB.so 的原厂模块表(44 字节条目)，输出
四代(a6600)与五代(ZV-1M2)的条目顺序、类型、psid/flag、file/init/exit/sus/res 名字。
并反汇编 libIMDB 自己的三个导出函数确认条目布局/查找语义。

只读分析，不执行目标代码。
输出: 03-证据/静态分析/boot5/imdb_<gen>.txt / imdb_<gen>.json
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io
import json
import struct

ROOT = Path(__file__).resolve().parent.parent
TARGETS = {
    "gen5": ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "libIMDB.so",
    "gen4": ROOT / "05-原始固件" / "a6600_fw" / "usr" / "lib" / "libIMDB.so",
}
OUTDIR = ROOT / "03-证据" / "静态分析" / "boot5"

KNOWN_TYPES = {
    0x00000001: "MODE",
    0x00000002: "TAG2",
    0x00000003: "TAG3",
    0x00000004: "TAG4",
    0x10000001: "LIRO_MAP_PATH",
    0x10000002: "LIRO_MAP_BACKUP",
    0x10000003: "LIRO_MAP3",
    0x20000001: "LIB",
    0x20000002: "LIB2",
    0x20000003: "LIB3",
    0x20000004: "APPLIB",
    0x40000001: "SHELL",
    0x00000028: "END",
}
for k in range(1, 10):
    KNOWN_TYPES[0x08000000 | k] = f"PHASE{k}"


def vhex(x):
    return f"0x{x:x}"


class IMDB:
    def __init__(self, path):
        self.path = path
        self.raw = path.read_bytes()
        self.elf = ELFFile(io.BytesIO(self.raw))
        self.secs = {}
        for s in self.elf.iter_sections():
            self.secs[s.name] = {
                "name": s.name, "type": s["sh_type"], "addr": s["sh_addr"],
                "off": s["sh_offset"], "size": s["sh_size"],
                "data": None if s["sh_type"] == "SHT_NOBITS" else s.data(),
            }
        self.dynsym = self.elf.get_section_by_name(".dynsym")
        self.syms = {}
        if self.dynsym:
            for i in range(self.dynsym.num_symbols()):
                s = self.dynsym.get_symbol(i)
                if s.name:
                    self.syms[s.name] = (s["st_value"], s["st_size"], s["st_shndx"])
        # relocation map
        self.relocs = {}
        rel = self.elf.get_section_by_name(".rel.dyn")
        if rel:
            for r in rel.iter_relocations():
                self.relocs[r["r_offset"]] = (r["r_info_type"], r["r_info_sym"])

    def sec_of(self, va):
        for s in self.secs.values():
            if s["data"] is None:
                continue
            if s["addr"] and s["addr"] <= va < s["addr"] + s["size"]:
                return s
        return None

    def u32(self, va):
        s = self.sec_of(va)
        if s is None or va + 4 > s["addr"] + s["size"]:
            return None
        return struct.unpack_from("<I", s["data"], va - s["addr"])[0]

    def cstr(self, va, maxlen=160):
        s = self.sec_of(va)
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

    def str_at(self, va):
        """If va is an in-image string pointer, return its text."""
        s = self.sec_of(va)
        if s is None:
            return None
        txt = self.cstr(va)
        if txt is None or len(txt) < 1:
            return None
        return txt


def find_layout(t):
    """Entries start at imdb_raw(.data.rel.ro) + 0x84 (imdb_raw header is 132 B)."""
    dr = t.secs.get(".data.rel.ro")
    start = dr["addr"] + 0x84
    n = 0
    while start + (n + 1) * 0x2C <= dr["addr"] + dr["size"]:
        typ = t.u32(start + n * 0x2C)
        if typ is None or typ == 0x28:
            break
        if typ not in KNOWN_TYPES and not (0 < typ < 0x100):
            break
        n += 1
    return [(start, n, n)]


def decode_entries(t, start, max_entries=400):
    dr = t.secs[".data.rel.ro"]
    entries = []
    for idx in range(max_entries):
        e = start + idx * 0x2C
        if e + 0x2C > dr["addr"] + dr["size"]:
            break
        typ = t.u32(e)
        if typ is None or typ == 0x28:
            break
        if typ not in KNOWN_TYPES and not (0 < typ < 0x100):
            break
        version = t.u32(e + 4)
        target = t.u32(e + 8)
        me_psid = t.u32(e + 0xC)
        me = me_psid & 0xFFFF
        psid = (me_psid >> 16) & 0xFFFF
        fields = {}
        for name, off in (("file", 0x10), ("init", 0x14), ("exit", 0x18),
                          ("sus", 0x1C), ("res", 0x20), ("inact", 0x24), ("act", 0x28)):
            v = t.u32(e + off)
            s = t.str_at(v) if v else None
            fields[name] = {"ptr": v, "str": s}
        entries.append({
            "index": idx,
            "entry_va": e,
            "type": typ,
            "type_name": KNOWN_TYPES.get(typ, "?"),
            "version": version,
            "target": target,
            "me": me,
            "psid": psid,
            "fields": fields,
        })
    return entries


def disasm_libimdb(t):
    text = t.secs.get(".text")
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = False
    lines = []
    for name in ("IMDB_find_entry", "IMDB_get_entries", "IMDB_find_target_bit"):
        sv = t.syms.get(name)
        if not sv:
            continue
        val, size, shndx = sv
        start = val & ~1
        code = text["data"][start - text["addr"]: start - text["addr"] + (size or 80)]
        lines.append(f"## {name} @ {vhex(start)} size={size}")
        for ins in md.disasm(code, start):
            note = ""
            if ins.mnemonic.startswith("ldr") and "[pc" in ins.op_str:
                try:
                    imm = int(ins.op_str.split("#")[-1].rstrip("]"), 0)
                except ValueError:
                    imm = None
                if imm is not None:
                    lit = ((ins.address + 4) & ~3) + imm
                    val2 = t.u32(lit)
                    note = f"  ; [{vhex(lit)}]={vhex(val2) if val2 is not None else '?'}"
                    if val2 is not None:
                        s = t.str_at(val2)
                        if s:
                            note += f' "{s}"'
            lines.append(f"  {vhex(ins.address)}: {ins.bytes.hex():>10s} {ins.mnemonic:8s} {ins.op_str}{note}")
            if ins.address + ins.size >= start + (size or 80):
                break
        lines.append("")
    return lines


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    summary = {}
    for gen, path in TARGETS.items():
        t = IMDB(path)
        cands = find_layout(t)
        lines = [f"# {gen} libIMDB {path.name} size={len(t.raw)}",
                 f".data.rel.ro @ {vhex(t.secs['.data.rel.ro']['addr'])} "
                 f"size={t.secs['.data.rel.ro']['size']}",
                 f"candidate table starts: {[(vhex(a), n, ok) for a, n, ok in cands]}",
                 ""]
        lines += disasm_libimdb(t)
        if not cands:
            (OUTDIR / f"imdb_{gen}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            continue
        start, n, ok = max(cands, key=lambda c: c[1])
        entries = decode_entries(t, start)
        lines.append(f"# decoded {len(entries)} entries at {vhex(start)} stride 0x2c")
        for e in entries:
            lines.append(
                "%3d %s type=0x%08x(%s) ver=0x%08x target=0x%08x me=0x%04x psid=0x%04x "
                "file=%r init=%r exit=%r sus=%r res=%r" % (
                    e["index"], vhex(e["entry_va"]), e["type"], e["type_name"],
                    e["version"], e["target"], e["me"], e["psid"],
                    e["fields"]["file"]["str"], e["fields"]["init"]["str"],
                    e["fields"]["exit"]["str"], e["fields"]["sus"]["str"],
                    e["fields"]["res"]["str"]))
        (OUTDIR / f"imdb_{gen}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (OUTDIR / f"imdb_{gen}.json").write_text(
            json.dumps({"path": str(path), "table_start": start, "entries": entries},
                       indent=1, ensure_ascii=False), encoding="utf-8")
        summary[gen] = len(entries)
        # 关注条目: 用户点名的初始化 + 阶段分隔
        want = ("uxengine", "MWF", "grm", "DDS", "infra_input", "dmp_allocator",
                "GpeInit", "core_sync", "WidgetLayouter", "appFwBoot", "Application_",
                "libObj")
        print(f"== {gen}: {len(entries)} entries, table_start={vhex(start)}")
        for e in entries:
            if e["type"] in KNOWN_TYPES and 0x08000001 <= e["type"] <= 0x08000009:
                print("%3d ---- %s ----" % (e["index"], e["type_name"]))
                continue
            blob = " ".join(str(e["fields"][k]["str"]) for k in e["fields"])
            if any(w.lower() in blob.lower() for w in want):
                print("%3d %-14s psid=0x%02x file=%r init=%r" % (
                    e["index"], e["type_name"], e["psid"],
                    e["fields"]["file"]["str"], e["fields"]["init"]["str"]))
    print("summary", summary)


if __name__ == "__main__":
    main()
