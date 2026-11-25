"""appfwboot_elfinfo.py — 五代 appFwBoot.so 的 ELF 元数据 / 导入导出 / 字符串 / 重定位转储.

只读分析：读 05-原始固件/zv1m2_fw/gen5/appFwBoot.so，把结果写到
03-证据/静态分析/boot5/。不执行目标代码。

输出:
  elf_header.json, sections.txt, program_headers.txt, dynamic.txt,
  dynsym.txt, relocs.json, strings.txt, exidx_functions.txt, info.json
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "appFwBoot.so"
OUTDIR = ROOT / "03-证据" / "静态分析" / "boot5"

DT_NEEDED_TAG = "DT_NEEDED"


def vhex(x):
    return f"0x{x:x}" if isinstance(x, int) else str(x)


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    raw = SRC.read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    info = {}

    # ---- ELF header ----
    hdr = {
        "path": str(SRC),
        "size": len(raw),
        "class": elf.elfclass,
        "little_endian": elf.little_endian,
        "machine": elf["e_machine"],
        "type": elf["e_type"],
        "entry": vhex(elf["e_entry"]),
        "phnum": elf["e_phnum"],
        "shnum": elf["e_shnum"],
    }
    info["header"] = hdr

    # ---- sections ----
    secs = []
    for s in elf.iter_sections():
        secs.append(
            {
                "name": s.name,
                "type": s["sh_type"],
                "addr": vhex(s["sh_addr"]),
                "off": vhex(s["sh_offset"]),
                "size": s["sh_size"],
                "entsize": s["sh_entsize"],
                "flags": vhex(s["sh_flags"]),
                "link": s["sh_link"],
                "info": s["sh_info"],
            }
        )
    info["sections"] = secs
    with (OUTDIR / "sections.txt").open("w", encoding="utf-8") as f:
        f.write(f"{'name':22s} {'type':18s} {'addr':>10s} {'off':>8s} {'size':>8s} {'es':>4s} flags\n")
        for s in secs:
            f.write(
                f"{s['name']:22s} {s['type']:18s} {s['addr']:>10s} {s['off']:>8s} "
                f"{s['size']:>8d} {s['entsize']:>4d} {s['flags']}\n"
            )

    # ---- program headers ----
    phs = []
    for p in elf.iter_segments():
        phs.append(
            {
                "type": p["p_type"],
                "offset": vhex(p["p_offset"]),
                "vaddr": vhex(p["p_vaddr"]),
                "filesz": p["p_filesz"],
                "memsz": p["p_memsz"],
                "flags": p["p_flags"],
                "align": vhex(p["p_align"]),
            }
        )
    info["program_headers"] = phs
    with (OUTDIR / "program_headers.txt").open("w", encoding="utf-8") as f:
        for p in phs:
            f.write(
                f"{p['type']:22s} off={p['offset']:>8s} vaddr={p['vaddr']:>10s} "
                f"filesz={p['filesz']:>6d} memsz={p['memsz']:>6d} flags={p['flags']} align={p['align']}\n"
            )

    # ---- dynamic ----
    needed = []
    dyn_tags = []
    dyn = elf.get_section_by_name(".dynamic")
    if dyn is not None:
        for t in dyn.iter_tags():
            rec = {"tag": t.entry.d_tag, "value": None, "name": None}
            if t.entry.d_tag == "DT_NEEDED":
                rec["name"] = t.needed
                needed.append(t.needed)
            elif t.entry.d_tag in ("DT_SONAME", "DT_RPATH", "DT_RUNPATH"):
                rec["name"] = t.soname if hasattr(t, "soname") else str(t.entry.d_val)
            else:
                rec["value"] = vhex(t.entry.d_val) if t.entry.d_val < (1 << 32) else str(t.entry.d_val)
            dyn_tags.append(rec)
    info["needed"] = needed
    info["dynamic"] = dyn_tags
    with (OUTDIR / "dynamic.txt").open("w", encoding="utf-8") as f:
        for t in dyn_tags:
            f.write(f"{t['tag']:24s} {t['name'] or t['value']}\n")

    # ---- dynsym ----
    dynsym_sec = elf.get_section_by_name(".dynsym")
    syms = []
    if dynsym_sec is not None:
        for i in range(dynsym_sec.num_symbols()):
            s = dynsym_sec.get_symbol(i)
            syms.append(
                {
                    "index": i,
                    "name": s.name,
                    "value": vhex(s["st_value"]),
                    "size": s["st_size"],
                    "bind": s["st_info"]["bind"],
                    "type": s["st_info"]["type"],
                    "vis": s["st_other"]["visibility"],
                    "shndx": s["st_shndx"],
                }
            )
    info["dynsym"] = syms
    with (OUTDIR / "dynsym.txt").open("w", encoding="utf-8") as f:
        for s in syms:
            f.write(
                f"[{s['index']:3d}] {s['name']:48s} val={s['value']:>10s} size={s['size']:>5d} "
                f"{s['bind']:8s} {s['type']:10s} shndx={s['shndx']}\n"
            )

    # ---- relocations ----
    relocs = []
    for secname in (".rel.dyn", ".rel.plt", ".rela.dyn", ".rela.plt", ".rel.ARM.exidx", ".rela.ARM.exidx"):
        sec = elf.get_section_by_name(secname)
        if sec is None:
            continue
        for r in sec.iter_relocations():
            sym_idx = r["r_info_sym"]
            symname = ""
            if dynsym_sec is not None and sym_idx < dynsym_sec.num_symbols():
                symname = dynsym_sec.get_symbol(sym_idx).name
            addend = r["r_addend"] if secname.startswith(".rela") else None
            relocs.append(
                {
                    "section": secname,
                    "offset": vhex(r["r_offset"]),
                    "type": r["r_info_type"],
                    "sym_index": sym_idx,
                    "sym": symname,
                    "addend": addend,
                }
            )
    info["relocs"] = relocs
    with (OUTDIR / "relocs.txt").open("w", encoding="utf-8") as f:
        for r in relocs:
            f.write(
                f"{r['section']:14s} off={r['offset']:>10s} type={r['type']:>3d} "
                f"sym[{r['sym_index']:3d}]={r['sym']}"
                + (f" addend={r['addend']}" if r["addend"] is not None else "")
                + "\n"
            )

    # ---- strings ----
    strings = []
    for s in elf.iter_sections():
        if s["sh_type"] == "SHT_NOBITS" or s["sh_size"] == 0:
            continue
        data = s.data()
        base = s["sh_addr"]
        if s["sh_type"] == "SHT_STRTAB":
            continue
        i = 0
        while i < len(data):
            j = data.find(b"\x00", i)
            if j < 0:
                break
            chunk = data[i:j]
            if len(chunk) >= 4 and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in chunk):
                strings.append(
                    {
                        "section": s.name,
                        "addr": vhex(base + i),
                        "file_off": vhex(s["sh_offset"] + i),
                        "text": chunk.decode("ascii", "replace"),
                    }
                )
            i = j + 1
    info["strings"] = strings
    with (OUTDIR / "strings.txt").open("w", encoding="utf-8") as f:
        for st in strings:
            f.write(f"{st['addr']:>10s} {st['section']:14s} {st['file_off']:>8s}  {st['text']}\n")

    # ---- .ARM.exidx function starts ----
    exidx = elf.get_section_by_name(".ARM.exidx")
    funcs = []
    if exidx is not None:
        data = exidx.data()
        base = exidx["sh_addr"]
        for k in range(0, len(data), 8):
            w = struct.unpack_from("<I", data, k)[0]
            # prel31: 31-bit signed value, bit30 is the sign bit
            pre = w & 0x7FFFFFFF
            if pre & 0x40000000:
                pre -= 0x80000000
            funcs.append(((base + k + pre) & 0xFFFFFFFF))
        funcs = sorted(set(funcs))
    info["exidx_entries"] = [vhex(x) for x in funcs]
    with (OUTDIR / "exidx_functions.txt").open("w", encoding="utf-8") as f:
        for x in funcs:
            f.write(f"{vhex(x)}  thumb={bool(x & 1)}\n")

    (OUTDIR / "info.json").write_text(json.dumps(info, indent=1, ensure_ascii=False), encoding="utf-8")

    print("SRC", SRC, len(raw), "bytes")
    print("machine", elf["e_machine"], "type", elf["e_type"], "entry", vhex(elf["e_entry"]))
    print("sections", len(secs), "program headers", len(phs))
    print("DT_NEEDED", needed)
    print("dynsyms", len(syms))
    print("relocs", len(relocs))
    print("strings", len(strings))
    print("exidx entries", len(funcs))
    print("OUTDIR", OUTDIR)


if __name__ == "__main__":
    main()
