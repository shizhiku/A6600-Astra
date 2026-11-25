"""appfwboot_libs_scan.py — 扫描四/五代固件库：目标初始化符号由谁定义/导入、DT_NEEDED、
以及原厂 IMDB 启动表里的名字出现情况。

只读分析，不执行任何目标代码。输出到 03-证据/静态分析/boot5/。
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io
import json
import re

ROOT = Path(__file__).resolve().parent.parent
GEN5 = ROOT / "05-原始固件" / "zv1m2_fw" / "gen5"
GEN4LIB = ROOT / "05-原始固件" / "a6600_fw" / "usr" / "lib"
OUTDIR = ROOT / "03-证据" / "静态分析" / "boot5"

# 用户点名 + 我们桥接实验涉及的初始化符号
WANTED = [
    "uxengine_init2", "uxengine_init", "uxengine",
    "MWF_Init", "grm_init", "DDSUserInit", "infra_input_init",
    "dmp_allocator_lib_init", "dmp_allocator_mmap_init",
    "GpeInit", "core_sync_user_init",
    "Application_System_Init", "Application_Start",
    "WidgetLayouter", "sys_initialize",
    "osal_create_waitable_thread", "osal_valloc_msg_wait",
    "osal_snd_sync_msg", "osal_free_msg", "osal_set_cpu",
    "stella_print_log",
]

# 原厂 libIMDB 启动表关键字（在 libIMDB.so 的 .rodata 中）
TABLE_NAMES = [
    "appFwBoot.so", "Application_System_Init", "AppConfig.so",
    "libObj.so", "libmpr.so", "libMWF.so", "MWF_Init",
    "libInfraInput.so", "infra_input_init",
]


def scan_file(path):
    raw = path.read_bytes()
    rec = {"path": str(path.relative_to(ROOT)), "size": len(raw)}
    try:
        elf = ELFFile(io.BytesIO(raw))
    except Exception as e:  # not an ELF
        rec["error"] = f"not ELF: {e}"
        return rec
    rec["machine"] = elf["e_machine"]
    rec["type"] = elf["e_type"]
    rec["needed"] = []
    dyn = elf.get_section_by_name(".dynamic")
    soname = None
    if dyn is not None:
        for t in dyn.iter_tags():
            if t.entry.d_tag == "DT_NEEDED":
                rec["needed"].append(t.needed)
            elif t.entry.d_tag == "DT_SONAME":
                soname = t.soname
    rec["soname"] = soname
    dynsym = elf.get_section_by_name(".dynsym")
    defined, undefined = [], []
    if dynsym is not None:
        for i in range(dynsym.num_symbols()):
            s = dynsym.get_symbol(i)
            name = s.name
            if not name:
                continue
            hit = None
            for w in WANTED:
                if w.lower() in name.lower():
                    hit = w
                    break
            if hit is None:
                continue
            item = {"name": name, "value": s["st_value"], "size": s["st_size"], "shndx": s["st_shndx"]}
            if s["st_shndx"] == "SHN_UNDEF":
                undefined.append(item)
            else:
                defined.append(item)
    rec["defined_hits"] = defined
    rec["undefined_hits"] = undefined
    # raw ASCII string hits
    str_hits = {}
    for pat in WANTED + TABLE_NAMES:
        offs = [m.start() for m in re.finditer(re.escape(pat.encode()), raw)]
        if offs:
            str_hits[pat] = [hex(o) for o in offs[:8]]
    rec["string_hits"] = str_hits
    return rec


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    files = sorted(GEN5.glob("*.so")) + sorted(GEN4LIB.glob("*.so"))
    out = []
    for f in files:
        rec = scan_file(f)
        out.append(rec)
        print(f"== {rec['path']} size={rec['size']}")
        if "error" in rec:
            print("   ", rec["error"])
            continue
        print("   needed:", rec["needed"])
        for d in rec["defined_hits"]:
            print(f"   DEF {d['name']} @ {hex(d['value'])} size={d['size']} shndx={d['shndx']}")
        for d in rec["undefined_hits"]:
            print(f"   UND {d['name']}")
        for k, v in rec["string_hits"].items():
            print(f"   STR {k}: {v}")
    (OUTDIR / "libs_scan.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", OUTDIR / "libs_scan.json")


if __name__ == "__main__":
    main()
