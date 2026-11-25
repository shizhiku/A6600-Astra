"""appfwboot_providers.py — 解析 appFwBoot.so 的未定义导入符号分别由哪个五代库提供，
并核对原厂 IMDB 表里的初始化入口在哪个库中定义（libObj / libMWF / osal）。

只读分析，不执行目标代码。
输出: 03-证据/静态分析/boot5/providers.txt
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io
import json

ROOT = Path(__file__).resolve().parent.parent
OUTDIR = ROOT / "03-证据" / "静态分析" / "boot5"
IMAGE_LIB = OUTDIR / "image" / "lib"

BOOT = ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "appFwBoot.so"

CANDIDATES = [
    ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "libObj.so",
    ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "libMWF.so",
    ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "libmpr.so",
    ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "appFw.so",
    ROOT / "05-原始固件" / "zv1m2_fw" / "gen5" / "AdjChkConfig.so",
    IMAGE_LIB / "libMWF.so",
    IMAGE_LIB / "libosal_uipc.so",
    IMAGE_LIB / "libosal_ulogio.so",
    IMAGE_LIB / "libosal_utm.so",
    IMAGE_LIB / "libSysDef.so",
    IMAGE_LIB / "libtestcmd.so",
]

INIT_ENTRIES = [
    "MWF_Init", "infra_input_init", "core_sync_user_init", "grm_init", "GpeInit",
    "DDSUserInit", "uxengine_init", "uxengine_init2", "uxengine_app_fw_init",
    "dmp_allocator_lib_init", "dmp_allocator_mmap_init",
    "_ZN2ux6wgtlay14WidgetLayouter14sys_initializeEv",
    "Application_System_Init", "Application_Start",
    "osal_create_waitable_thread", "osal_valloc_msg_wait", "osal_snd_sync_msg",
    "osal_free_msg", "osal_set_cpu", "stella_print_log",
]


def elf_facts(path):
    raw = path.read_bytes()
    e = ELFFile(io.BytesIO(raw))
    ds = e.get_section_by_name(".dynsym")
    defined, needed, soname = {}, [], None
    dyn = e.get_section_by_name(".dynamic")
    if dyn:
        for t in dyn.iter_tags():
            if t.entry.d_tag == "DT_NEEDED":
                needed.append(t.needed)
            elif t.entry.d_tag == "DT_SONAME":
                soname = t.soname
    if ds:
        for i in range(ds.num_symbols()):
            s = ds.get_symbol(i)
            if not s.name:
                continue
            if s["st_shndx"] != "SHN_UNDEF":
                defined[s.name] = (s["st_value"], s["st_size"])
    return {
        "path": str(path),
        "size": len(raw),
        "soname": soname,
        "needed": needed,
        "defined": defined,
    }


def boot_imports(path):
    raw = path.read_bytes()
    e = ELFFile(io.BytesIO(raw))
    ds = e.get_section_by_name(".dynsym")
    out = []
    for i in range(ds.num_symbols()):
        s = ds.get_symbol(i)
        if not s.name:
            continue
        if s["st_shndx"] == "SHN_UNDEF":
            out.append({"name": s.name, "bind": s["st_info"]["bind"],
                        "type": s["st_info"]["type"]})
    return out


def main():
    libs = []
    for p in CANDIDATES:
        if p.exists():
            libs.append(elf_facts(p))
        else:
            print("skip missing", p)
    imports = boot_imports(BOOT)
    lines = []
    lines.append("# appFwBoot.so 导入符号的提供者（五代闭包）")
    lines.append("")
    lines.append("## 候选库")
    for L in libs:
        lines.append("  %-60s SONAME=%-12s NEEDED=%s" % (
            Path(L["path"]).name, L["soname"], ",".join(L["needed"])))
    lines.append("")
    lines.append("## appFwBoot.so 未定义导入 (%d)" % len(imports))
    unresolved = []
    for imp in imports:
        providers = [Path(L["path"]).name for L in libs if imp["name"] in L["defined"]]
        if not providers:
            unresolved.append(imp["name"])
        lines.append("  %-64s %-6s %-8s <- %s" % (
            imp["name"], imp["bind"], imp["type"], ", ".join(providers) or "UNRESOLVED"))
    lines.append("")
    lines.append("## 原厂 IMDB 初始化入口的提供者")
    for name in INIT_ENTRIES:
        providers = []
        for L in libs:
            if name in L["defined"]:
                v, sz = L["defined"][name]
                providers.append("%s @%#x size=%d" % (Path(L["path"]).name, v, sz))
        lines.append("  %-64s <- %s" % (name, "; ".join(providers) or "NOT FOUND in closure"))
    lines.append("")
    lines.append("## appFwBoot 未解析导入: %s" % (", ".join(unresolved) or "none"))
    text = "\n".join(lines) + "\n"
    (OUTDIR / "providers.txt").write_text(text, encoding="utf-8")
    (OUTDIR / "providers.json").write_text(json.dumps(
        {"boot": str(BOOT), "imports": imports,
         "libs": [{k: v for k, v in L.items() if k != "defined"} for L in libs]},
        indent=1, ensure_ascii=False), encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
