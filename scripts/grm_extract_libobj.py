"""grm_extract_libobj.py -- 只读提取五代(ZV-1M2) /usr 镜像里的 libObj.so 与 grm 依赖.

数据源: 05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15
输出:   03-证据/静态分析/grm/  (仅写该目录)
用法:   python 02-脚本/grm_extract_libobj.py
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(WS, "02-脚本"))
from a6600_usr import Ext2  # noqa: E402  (只复用 Ext2 类, 不改动该脚本)

IMG = os.path.join(WS, "05-原始固件", "zv1m2_fw", "extracted",
                   "0700_part_image", "dev", "nflasha15")
OUT = os.path.join(WS, "03-证据", "静态分析", "grm")

# 必须提取的目标
MUST = ["/lib/libObj.so", "/kmod/grm_gles.ko", "/kmod/grm_ma.ko"]

# 名称候选: 与 grm/DDS/osal/GPU 相关的库和模块
CAND_SUBSTR = ("grm", "gpe", "dds", "osal", "uxengine", "ob5", "uipc", "sugilite")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def elf_facts(data: bytes) -> dict:
    """用 pyelftools 读出 libObj 的 ELF 事实 (NEEDED/SONAME/导出初始化符号/PLT)."""
    from io import BytesIO
    from elftools.elf.elffile import ELFFile

    facts = {}
    try:
        elf = ELFFile(BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        return {"error": "not an ELF: %s" % exc}
    facts["class"] = elf.elfclass
    facts["little_endian"] = elf.little_endian
    facts["machine"] = elf.get_machine_arch()
    facts["type"] = str(elf.header["e_type"])
    facts["entry"] = elf.header["e_entry"]
    facts["sections"] = []
    for sec in elf.iter_sections():
        if sec["sh_flags"] & 0x2 or sec.name in (".dynsym", ".dynstr",
                                                ".rel.plt", ".rel.dyn"):
            facts["sections"].append(
                {"name": sec.name, "addr": sec["sh_addr"],
                 "off": sec["sh_offset"], "size": sec["sh_size"]})
    dyn = elf.get_section_by_name(".dynamic")
    facts["needed"] = []
    facts["soname"] = None
    if dyn:
        for tag in dyn.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                facts["needed"].append(tag.needed)
            elif tag.entry.d_tag == "DT_SONAME":
                facts["soname"] = tag.soname
    # 导出符号里的初始化入口
    want = ("infra_input_init", "uxengine_init", "grm_init", "DDSUserInit",
            "GpeInit", "core_sync_user_init", "dmp_allocator_lib_init",
            "dmp_allocator_mmap_init")
    syms = elf.get_section_by_name(".dynsym")
    facts["init_symbols"] = []
    facts["dynsym_count"] = 0
    if syms:
        facts["dynsym_count"] = syms.num_symbols()
        for i in range(syms.num_symbols()):
            s = syms.get_symbol(i)
            nm = s.name
            if not nm:
                continue
            if nm in want or any(k in nm for k in
                                 ("osal_rcv_msg_tmo", "osal_wai_sem_tmo",
                                  "osal_snd_sync", "osal_sig_sem",
                                  "ioctl", "poll", "futex", "pthread_cond_wait",
                                  "GLES", "DMP_2D", "grm_")):
                facts["init_symbols"].append({
                    "name": nm, "value": s["st_value"],
                    "size": s["st_size"], "info": str(s["st_info"]),
                    "shndx": s["st_shndx"]})
    # PLT 槽位: .rel.plt 里 R_ARM_JUMP_SLOT
    plt = []
    relplt = elf.get_section_by_name(".rel.plt")
    if relplt:
        for rel in relplt.iter_relocations():
            sym = syms.get_symbol(rel["r_info_sym"]) if syms else None
            plt.append({"slot": rel["r_offset"], "sym": sym.name if sym else "",
                        "off": rel["r_offset"]})
    facts["plt"] = plt
    return facts


def main() -> int:
    if not os.path.isfile(IMG):
        print("MISSING image:", IMG)
        return 1
    os.makedirs(OUT, exist_ok=True)
    fs = Ext2(IMG)
    print("ext2: bs=%d blocks=%d groups=%d inode_size=%d"
          % (fs.bs, fs.blocks, fs.ngroups, fs.inode_size))

    listing = []
    for path, ino, is_dir in fs.walk():
        if not is_dir:
            mode, size, _ = fs.inode(ino)
            listing.append((path, size, ino))
    listing.sort()
    print("files in image: %d" % len(listing))

    with open(os.path.join(OUT, "image_filelist.txt"), "w",
              encoding="utf-8") as f:
        for path, size, ino in listing:
            f.write("%10d %8d %s\n" % (size, ino, path))

    # /lib 与 /kmod 清单(便于核对依赖)
    by_path = {p: (s, i) for p, s, i in listing}
    for sub in ("/lib", "/kmod", "/usr/lib"):
        names = [p for p in by_path if p.startswith(sub + "/") and
                 "/" not in p[len(sub) + 1:]]
        print("%s: %d entries" % (sub, len(names)))

    targets = list(MUST)
    for path in by_path:
        low = path.lower()
        if any(k in low for k in CAND_SUBSTR) and path not in targets:
            targets.append(path)

    manifest = []
    for path in targets:
        if path not in by_path:
            print("%-40s MISSING in image" % path)
            continue
        size, ino = by_path[path]
        data = fs.read_file(ino)
        dst = os.path.join(OUT, path.lstrip("/").replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data)
        rec = {"path": path, "service_size": size, "bytes": len(data),
               "sha256": sha256(data), "out": os.path.relpath(dst, WS)}
        manifest.append(rec)
        print("%-40s %9d  sha256=%s" % (path, len(data), rec["sha256"][:16]))

    libobj = os.path.join(OUT, "lib", "libObj.so")
    facts = {}
    if os.path.isfile(libobj):
        data = open(libobj, "rb").read()
        facts = elf_facts(data)
        facts["sha256"] = sha256(data)
        facts["bytes"] = len(data)
        with open(os.path.join(OUT, "libobj_gen5_elf_facts.json"), "w",
                  encoding="utf-8") as f:
            json.dump(facts, f, ensure_ascii=False, indent=1)
        print("libObj: %s %d bytes" % (facts.get("machine"), len(data)))
        print("  SONAME:", facts.get("soname"))
        print("  NEEDED:", ", ".join(facts.get("needed", [])))
        for s in facts.get("init_symbols", []):
            if s["name"] in ("infra_input_init", "uxengine_init", "grm_init",
                             "DDSUserInit", "GpeInit",
                             "core_sync_user_init"):
                print("  init_symbol %-22s value=0x%x size=%d shndx=%s"
                      % (s["name"], s["value"], s["size"], s["shndx"]))

        # 按 NEEDED 二次提取同类依赖
        extra = []
        for n in facts.get("needed", []):
            for p in ("/lib/" + n, "/usr/lib/" + n):
                if p in by_path and not os.path.isfile(
                        os.path.join(OUT, p.lstrip("/").replace("/", os.sep))):
                    size, ino = by_path[p]
                    d = fs.read_file(ino)
                    dst = os.path.join(OUT, p.lstrip("/").replace("/", os.sep))
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    open(dst, "wb").write(d)
                    extra.append({"path": p, "bytes": len(d),
                                  "sha256": sha256(d)})
                    break
        if extra:
            manifest.extend(extra)
            print("extracted NEEDED siblings:", [e["path"] for e in extra])

    with open(os.path.join(OUT, "grm_extract_manifest.json"), "w",
              encoding="utf-8") as f:
        json.dump({"image": os.path.relpath(IMG, WS),
                   "image_bytes": os.path.getsize(IMG),
                   "sha256_tool": "hashlib.sha256",
                   "extracted": manifest}, f, ensure_ascii=False, indent=1)
    print("done ->", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
