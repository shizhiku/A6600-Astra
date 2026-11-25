"""testcmd_extract.py — ZV-1M2 五代根镜像 (nflasha15 ext2) 只读提取
testcmd / scenario / adjust(AdjChk) 相关文件，并扫描 /lib /bin /scenario 内
"testcmd"/"scenario"/"adjchk" 字节串命中。

只读：不修改镜像；输出到 03-证据/静态分析/testcmd/image/。
用法:
    python 02-脚本/testcmd_extract.py --list   # 只列出镜像内相关路径/大小
    python 02-脚本/testcmd_extract.py          # 完整提取 + 字符串扫描
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(WS, "02-脚本"))
from a6600_usr import Ext2  # noqa: E402

IMG = os.path.join(WS, "05-原始固件", "zv1m2_fw", "extracted",
                   "0700_part_image", "dev", "nflasha15")
OUT = os.path.join(WS, "03-证据", "静态分析", "testcmd")
IMGDIR = os.path.join(OUT, "image")

# 明确提取清单（存在才提；image_size 是镜像内真实大小）
EXPLICIT = [
    "/bin/im.elf",
    "/bin/bootin.elf",
    "/bin/scenario.elf",
    "/bin/testcmd.elf",
    "/bin/Wltestcmd",
    "/lib/libIMDB.so",
    "/lib/libtestcmd.so",
    "/lib/libtestcmd_scn.so",
    "/lib/AdjChkConfig.so",
    "/lib/libBTAdjust.so",
    "/lib/libWlanAdjust.so",
    "/lib/libInfraMakeScenario.so",
    "/lib/appFw.so",
    "/lib/appFwBoot.so",
    "/lib/libObj.so",
    "/lib/libmpr.so",
    "/lib/libMWF.so",
]
# 整棵提取的目录
DIR_PREFIX = ("/scenario",)
# 目录内“名字命中”才提取
NAME_DIRS = ("/bin", "/sbin", "/lib", "/kmod", "/wifi-scripts")
NAME_KEYS = ("testcmd", "scenario", "adjchk", "demomovie", "factory")
# 字节串扫描根 + 模式
SCAN_ROOTS = ("/lib", "/bin", "/sbin", "/kmod", "/scenario",
              "/wifi-scripts", "/codec", "/local", "/wlan", "/tool")
PATTERNS = [b"testcmd", b"TestCmd", b"Testcmd", b"TESTCMD",
            b"scenario", b"Scenario", b"SCENARIO",
            b"adjchk", b"AdjChk", b"ADJCHK",
            b"demomovie", b"DemoMovie", b"DEMOMOVIE"]
# 扫描命中文件也提取（只要不太大）
MAX_SCAN_BYTES = 48 * 1024 * 1024
# 超过该大小只记录 sha256/大小，不写盘（大库在 05-原始固件/.../gen5/ 有同源副本）
NO_DUMP_BYTES = 8 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if not os.path.isfile(IMG):
        print("MISSING image:", IMG)
        return 1
    fs = Ext2(IMG)
    print("ext2: bs=%d blocks=%d groups=%d inode_size=%d"
          % (fs.bs, fs.blocks, fs.ngroups, fs.inode_size))

    # ---- 0) 全镜像索引 ----
    files = {}
    for path, ino, is_dir in fs.walk():
        if is_dir:
            continue
        mode, size, blocks = fs.inode(ino)
        files[path] = (size, ino, blocks)
    print("files in image:", len(files))

    # ---- 1) 选定目标 ----
    sel = {}
    for p in sorted(files):
        if p in EXPLICIT:
            sel[p] = "explicit"
        elif any(p == d or p.startswith(d + "/") for d in DIR_PREFIX):
            sel[p] = "scenario-dir"
        else:
            base = os.path.basename(p).lower()
            if any(p.startswith(d + "/") for d in NAME_DIRS) and \
                    any(k in base for k in NAME_KEYS):
                sel[p] = "name-key"
    # 顶层目录清单（证据，便于判断缺失）
    top_dirs = sorted({p.split("/")[1] for p in files if p.count("/") >= 1})
    # /bin /sbin 全量清单（小，作为上下文证据）
    bin_listing = [{"path": p, "size": files[p][0]}
                   for p in sorted(files) if p.startswith(("/bin/", "/sbin/"))]
    # /kmod 名字清单
    kmod_listing = [{"path": p, "size": files[p][0]}
                    for p in sorted(files) if p.startswith("/kmod/")]

    # ---- 2) 字节串扫描（/lib 等目录）----
    scan = []
    n_read = 0
    for p in sorted(files):
        if not any(p.startswith(r + "/") for r in SCAN_ROOTS):
            continue
        size, ino, _ = files[p]
        if size == 0 or size > MAX_SCAN_BYTES:
            continue
        data = fs.read_file(ino)
        n_read += 1
        hits = {}
        for pat in PATTERNS:
            c = data.count(pat)
            if c:
                hits[pat.decode("latin1")] = c
        if hits:
            scan.append({"path": p, "size": size,
                         "sha256": sha256(data), "hits": hits})
    print("scanned files: %d, hit files: %d" % (n_read, len(scan)))

    # 扫描命中且足够小的库/可执行文件也纳入提取
    hitset = {s["path"]: s for s in scan}
    for p in sorted(hitset):
        if p not in sel and files[p][0] <= 4 * 1024 * 1024 and \
                os.path.splitext(p)[1] in (".so", ".elf", ".bin", ""):
            sel[p] = "string-hit"

    rows = [{"path": p, "size": files[p][0], "reason": sel[p]}
            for p in sorted(sel)]
    print("selected files: %d" % len(rows))
    if "--list" in sys.argv:
        for r in rows:
            print("%10d %-16s %s" % (r["size"], r["reason"], r["path"]))
        return 0

    # ---- 3) 提取 ----
    os.makedirs(IMGDIR, exist_ok=True)
    manifest = []
    for r in rows:
        p = r["path"]
        size, ino, _ = files[p]
        data = fs.read_file(ino)
        rec = {"path": p, "image_size": size, "bytes": len(data),
               "sha256": sha256(data), "reason": r["reason"], "out": None}
        if len(data) <= NO_DUMP_BYTES:
            dst = os.path.join(IMGDIR, p.lstrip("/").replace("/", os.sep))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(data)
            rec["out"] = os.path.relpath(dst, WS)
        manifest.append(rec)
    print("extracted:", sum(1 for m in manifest if m["out"]),
          "record-only:", sum(1 for m in manifest if not m["out"]))

    # ---- 4) 落盘 ----
    out = {
        "image": os.path.relpath(IMG, WS),
        "image_size": os.path.getsize(IMG),
        "image_top_dirs": {d: sum(1 for p in files if p.startswith("/" + d + "/"))
                           for d in top_dirs},
        "scanned_files": n_read,
        "patterns": [p.decode("latin1") for p in PATTERNS],
        "selected": manifest,
        "string_hits": scan,
        "bin_sbin_listing": bin_listing,
        "kmod_listing": kmod_listing,
    }
    mpath = os.path.join(OUT, "extract_manifest.json")
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("done ->", mpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
