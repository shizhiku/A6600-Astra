"""appfwboot_extract.py — 从 ZV-1M2 五代根镜像 (nflasha15 ext2) 只读提取
appFwBoot 原厂启动链需要核对的少数文件: im.elf / bootin.elf / mwf_monio.elf 等。

只读：不修改镜像；输出到 03-证据/静态分析/boot5/image/。
用法: python 02-脚本/appfwboot_extract.py [--list]
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
IMG4 = os.path.join(WS, "05-原始固件", "a6600_fw", "extracted",
                    "0700_part_image", "dev", "nflasha15")
OUT = os.path.join(WS, "03-证据", "静态分析", "boot5", "image")

TARGETS = [
    "/bin/im.elf",
    "/bin/bootin.elf",
    "/bin/mwf_monio.elf",
    "/lib/libSysDef.so",
    "/lib/libtestcmd.so",
    "/lib/libosal_uipc.so",
    "/lib/libosal_ulogio.so",
    "/lib/libosal_utm.so",
    "/lib/libMWF.so",
]

# 四代(a6600)根镜像里关注的初始化包装库
TARGETS4 = [
    "/lib/libgrm.so",
    "/lib/libDDS.so",
    "/lib/libgpe.so",
    "/lib/libuxengine.so",
    "/lib/libCoreSync.so",
    "/lib/libInfraInput.so",
    "/lib/libMWF.so",
    "/lib/libObj.so",
    "/lib/libmpr.so",
    "/bin/im.elf",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    gen4 = "--gen4" in sys.argv
    img = IMG4 if gen4 else IMG
    targets = TARGETS4 if gen4 else TARGETS
    out = os.path.join(OUT, "gen4") if gen4 else OUT
    if not os.path.isfile(img):
        print("MISSING image:", img)
        return 1
    fs = Ext2(img)
    by_path = {}
    for path, ino, is_dir in fs.walk():
        if not is_dir:
            mode, size, _ = fs.inode(ino)
            by_path[path] = (size, ino)
    print("files in image:", len(by_path))
    if "--list" in sys.argv:
        for p in sorted(by_path):
            if any(k in p.lower() for k in ("im.elf", "bootin", "mwf_monio",
                                            "area_check", "global.xdb",
                                            "libgrm", "libdds", "libgpe",
                                            "libuxengine", "libcoresync",
                                            "libinfrainput")):
                print("%10d %8d %s" % (by_path[p][0], by_path[p][1], p))
        return 0

    os.makedirs(out, exist_ok=True)
    manifest = []
    for path in targets:
        if path not in by_path:
            print("%-30s MISSING" % path)
            continue
        size, ino = by_path[path]
        data = fs.read_file(ino)
        dst = os.path.join(out, path.lstrip("/").replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data)
        rec = {"path": path, "image_size": size, "bytes": len(data),
               "sha256": sha256(data), "out": os.path.relpath(dst, WS)}
        manifest.append(rec)
        print("%-30s %9d  sha256=%s" % (path, len(data), rec["sha256"][:16]))

    # 附带检查: appFwBoot Main 需要的 /usr/share/app 资源(只记录是否存在/大小)
    checks = []
    if not gen4:
        for p in ("/share/app", "/share/app/area_check_data.dat",
                  "/share/app/global.xdb", "/usr/share/app",
                  "/usr/share/app/area_check_data.dat", "/usr/share/app/global.xdb"):
            checks.append({"path": p, "exists": p in by_path,
                           "size": by_path[p][0] if p in by_path else None})
        for c in checks:
            print("check %-40s exists=%s size=%s" % (c["path"], c["exists"], c["size"]))

    mname = "extract_manifest_gen4.json" if gen4 else "extract_manifest.json"
    with open(os.path.join(out, mname), "w", encoding="utf-8") as f:
        json.dump({"image": os.path.relpath(img, WS),
                   "extracted": manifest, "path_checks": checks},
                  f, ensure_ascii=False, indent=1)
    print("done ->", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
