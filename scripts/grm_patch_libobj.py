"""grm_patch_libobj.py -- 生成 grm_init 阻塞绕过的“离线诊断用” libObj.so 变体.

只读 03-证据/静态分析/grm/lib/libObj.so, 只写 03-证据/静态分析/grm/patched/ 下新文件;
不触碰 05-原始固件/ 与任何现有镜像。生成后由 QEMU 实验侧自行替换/重打包 /usr。

变体:
  B  : 0x1823D0 <- 00 20 70 47   (DMP_2D_Initialize 直接 return 0)
  B2 : 0x116B7A <- 00 20 00 BF   (仅 grm_init 内跳过 DMP_2D_Initialize)
  BC : B + 0x116B76 <- 00 20 00 BF (同时跳过 sub_115078)
  D  : 0x116AE4 <- 00 20 70 47   (grm_init 入口直接 return 0)
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(WS, "03-证据", "静态分析", "grm", "lib", "libObj.so")
OUT = os.path.join(WS, "03-证据", "静态分析", "grm", "patched")

PATCHES = {
    "B_no_dmp2d": [
        (0x1823D0, bytes.fromhex("00 20 70 47"),
         "DMP_2D_Initialize wrapper -> movs r0,#0; bx lr"),
    ],
    "B2_skip_dmp2d_call": [
        (0x116B7A, bytes.fromhex("00 20 00 bf"),
         "grm_init internal bl DMP_2D_Initialize -> movs r0,#0; nop"),
    ],
    "BC_no_dmp2d_no_115078": [
        (0x1823D0, bytes.fromhex("00 20 70 47"),
         "DMP_2D_Initialize -> 0"),
        (0x116B76, bytes.fromhex("00 20 00 bf"),
         "grm_init internal bl sub_115078 -> movs r0,#0; nop"),
    ],
    "D_skip_grm_init": [
        (0x116AE4, bytes.fromhex("00 20 70 47"),
         "grm_init entry -> movs r0,#0; bx lr"),
    ],
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if not os.path.isfile(SRC):
        print("MISSING:", SRC)
        return 1
    src = open(SRC, "rb").read()
    os.makedirs(OUT, exist_ok=True)
    manifest = {"source": os.path.relpath(SRC, WS), "source_sha256": sha256(src),
                "source_bytes": len(src), "variants": []}
    for name, patches in PATCHES.items():
        data = bytearray(src)
        diffs = []
        for off, new, desc in patches:
            old = bytes(data[off:off + len(new)])
            assert len(old) == len(new), (name, off)
            data[off:off + len(new)] = new
            diffs.append({"offset": "0x%x" % off, "old": old.hex(" "),
                          "new": new.hex(" "), "desc": desc})
        dst = os.path.join(OUT, "libObj.%s.so" % name)
        with open(dst, "wb") as f:
            f.write(data)
        manifest["variants"].append({
            "name": name, "out": os.path.relpath(dst, WS),
            "sha256": sha256(data), "bytes": len(data), "patches": diffs,
        })
        print("%-24s -> %s  sha256=%s" % (name, os.path.relpath(dst, WS),
                                         sha256(data)[:16]))
    with open(os.path.join(OUT, "patch_manifest.json"), "w",
              encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    print("done ->", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
