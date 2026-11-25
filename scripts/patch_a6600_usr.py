"""把 S2 定案的 5 处补丁应用到 a6600 的文件副本上，并逐条校验。"""
import hashlib
import shutil
import sys
from pathlib import Path

ROOT = Path(r"<LEGACY_WORKSPACE>")
SRC = ROOT / "a6600_fw" / "usr"
OUT = ROOT / "a6600_port" / "patched"
SHIM = ROOT / "a6600_port" / "appFwBoot.so"

PATCHES = [
    # (file, offset, old, new, note)
    ("lib/libIMDB.so", 0x4CC9, b"testcmd_scn.so\x00", b"appFwBoot.so\x00", "借用字符串槽"),
    ("lib/libIMDB.so", 0x70F8 + 12, b"\x83\x00\xfb\x07", b"\x83\x00\x00\x00", "me_psid -> 0x83"),
    ("lib/libIMDB.so", 0x70F8 + 16, b"\x6f\x49\x00\x00", b"\xc9\x4c\x00\x00", "file -> appFwBoot.so"),
    ("bin/im.elf", 0x152A, b"\x02\x46", b"\x01\x22", "mov r2,r0 -> movs r2,#1"),
    ("lib/libMWF.so", 0x2DD70, b"\xa0\xb1", b"\x00\xbf", "cbz r0 -> nop"),
]


def main():
    if not SHIM.exists():
        raise SystemExit(f"缺少垫片 {SHIM}，先跑 build_shim.py")
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    # 只复制需要改的文件
    files = {p[0] for p in PATCHES} | {"lib/appFwBoot.so"}
    for rel in sorted(files):
        src = SRC / rel
        if rel == "lib/appFwBoot.so":
            src = SHIM
        dst = OUT / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    # 应用补丁
    for rel, off, old, new, note in PATCHES:
        p = OUT / rel
        data = bytearray(p.read_bytes())
        cur = bytes(data[off:off + len(old)])
        if cur != old:
            raise SystemExit(f"{rel} @{off:#x}: 期望 {old.hex(' ')}，实际 {cur.hex(' ')}")
        data[off:off + len(new)] = new
        p.write_bytes(bytes(data))
        print(f"[+] {rel:16s} @{off:#06x}  {old.hex(' '):<24} -> {new.hex(' '):<24} {note}")

    print()
    for rel in sorted(files):
        p = OUT / rel
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        print(f"    {rel:20s} {p.stat().st_size:10,d} B  sha256={h}")


if __name__ == "__main__":
    main()
