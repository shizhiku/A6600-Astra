"""编译 a6600 最小垫片：zig → ARM EABI5，e_flags 对齐 0x05000002，并校验 ABI。"""
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

ROOT = Path(r"<LEGACY_WORKSPACE>")
SRC = ROOT / "a6600_port" / "shim_minimal.c"
OUT = ROOT / "a6600_port" / "appFwBoot.so"
TARGET_EFLAGS = 0x05000002
MAX_GLIBC = (2, 11)


def main():
    cmd = [
        sys.executable, "-m", "ziglang", "cc",
        "-target", "arm-linux-gnueabi.2.4",
        "-mcpu=cortex_a9", "-mthumb", "-shared", "-fPIC", "-O2", "-s",
        "-Wall", "-Wextra",
        "-fvisibility=default",
        "-Wl,-z,lazy", "-Wl,-z,norelro", "-Wl,-z,max-page-size=0x1000",
        "-Wl,-soname,appFwBoot.so",
        "-o", str(OUT), str(SRC),
    ]
    print("[*]", " ".join(cmd))
    subprocess.run(cmd, check=True)

    raw = bytearray(OUT.read_bytes())
    old = struct.unpack_from("<I", raw, 36)[0]
    struct.pack_into("<I", raw, 36, TARGET_EFLAGS)
    OUT.write_bytes(raw)
    print(f"[+] e_flags 0x{old:08x} -> 0x{TARGET_EFLAGS:08x}")

    with open(OUT, "rb") as f:
        e = ELFFile(f)
        dyn = e.get_section_by_name(".dynsym")
        exports = sorted(s.name for s in dyn.iter_symbols()
                         if s.name and s["st_shndx"] != "SHN_UNDEF"
                         and s["st_info"]["bind"] == "STB_GLOBAL")
        undef = sorted(s.name for s in dyn.iter_symbols()
                       if s.name and s["st_shndx"] == "SHN_UNDEF")
        vers = set()
        vr = e.get_section_by_name(".gnu.version_r")
        if vr:
            for _, auxs in vr.iter_versions():
                for x in auxs:
                    vers.add(x.name)
    print(f"[+] 导出: {exports}")
    print(f"[+] 外部依赖: {undef}")
    print(f"[+] 版本需求: {sorted(vers)}")

    bad = [v for v in vers if v.startswith("GLIBC_") and tuple(map(int, v[6:].split(".")[:2])) > MAX_GLIBC]
    assert "Application_System_Init" in exports, "没有导出 Application_System_Init"
    assert not bad, f"需要高于 glibc {MAX_GLIBC}: {bad}"
    print(f"[+] 大小 {OUT.stat().st_size:,} B  sha256={hashlib.sha256(OUT.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
