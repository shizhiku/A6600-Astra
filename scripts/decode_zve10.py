"""解包 ZV-E10 2.03 官方 exe：找 DAT、解密 FDAT、解出 tar 与分区镜像。"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fw_repos", "fwtool"))
from fwtool.io import FilePart
from fwtool.sony import dat, fdat

EXE = r"<UPDATER_DIR>\Update_ZVE10V203.exe"
OUT = r"<LEGACY_WORKSPACE>\zve10_fw"
MAGIC = b"\x89UFU\r\n\x1a\n"


def main():
    os.makedirs(OUT, exist_ok=True)
    size = os.path.getsize(EXE)
    print(f"exe {EXE} {size:,} B")

    # 1) 找 DAT 起点：magic + 合法 chunk 链
    hits = []
    with open(EXE, "rb") as f:
        pos = 0
        while True:
            b = f.read(1 << 22)
            if not b:
                break
            i = 0
            while True:
                i = b.find(MAGIC, i)
                if i < 0:
                    break
                hits.append(pos + i)
                i += 1
            pos += len(b)
    print("magic 命中:", [hex(h) for h in hits[:5]], f"(共 {len(hits)})")

    dat_off = None
    with open(EXE, "rb") as f:
        for h in hits:
            try:
                blob = dat.readDat(FilePart(f, h, size - h))
                dat_off = h
                break
            except Exception:
                continue
    if dat_off is None:
        raise SystemExit("没找到可解析的 DAT")
    print(f"DAT @0x{dat_off:X}")

    with open(EXE, "rb") as f:
        blob = dat.readDat(FilePart(f, dat_off, size - dat_off))
        print("normal USB:", [(hex(v), hex(p)) for v, p in blob.normalUsbDescriptors])
        crypter, dec = fdat.decryptFdat(blob.firmwareData)
        print("crypter:", crypter)

        plain_path = os.path.join(OUT, "fdat_plain.bin")
        written = 0
        with open(plain_path, "wb") as o:
            while True:
                chunk = dec.read(1020 * 256)
                if not chunk:
                    break
                o.write(chunk)
                written += len(chunk)
        print(f"明文 {written:,} B")

    with open(plain_path, "rb") as pf:
        h = fdat.readFdat(pf)
        print(f"model={h.model & 0xFFFFFFFF:#010x} version={h.version} region={h.region}")
        tar_path = os.path.join(OUT, "firmware.tar")
        with open(tar_path, "wb") as o:
            import shutil
            shutil.copyfileobj(h.firmware, o)
        print(f"tar {os.path.getsize(tar_path):,} B")


if __name__ == "__main__":
    main()
