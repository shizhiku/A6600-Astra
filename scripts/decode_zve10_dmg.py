"""解包 dmg 里的 FirmwareData_ZVE10V203.dat，取出 im.elf。"""
import os
import shutil
import sys
import tarfile

ROOT = r"<LEGACY_WORKSPACE>"
sys.path.insert(0, os.path.join(ROOT, "fw_repos", "fwtool"))
from fwtool.io import FilePart
from fwtool.sony import dat, fdat

DAT = os.path.join(ROOT, "zve10_fw", "dmg", "FirmwareData_ZVE10V203.dat")
OUT = os.path.join(ROOT, "zve10_fw")


def main():
    size = os.path.getsize(DAT)
    print(f"DAT {size:,} B")
    with open(DAT, "rb") as f:
        blob = dat.readDat(FilePart(f, 0, size))
        print("USB:", [(hex(v), hex(p)) for v, p in blob.normalUsbDescriptors])
        crypter, dec = fdat.decryptFdat(blob.firmwareData)
        print("crypter:", crypter)
        plain = os.path.join(OUT, "fdat_plain.bin")
        n = 0
        with open(plain, "wb") as o:
            while True:
                c = dec.read(1020 * 256)
                if not c:
                    break
                o.write(c)
                n += len(c)
        print(f"明文 {n:,} B")

    with open(plain, "rb") as pf:
        h = fdat.readFdat(pf)
        print(f"model={h.model & 0xFFFFFFFF:#010x} version={h.version} region={h.region}")
        tar_path = os.path.join(OUT, "firmware.tar")
        with open(tar_path, "wb") as o:
            shutil.copyfileobj(h.firmware, o)
        print(f"tar {os.path.getsize(tar_path):,} B")

    tf = tarfile.open(tar_path)
    for m in tf.getmembers():
        if m.name.startswith("0700_part_image"):
            print(f"  {m.name:<46} {m.size:>14,}")
    dev = os.path.join(OUT, "extracted", "0700_part_image", "dev")
    os.makedirs(dev, exist_ok=True)
    for name in ("nflasha15", "nflasha7"):
        m = tf.getmember(f"0700_part_image/dev/{name}")
        dst = os.path.join(dev, name)
        if os.path.exists(dst) and os.path.getsize(dst) == m.size:
            continue
        with tf.extractfile(m) as src, open(dst, "wb") as o:
            while True:
                b = src.read(1 << 20)
                if not b:
                    break
                o.write(b)
        print(f"extracted {name} {m.size:,} B")


if __name__ == "__main__":
    main()
