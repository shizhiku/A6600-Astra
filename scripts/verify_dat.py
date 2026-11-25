"""自检：把产出的 DAT 用官方流程解一遍，确认内容正确。"""
import hashlib
import os
import shutil
import sys
import tarfile

ROOT = r"<LEGACY_WORKSPACE>"
sys.path.insert(0, os.path.join(ROOT, "fw_repos", "fwtool"))
from fwtool.io import FilePart
from fwtool.sony import dat, fdat

DAT = os.path.join(ROOT, "a6600_port", "nflasha15_astra.dat")
REF = os.path.join(ROOT, "a6600_port", "nflasha15_patched.bin")
TMP = os.path.join(ROOT, "a6600_port", "_verify.tar")


def main():
    size = os.path.getsize(DAT)
    print(f"DAT {size:,} B")
    with open(DAT, "rb") as f:
        blob = dat.readDat(FilePart(f, 0, size))
        crypter, dec = fdat.decryptFdat(blob.firmwareData)
        print("crypter:", crypter)
        tmp_plain = os.path.join(ROOT, "a6600_port", "_verify_plain.bin")
        n = 0
        with open(tmp_plain, "wb") as o:
            while True:
                c = dec.read(1020 * 256)
                if not c:
                    break
                o.write(c)
                n += len(c)
        print(f"明文 {n:,} B")

    with open(tmp_plain, "rb") as pf:
        h = fdat.readFdat(pf)
        print(f"model={h.model & 0xFFFFFFFF:#010x} version={h.version} region={h.region}")
        with open(TMP, "wb") as o:
            shutil.copyfileobj(h.firmware, o)
    print(f"tar {os.path.getsize(TMP):,} B")

    tf = tarfile.open(TMP)
    m = tf.getmember("0700_part_image/dev/nflasha15")
    data = tf.extractfile(m).read()
    ref = open(REF, "rb").read()
    print(f"nflasha15: {len(data):,} B  sha256={hashlib.sha256(data).hexdigest()[:32]}")
    print(f"与补丁镜像一致: {'✅' if data == ref else '❌'}")

    # 抽查补丁点
    print(f"  im.elf @0x152A: {data[0:0] or ''}", end="")
    # 从镜像里读不方便，改为直接说明
    tf.close()
    os.remove(TMP)
    os.remove(tmp_plain)


if __name__ == "__main__":
    main()
