"""Extract a6600 partition images + config from firmware.tar and show the partition table."""
import os, sys, tarfile

BASE = os.path.dirname(os.path.abspath(__file__))
TAR = os.path.join(BASE, "a6600_fw", "firmware.tar")
OUT = os.path.join(BASE, "a6600_fw", "extracted")
os.makedirs(OUT, exist_ok=True)

WANT = (
    "0700_part_image/dev/",
    "0300_partconf/",
    "0100_config/",
)
SKIP_SUMS = True

with tarfile.open(TAR) as tf:
    for m in tf.getmembers():
        if m.isdir() or not m.name.startswith(WANT):
            continue
        if SKIP_SUMS and "_sum" in m.name:
            continue
        dst = os.path.join(OUT, m.name.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.exists(dst) and os.path.getsize(dst) == m.size:
            continue
        with tf.extractfile(m) as src, open(dst, "wb") as o:
            while True:
                b = src.read(1 << 20)
                if not b:
                    break
                o.write(b)
        print("extracted %-46s %12d" % (m.name, m.size))

p = os.path.join(OUT, "0300_partconf", "partinf.conf")
print("\n=== partinf.conf ===")
print(open(p, "r", encoding="utf-8", errors="replace").read())
