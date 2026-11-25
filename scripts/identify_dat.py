"""Identify a Sony UFU .DAT container: chunks, crypter, model, version."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fw_repos", "fwtool"))
from fwtool.io import FilePart
from fwtool.sony import dat, fdat

path = sys.argv[1]
size = os.path.getsize(path)
print(f"file {path} {size:,} B")

with open(path, "rb") as f:
    blob = dat.readDat(FilePart(f, 0, size))
    print("normal USB descriptors:", [(hex(v), hex(p)) for v, p in blob.normalUsbDescriptors])
    print("updater USB descriptors:", [(hex(v), hex(p)) for v, p in blob.updaterUsbDescriptors])
    print("isLens:", blob.isLens)

    print("decrypting FDAT (this can take a minute)...", flush=True)
    crypter, dec = fdat.decryptFdat(blob.firmwareData)
    print("crypter:", crypter)

    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fw_repos", "_tmp_plain.bin")
    written = 0
    with open(tmp, "wb") as o:
        while True:
            chunk = dec.read(1020 * 256)
            if not chunk:
                break
            o.write(chunk)
            written += len(chunk)
    print("plaintext:", written, "B")

with open(tmp, "rb") as pf:
    h = fdat.readFdat(pf)
    print("model=%#x region=%#x version=%s accessory=%s" % (h.model, h.region, h.version, h.isAccessory))
    print("firmware size:", h.firmware.size, "fs size:", h.fs.size)
