"""a6600 1.10 updater -> FDAT -> tar/fs  (offline, no camera)"""
import os, shutil, sys, tarfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fw_repos", "fwtool"))
from fwtool.io import FilePart
from fwtool.sony import dat, fdat

EXE = r"<UPDATER_DIR>\Update_ILCE6600V110.exe"
DAT_OFF = 0xAE9D4
DAT_LEN = 316672424
OUT = os.path.join(os.path.dirname(__file__), "a6600_fw")
os.makedirs(OUT, exist_ok=True)

tar_path = os.path.join(OUT, "firmware.tar")
fs_path = os.path.join(OUT, "updater.img")
plain_path = os.path.join(OUT, "fdat_plain.bin")

if not os.path.exists(plain_path):
    with open(EXE, "rb") as f:
        blob = dat.readDat(FilePart(f, DAT_OFF, DAT_LEN))
        print("DAT ok; normal USB descriptors:", len(blob.normalUsbDescriptors),
              "updater:", blob.updaterUsbDescriptors)
        crypter, dec = fdat.decryptFdat(blob.firmwareData)
        print("crypter:", crypter)
        written = 0
        with open(plain_path, "wb") as o:
            while True:
                chunk = dec.read(1020 * 256)
                if not chunk:
                    break
                o.write(chunk)
                written += len(chunk)
        print("plaintext:", written, "B")

with open(plain_path, "rb") as pf:
    h = fdat.readFdat(pf)
    print("model=%#x region=%#x version=%s accessory=%s" % (h.model, h.region, h.version, h.isAccessory))
    with open(tar_path, "wb") as o:
        shutil.copyfileobj(h.firmware, o)
    with open(fs_path, "wb") as o:
        shutil.copyfileobj(h.fs, o)

print("firmware.tar:", os.path.getsize(tar_path), "B")
print("updater.img :", os.path.getsize(fs_path), "B")

with tarfile.open(tar_path) as tf:
    names = tf.getnames()
    print("tar entries:", len(names))
    print("top-level:", sorted({n.split("/")[0] for n in names}))
    print("--- 0700_part_image ---")
    for m in tf.getmembers():
        if m.name.startswith("0700_part_image"):
            print("  %-48s %12d" % (m.name, m.size))
    print("--- 0300_partconf ---")
    for m in tf.getmembers():
        if m.name.startswith("0300_partconf"):
            print("  %-48s %12d" % (m.name, m.size))
