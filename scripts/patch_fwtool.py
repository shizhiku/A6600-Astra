"""给本地 fwtool 加上 CXD90045_k8 密钥/解密器。"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONST = ROOT / "fw_repos" / "fwtool" / "fwtool" / "sony" / "constants.py"
FDAT = ROOT / "fw_repos" / "fwtool" / "fwtool" / "sony" / "fdat.py"

K8_HEX = "REDACTED_KEY_K8_ZV1M2"

# 1) constants
s = CONST.read_text(encoding="utf-8")
if "key_cxd90045_k8" not in s:
    s += f'\nkey_cxd90045_k8 = bytes.fromhex("{K8_HEX}")\n'
    CONST.write_text(s, encoding="utf-8")
    print("constants.py: added key_cxd90045_k8")
else:
    print("constants.py: already present")

# 2) crypter table
t = FDAT.read_text(encoding="utf-8")
anchor = " ('CXD90045',     lambda: AesCbcCrypter(constants.key_aes, constants.key_cxd90045)),"
if "CXD90045_k8" not in t:
    assert anchor in t, "anchor not found"
    new_line = " ('CXD90045_k8',  lambda: AesCbcCrypter(constants.key_aes, constants.key_cxd90045_k8)),"
    t = t.replace(anchor, anchor + "\n" + new_line)
    FDAT.write_text(t, encoding="utf-8")
    print("fdat.py: added CXD90045_k8 crypter")
else:
    print("fdat.py: already present")

# 3) 自检：两个包都要能识别
import sys
sys.path.insert(0, str(ROOT / "fw_repos" / "fwtool"))
from fwtool.io import FilePart
from fwtool.sony import dat, fdat

for label, path, off, ln in [
    ("a6600 ", r"<UPDATER_DIR>\Update_ILCE6600V110.exe", 0xAE9D4, 316672424),
    ("ZV-1M2", r"<UPDATER_DIR>\BODYDATA.DAT", 0, None),
]:
    import os
    size = ln or os.path.getsize(path)
    with open(path, "rb") as f:
        blob = dat.readDat(FilePart(f, off, size))
        name, dec = fdat.decryptFdat(blob.firmwareData)
        # 只读头部：读 8 个块即够
        head = dec.read(1020 * 8)
        h = fdat.FdatHeader.unpack(head) if False else None
        import struct
        vmin, vmaj = head[32], head[33]
        model, region = struct.unpack("<ii", head[36:44])
        print(f"  {label}: crypter={name}  version={vmaj:x}.{vmin:02x}  model=0x{model & 0xFFFFFFFF:08X}")
