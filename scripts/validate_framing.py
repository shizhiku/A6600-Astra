"""Validate the FDAT framing logic against the known-good a6600 1.10 container."""
import mmap
import struct
import sys

from Cryptodome.Cipher import AES

K1 = bytes.fromhex("REDACTED_KEY_AES_ECB")
KEYS = {
    "cxd90057_k8": bytes.fromhex("REDACTED_KEY_CXD90057_K8"),
    "cxd90057_k0": bytes.fromhex("REDACTED_KEY_CXD90057_K0"),
    "cxd90045": bytes.fromhex("REDACTED_KEY_CXD90045"),
    "cxd90014": bytes.fromhex("REDACTED_KEY_CXD90014"),
}


def records(mm, n, base=0):
    off, recs = base + 8, []
    while off + 8 <= n:
        ln = struct.unpack(">I", mm[off:off + 4])[0]
        tag = bytes(mm[off + 4:off + 8])
        if not all(32 <= c < 127 for c in tag):
            break
        recs.append((tag.decode(), off + 8, ln))
        if tag == b"FDAT":
            break
        off += 8 + ln
    return recs


def frame_ok(p):
    ck, se = struct.unpack("<HH", p[0:4])
    return ck == (sum(struct.unpack_from("<511H", p, 2)) & 0xFFFF)


def probe(path, base, iv_mode):
    f = open(path, "rb")
    n = f.seek(0, 2)
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    recs = records(mm, n, base)
    tag, off, ln = recs[-1]
    payload_end = off + ln
    if iv_mode == "payload":
        iv = bytes(mm[payload_end - 272:payload_end - 256])
    else:
        iv = bytes(mm[n - 272:n - 256])
    print(f"{path} base=0x{base:X} FDAT@0x{off:X} len={ln:,} iv={iv.hex()} ({iv_mode})")
    for name, key in KEYS.items():
        ecb = AES.new(K1, AES.MODE_ECB)
        cbc = AES.new(key, AES.MODE_CBC, iv)
        bad = 0
        for k in range(32):
            o = off + k * 1024
            blk = mm[o:o + 1024]
            p = (ecb.decrypt(blk[:512]) + cbc.decrypt(blk[512:])) if k == 0 else cbc.decrypt(blk)
            if not frame_ok(p):
                bad += 1
        print(f"   {name:14s} bad {bad}/32")
    mm.close()
    f.close()


if __name__ == "__main__":
    probe(r"<UPDATER_DIR>\Update_ILCE6600V110.exe", 0xAE9D4, "payload")
    probe(r"<UPDATER_DIR>\BODYDATA.DAT", 0, "payload")
