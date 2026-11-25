"""Decrypt a CXD90057-style UFU/FDAT container (A6700 / ZV-1M2 family).

Container:  8-byte magic + records (u32be len, 4-byte tag) ... FDAT
FDAT:       frames of 1024 B + 272 B trailer (IV 16 + RSA-256)
Frame 0:    AES-ECB(K1) on [0,512) + AES-CBC(Kn) on [512,1024)
Frame k>0:  AES-CBC(Kn) over the whole frame (same chain)
"""
import mmap
import struct
import sys
import zlib

from Cryptodome.Cipher import AES

K1 = bytes.fromhex("REDACTED_KEY_AES_ECB")
KEYS = {
    "cxd90057_k8": bytes.fromhex("REDACTED_KEY_CXD90057_K8"),
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


def main():
    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "probe"
    f = open(path, "rb")
    n = f.seek(0, 2)
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    recs = records(mm, n)
    print("records:", [(t, hex(o), s) for t, o, s in recs])
    tag, off, ln = recs[-1]
    nframes = (ln - 272) // 1024
    iv = bytes(mm[n - 12 - 272: n - 12 - 272 + 16])
    print(f"FDAT @0x{off:X} len={ln:,} frames={nframes:,} IV={iv.hex()}")

    # --- key probe on the first 32 frames ---
    probe = min(32, nframes)
    for name, key in KEYS.items():
        ecb = AES.new(K1, AES.MODE_ECB)
        cbc = AES.new(key, AES.MODE_CBC, iv)
        bad = 0
        for k in range(probe):
            o = off + k * 1024
            blk = mm[o:o + 1024]
            p = (ecb.decrypt(blk[:512]) + cbc.decrypt(blk[512:])) if k == 0 else cbc.decrypt(blk)
            if not frame_ok(p):
                bad += 1
        print(f"  key {name}: bad {bad}/{probe}")
        if bad == 0:
            break

    if mode == "probe":
        return

    # --- full decrypt ---
    chosen = None
    for name, key in KEYS.items():
        ecb = AES.new(K1, AES.MODE_ECB)
        cbc = AES.new(key, AES.MODE_CBC, iv)
        blk = mm[off:off + 1024]
        p = ecb.decrypt(blk[:512]) + cbc.decrypt(blk[512:])
        if frame_ok(p):
            chosen = (name, key)
            break
    if not chosen:
        print("no key works")
        return
    name, key = chosen
    print("using key:", name)

    ecb = AES.new(K1, AES.MODE_ECB)
    cbc = AES.new(key, AES.MODE_CBC, iv)
    out = bytearray()
    hdr = None
    for k in range(nframes):
        o = off + k * 1024
        blk = mm[o:o + 1024]
        p = (ecb.decrypt(blk[:512]) + cbc.decrypt(blk[512:])) if k == 0 else cbc.decrypt(blk)
        size = struct.unpack("<H", p[2:4])[0] & 0x7FFF
        if k == 0:
            hdr = bytes(p[4:4 + 512])
        out += p[4:4 + size]
        if k % 50000 == 0:
            print(f"  {k}/{nframes}", flush=True)
    print("plaintext:", len(out))
    open(path + ".plain", "wb").write(out)
    print("written", path + ".plain")

    hmagic = hdr[0:8]
    hcrc_s = struct.unpack("<I", hdr[8:12])[0]
    hcrc_c = zlib.crc32(hdr[12:512]) & 0xFFFFFFFF
    vmin, vmaj = hdr[32], hdr[33]
    model, region = struct.unpack("<ii", hdr[36:44])
    fwOff, fwSize, numFs = struct.unpack("<iii", hdr[48:60])
    print(f"header magic={hmagic} version={vmaj:x}.{vmin:02x} model=0x{model & 0xFFFFFFFF:X} region={region}")
    print(f"fwOff={fwOff} fwSize={fwSize} numFs={numFs} crc_ok={hcrc_s == hcrc_c}")


if __name__ == "__main__":
    main()
