"""ZV-1M2 2.01 全量解密 + 提取（key_cxd90045_k8 已验证）。"""
import mmap
import os
import struct
import sys
import time

from Cryptodome.Cipher import AES

KEY_AES = bytes.fromhex("REDACTED_KEY_AES_ECB")
KEY_K8 = bytes.fromhex("REDACTED_KEY_K8_ZV1M2")
PATH = r"<UPDATER_DIR>\BODYDATA.DAT"
OUT = r"<LEGACY_WORKSPACE>\zv1m2_fw"
FDAT = 0x6C


def main():
    os.makedirs(OUT, exist_ok=True)
    f = open(PATH, "rb")
    n = f.seek(0, 2)
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    iv = bytes(mm[n - 284:n - 268])
    nframes = (n - 12 - FDAT - 272) // 1024
    print(f"file={n:,} FDAT@{FDAT:#x} frames={nframes:,} IV={iv.hex()}", flush=True)

    ecb = AES.new(KEY_AES, AES.MODE_ECB)
    cbc = AES.new(KEY_K8, AES.MODE_CBC, iv)
    plain = bytearray()
    hdr = None
    t0 = time.time()
    for k in range(nframes):
        o = FDAT + k * 1024
        blk = mm[o:o + 1024]
        p = (ecb.decrypt(blk[:512]) + cbc.decrypt(blk[512:])) if k == 0 else cbc.decrypt(blk)
        size = struct.unpack_from("<H", p, 2)[0] & 0x7FFF
        if k == 0:
            hdr = bytes(p[4:516])
        plain += p[4:4 + size]
        if k % 150000 == 0 and k:
            print(f"  {k:,}/{nframes:,}  {time.time()-t0:.0f}s", flush=True)

    print(f"明文 {len(plain):,} B  用时 {time.time()-t0:.1f}s", flush=True)
    open(os.path.join(OUT, "fdat_plain.bin"), "wb").write(bytes(plain))

    vmin, vmaj = hdr[32], hdr[33]
    model, region = struct.unpack("<ii", hdr[36:44])
    fw_off, fw_size, nfs = struct.unpack("<iii", hdr[48:60])
    print(f"magic={hdr[0:8]!r} version={vmaj:x}.{vmin:02x} model={model & 0xFFFFFFFF:#010x} "
          f"fwOff={fw_off:,} fwSize={fw_size:,} numFs={nfs}", flush=True)

    # 文件系统头
    base = 64
    for i in range(min(nfs, 4)):
        o = base + i * 12
        mode = hdr[o:o + 1]
        off, size = struct.unpack("<ii", hdr[o + 4:o + 12])
        print(f"  fs[{i}] mode={mode!r} offset={off:,} size={size:,}", flush=True)

    # 提取 tar（firmware 区）
    tar = bytes(plain[fw_off:fw_off + fw_size])
    print(f"firmware 区 {len(tar):,} B，前 8 字节={tar[:8]!r}", flush=True)
    open(os.path.join(OUT, "firmware.tar"), "wb").write(tar)


if __name__ == "__main__":
    main()
