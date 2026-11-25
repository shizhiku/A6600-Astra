"""把打补丁的 nflasha15 重新封装成 a6600 固件 DAT。"""
import os
import struct
import sys
import tarfile
import time
import zlib

from Cryptodome.Cipher import AES

ROOT = r"<LEGACY_WORKSPACE>"
PLAIN = os.path.join(ROOT, "a6600_fw", "fdat_plain.bin")
TAR = os.path.join(ROOT, "a6600_fw", "firmware.tar")
NEW_PART = os.path.join(ROOT, "a6600_port", "nflasha15_patched.bin")
OUT = os.path.join(ROOT, "a6600_port")

KEY_AES = bytes.fromhex("REDACTED_KEY_AES_ECB")
KEY_CBC = bytes.fromhex("REDACTED_KEY_CXD90045")
BLOCK, PAYLOAD = 1024, 1020
PART_NAME = "0700_part_image/dev/nflasha15"


def encrypt_fdat(plain, iv):
    ecb = AES.new(KEY_AES, AES.MODE_ECB)
    cbc = None
    out = bytearray()
    pos, n = 0, len(plain)
    while pos < n:
        chunk = plain[pos:pos + PAYLOAD]
        pos += len(chunk)
        flag = 0x8000 if pos >= n else 0
        body = struct.pack("<H", len(chunk) | flag) + chunk + b"\xff" * (PAYLOAD - len(chunk))
        blk = struct.pack("<H", sum(struct.unpack("<511H", body)) & 0xFFFF) + body
        if cbc is None:
            cbc = AES.new(KEY_CBC, AES.MODE_CBC, iv)
            out += ecb.encrypt(blk[:512]) + cbc.encrypt(blk[512:])
        else:
            out += cbc.encrypt(blk)
    return bytes(out)


def rebuild_tar():
    dst = os.path.join(OUT, "firmware_patched.tar")
    t0 = time.time()
    with tarfile.open(TAR) as src, tarfile.open(dst, "w", format=tarfile.GNU_FORMAT) as out:
        for m in src.getmembers():
            if m.name == PART_NAME:
                info = tarfile.TarInfo(m.name)
                info.size = os.path.getsize(NEW_PART)
                info.mode = m.mode
                info.mtime = m.mtime
                info.uid, info.gid = m.uid, m.gid
                with open(NEW_PART, "rb") as f:
                    out.addfile(info, f)
                print(f"  [替换] {m.name}  {m.size:,} -> {info.size:,} B")
            else:
                if m.issym() or m.islnk() or m.isdir():
                    out.addfile(m)
                else:
                    out.addfile(m, src.extractfile(m))
    print(f"[+] firmware_patched.tar {os.path.getsize(dst):,} B  ({time.time()-t0:.1f}s)")
    return dst


def main():
    tar_new = rebuild_tar()

    plain = bytearray(open(PLAIN, "rb").read())
    fw_off, fw_size, nfs = struct.unpack_from("<iii", plain, 48)
    print(f"[*] 原明文 {len(plain):,} B  fwOff={fw_off:,} fwSize={fw_size:,} numFs={nfs}")

    new_tar = open(tar_new, "rb").read()
    rebuilt = bytearray(plain[:fw_off]) + bytearray(new_tar)
    struct.pack_into("<i", rebuilt, 52, len(new_tar))
    crc = zlib.crc32(bytes(rebuilt[12:512])) & 0xFFFFFFFF
    struct.pack_into("<I", rebuilt, 8, crc)
    print(f"[*] 新明文 {len(rebuilt):,} B  fwSize={len(new_tar):,}  header_crc={crc:#010x}")

    iv = bytes(plain[-272:-256]) if False else None
    # IV 来自原 DAT 尾部
    dat_src = open(os.path.join(ROOT, "build_out", "a6600_repacked.dat"), "rb").read() \
        if os.path.exists(os.path.join(ROOT, "build_out", "a6600_repacked.dat")) else None
    if dat_src is None:
        raise SystemExit("需要 build_out/a6600_repacked.dat")
    # 正确解析 chunk：每个 chunk 头 = 4B 大端长度 + 4B tag，数据紧随其后
    off = 8
    fdat_hdr = fdat_data = fdat_len = None
    while off + 8 <= len(dat_src):
        size = struct.unpack(">i", dat_src[off:off + 4])[0]
        tag = dat_src[off + 4:off + 8]
        if tag == b"FDAT":
            fdat_hdr, fdat_data, fdat_len = off, off + 8, size
            break
        off += 8 + size
    print(f"[*] FDAT hdr@{fdat_hdr:#x} data@{fdat_data:#x} len={fdat_len:,}")
    iv = dat_src[fdat_data + fdat_len - 272: fdat_data + fdat_len - 256]
    trailer = dat_src[fdat_data + fdat_len - 256: fdat_data + fdat_len]
    print(f"[*] IV={iv.hex()}  trailer={len(trailer)} B")

    print("[*] 重新加密 ...")
    t0 = time.time()
    cipher = encrypt_fdat(bytes(rebuilt), iv)
    print(f"[+] 密文 {len(cipher):,} B  ({time.time()-t0:.1f}s)")

    fdat_new = cipher + iv + trailer
    dat = bytearray(dat_src)
    # 用原长度做切片终点，保留其后的 DEND 尾部
    dat[fdat_data:fdat_data + fdat_len] = fdat_new
    struct.pack_into(">i", dat, fdat_hdr, len(fdat_new))
    # DEND
    dend_hdr = len(dat) - 12
    doff = dend_hdr + 8
    new_crc = zlib.crc32(bytes(dat[:dend_hdr])) & 0xFFFFFFFF
    struct.pack_into(">I", dat, doff, new_crc)
    print(f"[+] DEND CRC = {new_crc:#010x}")

    out_path = os.path.join(OUT, "nflasha15_astra.dat")
    open(out_path, "wb").write(bytes(dat))
    print(f"[+] 输出 {out_path}  {len(dat):,} B")


if __name__ == "__main__":
    main()
