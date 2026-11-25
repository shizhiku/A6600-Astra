"""a6600 固件重打包器 —— 目标：用原始内容重建出与索尼原包逐字节一致的 DAT。

流程：DAT 切片 -> 解析 chunk -> FDAT 解密/重加密 -> 重建 DAT -> 重算 DEND CRC -> 比对
"""
import hashlib
import mmap
import os
import struct
import sys
import time
import zlib

from Cryptodome.Cipher import AES

ROOT = os.path.dirname(os.path.abspath(__file__))
EXE = r"<UPDATER_DIR>\Update_ILCE6600V110.exe"
DAT_OFF = 0xAE9D4
DAT_LEN = 316672424

KEY_AES = bytes.fromhex("REDACTED_KEY_AES_ECB")
KEY_CBC = bytes.fromhex("REDACTED_KEY_CXD90045")
BLOCK = 1024
PAYLOAD = BLOCK - 4
TRAILER = 0x110

PLAIN = os.path.join(ROOT, "a6600_fw", "fdat_plain.bin")
OUT = os.path.join(ROOT, "build_out")
os.makedirs(OUT, exist_ok=True)


def walk_chunks(buf):
    assert buf[:8] == b"\x89UFU\r\n\x1a\n", buf[:8]
    out, off = [], 8
    while off + 8 <= len(buf):
        size, typ = struct.unpack(">i4s", buf[off:off + 8])
        out.append((typ, off + 8, size, off))
        off += 8 + size
        if typ == b"DEND":
            break
    return out, off


def encrypt_fdat(plain, iv):
    """逆运算：plain(1020/块) -> 密文(1024/块)，首块前 512 用 ECB，其余 CBC 链。"""
    ecb = AES.new(KEY_AES, AES.MODE_ECB)
    cbc = None
    out = bytearray()
    pos, n = 0, len(plain)
    while pos < n:
        chunk = plain[pos:pos + PAYLOAD]
        pos += len(chunk)
        flag = 0x8000 if pos >= n else 0
        body = struct.pack("<H", len(chunk) | flag) + chunk + b"\xff" * (PAYLOAD - len(chunk))
        block = struct.pack("<H", sum(struct.unpack("<511H", body)) & 0xFFFF) + body
        assert len(block) == BLOCK
        if cbc is None:
            cbc = AES.new(KEY_CBC, AES.MODE_CBC, iv)
            out += ecb.encrypt(block[:512]) + cbc.encrypt(block[512:])
        else:
            out += cbc.encrypt(block)
    return bytes(out)


def main():
    t0 = time.time()
    print(f"[*] 读取原包 {EXE}")
    with open(EXE, "rb") as f:
        f.seek(DAT_OFF)
        dat = f.read(DAT_LEN)
    print(f"[*] DAT {len(dat):,} B  sha256={hashlib.sha256(dat).hexdigest()}")

    chunks, dat_end = walk_chunks(dat)
    print("[*] chunks:", [(t.decode(), hex(o), s) for t, o, s, h in chunks])

    fdat = next(c for c in chunks if c[0] == b"FDAT")
    _, foff, fsize, fhdr = fdat
    payload = dat[foff:foff + fsize]
    iv = payload[-TRAILER:-TRAILER + 16]
    trailer = payload[-TRAILER + 16:]
    print(f"[*] FDAT @0x{fhdr:X} cipher={fsize - TRAILER:,} IV={iv.hex()} trailer={len(trailer)}")

    plain = open(PLAIN, "rb").read()
    print(f"[*] 明文 {len(plain):,} B  sha256={hashlib.sha256(plain).hexdigest()}")

    print("[*] 重加密 ...")
    cipher_new = encrypt_fdat(plain, iv)
    print(f"    密文 {len(cipher_new):,} B (原 {fsize - TRAILER:,} B)")
    if cipher_new == payload[:len(cipher_new)]:
        print("[+] 密文：逐字节一致 ✅")
    else:
        bad = sum(1 for a, b in zip(cipher_new, payload) if a != b)
        print(f"[!] 密文：不一致，差异字节 {bad}")

    fdat_new = cipher_new + iv + trailer

    # 重建 DAT：同样的 chunk 顺序，FDAT 内容替换，DEND CRC 重算
    dend = next(c for c in chunks if c[0] == b"DEND")
    _, doff, dsize, dhdr = dend
    rebuilt = bytearray(dat)
    rebuilt[foff:foff + fsize] = fdat_new
    rebuilt[dhdr:dhdr + 8] = struct.pack(">i4s", dsize, b"DEND")
    crc = zlib.crc32(bytes(rebuilt[:dhdr])) & 0xFFFFFFFF
    struct.pack_into(">i", rebuilt, doff, crc)
    orig_crc = struct.unpack(">i", dat[doff:doff + 4])[0] & 0xFFFFFFFF
    print(f"[*] DEND CRC 原={orig_crc:08X} 新={crc:08X} {'一致' if crc == orig_crc else '不一致'}")

    if bytes(rebuilt) == dat:
        print(f"[+] DAT：逐字节一致 ✅  ({len(rebuilt):,} B)  {time.time()-t0:.1f}s")
    else:
        diff = next(i for i in range(len(dat)) if dat[i] != rebuilt[i])
        print(f"[!] DAT：第一个差异 @0x{diff:X}")

    out_dat = os.path.join(OUT, "a6600_repacked.dat")
    open(out_dat, "wb").write(bytes(rebuilt))
    print(f"[+] 输出 {out_dat}")


if __name__ == "__main__":
    main()
