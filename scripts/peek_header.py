"""用公开 key_aes 解 FDAT 前 512 字节（ECB）并正确解析包头。

帧格式：每 1024 B 解密后 = [u16 校验和][u16 size|0x8000 endflag][payload]
所以包头从解密块的偏移 4 开始。
"""
import struct

from Cryptodome.Cipher import AES

KEY_AES = bytes.fromhex("REDACTED_KEY_AES_ECB")
PATH = r"<UPDATER_DIR>\BODYDATA.DAT"
FDAT = 0x6C


def main():
    with open(PATH, "rb") as f:
        f.seek(FDAT)
        blk = f.read(512)
    raw = AES.new(KEY_AES, AES.MODE_ECB).decrypt(blk)

    ck, se = struct.unpack("<HH", raw[0:4])
    size = se & 0x7FFF
    end = bool(se & 0x8000)
    # 校验和覆盖 [2:1024]，其中 512..1024 是 CBC 密文，无密钥无法验证
    print(f"帧头: 校验和={ck:#06x}（无法验证：覆盖区间含 CBC 段）  size={size} end={end}")

    p = raw[4:]
    print("payload 前 64 字节:", p[:64].hex())
    print("ascii:", "".join(chr(b) if 32 <= b < 127 else "." for b in p[:64]))

    magic = p[0:8]
    crc_stored = struct.unpack("<I", p[8:12])[0]
    ver = p[12:16]
    vmin, vmaj = p[32], p[33]
    model, region = struct.unpack("<ii", p[36:44])
    fw_off, fw_size, nfs = struct.unpack("<iii", p[48:60])

    print()
    print(f"magic          = {magic!r}")
    print(f"header crc     = 0x{crc_stored:08X}")
    print(f"version tag    = {ver!r}")
    print(f"version        = {vmaj:x}.{vmin:02x}")
    print(f"model          = 0x{model & 0xFFFFFFFF:08X}")
    print(f"region         = {region}")
    print(f"firmwareOffset = {fw_off:,}")
    print(f"firmwareSize   = {fw_size:,}")
    print(f"numFileSystems = {nfs}")
    print()
    print("文件系统表:")
    for i in range(min(nfs, 3)):
        o = 60 + i * 12
        mode = p[o:o + 1]
        off, sz = struct.unpack("<ii", p[o + 4:o + 12])
        print(f"  [{i}] mode={mode!r} offset={off:,} size={sz:,}")


if __name__ == "__main__":
    main()
