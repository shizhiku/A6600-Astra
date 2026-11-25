#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fwsearch_dat_source.py —— 核实 Downloads\\BODYDATA.DAT 与工作区 ZV-1M2 固件的来源关系

团队解密脚本 02-脚本/decrypt_zv1m2.py 明确以
  C:\\Users\\<user>\\Downloads\\BODYDATA.DAT
为输入。本脚本只解密第一帧（不写任何镜像），读取 FDAT 头中的
model / version / fwOff / fwSize，并与
  05-原始固件/zv1m2_fw/fdat_plain.bin  首 512 字节做一致性对照；
同时输出候选文件 SHA-256 清单。
"""
from __future__ import annotations

import hashlib
import os
import struct

from Cryptodome.Cipher import AES

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(WS, "03-证据", "静态分析", "firmware_search", "source_verify")
os.makedirs(EV, exist_ok=True)

BODYDATA = os.path.join(os.path.expanduser("~"), "Downloads", "BODYDATA.DAT")
FDAT_PLAIN = os.path.join(WS, "05-原始固件", "zv1m2_fw", "fdat_plain.bin")
KEY_AES = bytes.fromhex("REDACTED_KEY_AES_ECB")
KEY_K8 = bytes.fromhex("REDACTED_KEY_K8_ZV1M2")
FDAT = 0x6C


def sha256_file(path: str, limit: int | None = None) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        remain = limit
        while True:
            n = 4 * 1024 * 1024 if remain is None else min(4 * 1024 * 1024, remain)
            b = f.read(n)
            if not b:
                break
            h.update(b)
            if remain is not None:
                remain -= len(b)
                if remain <= 0:
                    break
    return h.hexdigest()


def first_frame_header(path: str):
    f = open(path, "rb")
    n = f.seek(0, 2)
    f.seek(n - 284)
    iv = f.read(16)
    f.seek(FDAT)
    blk = f.read(1024)
    ecb = AES.new(KEY_AES, AES.MODE_ECB)
    cbc = AES.new(KEY_K8, AES.MODE_CBC, iv)
    p = ecb.decrypt(blk[:512]) + cbc.decrypt(blk[512:])
    size = struct.unpack_from("<H", p, 2)[0] & 0x7FFF
    hdr = bytes(p[4:4 + size])
    return n, iv, hdr


def main():
    lines = ["# BODYDATA.DAT 与工作区 ZV-1M2 固件来源核验", ""]
    if not os.path.exists(BODYDATA):
        print("BODYDATA.DAT 不存在"); return
    if not os.path.exists(FDAT_PLAIN):
        print("fdat_plain.bin 不存在")
    n, iv, hdr = first_frame_header(BODYDATA)
    vmin, vmaj = hdr[32], hdr[33]
    model, region = struct.unpack("<ii", hdr[36:44])
    fw_off, fw_size, nfs = struct.unpack("<iii", hdr[48:60])
    nframes = (n - 12 - FDAT - 272) // 1024
    lines += [
        f"- BODYDATA.DAT: `{BODYDATA}`",
        f"- 大小: {n:,} B",
        f"- SHA-256: `{sha256_file(BODYDATA)}`",
        f"- FDAT 帧数（按 1024 B 帧推算）: {nframes:,}",
        f"- 首帧 IV: `{iv.hex()}`",
        f"- 明文头 magic: `{hdr[0:8]!r}`",
        f"- 版本字节: vmaj=0x{vmaj:02x} vmin=0x{vmin:02x} → 字符串形式约 "
        f"{vmaj}.{vmin:02x}",
        f"- model=0x{model & 0xFFFFFFFF:08x}  region=0x{region & 0xFFFFFFFF:08x}",
        f"- firmware 区: offset={fw_off:,} size={fw_size:,} numFs={nfs}",
        "",
    ]
    # 与工作区已解出的明文对照
    if os.path.exists(FDAT_PLAIN):
        plain = open(FDAT_PLAIN, "rb").read(4096)
        eq = plain[:len(hdr)] == hdr
        lines += [
            f"- 工作区 `fdat_plain.bin` 大小: {os.path.getsize(FDAT_PLAIN):,} B",
            f"- `fdat_plain.bin` SHA-256: "
            f"`{sha256_file(FDAT_PLAIN)}`",
            f"- 首帧解密头（{len(hdr)} B）与 `fdat_plain.bin` 开头一致: **{eq}**",
            f"- 首帧解密头 SHA-256: `{hashlib.sha256(hdr).hexdigest()}`",
            "",
        ]
    # 固件 tar 对照
    fw_tar = os.path.join(WS, "05-原始固件", "zv1m2_fw", "firmware.tar")
    if os.path.exists(fw_tar):
        lines += [
            f"- 从明文解出的 `firmware.tar` 大小: {os.path.getsize(fw_tar):,} B"
            + ("（与 FDAT 头记载的 fwSize 一致）" if os.path.getsize(fw_tar) == fw_size else "（与 fwSize 不符！）"),
            f"- `firmware.tar` SHA-256: `{sha256_file(fw_tar)}`",
            "",
        ]
    out = os.path.join(EV, "bodystata_dat_source.md")
    open(out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"[done] {out}")


if __name__ == "__main__":
    main()
