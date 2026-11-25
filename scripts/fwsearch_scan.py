#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fwsearch_scan.py —— 五代 ASTRA 缺失库的本地全量只读检索

遍历指定根目录下所有普通文件（分块读取，8 MiB/块 + 64 B 重叠，不整文件载入内存），
搜索：
  A. 候选库文件名（libInfraInput / libuxengine / libgrm / libgpe / libDDS / libCoreSync /
     libOb5 / a5bObj 等，含 "uxengine" 这类短词）
  B. 五代 IMDB 初始化表中的符号串（infra_input_init / uxengine_init / grm_init / GpeInit /
     DDSUserInit / core_sync_user_init 及其 sus/res 变体）
输出：
  * raw_scan/hits.jsonl          —— 每个命中文件一行（偏移、命中模式、上下文、SHA256、文件类别）
  * raw_scan/pattern_summary.tsv —— 每个模式的文件数与命中数
  * raw_scan/candidates.tsv      —— 所有 >1 MiB 文件的清单（大小、magic、SHA256）
用法：python fwsearch_scan.py [--root 目录 ...] [--out 证据目录]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time

CHUNK = 8 * 1024 * 1024
OVERLAP = 64
CTX = 40  # 上下文前后字节数

# ---- 检索模式（字节串，区分大小写；ELF 字符串区通常为 ASCII）----
PATTERNS: list[tuple[str, str, bytes]] = [
    # (类别, 名称, 字节模式)
    ("fname", "libInfraInput", b"libInfraInput"),
    ("fname", "libuxengine", b"libuxengine"),
    ("fname", "libgrm", b"libgrm"),
    ("fname", "libgpe", b"libgpe"),
    ("fname", "libDDS", b"libDDS"),
    ("fname", "libCoreSync", b"libCoreSync"),
    ("fname", "libOb5", b"libOb5"),
    ("fname", "libOb4", b"libOb4"),
    ("fname", "a5bObj", b"a5bObj"),
    ("fname", "a5bFw", b"a5bFw"),
    ("fname", "libSTMcmdexecute", b"libSTMcmdexecute"),
    ("fname", "libInfraSKD", b"libInfraSKD"),
    ("fname", "uxengine", b"uxengine"),
    ("fname", "GpeInit", b"GpeInit"),
    ("fname", "DDSUserInit", b"DDSUserInit"),
    # 符号
    ("symbol", "infra_input_init", b"infra_input_init"),
    ("symbol", "infra_input_sus", b"infra_input_sus"),
    ("symbol", "infra_input_res", b"infra_input_res"),
    ("symbol", "core_sync_user_init", b"core_sync_user_init"),
    ("symbol", "core_sync_user_sus", b"core_sync_user_sus"),
    ("symbol", "core_sync_user_res", b"core_sync_user_res"),
    ("symbol", "grm_init", b"grm_init"),
    ("symbol", "grm_sus", b"grm_sus"),
    ("symbol", "grm_res", b"grm_res"),
    ("symbol", "uxengine_init", b"uxengine_init"),
    ("symbol", "uxengine_sus", b"uxengine_sus"),
    ("symbol", "uxengine_res", b"uxengine_res"),
    ("symbol", "GpeInit", b"GpeInit"),
    ("symbol", "GpeSus", b"GpeSus"),
    ("symbol", "GpeRes", b"GpeRes"),
    ("symbol", "DDSUserInit", b"DDSUserInit"),
    ("symbol", "DDSUserSus", b"DDSUserSus"),
    ("symbol", "DDSUserRes", b"DDSUserRes"),
]
MAXPAT = max(len(p[2]) for p in PATTERNS)

# ---- 文件类别 sniff（首块）----
def sniff(head: bytes) -> str:
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(b"WBI1"):
        return "WBI"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP"
    if head.startswith(b"\x1f\x8b"):
        return "GZIP"
    if head.startswith(b"BZh"):
        return "BZIP2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "XZ"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "ZSTD"
    if head.startswith(b"070701") or head.startswith(b"070702"):
        return "CPIO_NEWC"
    if head.startswith(b"hsqs"):
        return "SQUASHFS"
    if head.startswith(b"ANDROID!"):
        return "ANDROID_BOOT"
    if head.startswith(b"IMELF") or head.startswith(b"imelf"):
        return "IMELF"
    if len(head) > 0x43C and head[0x438:0x43A] == b"\x53\xef":
        return "EXT2/3/4"
    if head.startswith(b"KDM") or head.startswith(b"KDI"):
        return "KDMP"
    if head[0x36:0x3A] == b"FAT" or head[0x52:0x56] == b"FAT" or head[0x36:0x3B] == b"FAT12":
        return "FAT"
    if len(head) > 0x106 and head[0x102:0x106] == b"FAT":
        return "FAT"
    # tar: 257 偏移处 ustar
    if len(head) > 265 and head[257:262] == b"ustar":
        return "TAR"
    if all(b == 0 for b in head):
        return "ZERO"
    # 文本判断
    if b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "TEXT"
        except UnicodeDecodeError:
            return "UNKNOWN"
    return "UNKNOWN"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(4 * 1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def find_all(buf: bytes, pat: bytes):
    start = 0
    while True:
        i = buf.find(pat, start)
        if i < 0:
            return
        yield i
        start = i + 1


def context(buf: bytes, off: int, plen: int) -> str:
    a = max(0, off - CTX)
    b = min(len(buf), off + plen + CTX)
    frag = buf[a:b]
    out = []
    for byte in frag:
        if 32 <= byte < 127 or byte in (9,):
            out.append(chr(byte))
        else:
            out.append(".")
    return "".join(out)


def scan_file(path: str, rel: str, out_dir: str, cand_out) -> dict | None:
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size == 0:
        return None
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
            kind = sniff(head)
            f.seek(0)
            per_pat: dict[str, list[int]] = {}
            tail = b""
            base = 0
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                buf = tail + chunk
                blen = len(buf)
                for cat, name, pat in PATTERNS:
                    # 去重：filename/symbol 同名模式只记一次
                    for i in find_all(buf, pat):
                        per_pat.setdefault(name, [])
                        if len(per_pat[name]) < 8:
                            per_pat[name].append(base - len(tail) + i)
                tail = buf[-(MAXPAT - 1):]
                base += blen - len(tail)
        if not per_pat:
            return None
        sha = sha256_file(path)
        hit = {
            "path": rel,
            "size": size,
            "kind": kind,
            "sha256": sha,
            "hits": {k: {"count": len(v), "offsets": v[:8]} for k, v in sorted(per_pat.items())},
            "contexts": {},
        }
        # 重新采样上下文（只读少量）
        with open(path, "rb") as f:
            for name, offs in hit["hits"].items():
                if not offs["offsets"]:
                    continue
                off = offs["offsets"][0]
                f.seek(max(0, off - CTX))
                frag = f.read(2 * CTX + 64)
                hit["contexts"][name] = context(frag, CTX if off > CTX else off, len(name))
        with open(os.path.join(out_dir, "hits.jsonl"), "a", encoding="utf-8") as fo:
            fo.write(json.dumps(hit, ensure_ascii=False) + "\n")
        if cand_out is not None and (size >= 1024 * 1024 or kind in ("ELF", "EXT2/3/4", "WBI", "TAR", "FAT")):
            cand_out.write(f"{rel}\t{size}\t{kind}\t{sha}\n")
        return hit
    except OSError as e:
        print(f"[warn] {rel}: {e}", file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", action="append", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    ws = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    roots = args.root or [ws]
    out_dir = args.out or os.path.join(ws, "03-证据", "静态分析", "firmware_search", "raw_scan")
    os.makedirs(out_dir, exist_ok=True)
    self_ev = os.path.join(ws, "03-证据", "静态分析", "firmware_search").lower()
    # 只排除本脚本自己生成的输出子目录；extracted_partitions 是要被检索的候选镜像，保留
    self_gen = {"raw_scan", "fs_inventory", "symbols", "fat_inventory", "imdb_refs", "tarlists", "wbi", "wbi_scan"}

    hits_path = os.path.join(out_dir, "hits.jsonl")
    cand_path = os.path.join(out_dir, "candidates.tsv")
    summary_path = os.path.join(out_dir, "pattern_summary.tsv")
    if os.path.exists(hits_path):
        os.remove(hits_path)
    if os.path.exists(cand_path):
        os.remove(cand_path)
    if os.path.exists(summary_path):
        os.remove(summary_path)

    all_files = []
    for root in roots:
        root = os.path.abspath(root)
        if os.path.isfile(root):
            all_files.append((root, os.path.relpath(root, ws)))
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            low = dirpath.lower()
            dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".git")]
            if low.startswith(self_ev):
                # 位于证据目录内：只排除脚本自己生成的输出子目录
                tail = low[len(self_ev):].strip("\\/")
                if tail.split("\\")[0].split("/")[0] in self_gen:
                    continue
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, ws)
                rel_low = rel.lower()
                if rel_low.startswith("03-证据\\静态分析\\firmware_search"):
                    tail = rel_low[len("03-证据\\静态分析\\firmware_search\\"):]
                    if tail.split("\\")[0] in self_gen:
                        continue
                all_files.append((p, rel))

    print(f"[info] files to scan: {len(all_files)}")
    total_bytes = 0
    hit_files = 0
    pat_counter: dict[str, int] = {}
    t0 = time.time()
    with open(cand_path, "w", encoding="utf-8") as cand_out:
        cand_out.write("path\tsize\tkind\tsha256\n")
        for idx, (p, rel) in enumerate(all_files, 1):
            try:
                total_bytes += os.path.getsize(p)
            except OSError:
                pass
            h = scan_file(p, rel, out_dir, cand_out)
            if h:
                hit_files += 1
                for k, v in h["hits"].items():
                    pat_counter[k] = pat_counter.get(k, 0) + v["count"]
            if idx % 200 == 0:
                print(f"[info] {idx}/{len(all_files)} files, {total_bytes/1e9:.2f} GB, "
                      f"hits={hit_files}, {time.time()-t0:.1f}s", flush=True)

    with open(summary_path, "w", encoding="utf-8") as fo:
        fo.write("pattern\toccurrences\n")
        for k in sorted(pat_counter):
            fo.write(f"{k}\t{pat_counter[k]}\n")
    print(f"[done] scanned {len(all_files)} files, {total_bytes/1e9:.2f} GB, "
          f"hit_files={hit_files}, elapsed={time.time()-t0:.1f}s")
    print(f"[done] out: {out_dir}")


if __name__ == "__main__":
    main()
