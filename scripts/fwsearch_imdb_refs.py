#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fwsearch_imdb_refs.py —— 解析 a6600 / ZV-1M2 两代 libIMDB.so 的“库初始化表”，
并与本机已枚举的文件系统清单对照，回答“IMDB 引用的库在本机是否以独立文件存在”。

输出（03-证据/静态分析/firmware_search/imdb_refs/）：
  a6600_imdb_table.tsv     条目序号、库名、init/sus/res 符号名
  zv1m2_imdb_table.tsv     同上
  a6600_missing_libs.txt   在本机 a6600 全部分区中找不到独立文件的被引用库
  zv1m2_missing_libs.txt   同上（ZV-1M2）
  compare_summary.md       汇总
"""
from __future__ import annotations

import os
import re

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(WS, "03-证据", "静态分析", "firmware_search")
OUT = os.path.join(EV, "imdb_refs")
os.makedirs(OUT, exist_ok=True)

IMDBS = {
    "a6600": os.path.join(WS, "05-原始固件", "a6600_fw", "usr", "lib", "libIMDB.so"),
    "zv1m2": os.path.join(WS, "05-原始固件", "zv1m2_fw", "gen5", "libIMDB.so"),
    "zve10": os.path.join(WS, "03-证据", "静态分析", "firmware_search",
                          "extracted_libs_zve10", "libIMDB.so"),
}
# 已经过文件系统枚举的清单（TSV: 类型\t大小\t路径）与挂载点前缀
FILELISTS = {
    "a6600": [("a6600_usr_filelist.tsv", "/usr"), ("a6600_rootfs_filelist.tsv", "/rootfs")],
    "zv1m2": [("zv1m2_usr_filelist.tsv", "/usr"), ("zv1m2_rootfs_filelist.tsv", "/rootfs")],
    "zve10": [("zve10_usr_filelist.tsv", "/usr"), ("zve10_rootfs_filelist.tsv", "/rootfs")],
}
FAT_LISTS = {"zv1m2": ["zv1m2_system_filelist.tsv"],
             "a6600": ["a6600_system_filelist.tsv"],
             "zve10": ["zve10_system_filelist.tsv"]}

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def ascii_strings(data: bytes, minlen: int = 4):
    """按出现顺序返回可打印 ASCII 串列表（与文件内偏移顺序一致）"""
    out = []
    for m in re.finditer(rb"[ -~]{%d,}" % minlen, data):
        out.append((m.start(), m.group(0).decode("latin1")))
    return out


def parse_imdb_table(path: str):
    data = open(path, "rb").read()
    strings = ascii_strings(data, 4)
    entries = []
    cur = None
    for off, s in strings:
        if re.fullmatch(r"lib[A-Za-z0-9_+.-]+\.so(\.\d+)*", s):
            cur = {"off": off, "lib": s, "syms": []}
            entries.append(cur)
        elif cur is not None and IDENT.match(s) and not s.startswith("lib"):
            # 只收入紧跟在库名之后、形如 init/sus/res 的符号
            cur["syms"].append(s)
    return data, entries


def load_filelist(model: str) -> dict[str, list[str]]:
    """basename -> [挂载点+路径...]，只统计文件系统清单中的普通文件/符号链接"""
    idx: dict[str, list[str]] = {}
    for fn, prefix in FILELISTS.get(model, []):
        p = os.path.join(EV, "fs_inventory", fn)
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8", errors="replace"):
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3 or parts[0] not in ("f", "l"):
                continue
            path = parts[2]
            if not path.startswith("/"):
                continue
            idx.setdefault(os.path.basename(path), []).append(prefix + path)
    for fn in FAT_LISTS.get(model, []):
        p = os.path.join(EV, "fat_inventory", fn)
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8", errors="replace"):
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3 or parts[0] not in ("f", "l"):
                continue
            path = parts[2]
            if path.startswith("/"):
                idx.setdefault(os.path.basename(path), []).append("/system" + path)
    return idx


def main():
    summary = ["# libIMDB 初始化表 vs 本机文件系统清单", ""]
    for model, imp in IMDBS.items():
        if not os.path.exists(imp):
            print(f"[skip] {model}: {imp} 不存在")
            continue
        data, entries = parse_imdb_table(imp)
        tbl = os.path.join(OUT, f"{model}_imdb_table.tsv")
        with open(tbl, "w", encoding="utf-8") as fo:
            fo.write("index\tlib\tsymbols\tfile_offset\n")
            for i, e in enumerate(entries):
                fo.write(f"{i}\t{e['lib']}\t{','.join(e['syms'])}\t0x{e['off']:x}\n")
        idx = load_filelist(model)
        missing, present = [], []
        for e in entries:
            if e["lib"] in idx:
                present.append((e["lib"], idx[e["lib"]][0]))
            else:
                missing.append(e["lib"])
        with open(os.path.join(OUT, f"{model}_missing_libs.txt"), "w", encoding="utf-8") as fo:
            for s in missing:
                fo.write(s + "\n")
        with open(os.path.join(OUT, f"{model}_present_libs.txt"), "w", encoding="utf-8") as fo:
            for s, p in present:
                fo.write(f"{s}\t{p}\n")
        summary.append(f"## {model}")
        summary.append("")
        summary.append(f"- IMDB: `{os.path.relpath(imp, WS)}`（{len(data)} B）")
        summary.append(f"- 解析到库初始化条目：**{len(entries)}** 条")
        summary.append(f"- 本机对应机型分区中能找到同名独立文件：**{len(present)}** 条")
        summary.append(f"- 找不到同名独立文件：**{len(missing)}** 条")
        summary.append("")
        summary.append("缺失清单：")
        summary.append("")
        summary.append("```")
        summary.extend(missing)
        summary.append("```")
        summary.append("")
    with open(os.path.join(OUT, "compare_summary.md"), "w", encoding="utf-8") as fo:
        fo.write("\n".join(summary) + "\n")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
