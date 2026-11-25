#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fwsearch_summarize.py —— 汇总“五代 ASTRA 缺失库本机检索”的全部证据

输入（均位于 03-证据/静态分析/firmware_search/）：
  fs_inventory/*_filelist.tsv        各 ext2 分区的全量文件清单
  fat_inventory/*_filelist.tsv       各 FAT(/system) 分区清单
  raw_scan/hits.jsonl                工作区全量分块字符串扫描命中
  raw_scan_zvparts/hits.jsonl        ZV nflasha3/5 扫描命中
  raw_scan_host/hits.jsonl           Downloads 固件候选文件扫描命中
  raw_scan_oldws/hits.jsonl          旧工作区固件目录扫描命中
  imdb_refs/*_imdb_table.tsv         libIMDB 初始化表解析结果
输出：
  summary/target_name_matrix.tsv     每个分区中“目标库文件名”的命中情况
  summary/reference_only_files.tsv   仅作为字符串/符号被引用（不是独立文件）的二进制
  summary/firmware_material_inventory.tsv  本机固件材料清单（大小+SHA256+类型）
  summary/SUMMARY.md                 汇总数据（供报告引用）
"""
from __future__ import annotations

import json
import os

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(WS, "03-证据", "静态分析", "firmware_search")
OUT = os.path.join(EV, "summary")
os.makedirs(OUT, exist_ok=True)

# 六类“五代 IMDB 引用的初始化库” + 常见别名
TARGET_LIBS = [
    "libInfraInput.so", "libuxengine.so", "libgrm.so", "libgpe.so",
    "libDDS.so", "libCoreSync.so",
]
ALIASES = ["libOb5.so", "libOb4.so", "a5bObj", "a5bFw", "libSTMcmdexecute.so"]
PATTERNS = ["libInfraInput", "libuxengine", "libgrm", "libgpe", "libDDS",
            "libCoreSync", "libOb5", "a5bObj", "libSTMcmdexecute"]


def read_filelist(path: str):
    rows = []
    if not os.path.exists(path):
        return rows
    for line in open(path, encoding="utf-8", errors="replace"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 3:
            rows.append(parts)
    return rows


def load_hits(path: str):
    hits = []
    if not os.path.exists(path):
        return hits
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            hits.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return hits


def write_matrix():
    rows = []
    inventories = [
        ("zv1m2_usr", "/usr", "fs_inventory"),
        ("zv1m2_rootfs", "/rootfs", "fs_inventory"),
        ("zv1m2_system", "/system", "fat_inventory"),
        ("a6600_usr", "/usr", "fs_inventory"),
        ("a6600_rootfs", "/rootfs", "fs_inventory"),
        ("a6600_system", "/system", "fat_inventory"),
        ("zve10_usr", "/usr", "fs_inventory"),
        ("zve10_rootfs", "/rootfs", "fs_inventory"),
        ("zve10_system", "/system", "fat_inventory"),
    ]
    out = [("partition", "mount", "files", *TARGET_LIBS, *ALIASES)]
    for label, mount, kind in inventories:
        path = os.path.join(EV, kind, f"{label}_filelist.tsv")
        files = [r for r in read_filelist(path) if r[0] in ("f", "l")]
        names = [os.path.basename(r[2]) for r in files]
        counts = []
        for pat in TARGET_LIBS + ALIASES:
            counts.append(sum(1 for n in names if pat.lower() in n.lower()))
        out.append((label, mount, str(len(files)), *map(str, counts)))
    with open(os.path.join(OUT, "target_name_matrix.tsv"), "w", encoding="utf-8") as fo:
        for row in out:
            fo.write("\t".join(row) + "\n")
    return out


def write_reference_only():
    srcs = [
        ("workspace", os.path.join(EV, "raw_scan", "hits.jsonl")),
        ("zv_parts", os.path.join(EV, "raw_scan_zvparts", "hits.jsonl")),
        ("host_downloads", os.path.join(EV, "raw_scan_host", "hits.jsonl")),
        ("old_workspace", os.path.join(EV, "raw_scan_oldws", "hits.jsonl")),
    ]
    rows = []
    for label, p in srcs:
        for h in load_hits(p):
            kind = h.get("kind", "")
            rows.append((label, kind, str(h.get("size", 0)), h.get("path", ""),
                         h.get("sha256", ""), ",".join(sorted(h.get("hits", {}).keys()))))
    with open(os.path.join(OUT, "reference_only_files.tsv"), "w", encoding="utf-8") as fo:
        fo.write("scan\tkind\tsize\tpath\tsha256\tpatterns\n")
        for r in rows:
            fo.write("\t".join(r) + "\n")
    return rows


def write_material_inventory():
    rows = []
    seen = set()
    for sub in ("raw_scan", "raw_scan_zvparts", "raw_scan_host", "raw_scan_oldws", "raw_scan_partitions"):
        cand = os.path.join(EV, sub, "candidates.tsv")
        if os.path.exists(cand):
            for line in open(cand, encoding="utf-8", errors="replace"):
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 4 and parts[0] != "path":
                    key = (sub, parts[0])
                    if key not in seen:
                        seen.add(key)
                        rows.append(parts)
    # 显式加入关键材料（含 <1MiB 的提取件）
    extra = [
        ("05-原始固件/zv1m2_fw/gen5/libIMDB.so", None),
        ("05-原始固件/zv1m2_fw/gen5/appFwBoot.so", None),
        ("05-原始固件/zv1m2_fw/gen5/AdjChkConfig.so", None),
        ("05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha3", None),
        ("05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha5", None),
        ("03-证据/静态分析/firmware_search/extracted_partitions/0700_part_image/dev/nflasha3", None),
        ("03-证据/静态分析/firmware_search/extracted_partitions/0700_part_image/dev/nflasha5", None),
        ("03-证据/静态分析/firmware_search/extracted_partitions/zve10/0700_part_image/dev/nflasha3", None),
        ("03-证据/静态分析/firmware_search/extracted_partitions/zve10/0700_part_image/dev/nflasha5", None),
        ("03-证据/静态分析/97_abi/zvroot_libSTMcmdexecute.so", None),
        ("03-证据/静态分析/97_abi/zvusr_libIMDB.so", None),
        ("03-证据/静态分析/97_abi/zvusr_libObj.so", None),
        ("03-证据/静态分析/97_abi/zvusr_appFw.so", None),
        ("03-证据/静态分析/97_abi/zvusr_appFwBoot.so", None),
        ("03-证据/静态分析/97_abi/zvusr_im.elf", None),
        ("03-证据/静态分析/firmware_search/extracted_libs_zve10/libObj.so", None),
        ("03-证据/静态分析/firmware_search/extracted_libs_zve10/libIMDB.so", None),
        ("<UPDATER_DIR>/BODYDATA.DAT", None),
        ("<UPDATER_DIR>/Update_ILCE6600V110.exe", None),
        ("<UPDATER_DIR>/Update_ZVE10V203.exe", None),
        ("<UPDATER_DIR>/Update_ZVE10V203.dmg", None),
        ("<LEGACY_WORKSPACE>/zve10_fw/firmware.tar", None),
        ("<LEGACY_WORKSPACE>/zve10_fw/fdat_plain.bin", None),
        ("<LEGACY_WORKSPACE>/zve10_fw/extracted/0700_part_image/dev/nflasha15", None),
        ("<LEGACY_WORKSPACE>/zve10_fw/extracted/0700_part_image/dev/nflasha7", None),
    ]
    have = {r[0].replace("/", "\\").lower() for r in rows}
    import hashlib

    def sha256(p):
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(4 * 1024 * 1024), b""):
                h.update(b)
        return h.hexdigest()

    for rel, _ in extra:
        key = rel.replace("/", "\\").lower()
        if key in have:
            continue
        p = rel if os.path.isabs(rel) else os.path.join(WS, rel.replace("/", os.sep))
        if not os.path.exists(p):
            continue
        try:
            rows.append([rel, str(os.path.getsize(p)), "EXTRA", sha256(p)])
        except OSError:
            pass
    with open(os.path.join(OUT, "firmware_material_inventory.tsv"), "w", encoding="utf-8") as fo:
        fo.write("path\tsize\tkind\tsha256\n")
        for r in rows:
            if r[2] in ("TEXT",):
                continue
            fo.write("\t".join(r) + "\n")
    return [r for r in rows if r[2] not in ("TEXT",)]


def main():
    matrix = write_matrix()
    refs = write_reference_only()
    mats = write_material_inventory()
    # IMDB 表解析统计
    imdb_lines = []
    for model in ("a6600", "zv1m2"):
        tbl = os.path.join(EV, "imdb_refs", f"{model}_imdb_table.tsv")
        miss = os.path.join(EV, "imdb_refs", f"{model}_missing_libs.txt")
        pres = os.path.join(EV, "imdb_refs", f"{model}_present_libs.txt")
        n = sum(1 for _ in open(tbl, encoding="utf-8")) - 1 if os.path.exists(tbl) else 0
        nm = sum(1 for _ in open(miss, encoding="utf-8")) if os.path.exists(miss) else 0
        np = sum(1 for _ in open(pres, encoding="utf-8")) if os.path.exists(pres) else 0
        imdb_lines.append(f"- {model}: 表条目={n}，本机有独立文件={np}，无独立文件={nm}")

    lines = ["# 五代缺失库本机检索 · 机器汇总", ""]
    lines.append("## 一、各分区“目标库文件名”命中矩阵")
    lines.append("")
    lines.append("| 分区 | 挂载点 | 文件数 | " + " | ".join(TARGET_LIBS + ALIASES) + " |")
    lines.append("|---|---|---|" + "|".join(["---"] * (len(TARGET_LIBS) + len(ALIASES))) + "|")
    for row in matrix[1:]:
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append("> 数值为文件名包含该关键字的文件数。除 `libInfraSKD.so`（非目标库）与")
    lines.append("> ZV/ZV-E10 rootfs 的 `libSTMcmdexecute.so` 外，六类目标库在所有分区均为 0。")
    lines.append("")
    lines.append("## 二、libIMDB 初始化表 vs 本机文件")
    lines.append("")
    lines.extend(imdb_lines)
    lines.append("")
    lines.append("## 三、扫描规模")
    lines.append("")
    lines.append(f"- 工作区全量分块扫描命中文件：{len([r for r in refs if r[0]=='workspace'])}")
    lines.append(f"- ZV nflasha3/5 命中文件：{len([r for r in refs if r[0]=='zv_parts'])}")
    lines.append(f"- 旧工作区固件目录命中文件：{len([r for r in refs if r[0]=='old_workspace'])}")
    lines.append(f"- Downloads 固件候选文件命中：{len([r for r in refs if r[0]=='host_downloads'])}")
    lines.append("")
    lines.append("## 四、固件材料清单（节选，完整见 firmware_material_inventory.tsv）")
    lines.append("")
    lines.append("| 路径 | 大小 | 类型 | SHA-256（前32） |")
    lines.append("|---|---|---|---|")
    for r in mats[:45]:
        lines.append(f"| `{r[0]}` | {r[1]} | {r[2]} | `{r[3][:32]}` |")
    lines.append("")
    with open(os.path.join(OUT, "SUMMARY.md"), "w", encoding="utf-8") as fo:
        fo.write("\n".join(lines) + "\n")
    print("\n".join(lines[:60]))
    print(f"[done] {OUT}")


if __name__ == "__main__":
    main()
