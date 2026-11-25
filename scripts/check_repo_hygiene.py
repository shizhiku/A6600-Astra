#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仓库卫生检查：确保没有混入固件、索尼二进制、密钥或未脱敏的个人路径。

用法：
    python scripts/check_repo_hygiene.py            # 检查整个仓库
    python scripts/check_repo_hygiene.py --staged   # 只检查 git 暂存区

退出码：0 = 通过，1 = 发现问题。
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

# ---------------------------------------------------------------- 规则

# 绝不允许出现在仓库里的扩展名（固件 / 镜像 / 索尼二进制 / 密钥容器）
FORBIDDEN_EXT = {
    ".bin", ".img", ".dat", ".so", ".ko", ".elf", ".exe", ".msi", ".iso",
    ".tar", ".gz", ".tgz", ".zip", ".7z", ".qcow2", ".dmg", ".ipa", ".apk",
    ".o", ".a", ".pyc", ".pyo", ".class", ".dll", ".dylib", ".ufu", ".fdat",
    ".sdm", ".sum", ".pem", ".p12", ".pfx", ".key",
}

ALLOWED_EXT = {
    ".md", ".txt", ".csv", ".json", ".py", ".sh", ".c", ".h", ".png",
    ".yml", ".yaml", ".toml", ".cfg", ".conf", ".ini",
}

# 无扩展名但允许的文件（许可证、忽略规则等）
ALLOWED_BARE_NAMES = {
    ".gitignore", ".gitattributes", ".editorconfig",
    "LICENSE", "NOTICE", "Makefile", "Dockerfile",
}

# 文件名黑名单（命中即拒绝）
FORBIDDEN_NAMES = {
    "nflasha1", "nflasha2", "nflasha3", "nflasha4", "nflasha5", "nflasha7",
    "nflasha15", "emmc.img", "bodidata.dat", "bodaydata.dat",
    "libobj.so", "appfw.so", "appfwboot.so", "libimdb.so", "input.ko",
    "liro.ko", "emmc.ko", "im.elf", "av-cam.bin", "backup.bin",
}

# 目录黑名单
FORBIDDEN_DIRS = {
    "a6600_fw", "zv1m2_fw", "zve10_fw", "qemu_in", "extracted",
    "part_image", "0700_part_image", "__pycache__", "_safe_repo_build",
}

# 未脱敏的个人路径（允许 <you> 这类示例占位符）
PATH_LEAK_PATTERNS = [
    (re.compile(r"C:[\\/]Users[\\/](?!<you>)[^\\/\"'<>\r\n]{2,}"), "Windows 绝对用户路径"),
    (re.compile(r"<HOME>/\"'<>\r\n]{2,}"), "WSL 绝对用户路径"),
    (re.compile(r"/home/(?!<user>|you)[a-z0-9_.-]{2,}/"), "Linux home 绝对路径"),
]

# 32/64 位十六进制密钥块（SHA-256 摘要非常常见，必须结合上下文区分）
KEY_LIKE = re.compile(r"\b[0-9a-fA-F]{64}\b")
KEY_LIKE_32 = re.compile(r"\b[0-9a-fA-F]{32}\b")
KEY_LIKE_16 = re.compile(r"\b[0-9a-fA-F]{16}\b")

# 这些上下文里的 hex 是哈希，不算密钥
HASH_CONTEXT = re.compile(
    r"(?i)(sha[-_ ]?256|sha[-_ ]?1|sha256sum|md5|hash|digest|checksum|"
    r"校验|摘要|指纹|manifest|\.sum|image_sha|"
    r"\|\s*`?(?:sha256|hash)`?\s*\|)"
)

# 真正危险的写法：从十六进制字面量装载密钥。
# 阈值取 32 个 hex 字符（16 字节）——ARM 指令补丁只有 8~16 字符，不会被误报，
# 而 AES-128/192/256 密钥正好是 32/48/64 字符。
KEY_LITERAL_USE = re.compile(
    r"(?i)(?:fromhex|unhexlify)\s*\(\s*[rbuf]*[\"'][0-9a-fA-F]{32,}[\"']"
)

# 密钥占位符是允许的（表示"此处应为密钥，但仓库不提供"）
REDACTED_MARK = re.compile(r"REDACTED_KEY_[A-Z0-9_]+")

MAX_TEXT_BYTES = 4 * 1024 * 1024


def iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in {".git", ".github"} and d not in FORBIDDEN_DIRS
        )
        # .github 需要遍历，但它的目录名单独处理
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def is_text(ext: str, path: str) -> bool:
    if ext in {".png"}:
        return False
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return False
    if b"\x00" in head:
        return False
    return True


def check_file(path: str, repo: str) -> tuple[list[str], list[str]]:
    """返回 (errors, warnings)。"""
    problems: list[str] = []
    warnings: list[str] = []
    rel = os.path.relpath(path, repo).replace("\\", "/")
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()

    if ext in FORBIDDEN_EXT:
        problems.append(f"[扩展名] {rel} —— 固件/二进制/密钥类扩展名")
    elif ext == "":
        if name.lower() not in {n.lower() for n in ALLOWED_BARE_NAMES}:
            problems.append(f"[扩展名] {rel} —— 无扩展名且不在白名单")
    elif ext not in ALLOWED_EXT:
        problems.append(f"[扩展名] {rel} —— 未在白名单内的扩展名 {ext}")

    if name.lower() in FORBIDDEN_NAMES:
        problems.append(f"[文件名] {rel} —— 索尼固件或库文件名")

    parts = set(p.lower() for p in rel.split("/")[:-1])
    if parts & FORBIDDEN_DIRS:
        problems.append(f"[目录] {rel} —— 位于禁止目录 {sorted(parts & FORBIDDEN_DIRS)}")

    if os.path.getsize(path) > MAX_TEXT_BYTES:
        problems.append(f"[体积] {rel} —— 超过 4 MiB 的文本，请确认不是数据文件")
        return problems, warnings

    if not is_text(ext, path):
        return problems, warnings

    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (UnicodeDecodeError, OSError):
        problems.append(f"[编码] {rel} —— 非 UTF-8 文本")
        return problems, warnings

    for rx, desc in PATH_LEAK_PATTERNS:
        m = rx.search(text)
        if m:
            problems.append(f"[路径] {rel} —— {desc}: {m.group(0)[:60]}")

    # 唯一硬性密钥判据：fromhex/unhexlify 装载长 hex 字面量
    for m in KEY_LITERAL_USE.finditer(text):
        problems.append(
            f"[密钥] {rel} —— 从 hex 字面量装载密钥：{m.group(0)[:48]}…"
        )
        break

    # 64 位 hex 无哈希标注：仅警告（绝大多数是 SHA-256 摘要）
    if not problems:
        for m in KEY_LIKE.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            line = text[line_start: line_end if line_end != -1 else len(text)]
            if HASH_CONTEXT.search(line) or REDACTED_MARK.search(line):
                continue
            warnings.append(
                f"[提示] {rel} —— 64 位 hex（疑似 SHA-256，请确认非密钥）：{m.group(0)[:16]}…"
            )
            break

    return problems, warnings


def git_staged_files(repo: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", repo, "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True, text=True, check=False,
    )
    return [os.path.join(repo, p) for p in out.stdout.splitlines() if p.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--staged", action="store_true", help="只检查 git 暂存区")
    ap.add_argument("--path", default=".", help="仓库根目录，默认当前目录")
    args = ap.parse_args()

    # Windows 控制台可能是 GBK/CP936，避免因 ✗/✓ 或多字节字符崩溃
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    repo = os.path.abspath(args.path)
    if args.staged:
        files = [f for f in git_staged_files(repo) if os.path.isfile(f)]
        mode = "暂存区"
    else:
        files = list(iter_files(repo))
        mode = "工作树"

    problems: list[str] = []
    warnings: list[str] = []
    for f in files:
        errs, warns = check_file(f, repo)
        problems.extend(errs)
        warnings.extend(warns)

    print(f"检查模式：{mode}")
    print(f"检查文件：{len(files)}")

    if warnings:
        print(f"\n{len(warnings)} 条提示（不阻断，建议人工确认）：\n")
        for w in warnings:
            print(f"  ! {w}")

    if problems:
        print(f"\n发现 {len(problems)} 个问题：\n")
        for p in problems:
            print(f"  x {p}")
        print("\n请修正后重新提交。规则见 CONTRIBUTING.md 与 SECURITY.md。")
        return 1

    print("\n通过：未发现固件、二进制、密钥或未脱敏路径。")
    print("提示：自动检查不能替代人工确认，提交前请再看一眼 diff。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
