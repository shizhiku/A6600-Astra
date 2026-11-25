#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_extract_upm.py -- 从四代/五代 usr ext2 镜像中提取 upm.ko 等关键文件。

只读打开原固件镜像，提取件写入 03-证据/静态分析/keystatus/。
不修改镜像、不执行目标代码。

用法: python 02-脚本/keystatus_extract_upm.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / '02-脚本'))

spec = importlib.util.spec_from_file_location('_ext2', ROOT / '02-脚本/a6600_usr.py')
_ext2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_ext2)
Ext2 = _ext2.Ext2

IMAGES = {
    'g4': ROOT / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15',
    'g5': ROOT / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15',
}
OUT = ROOT / '03-证据/静态分析/keystatus'
WANT_NAME = {'upm.ko', 'input.ko', 'mcmn_drv.ko', 'liro.ko'}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    report = []
    for gen, img in IMAGES.items():
        if not img.exists():
            print('missing image', img)
            continue
        fs = Ext2(str(img))
        print(f'==== {gen} {img}')
        found = {}
        for path, ino, is_dir in fs.walk():
            if is_dir:
                continue
            base = path.rsplit('/', 1)[-1]
            if base in WANT_NAME or 'upm' in base.lower():
                found[path] = ino
        for path, ino in sorted(found.items()):
            mode, size, _ = fs.inode(ino)
            data = fs.read_file(ino)
            sha = hashlib.sha256(data).hexdigest()
            base = path.rsplit('/', 1)[-1]
            dst = OUT / f'{gen}_{base}'
            if not dst.exists():
                dst.write_bytes(data)
            line = f'{gen} {path} size={size} sha256={sha} -> {dst.name}'
            print(line)
            report.append(line)
    (OUT / '00_extracted_files.txt').write_text('\n'.join(report) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    sys.exit(main())
