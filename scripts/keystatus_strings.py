#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_strings.py -- 列出指定函数内所有 PC 字面量/字符串引用。

用法: python 02-脚本/keystatus_strings.py [起始地址 hex] [结束地址 hex]
默认输出 0x2BBA4CC 函数（UPM->model 转换分发器）的全部字符串。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from keystatus_elfutil import DEFAULT_BIN, OUT_DIR, Dis, Img  # noqa: E402


def main() -> int:
    start = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x2BBA4CC
    img = Img(DEFAULT_BIN)
    st, en = img.func_range(start)
    end = int(sys.argv[2], 0) if len(sys.argv) > 2 else en
    lines = [f'# 函数 0x{st:08x}..0x{end:08x} 的字符串/符号引用']
    d = Dis(img)
    seen = set()
    for ins, ann in d.disasm(st, end):
        if '-> 0x' in ann and '"' in ann:
            s = ann.split('"')[1]
            if s in seen:
                continue
            seen.add(s)
            lines.append(f'{ins.address:08x}  "{s}"')
    txt = '\n'.join(lines) + '\n'
    outp = OUT_DIR / '08_function_strings.txt'
    outp.write_text(txt, encoding='utf-8')
    print(txt)
    return 0


if __name__ == '__main__':
    sys.exit(main())
