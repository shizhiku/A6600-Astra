#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_disasm.py -- 反汇编五代 appFw.so 中 key_status 相关函数。

输出到 03-证据/静态分析/keystatus/。只读分析，不执行目标，不修改镜像。

用法:
    python 02-脚本/keystatus_disasm.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from keystatus_elfutil import DEFAULT_BIN, OUT_DIR, Dis, Img  # noqa: E402

# 任务书给定的地址（文件内 VA）
TARGETS = [
    (0x2BBA4CC, 'A. 模型/状态同步请求+分发器（notify_model_system_error 直接调用者）'),
    (0x2B44978, 'B. 上层包装（event 9 的调用者）'),
    (0x2B1E4BC, 'C. event 9 thunk'),
    (0x2B1E408, 'D. thunk 组附近'),
    (0x2B1E4D0, 'E. thunk 组第二入口'),
    (0x2CE8498, 'F. 接收函数（实为 ARM 长跳 veneer -> osal_valloc_msg_wait）'),
    (0x2CE7E5C, 'G. veneer -> osal_snd_sync_msg'),
    (0x2CE8654, 'H. veneer -> usleep'),
    (0x2CE8790, 'I. veneer -> printf'),
    (0x2BB78C0, 'J. 另一个引用 qid 0x920111 的区域（如有）'),
    (0x2BBA3C0, 'K. 0x2BBA4CC 前一个函数（另一处 0x924127 引用）'),
]


def main() -> int:
    img = Img(DEFAULT_BIN)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / '01_disasm_key_functions.txt'
    dis = Dis(img, 'thumb')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(f'# 目标: {DEFAULT_BIN}\n')
        f.write(f'# .text 0x{img.elf.get_section_by_name(".text")["sh_addr"]:x} + '
                f'0x{img.elf.get_section_by_name(".text")["sh_size"]:x}\n')
        f.write(f'# exidx 函数数={len(img.exidx_starts)}  PLT 导入={len(img.plt_syms)}  '
                f'ARM 长跳 veneer={len(img.veneer_syms)}\n')
        for start, title in TARGETS:
            st, en = img.func_range(start)
            f.write(f'\n===== {title}\n')
            f.write(f'===== FUNC 0x{st:08x}..0x{en:08x} ({en - st} B)\n')
            n = 0
            for ins, ann in dis.disasm(st, en):
                f.write(f'{ins.address:08x}  {ins.bytes.hex():<10} {ins.mnemonic:<8} {ins.op_str}{ann}\n')
                n += 1
            f.write(f'# ({n} instructions)\n')
    print('written', out_path, out_path.stat().st_size, 'B')
    return 0


if __name__ == '__main__':
    sys.exit(main())
