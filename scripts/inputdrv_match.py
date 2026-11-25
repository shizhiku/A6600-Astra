# -*- coding: utf-8 -*-
"""inputdrv_match.py — 用"归一化指令序列相似度"把五代 libObj 的静态函数对到四代已知 InfraInput 线程。

四代已知（文档 92）：
  InfraInput::MainThread  0x862430 size 0x780
  InfraInput::RecvThread  0x862D60 size 0x3F8
  InfraInput::EventThread 0x860A68 size 0x1C0
  InfraInput::RepeatThread 区 0x863158 size 0x1D4
五代：在 qidmap 命中的静态函数里找相似度最高的。
"""
import difflib
import importlib.util
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'
_spec = importlib.util.spec_from_file_location('c', BASE / '02-脚本/inputdrv_consumers.py')
c = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c)
_spec2 = importlib.util.spec_from_file_location('q', BASE / '02-脚本/inputdrv_queue.py')
q = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(q)

KNOWN = {
    'InfraInput::MainThread': (0x862430, 0x780),
    'InfraInput::RecvThread': (0x862D60, 0x3F8),
    'InfraInput::EventThread': (0x860A68, 0x1C0),
    'InfraInput::RepeatThread': (0x863158, 0x1D4),
}
CANDS = [0x209c58, 0x20a588, 0x208394, 0x2078a4]


def seq(ds, va, size):
    out = []
    for x in ds.dis(va, size):
        parts = x.split()
        if len(parts) >= 3:
            mn = parts[2]
            # 去掉地址/操作数里的立即数差异，只留助记符
            out.append(mn)
    return out


def main():
    g4 = q.Dso(OUT / 'g4_libObj.so')
    g5 = q.Dso(OUT / 'g5_libObj.so')
    lines = []
    s4 = {k: seq(g4, v, s) for k, (v, s) in KNOWN.items()}
    for k, v in s4.items():
        lines.append(f'g4 {k} @0x{KNOWN[k][0]:x}: {len(v)} insns')
    for cand in CANDS:
        s5 = seq(g5, cand, 0xC00)
        best = []
        for k, s in s4.items():
            r = difflib.SequenceMatcher(None, s, s5[:len(s) * 2], autojunk=False).ratio()
            best.append((r, k))
        best.sort(reverse=True)
        lines.append(f'g5 static_0x{cand:x}: ' +
                     ', '.join(f'{k}={r:.2f}' for r, k in best[:3]))
    (OUT / 'inputdrv_match_g5_to_g4.txt').write_text('\n'.join(lines), encoding='utf-8')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
