"""grm_runtime_evidence.py -- 从既有 QEMU 运行日志中摘出 grm_init 阻塞/成功对照证据.

只读 03-证据/ASTRA-97/*/serial.log; 只写 03-证据/静态分析/grm/grm_runtime_evidence.txt.
"""
from __future__ import annotations

import os

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(WS, "03-证据", "ASTRA-97")
OUT = os.path.join(WS, "03-证据", "静态分析", "grm", "grm_runtime_evidence.txt")
RUNS = {
    "bridge4_hang": "m1-init4-20261121T202636Z-13268-1",
    "bridge5_ok": "m1-init5-20261121T202852Z-13324-1",
    "bridge5_ok2": "m1-init5-threads-20261121T203304Z-13746-1",
    "bridge5_threads": "m1-threads3-20261121T201103Z-12068-1",
}


def lines(run: str) -> list[str]:
    p = os.path.join(BASE, run, "serial.log")
    with open(p, "rb") as f:
        return f.read().decode("utf-8", "replace").splitlines()


def find(ls: list[str], needle: str) -> list[int]:
    return [i + 1 for i, l in enumerate(ls) if needle in l]


def grab(out: list[str], run: str, ls: list[str], lo: int, hi: int,
         tag: str) -> None:
    out.append("===== %s  (%s)  行 %d-%d =====" % (tag, run, lo, hi))
    for i in range(max(0, lo - 1), min(hi, len(ls))):
        out.append("%6d  %s" % (i + 1, ls[i][:190]))
    out.append("")


def main() -> int:
    out: list[str] = []
    out.append("grm_init 运行时对照证据 (来源: 03-证据/ASTRA-97, 只摘录, 未改日志)")
    out.append("")
    # 1) bridge4 卡住
    run = RUNS["bridge4_hang"]
    ls = lines(run)
    i = find(ls, "init grm_init =")[0]
    grab(out, run, ls, i - 3, i + 14, "bridge4: 直接调用 grm_init, 卡住")
    out.append("该 run: '!!! GLES Vecgen'=%d 次, '===== DMP_2D_Initialize'=%d 次"
               % (len(find(ls, "!!! GLES Vecgen")),
                  len(find(ls, "===== DMP_2D_Initialize"))))
    out.append("=> 第二条 (5代) DMP_2D_Initialize 行永不出现, 也没有 'init grm_init returned'。")
    out.append("")
    # 2) bridge5 成功
    run = RUNS["bridge5_ok"]
    ls = lines(run)
    i = find(ls, "init grm_init start")[0]
    grab(out, run, ls, i - 24, i + 40,
         "bridge5: 在 DDS/uxengine/WidgetLayouter/infra_input/MWF 之后调用 -> 返回")
    out.append("该 run: '!!! GLES Vecgen'=%d 次, '===== DMP_2D_Initialize'=%d 次"
               % (len(find(ls, "!!! GLES Vecgen")),
                  len(find(ls, "===== DMP_2D_Initialize"))))
    out.append("")
    # 3) bridge5 线程名
    run = RUNS["bridge5_threads"]
    ls = lines(run)
    idx = [i for i in find(ls, "COMM grm_") + find(ls, "COMM THREAD_INFRA0")]
    if idx:
        grab(out, run, ls, idx[0] - 2, idx[0] + 8,
             "bridge5 成功路径里出现的 grm 相关线程")
    # 4) 两种顺序的 init 行对照
    for tag, r in (("bridge4", RUNS["bridge4_hang"]),
                   ("bridge5", RUNS["bridge5_ok"])):
        ls = lines(r)
        out.append("===== %s: [ASTRA97] 初始化行 =====" % tag)
        for i, l in enumerate(ls):
            if "[ASTRA97]" in l:
                out.append("%6d  %s" % (i + 1, l[:180]))
        out.append("")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print("written:", OUT, len(out), "lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
