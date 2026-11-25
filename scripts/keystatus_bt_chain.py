#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_bt_chain.py -- 还原"新断言"归属：FWRA 0x2B359F7/0x2B20821/0x2B20DA9/0x1D58FC1。

判定要点:
  * 每条 FWRA 是 TFRA 那帧的返回地址（奇数=Thumb），其所在函数才是"归属函数"；
  * 断言字符串/文件串直接给出函数身份；
  * 与 UPM boot-factor 家族(0x924127/0x28)对比: 队列、消息长度、检查类型全部不同。

产出 03-证据/静态分析/keystatus/10_bt_assert_chain.txt
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from keystatus_elfutil import DEFAULT_BIN, OUT_DIR, Dis, Img  # noqa: E402

FWRA = [0x2B359F7, 0x2B20821, 0x2B20DA9, 0x1D58FC1]
NOTIFY_RET = 0x2BC318B
UPM_FUNC = 0x2BBA4CC


def func_label(img: Img, s: int) -> str:
    return f'0x{s:08x}'


def main() -> int:
    img = Img(DEFAULT_BIN)
    dis = Dis(img)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    lines = ['# 新断言归属分析（运行期 FWRA: 0x2B359F7, 0x2B20821, 0x2B20DA9, 0x1D58FC1）',
             f'# notify 内部返回地址: 0x{NOTIFY_RET:08x}（0x2BC3174..0x2BC31BC 内）', '']

    # 1) 每个 FWRA 的归属函数
    lines.append('## 1. FWRA -> 归属函数')
    for ra in FWRA:
        a = ra & ~1
        fs = img.func_start(a)
        fe = img.func_end(a)
        lines.append(f'  FWRA 0x{ra:08x}  归属函数 0x{fs:08x}..0x{fe:08x} '
                     f'(帧内 +0x{a - fs:x}，即返回地址来自 0x{a - 4:08x} 的 BL)')
    lines.append('')

    # 2) 归属函数的断言字符串 + 关键调用
    detail = [
        (0x2B3571C, 'FWRA#1 归属: 断言直接调用者'),
        (0x2B20810, 'FWRA#2 归属: BT classic 相位包装'),
        (0x2B20CE0, 'FWRA#3 归属: 应用初始化序列'),
        (0x1D58F98, 'FWRA#4 归属: 顶层初始化函数'),
    ]
    lines.append('## 2. 各归属函数的身份证据')
    for start, title in detail:
        st, en = img.func_range(start)
        lines.append(f'### {title}: 0x{st:08x}..0x{en:08x} ({en - st} B)')
        strs, seen = [], set()
        for ins, ann in dis.disasm(st, min(en, st + 0x1800)):
            if '-> 0x' in ann and '"' in ann:
                s = ann.split('"')[1]
                if s not in seen:
                    seen.add(s)
                    if any(k in s for k in ('bt_classic', 'msg_qid', 'IM_', 'alloc_msgq',
                                            '.cpp', 'assert at', 'main(', 'Failure')):
                        strs.append((ins.address, s))
        for a, s in strs[:14]:
            lines.append(f'    {a:08x}  "{s}"')
        # 关键 BL
        calls = []
        for ins, ann in dis.disasm(st, min(en, st + 0x1800)):
            if '<' in ann and ins.mnemonic in ('bl', 'blx'):
                calls.append((ins.address, ann.split('<')[-1].rstrip('>')))
        lines.append('    关键调用: ' + ', '.join(f'0x{a:08x}->{n}' for a, n in calls[:12]))
        lines.append('')

    # 3) 与 UPM 家族对比
    lines.append('## 3. 与 UPM boot-factor 家族对比')
    lines.append('  项                  | UPM boot-factor 路径            | 本次新断言路径')
    lines.append('  --------------------|---------------------------------|---------------------------------')
    lines.append('  uipc qid            | 0x00924127（upm.ko framework#4）| 0x0094016A（im.elf 的 IM 服务）')
    lines.append('  请求 mid / 命令     | 0x00920111（get boot factor）    | 0x00940021（IM_open）')
    lines.append('  消息长度            | 请求/应答 0x28，四代只回填 0x1C  | 0x10（恰好填满，无越界读取）')
    lines.append('  失败判据            | 应答字段越出枚举集合 -> notify   | IM_open 返回码/应答[4]非0 -> notify')
    lines.append('  直接调用者          | infra_wrapper_upm::detail::      | infra_wrapper_bt_classic::detail::')
    lines.append('                      | upm2model_convert_*              | load_im() / create_msg_qid()')
    lines.append('  结论                | 四代内核 0x1C vs 五代 0x28 ABI   | IM 服务层失败（对象/后端不可用），')
    lines.append('                      | 越界 -> 本次补丁 A 修复          | 与 0x28 结构无关，是下一个独立阻塞点')
    lines.append('')

    # 4) IM 服务侧证据（im.elf）
    impl = img.data  # 仅用于对照默认镜像；IM 服务证据从 im.elf 单独读
    lines.append('## 4. IM 服务侧证据（四代 im.elf，与 appFw 同进程宿主）')
    lines.append('  - im.elf main() @0x9F58：0x9FB4 调用 0x91CC 注册/使用 qid 0x0094016A，')
    lines.append('    0x9FE4 起进入消息循环（0xA410/0x97C8/osal_rcv_msg_tmo 等）。')
    lines.append('  - IM 服务分发函数 @0x9634：msg[0] 分派')
    lines.append('      0x009400E1 -> 应答[4]=0x12345678（版本/握手）')
    lines.append('      0x00940021 -> IM_open：ldrh r0,[msg+4]=id(0x19F), r1=msg[8]=3(版本), r2=msg[0xC]')
    lines.append('      0x00940022 -> IM_close')
    lines.append('  - appFw 侧 helper 0x2B355C4：valloc(qid=0x0094016A,size=0x10) ->')
    lines.append('      填 {code=0x940021, id=0x19F, ver=3, arg} -> snd_sync -> 拷回 4 字应答')
    lines.append('  - load_im() 判定：helper 返回码非 0，或应答[+4] 非 0 -> "Failure IM_open()" -> notify。')
    lines.append('')
    lines.append('## 5. 结论')
    lines.append('  FWRA 链全部落在 infra_wrapper_bt_classic 的初始化相位（create_msg_qid/load_im），')
    lines.append('  与 upm2model_convert_* 家族无调用/数据关系；不是"读 0x28 字节检查五代新增字段"的同一族，')
    lines.append('  而是 UPM 断言被修复后暴露出的下一个独立阻塞点（IM_open 失败）。')

    outp = OUT_DIR / '10_bt_assert_chain.txt'
    outp.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('\n'.join(lines))
    print('written', outp)
    return 0


if __name__ == '__main__':
    sys.exit(main())
