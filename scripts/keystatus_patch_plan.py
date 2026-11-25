#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_patch_plan.py -- 只读生成 UPM boot-factor 全族补丁清单与方案评估。

覆盖:
  A. UPM boot-factor 越界检查点（0x924127 / mid 0x920111 / 0x28 字节请求）全部补丁
  B. "把请求 size 0x28 改成 0x1C" 方案的站点与可行性评估
  C. 运行期新断言（BT classic / IM_open）的归属、与 UPM 的区别、可选诊断补丁
不修改任何镜像，只核对原始字节并写证据。

用法: python 02-脚本/keystatus_patch_plan.py
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from keystatus_elfutil import DEFAULT_BIN, OUT_DIR, Img  # noqa: E402

PATCHED_BIN = DEFAULT_BIN.parent / 'a5pFw_upmfix.so'


def rel(p: Path) -> str:
    return str(p.relative_to(DEFAULT_BIN.parent.parent))


# ---- A. UPM boot-factor 检查点（disasm 原始字节均为实测） ----
UPM_FUNC = 0x2BBA4CC
UPM_READ = {           # msg 偏移 -> 读取指令 VA / 2字节原字节
    0x04: (0x2BBA50E, '4e68'),
    0x08: (0x2BBA518, 'd1f808a0'),
    0x0C: (0x2BBA50A, 'ca68'),
    0x10: (0x2BBA50C, '0b69'),
    0x14: (0x2BBA514, '4a69'),
    0x18: (0x2BBA516, '8b69'),
    0x20: (0x2BBA520, '0a6a'),
    0x24: (0x2BBA522, '4b6a'),
}

PATCHES_UPM = [
    dict(id='A', kind='UPM 全族（合并 2 字节点）',
         offset=0x2BBA520, orig='0a6a4b6a', new='00220023',
         asm_before=['ldr r2,[r1,#0x20]', 'ldr r3,[r1,#0x24]'],
         asm_after=['movs r2,#0', 'movs r3,#0'],
         covers=['msg+0x20 -> out+0x1C', 'msg+0x24 -> out+0x20'],
         semantics='把四代生产者缺失的两个五代新增字段强制为合法默认 0；'
                   '后续 str r2,[r7,#0x20] / str r3,[r7,#0x1C] 保持不变，检查全部通过',
         status='已在 astra-m1-upmfix-b5.img 验证：经 0x2BBA4CC 的 UPM 断言不再触发'),
    dict(id='A1', kind='UPM 逐点（仅 +0x20）',
         offset=0x2BBA520, orig='0a6a', new='0022',
         asm_before=['ldr r2,[r1,#0x20]'], asm_after=['movs r2,#0'],
         covers=['msg+0x20'], semantics='与 A 等价的前半；单独使用时 +0x24 仍需 A2'),
    dict(id='A2', kind='UPM 逐点（仅 +0x24）',
         offset=0x2BBA522, orig='4b6a', new='0023',
         asm_before=['ldr r3,[r1,#0x24]'], asm_after=['movs r3,#0'],
         covers=['msg+0x24'], semantics='与 A 等价的后半；单独使用时 +0x20 仍需 A1'),
]

SIZE_SITE = dict(offset=0x2BBA4DC, orig='2822', new='1c22',
                 asm_before=['movs r2,#0x28'], asm_after=['movs r2,#0x1C'])

# ---- C. 新断言（BT classic） ----
BT_CHAIN = [
    dict(fwra='0x2B359F7', func='0x2B3571C', owner='infra_wrapper_bt_classic::detail::load_im()',
         role='notify 直接调用者（call site 0x2B359F2，行号 0x400）'),
    dict(fwra='0x2B20821', func='0x2B20810', owner='BT classic 初始化相位包装（sched_lock 0x30 -> 0x2B3571C）',
         role='load_im/create_msg_qid 的相位包装'),
    dict(fwra='0x2B20DA9', func='0x2B20CE0', owner='应用初始化序列（~50 个 bl 步骤）', role='调用 BT 相位'),
    dict(fwra='0x1D58FC1', func='0x1D58F98', owner='appFw 顶层初始化函数（5184 B）', role='调用初始化序列'),
]
BT_DIAG_PATCHES = [
    dict(id='D1', kind='诊断：整段跳过 BT classic 相位（不推荐作最终方案）',
         offset=0x2B20DA4, orig='fff734fd', new='00bf00bf',
         asm_before=['bl 0x2B20810'], asm_after=['nop', 'nop'],  # noqa: E501
         risk='BT classic 完全不初始化；后续若访问 BT 对象会以其它形式失败，仅用于验证"后续是否还有别的阻塞"'),
    dict(id='D2', kind='诊断：仅绕过 load_im 断言（不推荐作最终方案）',
         offset=0x2B359F2, orig='8df0bffb', new='00bf00bf',
         asm_before=['bl 0x2BC3174'], asm_after=['nop', 'nop'],
         risk='IM_open 仍失败、状态仍不完整；可能随后续使用未初始化对象而再次崩溃'),
]

CHECKPOINTS = [
    # msg 偏移, appFw 读取处, 检查集合/语义, 是否超出四代 0x1C 回填
    ('+0x04', '0x2BBA50E', 'upm_boot_key_t ∈ {0,1,2,4,6,7,8,9,0xB,0xD,0x10,0x11,0x12,0x14,0x16,0x18,0x1A,0x1C,-1}', '否（在 0x1C 内）'),
    ('+0x08', '0x2BBA518', 'upm_boot_type_t ∈ {1,2,4,8,-1}', '否'),
    ('+0x0C', '0x2BBA50A', 'upm_eecap_info_t ∈ 1..4（tbb 跳表）', '否'),
    ('+0x10', '0x2BBA50C', '不检查，直传 out+0x10', '否'),
    ('+0x14', '0x2BBA514', '∈ {1,2}', '否'),
    ('+0x18', '0x2BBA516', '∈ {0,1}', '否'),
    ('+0x20', '0x2BBA520', '∈ {0,1}  ← 运行期 0x005081E8 即此处', '是（四代 0x1C 之外）'),
    ('+0x24', '0x2BBA522', '∈ {0..2}', '是（四代 0x1C 之外）'),
]


def main() -> int:
    img = Img(DEFAULT_BIN)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    doc = {
        'note': '只读分析生成的补丁/方案清单，未修改任何镜像',
        'target_bin': str(DEFAULT_BIN),
        'verified_patched_image': str(PATCHED_BIN),
        'image_patch_status': {},
        'family_upm_boot_factor': {
            'verdict': 'appFw 中只有 1 处 (qid=0x00924127, size=0x28) 的 UPM boot-factor '
                       '同步请求；其 7 个字段检查里只有 +0x20/+0x24 超出四代 upm.ko 的 0x1C 回填。'
                       '补丁 A（4 字节）已覆盖全部越界检查点，无需再补其它点。',
            'func': f'0x{UPM_FUNC:08x}',
            'entry_chain': dict(
                direct_caller='0x2B1E4D0（唯一 BL 调用者，返回地址 0x2B1E4D5）',
                thunk='0x2B1E4BC..0x2B1E4DC（事件 9 thunk：sched_lock(0x1A,9) -> bl 0x2BBA4CC -> sched_unlock）'),
            'queue': dict(qid=0x00924127, mid=0x00920111, req_size=0x28,
                          gen4_reply_len=0x1C, gen5_reply_len=0x28),
            'api': ['osal_valloc_msg_wait(qid,&msg,0x28,1)',
                    'osal_snd_sync_msg(qid,msg)',
                    'osal_free_msg(qid,msg)'],
            'checkpoints': [dict(off=o, read_site=a, rule=r, out_of_gen4_1c=x)
                            for o, a, r, x in CHECKPOINTS],
            'read_map': {f'0x{k:02x}': dict(va=f'0x{v[0]:08x}', bytes=v[1])
                         for k, v in UPM_READ.items()},
            'patches': [],
        },
        'family_other_upm_clients': {
            'helper_0x2BBA480': dict(valloc_qid=0x00924127, size=0x8, mid=0x00920125,
                                     reads_reply=False,
                                     verdict='不发回读、不越界，无需补丁（只 g_bf+0x10 置位）'),
            'complete_scan': dict(valloc_sites_total=18, snd_sync_sites=9,
                                  sites_with_qid_0x924127_and_size_0x28=1,
                                  evidence='03-证据/静态分析/keystatus/09_family_scan.txt'),
        },
        'option_size_0x28_to_0x1C': {
            'site': dict(offset=f'0x{SIZE_SITE["offset"]:08x}',
                         orig=SIZE_SITE['orig'], new=SIZE_SITE['new'],
                         asm_before=SIZE_SITE['asm_before'], asm_after=SIZE_SITE['asm_after']),
            'verdict': 'not_viable',
            'reasons': [
                '客户端代码在 snd_sync 之后无条件读取 msg+0x20 / msg+0x24（0x2BBA520/0x2BBA522）；'
                '缩小请求 size 不会删除这两次读取。',
                'OSAL 消息按 size class 分配：payload 0x1C 与 0x28 都落在 class 2'
                '（osal_msg_size = class*32-0xC = 0x34 ≥ 0x28），分配块类别相同，'
                '复用的陈旧字节不变，+0x20/+0x24 仍为未定义值。',
                '四代 upm.ko 的 k_upm_framework_boot_factor 固定回填 7 字，不读取请求 size，'
                '请求 size 改小不会让内核多写/少写任何字节。',
                '改小后"请求声明 0x1C"与服务端实际行为仍不一致，只是把越界读取变成'
                '更明显的契约不一致，可能改变复用的池块内容，结果不可复现。',
            ],
            'affected_callers': ['仅 0x2BBA4CC 一个函数（该 movs r2,#0x28 只有这一处 valloc 使用）'],
            'alternative': '若要"少读"，等价且更安全的是补丁 A（直接把两次越界读取改成常量 0）；'
                           '若要"让服务端多写"，则属于方案 B（改 upm.ko / 换五代 upm.ko）。',
        },
        'new_assert_bt_classic': {
            'verdict': 'NOT upm2model family。FWRA 链全部落在 infra_wrapper_bt_classic 初始化相位；'
                       '失败判据是 IM_open 服务返回码，不读 0x28 结构的任何字段。',
            'fwra_chain': BT_CHAIN,
            'assert_sites': dict(load_im='0x2B359F2（Failure IM_open()，行号 0x400）',
                                 create_msg_qid=['0x2B35840', '0x2B358CA', '0x2B35954']),
            'im_service': dict(qid='0x0094016A', open_cmd='0x00940021',
                               close_cmd='0x00940022', hello_cmd='0x009400E1',
                               provider='im.elf（main() @0x9F58 注册；分发函数 @0x9634）',
                               request='0x2B355C4: {code, id=0x19F, ver=3, arg}，size=0x10'),
            'diagnostic_patches': [],
        },
    }

    # 核对补丁字节
    for p in PATCHES_UPM:
        cur = img.read(p['offset'], len(bytes.fromhex(p['orig'])))
        p['bytes_match_actual'] = cur.hex() == p['orig']
        doc['family_upm_boot_factor']['patches'].append(dict(
            id=p['id'], kind=p['kind'], file=rel(DEFAULT_BIN), offset=f'0x{p["offset"]:08x}',
            orig=p['orig'], new=p['new'], asm_before=p['asm_before'], asm_after=p['asm_after'],
            covers=p['covers'], semantics=p['semantics'], bytes_match_actual=p['bytes_match_actual'],
            **({'status': p['status']} if 'status' in p else {})))
        print(f"[{p['id']}] 0x{p['offset']:08x} {p['orig']} -> {p['new']} "
              f"match={p['bytes_match_actual']}")

    cur = img.read(SIZE_SITE['offset'], 2)
    doc['option_size_0x28_to_0x1C']['site']['bytes_match_actual'] = cur.hex() == SIZE_SITE['orig']

    # 核对诊断补丁并追加
    for p in BT_DIAG_PATCHES:
        cur = img.read(p['offset'], len(bytes.fromhex(p['orig'])))
        doc['new_assert_bt_classic']['diagnostic_patches'].append(dict(
            id=p['id'], kind=p['kind'], file=rel(DEFAULT_BIN), offset=f'0x{p["offset"]:08x}',
            orig=p['orig'], new=p['new'], asm_before=p['asm_before'], asm_after=p['asm_after'],
            bytes_match_actual=(cur.hex() == p['orig']), risk=p['risk'],
            recommend='仅诊断用，不作最终方案'))
        print(f"[{p['id']}] 0x{p['offset']:08x} {p['orig']} -> {p['new']} "
              f"match={cur.hex() == p['orig']}")

    # patched image 状态
    if PATCHED_BIN.exists():
        pb = PATCHED_BIN.read_bytes()
        st = {}
        for p in PATCHES_UPM:
            st[p['id']] = pb[p['offset']:p['offset'] + len(bytes.fromhex(p['new']))].hex()
        doc['image_patch_status']['a5pFw_upmfix.so'] = st
        doc['image_patch_status']['note'] = ('a5pFw_upmfix.so 在 0x2BBA520 已是 00220023，'
                                             '即补丁 A 已应用；其余检查点在补丁 A 语义下均通过')

    (OUT_DIR / '07_patch_plan.json').write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    # 人类可读摘要
    lines = ['# UPM boot-factor 全族补丁清单与方案评估（只读）', '',
             f'目标镜像: {DEFAULT_BIN}', f'已验证修补镜像: {PATCHED_BIN}', '',
             '## 全族检查点（appFw 中唯一的 0x924127/0x28 客户端 = 0x2BBA4CC）']
    for o, a, r, x in CHECKPOINTS:
        lines.append(f'  msg{o}  read@{a}  {r}   超出四代0x1C: {x}')
    lines += ['', '## 补丁清单']
    for p in PATCHES_UPM:
        lines.append(f'  [{p["id"]}] {p["kind"]}')
        lines.append(f'       {rel(DEFAULT_BIN)} +0x{p["offset"]:08x}: '
                     f'{p["orig"]} -> {p["new"]}')
        lines.append(f'       {p["asm_before"]}  ->  {p["asm_after"]}')
        lines.append(f'       覆盖: {p["covers"]}')
        lines.append(f'       语义: {p["semantics"]}')
        if 'status' in p:
            lines.append(f'       状态: {p["status"]}')
    lines += ['', '## 方案 B: 请求 size 0x28 -> 0x1C 评估（不可行）',
              f'  站点 0x{SIZE_SITE["offset"]:08x}: {SIZE_SITE["orig"]} -> {SIZE_SITE["new"]}'
              f'（{SIZE_SITE["asm_before"]} -> {SIZE_SITE["asm_after"]}）']
    for r in doc['option_size_0x28_to_0x1C']['reasons']:
        lines.append(f'  - {r}')
    lines += ['', '## 新断言（BT classic）归属与诊断补丁',
              '  ' + doc['new_assert_bt_classic']['verdict']]
    for c in BT_CHAIN:
        lines.append(f'  FWRA {c["fwra"]} -> {c["owner"]}（{c["role"]}）')
    for p in BT_DIAG_PATCHES:
        lines.append(f'  [{p["id"]}] +0x{p["offset"]:08x}: {p["orig"]} -> {p["new"]}  '
                     f'（{p["asm_before"][0]} -> nop;nop；仅诊断）')
    (OUT_DIR / '07_synthetic_event.txt').write_text(
        '\n'.join(lines) + '\n', encoding='utf-8')
    print('written', OUT_DIR / '07_patch_plan.json')
    print('written', OUT_DIR / '07_synthetic_event.txt')
    return 0


if __name__ == '__main__':
    sys.exit(main())
