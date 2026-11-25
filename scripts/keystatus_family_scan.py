#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_family_scan.py -- 全 .text 扫描 appFw 中所有 notify_model_system_error
调用点与所有 OSAL 分配/发送调用点，重建"UPM 同步消息客户端族"。

实现: 纯标准库。先按 Thumb-2 32 位指令首字节特征 (0xF0..0xF7, 半字对齐) 提取候选，
再解 BL/BLX 的 S/I1/I2/J1/J2 位域得到目标地址，避免逐指令 capstone 解码 41MB。

产出 03-证据/静态分析/keystatus/09_family_scan.txt
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from keystatus_elfutil import DEFAULT_BIN, OUT_DIR, Dis, Img  # noqa: E402

NOTIFY = 0x2BC3174
VALLOC = 0x2CE8498      # veneer -> osal_valloc_msg_wait
SNDSYNC = 0x2CE7E5C     # veneer -> osal_snd_sync_msg
FREEMSG = 0x2CE8420     # veneer -> osal_free_msg

CAND_RE = re.compile(rb'.[\xf0-\xf7]', re.DOTALL)


def decode_calls(text_addr: int, data: bytes, wanted: dict):
    """返回 {name: [(site_va, kind)]}，只保留命中 wanted 目标地址的调用。"""
    out = {k: [] for k in wanted}
    n = len(data)
    for m in CAND_RE.finditer(data):
        o = m.start()
        if o & 1 or o + 4 > n:
            continue
        hw1 = data[o] | (data[o + 1] << 8)
        hw2 = data[o + 2] | (data[o + 3] << 8)
        if (hw1 & 0xF800) != 0xF000:
            continue
        S = (hw1 >> 10) & 1
        imm10 = hw1 & 0x3FF
        J1 = (hw2 >> 13) & 1
        J2 = (hw2 >> 11) & 1
        I1 = 1 - (J1 ^ S)
        I2 = 1 - (J2 ^ S)
        a = text_addr + o
        pc = a + 4                      # Thumb-2 BL/BLX: PC = 指令地址 + 4（不额外对齐）
        if (hw2 & 0xD000) == 0xD000:          # BL: hw2 = 11 J1 1 J2 imm11
            imm32 = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | ((hw2 & 0x7FF) << 1)
            kind = 'bl'
        elif (hw2 & 0xD001) == 0xC000:        # BLX: hw2 = 11 J1 0 J2 imm10L, bit0=0
            imm10l = (hw2 >> 1) & 0x3FF
            imm32 = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm10l << 2)
            kind = 'blx'
        else:
            continue
        if imm32 >= (1 << 24):
            imm32 -= 1 << 25
        tgt = (pc + imm32) & 0xFFFFFFFF
        for name, want in wanted.items():
            if tgt == want:
                out[name].append((a, kind))
    return out


def main() -> int:
    img = Img(DEFAULT_BIN)
    text = img.elf.get_section_by_name('.text')
    tb, td = text['sh_addr'], text.data()
    hits = decode_calls(tb, td, {'notify': NOTIFY, 'valloc': VALLOC,
                                 'snd_sync': SNDSYNC, 'free': FREEMSG})
    for k, v in hits.items():
        print(k, len(v))

    lines = [f'# .text 0x{tb:08x}+0x{len(td):x}，Thumb-2 BL/BLX 立即数全量扫描',
             f'# notify=0x{NOTIFY:08x} valloc_veneer=0x{VALLOC:08x} '
             f'snd_sync_veneer=0x{SNDSYNC:08x} free_veneer=0x{FREEMSG:08x}', '']
    lines.append(f'## 命中计数: notify={len(hits["notify"])} valloc={len(hits["valloc"])} '
                 f'snd_sync={len(hits["snd_sync"])} free={len(hits["free"])}')
    lines.append('')

    def func_of(va):
        fs = img.func_start(va)
        return (fs & ~1) if fs is not None else None

    agg = {}
    for k in ('notify', 'valloc', 'snd_sync'):
        for site, kind in hits[k]:
            f = func_of(site)
            if f is None:
                continue
            agg.setdefault(f, {k2: [] for k2 in ('notify', 'valloc', 'snd_sync')})[k].append(site)

    lines.append(f'## notify 调用者函数数: {sum(1 for v in agg.values() if v["notify"])}')
    lines.append(f'## valloc 调用者函数数: {sum(1 for v in agg.values() if v["valloc"])}')
    lines.append(f'## 同时出现 valloc+notify 的函数数: '
                 f'{sum(1 for v in agg.values() if v["valloc"] and v["notify"])}')
    lines.append('')

    dis = Dis(img)

    def valloc_args(fstart, site):
        regs = {}
        for ins, ann in dis.disasm(fstart, site + 2):
            op = ins.op_str
            if ins.mnemonic.startswith('ldr') and '[pc' in op:
                i = op.rfind('#')
                if i >= 0:
                    imm = int(op[i + 1:].rstrip(']'), 0)
                    lva = ((ins.address + 4) & ~3) + imm
                    reg = op.split(',')[0].strip()
                    try:
                        regs[reg] = img.u32(lva)
                    except ValueError:
                        regs.pop(reg, None)
            elif ins.mnemonic in ('movs', 'mov.w', 'mov'):
                toks = [t.strip() for t in op.split(',')]
                if len(toks) == 2 and toks[1].startswith('#'):
                    try:
                        regs[toks[0]] = int(toks[1][1:], 0)
                    except ValueError:
                        pass
        return regs.get('r0'), regs.get('r2')

    # 只详细列出：同时含 notify 或 valloc 的函数（其余噪声略）
    for f, d in sorted(agg.items(), key=lambda x: x[0]):
        if not d['notify'] and not d['valloc']:
            continue
        st, en = img.func_range(f)
        lines.append(f'### func 0x{f:08x}..0x{en:08x} ({en - st} B)')
        if d['valloc']:
            for v in d['valloc']:
                qid, size = valloc_args(st, v)
                lines.append(f'    valloc@{v:08x}  qid={("0x%08x" % qid) if qid is not None else "?"} '
                             f'size={("0x%x" % size) if size is not None else "?"}')
        if d['snd_sync']:
            lines.append(f'    snd_sync@{",".join(hex(x) for x in d["snd_sync"])}')
        if d['notify']:
            lines.append(f'    notify@{",".join(hex(x) for x in d["notify"])}')
        strs = []
        seen = set()
        for ins, ann in dis.disasm(st, min(en, st + 0x1800)):
            if '-> 0x' in ann and '"' in ann:
                s = ann.split('"')[1]
                if s not in seen and ('upm' in s.lower() or '.cpp' in s or 'model' in s.lower()
                                      or 'convert' in s.lower()):
                    seen.add(s)
                    strs.append(s)
        if strs:
            lines.append('    签名串: ' + ' | '.join(x[:100] for x in strs[:6]))
        lines.append('')

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    outp = OUT_DIR / '09_family_scan.txt'
    outp.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('written', outp)
    return 0


if __name__ == '__main__':
    sys.exit(main())
