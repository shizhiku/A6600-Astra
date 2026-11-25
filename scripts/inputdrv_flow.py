# -*- coding: utf-8 -*-
"""inputdrv_flow.py — 还原 a6600 input.ko 的 uipc 事件流：消息构造/发送/注册与 proc 接口。

输出 03-证据/静态分析/input_drv/inputdrv_ko_flow_<gen>.txt：
  - 关键函数反汇编窗口（带重定位/字面量/字符串注释，地址带节前缀）
  - 每个 osal 发送点的到达 qid 与消息长度
  - kbd_timer_hndlr 内各发送点前 20 条指令（看参数如何算出）
只读。
"""
import importlib.util
import struct
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'
_spec = importlib.util.spec_from_file_location('ko', BASE / '02-脚本/inputdrv_ko.py')
ko = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ko)

# 关键区域（节内偏移）
WINDOWS = {
    'helper_adc_qid720018': (1, 0x000, 0x0bc),
    'helper_front_qid280132': (1, 0x0bc, 0x098),
    'helper_vgrip_qid18a04d1': (1, 0x154, 0x050),
    'key_event_envelope_sender': (1, 0xa20, 0x180),
    'small_event_sender_qid7a0020': (1, 0xba0, 0x170),
    'key_table_dispatch': (1, 0xd10, 0x164),
    'getkey_cb': (1, 0x121c, 0x020),
    'osal_cb_register': (1, 0x3c10, 0x16c),
    'kbd_close_unreg': (1, 0x3a58, 0x178),
    'kbd_probe_proc': (1, 0x40c0, 0x07c),
    'kbd_init_head': (3, 0x000, 0x120),
}
# kbd_timer_hndlr 发送点窗口
TIMER_SITES = [0x2208, 0x2240, 0x2764, 0x2adc, 0x2b28, 0x2b58, 0x2fa4, 0x3034, 0x3068, 0x3744]


def render(elf, sec_idx, start, size, prefix=''):
    lines, calls, lits = ko.analyze_function(
        elf, dict(name='x', shndx=sec_idx, value=start, size=size))
    tag = elf.secname(sec_idx)
    out = [f'{prefix}## {tag}+0x{start:x}..0x{start + size:x}']
    for ln in lines[1:]:
        out.append(prefix + ln)
    return out


def main():
    gens = sys.argv[1:] or ['g4', 'g5']
    for gen in gens:
        ko_path = OUT / f'{gen}_input.ko'
        if not ko_path.exists():
            continue
        elf = ko.RelElf(ko_path)
        L = [f'input.ko 事件流静态还原 ({gen})',
             f'file={ko_path.name} sha256={__import__("hashlib").sha256(elf.data).hexdigest()}',
             '',
             '== 说明：本模块为 ET_REL，节内 offset 独立编号；.text 函数与 .init.text/.exit.text 会有相同数字地址，',
             '   因此渲染时保留节名。qid 常量来自字面量池（LIT@）。 ==', '']
        for name, (sec, start, size) in WINDOWS.items():
            L.extend(render(elf, sec, start, size))
            L.append('')
        # timer 发送点上下文
        L.append('== kbd_timer_hndlr 发送点上下文 ==')
        lines, calls, _ = ko.analyze_function(
            elf, dict(name='kbd_timer_hndlr', shndx=1, value=0x21e4, size=0x16f0))
        addr2line = {}
        for ln in lines[1:]:
            a = int(ln.split()[0], 16)
            addr2line[a] = ln
        addrs = sorted(addr2line)
        for site in TIMER_SITES:
            if site not in addr2line:
                continue
            L.append(f'-- site 0x{site:x} --')
            lo = max(0, addrs.index(site) - 22)
            hi = min(len(addrs), addrs.index(site) + 3)
            for a in addrs[lo:hi]:
                L.append(addr2line[a])
            L.append('')
        (OUT / f'inputdrv_ko_flow_{gen}.txt').write_text('\n'.join(L), encoding='utf-8')
        print('wrote', OUT / f'inputdrv_ko_flow_{gen}.txt', len(L), 'lines')


if __name__ == '__main__':
    main()
