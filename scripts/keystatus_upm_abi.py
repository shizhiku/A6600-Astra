#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_upm_abi.py -- 四代/五代 UPM framework 队列表与 boot-factor 消息 ABI 差异。

内核模块 (.ko) 的所有段 sh_addr 都是 0，符号值是"段内偏移"，因此这里必须按
段(名) + 段内偏移寻址，不能把 VA 当全局地址。

产出 03-证据/静态分析/keystatus/06_upm_abi.txt:
  * upm.ko 的 25 项 framework 描述表（每项 0x24 字节，+0xC 为 uipc qid）
  * k_upm_notify_boot_factor 发送长度（g4=0x1C，g5=0x28）
  * k_upm_framework_boot_factor 回填长度（g4=7 字，g5=10 字）
"""
from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / '03-证据/静态分析/keystatus'

# framework 表在 .data 中的偏移（由 .data 内 0x924127 所在项 +0xC 反推）
TABLE = {
    'g4': dict(base=0x3A4, entries=25, ent_size=0x24, qid_off=0xC),
    'g5': dict(base=0x3B8, entries=25, ent_size=0x24, qid_off=0xC),
}


class Ko:
    def __init__(self, path: Path):
        self.d = path.read_bytes()
        self.e = ELFFile(io.BytesIO(self.d))
        self.sec = {}
        for s in self.e.iter_sections():
            if s['sh_type'] == 'SHT_NOBITS' or not s['sh_size']:
                continue
            self.sec[s.name] = (s['sh_addr'], s['sh_offset'], s['sh_size'])
        self.syms = {}
        st = self.e.get_section_by_name('.symtab')
        for s in st.iter_symbols():
            if s.name and s['st_value'] and s['st_info']['type'] in ('STT_FUNC', 'STT_OBJECT'):
                secname = self.e.get_section(s['st_shndx']).name
                self.syms.setdefault(s.name, (secname, s['st_value'], s['st_size']))

    def read(self, secname, off, n):
        base, foff, size = self.sec[secname]
        rel = off - base
        assert 0 <= rel < size, (secname, hex(off), hex(base), hex(size))
        return self.d[foff + rel:foff + rel + n]

    def u32(self, secname, off):
        return struct.unpack('<I', self.read(secname, off, 4))[0]

    def func_bytes(self, name):
        secname, off, size = self.syms[name]
        return secname, off, size, self.read(secname, off, size)


def main() -> int:
    lines = []
    for gen in ('g4', 'g5'):
        ko = Ko(OUT / f'{gen}_upm.ko')
        lines.append(f'================ {gen}  upm.ko ================')
        for nm in ('g_bf', 'k_upm_notify_boot_factor', 'k_upm_framework_boot_factor'):
            lines.append(f'  {nm:32s} {ko.syms[nm][0]}+0x{ko.syms[nm][1]:06x} size={ko.syms[nm][2]}')

        # notify 发送长度
        secname, off, size, blob = ko.func_bytes('k_upm_notify_boot_factor')
        nsize = None
        for k in range(0, len(blob) - 3, 4):
            w = struct.unpack_from('<I', blob, k)[0]
            if (w & 0xFFFFF000) == 0xE3A02000:
                nsize = w & 0xFFF
        lines.append(f'  k_upm_notify_boot_factor: 发送长度(r2) = 0x{nsize:X}  (源 g_bf+4)')

        # framework 表：.data 内
        t = TABLE[gen]
        lines.append(f'  -- .data framework 描述表 @+0x{t["base"]:x}, {t["entries"]} x 0x{t["ent_size"]:x} --')
        lines.append('     idx   qid(+0xC)')
        for i in range(t['entries']):
            ent = t['base'] + i * t['ent_size']
            qid = ko.u32('.data', ent + t['qid_off'])
            mark = '   <== case 4 boot_factor' if i == 4 else ''
            lines.append(f'     {i:2d}   0x{qid:08x}{mark}')

        # boot_factor 回填长度: 统计 ldm/stm 指令对
        secname, off, size, blob = ko.func_bytes('k_upm_framework_boot_factor')
        n_ldm = n_stm = 0
        regs_ldm = regs_stm = 0
        # ARM: LDMIA rN  = 0xE89?0000 ; LDMIA rN! = 0xE8B?0000
        #      STMIA rN  = 0xE88?0000 ; STMIA rN! = 0xE8A?0000 (寄存器列表在低16位)
        for k in range(0, len(blob) - 3, 4):
            w = struct.unpack_from('<I', blob, k)[0]
            m = w & 0x0FF00000
            if m in (0x08900000, 0x08B00000):
                n_ldm += 1
                regs_ldm += bin(w & 0xFFFF).count('1')
            elif m in (0x08800000, 0x08A00000):
                n_stm += 1
                regs_stm += bin(w & 0xFFFF).count('1')
        # 同一函数里有两段对称路径: mid 0x920111/0x920113 回填 与 mid 0x920128 写入
        per_path = regs_stm // 2 if regs_stm else 0
        lines.append(f'  k_upm_framework_boot_factor: LDM={n_ldm} 条(共 {regs_ldm} 字) / '
                     f'STM={n_stm} 条(共 {regs_stm} 字)，两段对称路径')
        lines.append(f'     -> 单条消息 回填/写入 = {per_path} 字 = {per_path * 4} 字节 '
                     f'= 1 个 mid 字 + {per_path - 1} 个数据字')
        lines.append('')

    txt = '\n'.join(lines) + '\n'
    (OUT / '06_upm_abi.txt').write_text(txt, encoding='utf-8')
    print(txt)
    return 0


if __name__ == '__main__':
    sys.exit(main())
