#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_find_qid_users.py -- 找出各 ELF/裸二进制中 qid 常量 (0x924127/0x920111)
的引用点，并解析到所属函数/被调用的 OSAL API。

方法:
  1. 全文件搜 4 字节小端常量；
  2. 落在 .text 里的 -> 视为 PC 字面量池，向前找 ldr rX,[pc,#imm] 的引用指令；
     落在 .rodata/.data 里的 -> 向前/向后找引用该地址的字面量；
  3. 用 ARM.exidx 还原函数边界；有符号则给出符号名；
  4. 若引用指令后 0x60 字节内出现对 osal_* / 其它 PLT 导入的 bl，一并列出。

只读，不执行。
"""
from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / '03-证据/静态分析/keystatus'

QIDS = [0x00924127, 0x00920111]

FILES = [
    '03-证据/静态分析/97_abi/a5pFw_actual.so',
    '03-证据/静态分析/input_drv/g5_libObj.so',
    '03-证据/静态分析/input_drv/g4_libObj.so',
    '03-证据/静态分析/grm/lib/libInfraMediaCommon.so',
    '03-证据/静态分析/97_abi/a6usr_im.elf',
    '03-证据/静态分析/input_drv/g5_im.elf',
    '03-证据/静态分析/input_drv/g4_libosal_uipc.so',
]


def prel31(w, place):
    v = w & 0x7FFFFFFF
    if v >= 0x40000000:
        v -= 0x80000000
    return (place + v) & 0xFFFFFFFF


class Elf:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.elf = ELFFile(io.BytesIO(self.data))
        self.secs = [(s['sh_addr'], s['sh_addr'] + s['sh_size'], s['sh_offset'], s.name)
                     for s in self.elf.iter_sections()
                     if s['sh_type'] != 'SHT_NOBITS' and s['sh_size']]
        self.syms = {}
        self.objs = {}
        ds = self.elf.get_section_by_name('.dynsym')
        if ds is not None:
            for s in ds.iter_symbols():
                if not s['st_value']:
                    continue
                if s['st_info']['type'] == 'STT_FUNC':
                    self.syms[s['st_value'] & ~1] = s.name
                elif s['st_info']['type'] == 'STT_OBJECT':
                    self.objs[s['st_value'] & ~1] = s.name
        # PLT -> 导入符号
        self.pltmap = {}
        plt = self.elf.get_section_by_name('.plt')
        rel = self.elf.get_section_by_name('.rel.plt')
        if plt is not None and rel is not None:
            relmap = {}
            rd = rel.data()
            for k in range(0, len(rd) - 7, 8):
                ro, ri = struct.unpack_from('<II', rd, k)
                relmap[ro] = ri >> 8
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            md.detail = True
            pb, pbase = plt.data(), plt['sh_addr']
            for k in range(0, len(pb) - 3, 4):
                w = struct.unpack_from('<I', pb, k)[0]
                if (w >> 16) != 0xE28F or ((w >> 12) & 0xF) != 0xC:
                    continue
                st = pbase + k
                ins = list(md.disasm(self.data[st:st + 12], st))
                try:
                    def imm(i):
                        im = [o.imm for o in i.operands if o.type == 2]
                        if not im:
                            return None
                        if len(im) >= 2:
                            return ((im[0] >> im[1]) | (im[0] << (32 - im[1]))) & 0xFFFFFFFF
                        return im[0]
                    i0, i1 = imm(ins[0]), imm(ins[1])
                    slot = (ins[0].address + 8 + i0 + i1 + ins[2].operands[1].mem.disp) & 0xFFFFFFFF
                except Exception:
                    continue
                if slot in relmap:
                    nm = ds.get_symbol(relmap[slot]).name if ds is not None else None
                    if nm:
                        self.pltmap[st] = nm
        # ARM 长跳 veneer
        self.veneers = {}
        pat = bytes.fromhex('00c09fe50cf08fe0')
        i = self.data.find(pat)
        while i >= 0:
            try:
                tgt = (struct.unpack_from('<I', self.data, i + 8)[0] + i + 12) & 0xFFFFFFFF
            except struct.error:
                tgt = None
            if tgt in self.pltmap:
                self.veneers[i] = self.pltmap[tgt]
            i = self.data.find(pat, i + 1)
        # exidx
        ex = self.elf.get_section_by_name('.ARM.exidx')
        self.starts = []
        if ex is not None:
            ed, eb = ex.data(), ex['sh_addr']
            for k in range(0, len(ed) - 7, 8):
                w = struct.unpack_from('<I', ed, k)[0]
                if w == 1:
                    continue
                self.starts.append(prel31(w, eb + k))
            self.starts.sort()

    def off(self, va):
        for a, b, o, _ in self.secs:
            if a <= va < b:
                return o + (va - a)
        return None

    def sec(self, va):
        for a, b, o, n in self.secs:
            if a <= va < b:
                return n
        return None

    def u32(self, va):
        return struct.unpack_from('<I', self.data, self.off(va))[0]

    def fstart(self, va):
        import bisect
        i = bisect.bisect_right(self.starts, va)
        return self.starts[i - 1] & ~1 if i else None

    def cstr(self, va, mx=160):
        o = self.off(va)
        if o is None:
            return None
        j = self.data.find(b'\0', o, o + mx)
        if j < 0:
            return None
        try:
            return self.data[o:j].decode('utf-8')
        except UnicodeDecodeError:
            return None


def scan_file(path: Path, out) -> None:
    e = Elf(path)
    mdt = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    print(f'===== {path}')
    out.write(f'===== {path}\n')
    for qid in QIDS:
        pat = struct.pack('<I', qid)
        offs = []
        i = e.data.find(pat)
        while i >= 0:
            offs.append(i)
            i = e.data.find(pat, i + 1)
        print(f'  qid 0x{qid:08x}: {len(offs)} 处')
        out.write(f'  qid 0x{qid:08x}: {len(offs)} 处\n')
        for o in offs:
            va = None
            for a, b, so, n in e.secs:
                if so <= o < so + (b - a):
                    va = a + (o - so)
                    secn = n
                    break
            if va is None:
                continue
            # 找引用: 在 va 之前 0x200 内找 ldr rX,[pc] 指向 va
            ref = None
            for back in range(0, 0x200, 2):
                cand = va - back
                if cand < 0:
                    break
                if e.off(cand) is None or e.sec(cand) != '.text':
                    continue
                for ins in mdt.disasm(e.data[e.off(cand):e.off(cand) + 4], cand):
                    if not (ins.mnemonic.startswith('ldr') and '[pc' in ins.op_str):
                        continue
                    j = ins.op_str.rfind('#')
                    if j < 0:
                        continue
                    try:
                        imm = int(ins.op_str[j + 1:].rstrip(']'), 0)
                    except ValueError:
                        continue
                    lva = ((ins.address + 4) & ~3) + imm
                    if lva == va:
                        ref = ins
                    break
                if ref:
                    break
            fs = e.fstart(va) if secn == '.text' else None
            fn = e.syms.get(fs) if fs else None
            line = (f'    @0x{va:08x} sec={secn} func=0x{fs:08x}' if fs else f'    @0x{va:08x} sec={secn}')
            if fn:
                line += f' <{fn}>'
            if ref is not None:
                line += f'  ref insn 0x{ref.address:08x}: {ref.mnemonic} {ref.op_str}'
                # 往后 0x80 找 bl 调用
                calls = []
                blk = e.data[e.off(ref.address):e.off(ref.address) + 0x100]
                for ins in mdt.disasm(blk, ref.address):
                    if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
                        t = int(ins.op_str[1:], 0)
                        nm = e.veneers.get(t) or e.pltmap.get(t) or e.syms.get(t & ~1)
                        if nm:
                            calls.append(f'{ins.address:08x}->{nm}')
                    if ins.mnemonic in ('pop',) and 'pc' in ins.op_str:
                        break
                if calls:
                    line += '  calls: ' + ', '.join(calls[:6])
            print(line)
            out.write(line + '\n')


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    outp = OUT_DIR / '04_qid_xrefs.txt'
    with open(outp, 'w', encoding='utf-8') as out:
        for f in FILES:
            p = ROOT / f
            if not p.exists():
                print('missing', p)
                continue
            try:
                scan_file(p, out)
            except Exception as ex:  # noqa: BLE001
                print('ERR', p, ex)
                out.write(f'ERR {p} {ex}\n')
    print('written', outp)
    return 0


if __name__ == '__main__':
    sys.exit(main())
