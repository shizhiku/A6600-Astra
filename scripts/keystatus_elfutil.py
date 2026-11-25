#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_elfutil.py -- 只读 ELF/反汇编工具库（供 keystatus_* 脚本共用）。

提供:
  * 段/函数边界 (ARM.exidx prel31) 解析
  * PLT 条目 -> .rel.plt -> .dynsym 符号名 的解析（appFw 用 ARM 长跳 veneer）
  * ARM 长跳 veneer (ldr r12,[pc,#0]; add pc,pc,r12; .word off) -> 导入符号名
  * Thumb/ARM 反汇编，自动解析 PC 字面量、字符串、函数指针、导入符号
"""
from __future__ import annotations

import io
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BIN = ROOT / '03-证据/静态分析/97_abi/a5pFw_actual.so'
OUT_DIR = ROOT / '03-证据/静态分析/keystatus'


def prel31(word: int, place: int) -> int:
    v = word & 0x7FFFFFFF
    if v >= 0x40000000:
        v -= 0x80000000
    return (place + v) & 0xFFFFFFFF


class Img:
    def __init__(self, path: Path = DEFAULT_BIN):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.elf = ELFFile(io.BytesIO(self.data))
        self.sections = []
        for s in self.elf.iter_sections():
            if s['sh_type'] == 'SHT_NOBITS' or s['sh_size'] == 0:
                continue
            self.sections.append((s['sh_addr'], s['sh_addr'] + s['sh_size'], s['sh_offset'], s.name))
        self.exidx_starts = self._load_exidx()
        self.dynsyms = self._load_dynsyms()
        self.plt_syms = self._load_plt()          # plt entry addr -> symbol name
        self.veneer_syms = self._load_veneers()   # veneer addr -> symbol name

    # ---------- 基础读取 ----------
    def off(self, va: int):
        for a, b, o, _ in self.sections:
            if a <= va < b:
                return o + (va - a)
        return None

    def sec_name(self, va: int):
        for a, b, o, n in self.sections:
            if a <= va < b:
                return n
        return None

    def read(self, va: int, n: int) -> bytes:
        o = self.off(va)
        return b'' if o is None else self.data[o:o + n]

    def u32(self, va: int) -> int:
        o = self.off(va)
        if o is None:
            raise ValueError(f'unmapped 0x{va:x}')
        return struct.unpack_from('<I', self.data, o)[0]

    def cstr(self, va: int, maxlen: int = 300):
        o = self.off(va)
        if o is None:
            return None
        end = self.data.find(b'\0', o, o + maxlen)
        if end < 0:
            return None
        raw = self.data[o:end]
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return raw.decode('latin1')

    # ---------- 符号 ----------
    def _load_dynsyms(self):
        sec = self.elf.get_section_by_name('.dynsym')
        return [s for s in sec.iter_symbols()] if sec is not None else []

    def sym_name(self, idx: int):
        if 0 <= idx < len(self.dynsyms):
            return self.dynsyms[idx].name
        return None

    def _load_plt(self) -> dict:
        """PLT 条目地址 -> 导入符号名。

        入口形态(ARM): add r12,pc,#hi ; add r12,r12,#lo ; ldr pc,[r12,#slot]!
        直接按三条指令解出 GOT 槽地址，再经 .rel.plt 查 .dynsym 符号名。
        """
        plt = self.elf.get_section_by_name('.plt')
        rel = self.elf.get_section_by_name('.rel.plt')
        if plt is None or rel is None:
            return {}
        pb, base = plt.data(), plt['sh_addr']
        relmap = {}
        rd = rel.data()
        for k in range(0, len(rd) - 7, 8):
            r_off, r_info = struct.unpack_from('<II', rd, k)
            relmap[r_off] = r_info >> 8
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        md.detail = True
        out = {}
        for k in range(0, len(pb) - 3, 4):
            w = struct.unpack_from('<I', pb, k)[0]
            if (w >> 16) != 0xE28F or ((w >> 12) & 0xF) != 0xC:
                continue
            st = base + k
            ins = list(md.disasm(self.data[st:st + 12], st))
            if len(ins) < 3:
                continue
            try:
                def imm_of(i):
                    imms = [o.imm for o in i.operands if o.type == 2]
                    if not imms:
                        return None
                    if len(imms) >= 2:
                        imm8, rot = imms[0], imms[1]
                        return ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xFFFFFFFF
                    return imms[0]
                i0 = imm_of(ins[0])
                i1 = imm_of(ins[1])
                m2 = ins[2].operands[1]
                if i0 is None or i1 is None or m2.type != 3:
                    continue
                slot = (ins[0].address + 8 + i0 + i1 + m2.mem.disp) & 0xFFFFFFFF
            except Exception:
                continue
            idx = relmap.get(slot)
            if idx is not None:
                name = self.sym_name(idx)
                if name:
                    out[st] = name
        return out

    def _load_veneers(self) -> dict:
        """ARM 长跳 veneer -> 导入符号名。

        形态: ldr r12,[pc,#0] ; add pc,pc,r12 ; .word (target - (V+12))
        """
        pat = bytes.fromhex('00c09fe50cf08fe0')
        out, i = {}, self.data.find(pat)
        while i >= 0:
            va = i  # .text 的 sh_addr == sh_offset，文件偏移即 VA
            try:
                tgt = (struct.unpack_from('<I', self.data, i + 8)[0] + va + 12) & 0xFFFFFFFF
            except struct.error:
                tgt = None
            if tgt is not None and tgt in self.plt_syms:
                out[va] = self.plt_syms[tgt]
            i = self.data.find(pat, i + 1)
        return out

    # ---------- 函数边界 ----------
    def _load_exidx(self) -> list:
        sec = self.elf.get_section_by_name('.ARM.exidx')
        if sec is None:
            return []
        d, base = sec.data(), sec['sh_addr']
        starts = []
        for k in range(0, len(d) - 7, 8):
            w = struct.unpack_from('<I', d, k)[0]
            if w == 1:
                continue
            starts.append(prel31(w, base + k))
        return sorted(set(starts))

    def func_start(self, va: int):
        lo, hi, ans = 0, len(self.exidx_starts) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if (self.exidx_starts[mid] & ~1) <= va:
                ans = self.exidx_starts[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return ans

    def func_end(self, va: int):
        st = self.func_start(va)
        if st is None:
            return None
        i = self.exidx_starts.index(st)
        return self.exidx_starts[i + 1] & ~1 if i + 1 < len(self.exidx_starts) else None

    def func_range(self, va: int, cap: int = 0x4000):
        st = self.func_start(va) or (va & ~1)
        en = self.func_end(va) or (st + cap)
        if en - st > cap:
            en = st + cap
        return st & ~1, en

    def func_of(self, va: int):
        st = self.func_start(va)
        return (st & ~1) if st is not None else None


# ---------------- 反汇编与注解 ----------------

class Dis:
    """Thumb/ARM 反汇编，带 PC 字面量 -> 值/字符串/符号 注解，以及寄存器字面量数据流。"""

    def __init__(self, img: Img, mode: str = 'thumb'):
        self.img = img
        self.mode = mode
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if mode == 'thumb' else CS_MODE_ARM)
        self.md.detail = True

    # 指令地址上界（用于数据流判断）
    def _align(self, a: int) -> int:
        return (a + 4) & ~3 if self.mode == 'thumb' else a

    def annotate(self, ins, reglit: dict) -> str:
        img, op = self.img, ins.op_str
        out = ''
        if ins.mnemonic.startswith('ldr') and '[pc' in op:
            mm = re.search(r'#(-?0x[0-9a-fA-F]+)', op)
            if mm:
                imm = int(mm.group(1), 0)
                lva = self._align(ins.address) + imm
                try:
                    val = img.u32(lva)
                except ValueError:
                    return ''
                reg = op.split(',')[0].strip()
                out = f'   ; [0x{lva:08x}]=0x{val:08x}'
                s = img.cstr(val)
                if s and len(s) >= 3 and all(32 <= ord(c) < 127 for c in s):
                    out += f' "{s[:100]}"'
                elif val in img.veneer_syms:
                    out += f'  veneer->{img.veneer_syms[val]}'
                elif val in img.plt_syms:
                    out += f'  plt->{img.plt_syms[val]}'
                elif img.func_of(val) == val and img.sec_name(val) == '.text':
                    out += '  (code ptr)'
                elif img.sec_name(val):
                    out += f'  ({img.sec_name(val)})'
        elif ins.mnemonic in ('add', 'add.w', 'adr', 'sub') and ', pc' in op:
            toks = [t.strip() for t in op.split(',')]
            target = 0
            if len(toks) == 2:  # add rX, pc  (register form)
                r = toks[0]
                if r in reglit:
                    target = (self._align(ins.address) + reglit[r]) & 0xFFFFFFFF
            else:
                i = op.rfind('#')
                if i >= 0:
                    imm = int(op[i + 1:], 0)
                    target = (self._align(ins.address) + imm) & 0xFFFFFFFF
            if target:
                out = f'   ; -> 0x{target:08x}'
                s = img.cstr(target)
                if s and len(s) >= 2 and all(32 <= ord(c) < 127 for c in s):
                    out += f' "{s[:100]}"'
                elif img.sec_name(target):
                    out += f' ({img.sec_name(target)})'
        elif ins.mnemonic in ('bl', 'b', 'blx') and op.startswith('#'):
            tgt = int(op[1:], 0)
            out = f'   ; -> 0x{tgt:08x}'
            nm = img.veneer_syms.get(tgt) or img.plt_syms.get(tgt)
            if nm:
                out += f'  <{nm}>'
            elif img.sec_name(tgt) == '.text':
                st = img.func_of(tgt)
                if st == tgt:
                    out += '  (func)'
                elif st is not None:
                    out += f'  (in func 0x{st:08x})'
        return out

    def disasm(self, start: int, end: int):
        img = self.img
        md = self.md
        blob = img.read(start, end - start)
        reglit = {}
        out = []
        for ins in md.disasm(blob, start):
            ann = self.annotate(ins, reglit)
            out.append((ins, ann))
            # 更新寄存器字面量
            op = ins.op_str
            if ins.mnemonic.startswith('ldr') and '[pc' in op:
                mm = re.search(r'#(-?0x[0-9a-fA-F]+)', op)
                if mm:
                    imm = int(mm.group(1), 0)
                    lva = self._align(ins.address) + imm
                    reg = op.split(',')[0].strip()
                    try:
                        reglit[reg] = img.u32(lva)
                    except ValueError:
                        reglit.pop(reg, None)
            elif ins.mnemonic in ('add', 'add.w') and ', pc' in op:
                toks = [t.strip() for t in op.split(',')]
                if len(toks) == 2 and toks[0] in reglit:
                    reglit[toks[0]] = (self._align(ins.address) + reglit[toks[0]]) & 0xFFFFFFFF
                else:
                    for r in list(reglit):
                        reglit[r] = 0
            elif ins.mnemonic in ('movw', 'movt'):
                toks = [t.strip() for t in op.split(',')]
                if len(toks) == 2 and toks[1].startswith('#'):
                    try:
                        v = int(toks[1][1:], 0)
                    except ValueError:
                        v = 0
                    if ins.mnemonic == 'movw':
                        reglit[toks[0]] = v & 0xFFFF
                    else:
                        reglit[toks[0]] = (reglit.get(toks[0], 0) & 0xFFFF) | ((v & 0xFFFF) << 16)
            # 其他会写目标寄存器的指令: 清掉该 reg 的字面量记录
            try:
                for iop in ins.operands:
                    if iop.type == 1 and iop.access & 2:  # ARM_OP_REG, write
                        rn = ins.reg_name(iop.reg)
                        if rn and not (ins.mnemonic.startswith('ldr') and '[pc' in op and rn == op.split(',')[0].strip()):
                            reglit.pop(rn, None)
            except Exception:
                pass
        return out


def demangle(name: str) -> str:
    """轻量 Itanium demangle：仅用于让 C++ 符号可读，失败则原样返回。"""
    if not name.startswith('_Z'):
        return name
    try:
        import subprocess
        r = subprocess.run(['c++filt', name], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return name
