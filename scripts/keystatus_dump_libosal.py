#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keystatus_dump_libosal.py -- 反汇编 libosal_uipc.so（OSAL 消息队列 API 实现）。

用途: 弄清 appFw 中 osal_valloc_msg_wait / osal_snd_sync_msg / osal_free_msg /
      osal_reg_sync_msg_queue_cb / osal_rcv_msg_tmo 的真实签名与语义，
      以及 uipc qid 的地址空间来源。只读，不执行。
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

CANDIDATES = [
    ROOT / '03-证据/静态分析/grm/lib/libosal_uipc.so',
    ROOT / '03-证据/静态分析/input_sen/libosal_uipc.so',
]

WANT = [
    'osal_valloc_msg_wait', 'osal_snd_sync_msg', 'osal_free_msg', 'osal_msg_size',
    'osal_reg_sync_msg_queue_cb', 'osal_reg_msg_queue_cb', 'osal_rcv_msg_tmo',
    'osal_snd_msg', 'osal_snd_sync_direct', 'osal_stat_msgq', 'osal_dynamic_id',
    'osal_set_msg_pri', 'osal_get_msg_pri', 'osal_lock', 'osal_unlock',
    'u_osal_snd_sync_msg', '__osal_snd_sync_msg', 'u_osal_reg_sync_msg_queue_cb',
    'u_osal_rcv_msg_tmo', 'u_osal_snd_msg', 'u_osal_snd_sync_direct',
    'u_osal_dynamic_id', 'u_osal_sig_sem', 'u_osal_wai_sem_tmo', 'u_uipc_init',
    'do_init', 'alloc_fblock', 'alloc_cb', 'free_cb', 'create_proxy_thread',
]


def prel31(word: int, place: int) -> int:
    v = word & 0x7FFFFFFF
    if v >= 0x40000000:
        v -= 0x80000000
    return (place + v) & 0xFFFFFFFF


def main() -> int:
    src = CANDIDATES[0]
    if len(sys.argv) > 1:
        src = Path(sys.argv[1])
    data = src.read_bytes()
    elf = ELFFile(io.BytesIO(data))
    secs = [(s['sh_addr'], s['sh_addr'] + s['sh_size'], s['sh_offset'], s.name)
            for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS' and s['sh_size']]

    def off(va):
        for a, b, o, _ in secs:
            if a <= va < b:
                return o + (va - a)
        return None

    def u32(va):
        return struct.unpack_from('<I', data, off(va))[0]

    def cstr(va, mx=200):
        o = off(va)
        if o is None:
            return None
        j = data.find(b'\0', o, o + mx)
        return data[o:j].decode('latin1') if j > 0 else None

    ds = elf.get_section_by_name('.dynsym')
    syms = {}
    for s in ds.iter_symbols():
        if s['st_value'] and s['st_info']['type'] == 'STT_FUNC':
            syms[s['st_value'] & ~1] = s.name
    objs = {}
    for s in ds.iter_symbols():
        if s['st_value'] and s['st_info']['type'] == 'STT_OBJECT':
            objs[s['st_value'] & ~1] = s.name
    ex = elf.get_section_by_name('.ARM.exidx'); ed = ex.data(); eb = ex['sh_addr']
    starts = sorted({prel31(struct.unpack_from('<I', ed, k)[0], eb + k)
                     for k in range(0, len(ed), 8)})

    import bisect
    def fend(st):
        i = bisect.bisect_left(starts, st & ~1)
        if i < len(starts) and starts[i] == (st & ~1):
            return (starts[i + 1] & ~1) if i + 1 < len(starts) else None
        return None

    plt = elf.get_section_by_name('.plt'); rel = elf.get_section_by_name('.rel.plt')
    relmap = {}
    if rel is not None:
        rd = rel.data()
        for k in range(0, len(rd) - 7, 8):
            ro, ri = struct.unpack_from('<II', rd, k)
            relmap[ro] = ri >> 8
    pltmap = {}
    if plt is not None:
        md0 = Cs(CS_ARCH_ARM, CS_MODE_ARM); md0.detail = True
        pb, pbase = plt.data(), plt['sh_addr']
        for k in range(0, len(pb) - 3, 4):
            w = struct.unpack_from('<I', pb, k)[0]
            if (w >> 16) != 0xE28F or ((w >> 12) & 0xF) != 0xC:
                continue
            st = pbase + k
            ins = list(md0.disasm(data[st:st + 12], st))
            try:
                def imm(i):
                    im = [o.imm for o in i.operands if o.type == 2]
                    if not im:
                        return None
                    if len(im) >= 2:
                        return ((im[0] >> im[1]) | (im[0] << (32 - im[1]))) & 0xFFFFFFFF
                    return im[0]
                i0, i1 = imm(ins[0]), imm(ins[1])
                m2 = ins[2].operands[1]
                slot = (ins[0].address + 8 + i0 + i1 + m2.mem.disp) & 0xFFFFFFFF
            except Exception:
                continue
            if slot in relmap:
                nm = ds.get_symbol(relmap[slot]).name
                if nm:
                    pltmap[st] = nm

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    out = open(OUT_DIR / '03_libosal_uipc_disasm.txt', 'w', encoding='utf-8')

    def w(s):
        out.write(s + '\n')

    w(f'# libosal_uipc.so  {src}')
    w(f'# size={len(data)} exidx funcs={len(starts)}')
    for name in WANT:
        va = next((a for a, n in syms.items() if n == name), None)
        if va is None:
            continue
        en = fend(va) or (va + 0x600)
        w('')
        w(f'===== {name}  0x{va:08x}..0x{en:08x} ({en - va} B)')
        reglit = {}
        for ins in md.disasm(data[off(va):off(va) + (en - va)], va):
            ann = ''
            op = ins.op_str
            if ins.mnemonic.startswith('ldr') and '[pc' in op:
                i = op.rfind('#')
                if i >= 0:
                    immv = int(op[i + 1:].rstrip(']'), 0)
                    lva = ((ins.address + 4) & ~3) + immv
                    try:
                        val = u32(lva)
                    except Exception:
                        val = 0
                    ann = f'   ; [0x{lva:08x}]=0x{val:08x}'
                    s = cstr(val)
                    if s and all(32 <= ord(c) < 127 for c in s) and len(s) > 1:
                        ann += f' "{s[:70]}"'
                    elif val & ~1 in syms:
                        ann += f' <{syms[val & ~1]}>'
                    elif val & ~1 in objs:
                        ann += f' obj<{objs[val & ~1]}>'
                    elif val in pltmap:
                        ann += f' plt<{pltmap[val]}>'
                    reglit[op.split(',')[0].strip()] = val
            elif ins.mnemonic in ('bl', 'blx', 'b') and op.startswith('#'):
                tgt = int(op[1:], 0)
                ann = f'   ; -> 0x{tgt:08x}'
                nm = syms.get(tgt & ~1) or pltmap.get(tgt)
                if nm:
                    ann += f' <{nm}>'
            elif ins.mnemonic in ('add', 'add.w') and ', pc' in op:
                toks = [t.strip() for t in op.split(',')]
                if len(toks) == 2 and toks[0] in reglit:
                    tgt = ((ins.address + 4) & ~3) + reglit[toks[0]]
                    tgt &= 0xFFFFFFFF
                    ann = f'   ; -> 0x{tgt:08x}'
                    s = cstr(tgt)
                    if s and all(32 <= ord(c) < 127 for c in s):
                        ann += f' "{s[:70]}"'
            w(f'{ins.address:08x}  {ins.bytes.hex():<10} {ins.mnemonic:<8} {ins.op_str}{ann}')
    out.close()
    print('written', OUT_DIR / '03_libosal_uipc_disasm.txt')
    return 0


if __name__ == '__main__':
    sys.exit(main())
