# -*- coding: utf-8 -*-
"""inputdrv_init.py — 四代/五代 libObj 的 init_array/构造器与 infra_input_init 调用线索。"""
import io
import struct
import sys
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'
LIB = {'g4': OUT / 'g4_libObj.so', 'g5': OUT / 'g5_libObj.so'}
IMG_ELF = {'g4': OUT / 'g4_im.elf', 'g5': OUT / 'g5_im.elf'}

if __name__ == '__main__':
    L = []
    for gen, p in LIB.items():
        if not p.exists():
            continue
        d = p.read_bytes()
        e = ELFFile(io.BytesIO(d))
        L.append(f'== {gen} {p.name} ({len(d)} bytes) ==')
        # dynsym 中与 input 初始化相关
        ds = e.get_section_by_name('.dynsym')
        for s in ds.iter_symbols():
            n = s.name
            if any(k in n for k in ('infra_input_init', 'infra_input_exit', 'infra_input_res',
                                    'infra_input_sus', 'infra_tp_init', 'InfraInput11GetInstance',
                                    'InfraInputC')):
                L.append(f'  dynsym {int(s["st_value"]):08x} {int(s["st_size"]):5d} {n}')
        for secname in ('.init_array', '.fini_array', '.preinit_array'):
            sec = e.get_section_by_name(secname)
            if sec is None:
                continue
            off, size = int(sec['sh_offset']), int(sec['sh_size'])
            vals = struct.unpack_from('<%dI' % (size // 4), d, off)
            L.append(f'  {secname}: {[hex(v) for v in vals]}')
            for v in vals:
                for s in ds.iter_symbols():
                    if int(s['st_value']) == v and s.name:
                        L.append(f'     -> {v:#x} {s.name}')
        # 字符串里搜 infra_input_init 的 dlsym/init 名
        for pat in (b'infra_input_init', b'infra_input_res', b'infra_input_sus'):
            i = d.find(pat)
            if i >= 0:
                L.append(f'  string "{pat.decode()}" @ file 0x{i:x}')
        L.append('')
    for gen, p in IMG_ELF.items():
        if not p.exists():
            continue
        d = p.read_bytes()
        e = ELFFile(io.BytesIO(d))
        L.append(f'== {gen} {p.name} ({len(d)} bytes) ==')
        dyn = e.get_section_by_name('.dynamic')
        needed = [t.needed for t in dyn.iter_tags() if t.entry.d_tag == 'DT_NEEDED'] if dyn else []
        L.append('  NEEDED: ' + repr(needed))
        ds = e.get_section_by_name('.dynsym')
        L.append('  dynsym: ' + repr([s.name for s in ds.iter_symbols() if s.name]))
        for pat in (b'infra_input_init', b'libObj', b'dlopen', b'dlsym'):
            offs = []
            i = 0
            while True:
                i = d.find(pat, i)
                if i < 0:
                    break
                offs.append(i)
                i += 1
            L.append(f'  string "{pat.decode()}" offsets={[hex(x) for x in offs[:8]]} count={len(offs)}')
        L.append('')
    (OUT / 'inputdrv_init_chain.txt').write_text('\n'.join(L), encoding='utf-8')
    print('\n'.join(L))
