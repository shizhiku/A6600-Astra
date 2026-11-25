# -*- coding: utf-8 -*-
"""
92_infra_key_map_scan.py
静态扫描 libObj.so：定位 InfraInput 的 key_code -> event_code 映射表。
只读，不修改任何文件。

用法: python -X utf8 92_infra_key_map_scan.py
"""
import sys, struct, io, os

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

LIB = r'<WORKSPACE>\03-证据\静态分析\libObj.so'

from elftools.elf.elffile import ELFFile

f = open(LIB, 'rb')
elf = ELFFile(f)

print('=== FILE ===')
print('size', os.path.getsize(LIB))
print('class', elf.elfclass, 'machine', elf.header.e_machine, 'type', elf.header.e_type)
print('entry 0x%X' % elf.header.e_entry)

print('\n=== SEGMENTS (PT_LOAD) ===')
loads = []
for i, seg in enumerate(elf.iter_segments()):
    if seg.header.p_type == 'PT_LOAD':
        va = seg.header.p_vaddr
        off = seg.header.p_offset
        fsz = seg.header.p_filesz
        ms = seg.header.p_memsz
        fl = seg.header.p_flags
        loads.append((va, off, fsz, ms, fl))
        print('  #%d va=0x%08X off=0x%08X filesz=0x%08X memsz=0x%08X flags=%s  vadelta=0x%X'
              % (i, va, off, fsz, ms,
                 ('R' if fl & 4 else '-') + ('W' if fl & 2 else '-') + ('X' if fl & 1 else '-'),
                 va - off))

print('\n=== SECTIONS ===')
for sec in elf.iter_sections():
    if sec.name and not sec.name.startswith('.debug'):
        print('  %-22s addr=0x%08X off=0x%08X size=0x%08X flags=%s'
              % (sec.name, sec['sh_addr'], sec['sh_offset'], sec['sh_size'],
                 str(sec['sh_flags'])))

# ---------------- helpers ----------------
data = open(LIB, 'rb').read()

# build va->off map from PT_LOAD / sections
segs = []
for sec in elf.iter_sections():
    if sec['sh_type'] == 'SHT_NOBITS' or sec['sh_size'] == 0:
        continue
    segs.append((sec['sh_addr'], sec['sh_offset'], sec['sh_size'], sec.name))

def va2off(va):
    for a, o, s, n in segs:
        if a <= va < a + s:
            return o + (va - a)
    return None

def off2va(off):
    for a, o, s, n in segs:
        if o <= off < o + s:
            return a + (off - o)
    return None

def r32(va):
    o = va2off(va)
    if o is None or o + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, o)[0]

def rbytes(va, n):
    o = va2off(va)
    if o is None:
        return None
    return data[o:o + n]

def cstr(va, maxlen=256):
    b = rbytes(va, maxlen)
    if b is None:
        return None
    z = b.find(b'\x00')
    if z >= 0:
        b = b[:z]
    try:
        return b.decode('utf-8', 'replace')
    except Exception:
        return None

# dynsym / symtab for names
sym_by_addr = {}
for sn in ('.dynsym', '.symtab'):
    sec = elf.get_section_by_name(sn)
    if sec is None:
        continue
    for s in sec.iter_symbols():
        a = s['st_value']
        if a:
            sym_by_addr.setdefault(a, []).append((s.name, s['st_size'], sn))

def nearest_syms(va, back=0x4000):
    out = []
    for a, l in sym_by_addr.items():
        if va - back <= a <= va:
            for nm, sz, sn in l:
                out.append((a, nm, sz, sn))
    out.sort()
    return out[-4:]

def sec_of(va):
    for a, o, s, n in segs:
        if a <= va < a + s:
            return n
    return '?'

print('\n=== KEY STRINGS ===')
STRINGS = [0x1012DD3, 0x1012DFD, 0x1012E27, 0x1012FB2,
           0x1012FB2 - 0x40, 0x1012DFD - 0x80]
# dump the whole neighbourhood of the INFRAINPUT dump strings
base = 0x1012C00
blob = rbytes(base, 0x600)
if blob:
    txt = blob.split(b'\x00')
    cur = base
    print('--- strings in 0x%X..0x%X ---' % (base, base + 0x600))
    for t in txt:
        if t.strip():
            printable = all(32 <= c < 127 or c in (9, 10, 13) for c in t)
            if printable:
                print('  0x%08X  %s' % (cur, t.decode('ascii', 'replace')))
        cur += len(t) + 1
