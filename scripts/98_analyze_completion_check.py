"""Analyze 0x11F766 - the real "is framebuffer update finished" check called by
GRM_fbrmCheckUpdateFinished.  If it returns non-1, the caller reports
"not finished" and drawFramebuffer is skipped -> draw==0, which is exactly what
we observe.

This is the function the reference project equivalently patches in its QEMU
build (forcing completion so software rendering can proceed).
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io
import struct

SRC = Path('03-证据/静态分析/grm/lib/libObj.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()


def sec_of(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s
    return None


def va_to_off(va):
    s = sec_of(va)
    return None if s is None else s['sh_offset'] + (va - s['sh_addr'])


def read_u32(va):
    o = va_to_off(va)
    if o is None or o + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, o)[0]


def cstr(va, limit=200):
    o = va_to_off(va)
    if o is None:
        return None
    end = d.find(b'\x00', o)
    if end < 0 or end - o > limit:
        return None
    return d[o:end].decode('latin1')


funcs = {}
from elftools.elf.sections import SymbolTableSection
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            if s['st_value'] and s.name:
                funcs.setdefault(s['st_value'] & ~1, s.name)

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
START = 0x11F766 & ~1
print('=== 0x11F766 (real completion check) ===')
print('symbol:', funcs.get(START, '(no symbol)'))
print('section:', sec_of(START).name if sec_of(START) else '?')
print()
for ins in md.disasm(td[START - tb:START - tb + 0x100], START):
    note = ''
    if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
        try:
            t = int(ins.op_str[1:], 16)
        except ValueError:
            t = None
        if t:
            nm = funcs.get(t & ~1)
            note = '   ; -> %#x %s' % (t, nm or '')
    if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
        try:
            imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
            lit = ((ins.address + 4) & ~3) + imm
            val = read_u32(lit)
            sv = cstr(val or 0)
            if sv and all(32 <= ord(c) < 127 for c in sv[:4]):
                note += '  "%s"' % sv[:70]
            elif val:
                note += '  lit=%#x' % val
        except Exception:
            pass
    print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                 ins.op_str, note))
