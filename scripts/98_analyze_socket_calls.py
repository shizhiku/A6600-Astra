"""Analyze 0x2BA0FAC (first call in the socket-like function 0x2B749CC).
Also resolve 0x2BA0E94 / 0x2BA074C / 0x2BA1818 / 0x2BA195C to see the family.
These addresses are 4-byte aligned ARM-ish? They are called via blx with odd
address, i.e. Thumb.  Let's disassemble at 0x2BA0FAC.
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from pathlib import Path
import io
import struct
import bisect

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
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


def cstr(va, limit=200):
    o = va_to_off(va)
    if o is None:
        return None
    end = d.find(b'\x00', o)
    if end < 0 or end - o > limit:
        return None
    return d[o:end].decode('latin1')


funcs = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            v = s['st_value']
            if v and s.name and s['st_info']['type'] == 'STT_FUNC':
                funcs.setdefault(v & ~1, s.name)
fa = sorted(funcs)


def containing(va):
    i = bisect.bisect_right(fa, va) - 1
    if i < 0:
        return None
    return fa[i], funcs[fa[i]]


def resolve_veneer(v):
    if d[v:v + 4] != bytes.fromhex('04c09fe5'):
        return None
    word = struct.unpack_from('<i', d, v + 12)[0]
    return ((v + 12) + word) & 0xFFFFFFFF


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def dump(start, size, title):
    print('=== %s: %#010x ===' % (title, start))
    c = containing(start)
    if c:
        print('  (inside %s+%#x)' % (c[1], start - c[0]))
    for ins in md.disasm(td[start - tb:start - tb + size], start):
        note = ''
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16)
            except ValueError:
                t = None
            if t:
                r = resolve_veneer(t & ~1)
                note = '   ; -> %#x %s' % (r if r else t,
                                           '(veneer)' if r else '')
        if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
            try:
                imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
                lit = ((ins.address + 4) & ~3) + imm
                o = va_to_off(lit)
                if o:
                    val = struct.unpack_from('<I', d, o)[0]
                    sv = cstr(val)
                    if sv and all(32 <= ord(ch) < 127 for ch in sv[:5]):
                        note += '  "%s"' % sv[:70]
            except Exception:
                pass
        print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                     ins.op_str, note))
    print()


dump(0x2BA0FAC, 0x80, '0x2BA0FAC (first call)')
dump(0x2BA0E94, 0x60, '0x2BA0E94 (loop read-like)')
dump(0x2BA074C, 0x60, '0x2BA074C (close-like)')
