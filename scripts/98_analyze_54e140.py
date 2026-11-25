"""Analyze 0x54E140 (called by the blocking 0x60E2F4) and 0x60E274 (its tail
call when the helper returns 1)."""
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


def resolve_veneer(v):
    if d[v:v + 4] != bytes.fromhex('04c09fe5'):
        return None
    word = struct.unpack_from('<i', d, v + 12)[0]
    return ((v + 12) + word) & 0xFFFFFFFF


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


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def dump(start, size, title):
    print('=== %s: %#010x ===' % (title, start))
    for ins in md.disasm(td[start - tb:start - tb + size], start):
        note = ''
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16)
            except ValueError:
                t = None
            if t:
                real = resolve_veneer(t & ~1)
                if real:
                    c = containing(real)
                    note = '   ; veneer -> %#x %s' % (
                        real, funcs.get(real) or
                        ('%s+%#x' % (c[1], real - c[0]) if c else '?'))
                else:
                    c = containing(t)
                    note = '   ; -> %#x %s' % (
                        t, funcs.get(t) or
                        ('%s+%#x' % (c[1], t - c[0]) if c else '?'))
        if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
            try:
                imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
                lit = ((ins.address + 4) & ~3) + imm
                o = va_to_off(lit)
                if o:
                    val = struct.unpack_from('<I', d, o)[0]
                    sv = cstr(val)
                    if sv and all(32 <= ord(ch) < 127 for ch in sv[:6]):
                        note += '  "%s"' % sv[:60]
            except Exception:
                pass
        print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                     ins.op_str, note))
    print()


dump(0x54E140, 0x120, '0x54E140 (helper called by blocker)')
dump(0x60E274, 0x80, '0x60E274 (tail call when helper returns 1)')
