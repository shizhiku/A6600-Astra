"""Resolve the blocking call 0x924500 at 0x60E2BE.

Probe batch 5 proved:
    L_after_schedlock    hit
    M_after_munmap_wrap  hit   (first loop iteration succeeded)
    N_after_9257D8       MISS  (0x60E2AE never reached again)
    O_after_924500       MISS

=> 0x60E2BE's `blx 0x924500` is the blocking call, on some iteration.

Resolve the veneer and dump the target.
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


def read_u32(va):
    o = va_to_off(va)
    if o is None or o + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, o)[0]


def cstr(va, limit=220):
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


V = 0x924500
print('raw veneer bytes at %#x: %s' % (V, d[V:V + 16].hex(' ')))
tgt = resolve_veneer(V)
print('resolve_veneer -> %s' % (hex(tgt) if tgt else 'NOT standard veneer'))

if tgt:
    ent = tgt & ~1
    c = containing(ent)
    print('containing: %s' % (funcs.get(ent) or
                              ('%s+%#x' % (c[1], ent - c[0]) if c else '?')))
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    print('--- disassembly ---')
    for ins in md.disasm(td[ent - tb:ent - tb + 0x160], ent):
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
                val = read_u32(lit)
                sv = cstr(val or 0)
                if sv and all(32 <= ord(ch) < 127 for ch in sv[:5]):
                    note += '  "%s"' % sv[:70]
                elif val:
                    note += '  lit=%#x' % val
            except Exception:
                pass
        print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                     ins.op_str, note))
