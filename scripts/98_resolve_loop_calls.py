"""Resolve the two veneer calls inside 0x60E274's reset loop:
   0x9257D8  and 0x924500
and disassemble their targets."""
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

reloc = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            reloc[r['r_offset']] = st.get_symbol(r['r_info_sym']).name


def containing(va):
    i = bisect.bisect_right(fa, va) - 1
    if i < 0:
        return None
    return fa[i], funcs[fa[i]]


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

for v in (0x9257D8, 0x924500):
    tgt = resolve_veneer(v)
    print('=== veneer %#010x -> %s ==='
          % (v, ('%#010x' % tgt) if tgt else 'NOT A VENEER'))
    if not tgt:
        continue
    ent = tgt & ~1
    c = containing(ent)
    print('  containing func: %s'
          % (funcs.get(ent) or ('%s+%#x' % (c[1], ent - c[0]) if c else '?')))
    for ins in md.disasm(td[ent - tb:ent - tb + 0x100], ent):
        note = ''
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16)
            except ValueError:
                t = None
            if t:
                r2 = resolve_veneer(t & ~1)
                if r2:
                    c2 = containing(r2)
                    note = '   ; -> %#x %s' % (
                        r2, funcs.get(r2) or
                        ('%s+%#x' % (c2[1], r2 - c2[0]) if c2 else '?'))
                else:
                    note = '   ; -> %#x' % t
        if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
            try:
                imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
                lit = ((ins.address + 4) & ~3) + imm
                o = va_to_off(lit)
                if o:
                    val = struct.unpack_from('<I', d, o)[0]
                    sv = cstr(val)
                    if sv and all(32 <= ord(ch) < 127 for ch in sv[:6]):
                        note += '  "%s"' % sv[:70]
            except Exception:
                pass
        print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                     ins.op_str, note))
    print()
