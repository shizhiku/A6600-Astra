"""Resolve the last link: where does the non-zero 'status' come from?

Chain (verified):
  GRM_fbrmCheckUpdateFinished (0x115618)
    -> bl 0x11F766
         0x11F766: bl 0x11F6E0 ; bl 0x12548C -> writes status to [sp+4]
                   returns (1 - status) clamped at 0
    -> caller needs exactly 1  =>  status must be 0

So the open question: what is 0x12548C, and why is status != 0?

Analyze 0x11F6E0 and 0x12548C.
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
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
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            if s['st_value'] and s.name:
                funcs.setdefault(s['st_value'] & ~1, s.name)

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def dump(start, size, title):
    ent = start & ~1
    print('=== %s: %#08x  symbol=%s ===' % (title, ent,
                                            funcs.get(ent, '(none)')))
    sec = sec_of(ent)
    if sec is None:
        print('  not mapped')
        return
    for ins in md.disasm(td[ent - tb:ent - tb + size], ent):
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
    print()


dump(0x11F6E0, 0x60, '0x11F6E0 (get status object)')
dump(0x12548C, 0xA0, '0x12548C (read status)')
