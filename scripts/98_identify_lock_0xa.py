"""Identify the subsystem that owns sched lock (group=0xf, id=0xa).

The lock wrapper is at 0x2B1B470 and its business function is 0x2B7450E.
Disassemble it and resolve its log strings to get the module name.
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io
import struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


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


def resolve_veneer(v):
    if d[v:v + 4] != bytes.fromhex('04c09fe5'):
        return None
    word = struct.unpack_from('<i', d, v + 12)[0]
    return ((v + 12) + word) & 0xFFFFFFFF


START = 0x2B7450E
print('=== business function for lock(group=0xf, id=0xa): %#010x ===' % START)
for ins in md.disasm(td[START - tb:START - tb + 0x200], START):
    note = ''
    if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
        try:
            t = int(ins.op_str[1:], 16)
        except ValueError:
            t = None
        if t:
            r = resolve_veneer(t & ~1)
            note = '   ; -> %#x %s' % (r if r else t, '(veneer)' if r else '')
    if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
        try:
            imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
            lit = ((ins.address + 4) & ~3) + imm
            val = read_u32(lit)
            sv = cstr(val or 0)
            if sv and all(32 <= ord(c) < 127 for c in sv[:5]):
                note += '  "%s"' % sv[:70]
            elif val:
                note += '  lit=%#x' % val
        except Exception:
            pass
    print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                 ins.op_str, note))
