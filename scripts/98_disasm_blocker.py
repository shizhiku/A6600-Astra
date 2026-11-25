"""Disassemble 0x1C7E69C — the real target of the 0x925FB0 veneer, which is
the call inside 0x54EF74 that never returns (proved by the staircase probe:
after_blx_r3 hit, after_925FB0 never hit).
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from pathlib import Path
import io
import struct

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
    if s is None:
        return None
    return s['sh_offset'] + (va - s['sh_addr'])


def cstr(va, limit=180):
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


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
ENTRY = 0x1C7E69C

print('=== disassembly of %#010x ===' % ENTRY)
insns = list(md.disasm(td[ENTRY - tb:ENTRY - tb + 0x200], ENTRY))
for ins in insns:
    note = ''
    if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
        try:
            t = int(ins.op_str[1:], 16)
        except ValueError:
            t = None
        if t is not None:
            real = resolve_veneer(t & ~1) if t else None
            note = '   ; -> %#x' % (real if real else t)
    # string refs via ldr/add pc
    if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
        try:
            imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
            lit = ((ins.address + 4) & ~3) + imm
            o = va_to_off(lit)
            if o:
                val = struct.unpack_from('<I', d, o)[0]
                note += '   ; lit=%#x' % val
        except Exception:
            pass
    print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic, ins.op_str, note))
