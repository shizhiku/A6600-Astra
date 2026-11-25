"""0x2BA0FAC etc. produce empty disassembly in Thumb mode -> they may be ARM
functions (the `blx` with an even address would select ARM).  Let's check the
address parity used by `blx` at 0x2B749E2 and disassemble accordingly.

From the dump:
  02b749e0  ldm r0, {r0, r1}
  02b749e2  blx #0x2ba0fac      <- operand printed without '#1' -> even addr
An even target in a blx means ARM state.
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


def va_to_off(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + (va - s['sh_addr'])
    return None


def cstr(va, limit=200):
    o = va_to_off(va)
    if o is None:
        return None
    end = d.find(b'\x00', o)
    if end < 0 or end - o > limit:
        return None
    return d[o:end].decode('latin1')


def dump_arm(start, size, title):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    print('=== %s (ARM): %#010x ===' % (title, start))
    for ins in md.disasm(td[start - tb:start - tb + size], start):
        note = ''
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16)
                note = '   ; -> %#x' % t
            except ValueError:
                pass
        if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
            try:
                imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
                lit = ((ins.address + 8) & ~3) + imm
                o = va_to_off(lit)
                if o:
                    val = struct.unpack_from('<I', d, o)[0]
                    sv = cstr(val)
                    if sv and all(32 <= ord(c) < 127 for c in sv[:5]):
                        note += '  "%s"' % sv[:70]
            except Exception:
                pass
        print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                     ins.op_str, note))
    print()


dump_arm(0x2BA0FAC, 0xA0, '0x2BA0FAC')
dump_arm(0x2BA0E94, 0x60, '0x2BA0E94')
dump_arm(0x2BA074C, 0x60, '0x2BA074C')
