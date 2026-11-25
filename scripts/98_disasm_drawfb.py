"""Disassemble the 5th-gen GraphicsEngine::drawFramebuffer (libObj+0xE565A,
250 bytes) to see what it actually does and why it would emit no GPU work.

This is the function reached by probe C (appFw 0x54ED82).  We need to know:
  - does it early-return on some flag?
  - does it call into gemini/DMP at all?
  - what conditions gate the actual submit?
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from pathlib import Path
import io
import struct

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / '03-证据/静态分析/grm/lib/libObj.so'
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb = text['sh_addr']
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def file_offset(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + (va - s['sh_addr'])
    return None


def read_u32(va):
    o = file_offset(va)
    if o is None or o + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, o)[0]


def cstr(va, limit=160):
    o = file_offset(va)
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

START = 0xE565A
print('=== GraphicsEngine::drawFramebuffer @ %#x (250 bytes) ===' % START)
for ins in md.disasm(d[file_offset(START):file_offset(START) + 250], START):
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
            if sv and all(32 <= ord(ch) < 127 for ch in sv[:4]):
                note += '  "%s"' % sv[:64]
            elif val:
                note += '  lit=%#x' % val
        except Exception:
            pass
    print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic, ins.op_str, note))
