"""Analyze 0x60E2F4 - the call at 0x54F71A that never returns.

Proved by probe batch 4:
    X_54F6D2 hit, Y_54F6E6 hit, Z_54F70E hit, AA_54F722 NOT hit
=> the call at 0x54F71A (bl 0x60E2F4) is the blocking call.

This script disassembles it and resolves its own calls (veneer formula
target = V + 12 + word) to find OSAL/cond/ioctl primitives.
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
START = 0x60E2F4
print('=== disassembly of %#010x (blocking call target) ===' % START)
insns = list(md.disasm(td[START - tb:START - tb + 0x300], START))
for ins in insns:
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
                nm = funcs.get(real) or ('%s+%#x' % (c[1], real - c[0])
                                         if c else '?')
                note = '   ; -> %#x %s' % (real, nm)
            else:
                c = containing(t)
                note = '   ; -> %#x %s' % (
                    t, funcs.get(t) or ('%s+%#x' % (c[1], t - c[0]) if c else '?'))
    if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
        try:
            imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
            lit = ((ins.address + 4) & ~3) + imm
            o = va_to_off(lit)
            if o:
                val = struct.unpack_from('<I', d, o)[0]
                note += '  lit=%#x' % val
                sv = cstr(val)
                if sv and all(32 <= ord(c) < 127 for c in sv[:8]):
                    note += ' "%s"' % sv[:60]
        except Exception:
            pass
    print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic, ins.op_str, note))
