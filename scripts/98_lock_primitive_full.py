"""Examine the sched_lock primitive 0x2C2E46C fully to find the wait.

If the lock (0xf,0xa) was never registered/initialised, the primitive may block
in a semaphore/cond wait inside.

Also examine 0x2C2B520 (the decision helper) and 0x2C2AF70 (table op).
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


def dump(start, size, title):
    print('=== %s: %#010x ===' % (title, start))
    for ins in md.disasm(td[start - tb:start - tb + size], start):
        note = ''
        if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
            try:
                imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
                lit = ((ins.address + 4) & ~3) + imm
                val = read_u32(lit)
                sv = cstr(val or 0)
                if sv and all(32 <= ord(c) < 127 for c in sv[:5]):
                    note = '  "%s"' % sv[:80]
                elif val:
                    note = '  lit=%#x' % val
            except Exception:
                pass
        print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                     ins.op_str, note))
    print()


dump(0x2C2E46C, 0x140, '0x2C2E46C sched_lock primitive')
dump(0x2C2B520, 0x80, '0x2C2B520 decision helper')
