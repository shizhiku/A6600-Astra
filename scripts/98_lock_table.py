"""Confirm 0x2C2E46C is the sched lock primitive and identify 0x2B7450E.

Also enumerate ALL (group,id) lock wrappers in the 0x2B1B4xx-0x2B1B5xx range so
we can see the lock-ID allocation table.  That table tells us which subsystem
owns id 0xa vs 0xf.
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


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

print('=== 0x2C2E46C (lock primitive) ===')
for ins in md.disasm(td[0x2C2E46C - tb:0x2C2E46C - tb + 0x80], 0x2C2E46C):
    note = ''
    if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
        try:
            imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
            lit = ((ins.address + 4) & ~3) + imm
            val = read_u32(lit)
            sv = cstr(val or 0)
            if sv and all(32 <= ord(c) < 127 for c in sv[:5]):
                note = '  "%s"' % sv[:70]
        except Exception:
            pass
    print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                 ins.op_str, note))

print()
print('=== scan 0x2B1B400..0x2B1B600 for sched_lock wrappers ===')
for ent in range(0x2B1B400, 0x2B1B600, 2):
    ins = list(md.disasm(td[ent - tb:ent - tb + 0x20], ent))
    if len(ins) < 4:
        continue
    # pattern: movs r0,#0xf ; movs r1,#ID ; bl lock
    if (ins[0].mnemonic == 'push' and
            ins[2].mnemonic == 'movs' and ins[2].op_str.startswith('r0') and
            ins[3].mnemonic == 'movs' and ins[3].op_str.startswith('r1')):
        try:
            grp = int(ins[2].op_str.split('#')[-1], 0)
            lid = int(ins[3].op_str.split('#')[-1], 0)
        except ValueError:
            continue
        # find the bl and its target
        tgt = None
        for k in ins[4:8]:
            if k.mnemonic in ('bl', 'blx') and k.op_str.startswith('#'):
                tgt = int(k.op_str[1:], 16)
                break
        print('  %#010x lock(group=%#x, id=%#x) -> business %s'
              % (ent, grp, lid, hex(tgt) if tgt else '?'))
