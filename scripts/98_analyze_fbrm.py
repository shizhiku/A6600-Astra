"""Analyze the gen5 rendering exit points found in libObj.so:

  GRM_fbrmCheckUpdateFinished   0x115619  (24 bytes)  <- the fn the reference patches
  GRM_fbrmSetScreenPreference   0x1155AD  (88 bytes)
  _ZN2ux6gfxeng14GraphicsEngine15drawFramebufferEv  0xE565B (250 bytes)

These are the framebuffer update path.  Dump them.
"""
from elftools.elf.elffile import ELFFile
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


def resolve_veneer(v):
    if d[v:v + 4] != bytes.fromhex('04c09fe5'):
        return None
    word = struct.unpack_from('<i', d, v + 12)[0]
    return ((v + 12) + word) & 0xFFFFFFFF


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def dump(start, size, title):
    print('=== %s: %#010x (%d bytes) ===' % (title, start, size))
    n = 0
    for ins in md.disasm(td[start - tb:start - tb + size + 32], start):
        if n > size // 2 + 8:
            break
        note = ''
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16)
            except ValueError:
                t = None
            if t:
                r = resolve_veneer(t & ~1)
                note = '   ; -> %#x%s' % (r if r else t,
                                          ' (veneer)' if r else '')
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
        n += 1
    print()


dump(0x115619, 24, 'GRM_fbrmCheckUpdateFinished')
dump(0x1155AD, 88, 'GRM_fbrmSetScreenPreference')
dump(0xE565B, 250, 'GraphicsEngine::drawFramebuffer')
