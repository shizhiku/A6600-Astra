"""Resolve the log strings of 0x2B749CC correctly.

Pattern:
    ldr r1, [pc, #imm]     -> literal L (an offset)
    ldr r2, [pc, #imm]     -> literal M
    add r1, pc             -> r1 = (add_addr + 4) + L
    add r2, pc             -> r2 = (add_addr + 4) + M
    ...
    bl  0x2C2B288          -> log function

So string = (add_addr + 4) + L  (Thumb 16-bit add to pc uses aligned PC).

Let's compute for both error paths.
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io
import struct
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))


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


def cstr(va, limit=240):
    if va is None:
        return None
    o = va_to_off(va)
    if o is None:
        return None
    end = d.find(b'\x00', o)
    if end < 0 or end - o > limit:
        return None
    return d[o:end].decode('latin1')


def read_u32(va):
    if va is None:
        return None
    s = sec_of(va)
    if s is None:
        return None
    off = s['sh_offset'] + (va - s['sh_addr'])
    if off + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, off)[0]


def lit_of(insn_addr):
    hw = struct.unpack_from('<H', d, insn_addr)[0]
    if (hw & 0xF800) == 0x4800:
        imm = (hw & 0xFF) * 4
        return ((insn_addr + 4) & ~3) + imm
    return None


# error path 1: literals loaded at 0x2B749EE (r1), 0x2B749F0 (r2), 0x2B749F8 (r0)
# add r1, pc at 0x2B749F2 ; add r2, pc at 0x2B749F4 ; add r0, pc at 0x2B749FC
pairs = [
    ('path1 r1', 0x2B749EE, 0x2B749F2),
    ('path1 r2', 0x2B749F0, 0x2B749F4),
    ('path1 r0', 0x2B749F8, 0x2B749FC),
    ('path2 r1', 0x2B74A18, 0x2B74A1C),
    ('path2 r2', 0x2B74A1A, 0x2B74A1E),
    ('path2 r0', 0x2B74A22, 0x2B74A26),
]
for name, ldr_a, add_a in pairs:
    lit = lit_of(ldr_a)
    if lit is None:
        print(name, 'not 16-bit ldr')
        continue
    off_val = read_u32(lit)
    add_pc = (add_a + 4) & ~3
    tgt = (add_pc + (off_val or 0)) & 0xFFFFFFFF
    print('%s: lit@%#x off=%#x add_pc=%#x -> %#x  %r'
          % (name, lit, off_val or 0, add_pc, tgt, cstr(tgt)))
