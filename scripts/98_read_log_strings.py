"""Read the log strings referenced by 0x2B749CC's error paths.

At 0x2B749EA..0x2B74A02 the code builds a log call with:
   ldr r1,[pc,#0x4c] / ldr r2,[pc,#0x4c] / ldr r0,[pc,#0x48]
   movw r3,#0x273
   bl 0x2C2B288
So literals at 0x2B74A3C..0x2B74A44 hold string pointers.  Decode them.
Same for the second error path at 0x2B74A28 (line 0x279).
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io
import struct

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


def cstr(va, limit=220):
    o = va_to_off(va)
    if o is None:
        return None
    end = d.find(b'\x00', o)
    if end < 0 or end - o > limit:
        return None
    return d[o:end].decode('latin1')


def read_u32(va):
    s = sec_of(va)
    if s is None:
        return None
    off = s['sh_offset'] + (va - s['sh_addr'])
    if off + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, off)[0]


# For each ldr rX,[pc,#imm] in 0x2B749CC..0x2B74A3C, print literal and string
print('=== pc-relative literals in 0x2B749CC error paths ===')
ins_addrs = [
    0x2B749EE, 0x2B749F0, 0x2B749F8,   # first error path
    0x2B74A18, 0x2B74A1A, 0x2B74A22,   # second error path
]
for a in ins_addrs:
    hw = struct.unpack_from('<H', d, a)[0]
    hw2 = struct.unpack_from('<H', d, a + 2)[0]
    # could be 16-bit ldr (0x48xx) or 32-bit (0xF8DF / 0x4Bxx with .w)
    lit = None
    if (hw & 0xF800) == 0x4800:
        imm = (hw & 0xFF) * 4
        lit = ((a + 4) & ~3) + imm
    elif hw == 0xF8DF:  # ldr.w Rt,[pc,#imm12]
        imm = (hw2 & 0x0FFF)
        lit = ((a + 4) & ~3) + imm
    print('  insn %#010x hw=%04x/%04x lit=%s'
          % (a, hw, hw2, hex(lit) if lit else None))
    if lit:
        val = read_u32(lit)
        print('      literal value %#x -> %r' % (val or 0, cstr(val or 0)))

print()
print('=== scan .rodata near 0x2B7xxxx for readable messages ===')
# The strings for this module likely live in .rodata; find any that contain
# keywords hinting at network/usb/transport.
for kw in (b'connect', b'socket', b'transport', b'usb', b'ptp', b'send',
           b'recv', b'open', b'timeout'):
    idx = 0
    count = 0
    while count < 6:
        idx = d.find(kw, idx)
        if idx < 0:
            break
        # is it inside .rodata?
        s = sec_of_off = None
        for sec in e.iter_sections():
            if sec['sh_type'] == 'SHT_NOBITS':
                continue
            if sec['sh_offset'] <= idx < sec['sh_offset'] + sec['sh_size']:
                s = sec
                break
        if s is not None and s.name == '.rodata':
            start = d.rfind(b'\x00', max(0, idx - 120), idx) + 1
            end = d.find(b'\x00', idx)
            if end > start and end - start < 160:
                txt = d[start:end]
                try:
                    t = txt.decode('ascii')
                    if all(32 <= ord(c) < 127 for c in t):
                        print('  %#010x %r' % (s['sh_addr'] + (start - s['sh_offset']), t))
                        count += 1
                except UnicodeDecodeError:
                    pass
        idx = end + 1 if end > 0 else idx + len(kw)
