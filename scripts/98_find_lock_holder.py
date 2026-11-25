"""Find all callers of the (group=0xf,id=0xa) lock wrapper 0x2B1B470.

If another thread holds this lock for a long time, its holder is whoever calls
0x2B1B470 or the underlying primitive with the same (0xf,0xa) pair.

This script scans .text for `bl 0x2b1b470` (the wrapper) to find its users.
Then for each caller we resolve nearby log strings to name the module.
"""
from elftools.elf.elffile import ELFFile
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
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

WRAPPER = 0x2B1B470


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


def cstr(va, limit=180):
    o = va_to_off(va)
    if o is None:
        return None
    end = d.find(b'\x00', o)
    if end < 0 or end - o > limit:
        return None
    return d[o:end].decode('latin1')


# veneers that resolve to WRAPPER
def resolve_veneer(v):
    if d[v:v + 4] != bytes.fromhex('04c09fe5'):
        return None
    word = struct.unpack_from('<i', d, v + 12)[0]
    return ((v + 12) + word) & 0xFFFFFFFF


print('=== scan for direct bl/blx to wrapper %#x ===' % WRAPPER)
callers = []
for ins in md.disasm(td, tb):
    if ins.mnemonic not in ('bl', 'blx') or not ins.op_str.startswith('#'):
        continue
    try:
        t = int(ins.op_str[1:], 16)
    except ValueError:
        continue
    if (t & ~1) == WRAPPER:
        callers.append((ins.address, 'direct'))
print('direct callers:', len(callers))
for a, k in callers[:40]:
    print('  %#010x %s' % (a, k))

print()
print('=== scan veneers resolving to wrapper ===')
ven = []
lo, hi = 0x920000, 0x930000
for v in range(lo, hi, 4):
    r = resolve_veneer(v)
    if r and (r & ~1) == WRAPPER:
        ven.append(v)
print('veneers:', [hex(x) for x in ven])
# then find callers of those veneers
if ven:
    for ins in md.disasm(td, tb):
        if ins.mnemonic not in ('bl', 'blx') or not ins.op_str.startswith('#'):
            continue
        try:
            t = int(ins.op_str[1:], 16)
        except ValueError:
            continue
        if (t & ~1) in ven:
            print('  caller %#010x -> veneer %#x' % (ins.address, t))
