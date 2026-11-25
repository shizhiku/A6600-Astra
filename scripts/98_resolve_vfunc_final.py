"""Correctly disassemble the vtable[0] function (== pointer & ~1) and map the
RTTI chain to identify which interface the object implements.

Findings so far:
  object vtable @ 0x0353C518
    vt[0] = 0x0054D05D  -> real entry 0x54D05C (Thumb bit set)
    vt[6] reloc _ZTVN10__cxxabiv120__si_class_type_infoE   (single inheritance)
    vt[7] = 0x02CEB040 "N8debug_if8debug_ifE"              (mangled type name)
    vt[9] reloc _ZTVN10__cxxabiv117__class_type_infoE      (base class info)
    vt[10] = 0x02CEB055 "10i_debug_if"                     (base class name)

Sibling vtables in the same area carry:
    "21i_touch_event_handler"
    "30i_display_update_event_handler"

So the object built by 0x54D154 is a debug_if implementation, and the block at
0x54F664 is touching the touch/display event handler interfaces.
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


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

for ptr in (0x0054D05D, 0x0054D063, 0x0054D069, 0x0054D06F, 0x0054D075):
    entry = ptr & ~1
    print('=== vtable entry %#010x -> entry %#08x ===' % (ptr, entry))
    off = entry - tb
    for ins in md.disasm(td[off:off + 0x40], entry):
        note = ''
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            note = '   ; -> %s' % ins.op_str
        print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                     ins.op_str, note))
    print()

print('=== RTTI chain for the object vtable @ 0x353C518 ===')
# vt[5] = offset-to-top (0), vt[6] = typeinfo ptr (RELOC), vt[7] = name ptr
for i in (5, 6, 7, 8, 9, 10, 11):
    a = 0x0353C518 + i * 4
    o = va_to_off(a)
    print('  vt[%2d] @ %#010x raw=%s' % (i, a, d[o:o + 4].hex(' ')))
print()
for va in (0x02CEB040, 0x02CEB055, 0x02CEB062, 0x02CEB07A):
    print('  %#010x %r' % (va, cstr(va)))

# Find all RTTI class-name strings mentioning touch/display in .rodata window
print()
print('=== scan .rodata 0x2CEA000..0x2CEB400 for interface names ===')
o0 = va_to_off(0x02CEA000)
blob = d[o0:o0 + 0x1400]
addr = 0x02CEA000
for part in blob.split(b'\x00'):
    if 6 <= len(part) <= 60:
        try:
            t = part.decode('ascii')
        except UnicodeDecodeError:
            addr += len(part) + 1
            continue
        if 'event_handler' in t or 'debug_if' in t or 'touch' in t:
            print('  %#010x %r' % (addr, t))
    addr += len(part) + 1
