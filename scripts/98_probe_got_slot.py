"""Read memory at the computed r4_base and find the GOT slot.

r4_base = 0x0377ABC6, and the load is `ldr r3, [r4, r3]` with r3 = 0x5E9F0,
so slot = 0x0377ABC6 + 0x5E9F0 = 0x037D95B6 (computed earlier).

But .got starts at 0x0377ABC8.  A 2-byte offset suggests the addition should
have used a 4-byte aligned PC.  Let's check BOTH:
  A) r4_base = 0x0377ABC6  -> slot 0x037D95B6
  B) r4_base = 0x0377ABC8  -> slot 0x037D95B8
and also scan a window of slots for a plausible vtable pointer (a value that
lands inside .data.rel.ro).
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
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


def read_u32(va):
    s = sec_of(va)
    if s is None:
        return None
    off = s['sh_offset'] + (va - s['sh_addr'])
    if off + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, off)[0]


relro = e.get_section_by_name('.data.rel.ro')
print('.data.rel.ro: va=%#x .. %#x'
      % (relro['sh_addr'], relro['sh_addr'] + relro['sh_size']))
got = e.get_section_by_name('.got')
print('.got: va=%#x .. %#x' % (got['sh_addr'], got['sh_addr'] + got['sh_size']))
print()

for base in (0x0377ABC6, 0x0377ABC8, 0x0377ABCA):
    slot = base + 0x5E9F0
    val = read_u32(slot)
    sec = sec_of(val) if val else None
    in_relro = (relro['sh_addr'] <= (val or 0) < relro['sh_addr'] + relro['sh_size'])
    print('base=%#010x slot=%#010x val=%#010x relro=%s sec=%s'
          % (base, slot, val or 0, in_relro, sec.name if sec else None))

print()
print('=== scan .got for dwords landing in .data.rel.ro (+8 within it) ===')
hits = []
for va in range(got['sh_addr'], got['sh_addr'] + got['sh_size'], 4):
    v = read_u32(va)
    if v is None:
        continue
    t = v + 8
    if relro['sh_addr'] <= t < relro['sh_addr'] + relro['sh_size']:
        hits.append((va, v, t))
print('candidates:', len(hits))
for va, v, t in hits[:20]:
    print('  slot %#010x val=%#010x -> vtable %#010x' % (va, v, t))
