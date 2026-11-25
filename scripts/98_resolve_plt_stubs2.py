"""Resolve the ARM PLT veneers used by gen5 appFw.

Veneer layout (verified by raw bytes):
    ldr ip, [pc, #4]     04 c0 9f e5
    add ip, pc, ip       0c c0 8f e0
    bx  ip               1c ff 2f e1
    .word X
The loaded word is used as a *GOT slot address* by some toolchains, and as a
pc-relative delta by others.  Both interpretations are reported.
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import Path
import io, struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()

# GOT slot VA -> imported symbol
got_names = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            got_names[r['r_offset']] = st.get_symbol(r['r_info_sym']).name
print('relocations', len(got_names))


def va_to_off(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + (va - s['sh_addr'])
    return None


def resolve_one(va):
    word = struct.unpack_from('<I', d, va + 8)[0]
    out = []
    # interpretation A: word is an absolute GOT slot address
    if word in got_names:
        out.append('abs-GOT %#x -> %s' % (word, got_names[word]))
    # interpretation B: GOT slot holds a pointer we can read
    foff = va_to_off(word)
    if foff is not None:
        ptr = struct.unpack_from('<I', d, foff)[0]
        out.append('slotptr word=%#x -> %#x %s' % (
            word, ptr, got_names.get(word, '(no reloc)')))
    # interpretation C: pc-relative delta
    tgt = (va + 8) + struct.unpack_from('<i', d, va + 8)[0]
    out.append('rel %#x' % tgt)
    return word, out


for va in (0x925FB0, 0x9246B8, 0x923900, 0x9256A8, 0x9240D4,
           0x925B48, 0x924B48, 0x924B04, 0x923B34, 0x9243E4,
           0x925468, 0x9249C4):
    word, notes = resolve_one(va)
    print('%#08x word=%#010x  %s' % (va, word, ' | '.join(notes)))
