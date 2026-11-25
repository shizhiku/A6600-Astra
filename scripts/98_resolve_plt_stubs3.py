"""Resolve gen5 appFw ARM PLT veneers (correct layout).

Verified raw bytes at 0x925FB0:
    04 c0 9f e5  ldr ip, [pc, #4]
    0c c0 8f e0  add ip, pc, ip
    1c ff 2f e1  bx  ip
    01 35 86 e1  .word 0x013586e1   <- at va+12

The loaded word is a pc-relative delta from (va+8), i.e. the veneer's own
"pc+8" base:  target = va + 8 + word.
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

# VA -> symbol name
funcs = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            v = s['st_value']
            if v and s.name and s['st_info']['type'] == 'STT_FUNC':
                funcs.setdefault(v & ~1, s.name)

# GOT slot VA -> imported symbol
got_names = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            got_names[r['r_offset']] = st.get_symbol(r['r_info_sym']).name


def va_to_off(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + (va - s['sh_addr'])
    return None


stubs = [0x925FB0, 0x9246B8, 0x923900, 0x9256A8, 0x9240D4,
         0x925B48, 0x924B48, 0x924B04, 0x923B34, 0x9243E4,
         0x925468, 0x9249C4]

for va in stubs:
    word = struct.unpack_from('<I', d, va + 12)[0]
    tgt = (va + 8) + word
    note = funcs.get(tgt & ~1)
    kind = 'internal' if tb <= tgt < tb + len(td) else 'external/GOT'
    got = ''
    if tgt in got_names:
        got = ' -> import %s' % got_names[tgt]
    else:
        foff = va_to_off(tgt)
        if foff is not None:
            ptr = struct.unpack_from('<I', d, foff)[0]
            got = ' slotval=%#x %s' % (ptr, got_names.get(tgt, ''))
    print('%#08x word=%#010x target=%#010x %-12s %s%s' % (
        va, word, tgt, kind, note or '', got))
