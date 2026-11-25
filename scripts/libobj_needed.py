"""List DT_NEEDED entries and undefined symbols referencing TextRM in libObj.so."""
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'

with open(LIB, 'rb') as f:
    e = ELFFile(f)
    print('=== DT_NEEDED ===')
    dyn = e.get_section_by_name('.dynamic')
    for tag in dyn.iter_tags():
        if tag.entry.d_tag == 'DT_NEEDED':
            print('  ', tag.needed)

    print('\n=== undefined symbols containing Text/Font ===')
    dynsym = e.get_section_by_name('.dynsym')
    hits = []
    for sym in dynsym.iter_symbols():
        if sym.entry.st_shndx == 'SHN_UNDEF' and sym.name:
            n = sym.name
            if 'Text' in n or 'Font' in n:
                hits.append(n)
    for n in hits[:40]:
        print('  ', n)
    print('total:', len(hits))
