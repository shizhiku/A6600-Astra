"""Map PLT slot offsets to relocation symbols in libObj.so."""
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'
SLOT = 0xFF588

with open(LIB, 'rb') as f:
    e = ELFFile(f)
    plt = e.get_section_by_name('.plt')
    rel = e.get_section_by_name('.rel.plt')
    dynsym = e.get_section_by_name('.dynsym')
    print(f'.plt addr={plt["sh_addr"]:#x} size={plt["sh_size"]:#x}')
    rels = []
    for r in rel.iter_relocations():
        sym = dynsym.get_symbol(r['r_info_sym'])
        rels.append(sym.name)
    print('relocations:', len(rels))

    delta = SLOT - plt['sh_addr']
    print(f'slot delta = {delta:#x} ({delta})')

    for header in (0, 8, 16, 20, 24, 32):
        for ent in (8, 12, 16, 20):
            if delta < header:
                continue
            idx, rem = divmod(delta - header, ent)
            if rem == 0 and idx < len(rels):
                print(f'  header={header} ent={ent} -> index {idx}: {rels[idx]}')

    # also print a window of relocations to inspect manually
    print('\nfirst 3:', rels[:3])
    for idx in range(870, 882):
        if idx < len(rels):
            print(f'  idx {idx}: {rels[idx]}')
