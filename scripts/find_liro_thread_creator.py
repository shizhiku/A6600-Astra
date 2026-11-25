"""Find liro.ko code that references the 'kliro_%d' thread-name format string."""
from pathlib import Path
import json
from elftools.elf.elffile import ELFFile

KO = Path(r'<WORKSPACE>\03-证据\静态分析\liro-fault-static\liro.ko')
TARGET = b'kliro_%d'

with open(KO, 'rb') as f:
    e = ELFFile(f)
    secs = {s.name: s for s in e.iter_sections()}
    stro = secs['.rodata.str1.1']
    blob = stro.data()
    off = blob.find(TARGET)
    if off < 0:
        raise SystemExit('string not found')
    print(f"'kliro_%d' at .rodata.str1.1+{off:#x}, section addr {stro['sh_addr']:#x}")

    # section symbol index for .rodata.str1.1 (used by relocations)
    target_sec_index = None
    for idx, s in enumerate(e.iter_sections()):
        if s.name == '.rodata.str1.1':
            target_sec_index = idx
            break

    hits = []
    for name in ('.rel.text', '.rel.init.text'):
        if name not in secs:
            continue
        symtab = e.get_section(secs[name]['sh_link'])
        for rel in secs[name].iter_relocations():
            sym = symtab.get_symbol(rel['r_info_sym']) if rel['r_info_sym'] else None
            # ARM ELF uses addend in place for REL; section symbol + addend
            if sym is not None and sym['st_shndx'] == target_sec_index:
                addend = rel['r_addend'] if rel.is_RELA() else None
                hits.append({'reloc_section': name, 'offset': hex(rel['r_offset']),
                             'type': rel['r_info_type'], 'addend': addend,
                             'symbol': sym.name})
    print(f'relocations against that string section: {len(hits)}')
    for h in hits[:30]:
        print(h)

    out = {'ko': str(KO), 'string_offset': hex(off), 'section_addr': hex(stro['sh_addr']),
           'relocations': hits}
    Path(KO.parent / 'liro-thread-name-refs.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
