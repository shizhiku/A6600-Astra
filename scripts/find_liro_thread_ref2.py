"""Filter ARM REL relocations by in-place addend to find the 'kliro_%d' reference."""
from pathlib import Path
import json, struct
from elftools.elf.elffile import ELFFile

KO = Path(r'<WORKSPACE>\03-证据\静态分析\liro-fault-static\liro.ko')
TARGET_STR = b'kliro_%d'

with open(KO, 'rb') as f:
    e = ELFFile(f)
    secs = {s.name: s for s in e.iter_sections()}
    stro = secs['.rodata.str1.1']
    str_off = stro.data().find(TARGET_STR)
    if str_off < 0:
        raise SystemExit('string missing')

    sec_index = {s.name: i for i, s in enumerate(e.iter_sections())}
    target_sec = sec_index['.rodata.str1.1']

    found = []
    for relname, txtname in (('.rel.text', '.text'), ('.rel.init.text', '.init.text')):
        if relname not in secs:
            continue
        text = secs[txtname]
        tdata = text.data()
        symtab = e.get_section(secs[relname]['sh_link'])
        for rel in secs[relname].iter_relocations():
            sym = symtab.get_symbol(rel['r_info_sym']) if rel['r_info_sym'] else None
            if sym is None or sym['st_shndx'] != target_sec:
                continue
            off = rel['r_offset']
            if off + 4 > len(tdata):
                continue
            addend = struct.unpack_from('<I', tdata, off)[0]
            if addend == str_off:
                found.append({'reloc': relname, 'text_offset': hex(off),
                              'virtual': hex(text['sh_addr'] + off), 'addend_hex': hex(addend)})

    print(f'references to {TARGET_STR!r} (offset {str_off:#x}): {len(found)}')
    for h in found:
        print(' ', h)

    out = {'ko': str(KO), 'string': TARGET_STR.decode(), 'string_offset': hex(str_off),
           'references': found}
    (KO.parent / 'liro-thread-name-refs.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
