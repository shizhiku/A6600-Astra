"""Find the liro code that prints the per-segment 'loaded' message, and its table."""
from pathlib import Path
import struct, json
from elftools.elf.elffile import ELFFile

KO = Path(r'<WORKSPACE>\03-证据\静态分析\liro-fault-static\liro.ko')
TARGETS = {
    b'%llx -> %p : %x %x loaded (%s)': 'segment_loaded_log',
    b'Address not set, firmware will no be loaded!': 'address_not_set',
    b'entry point:%08x': 'entry_point',
}

with open(KO, 'rb') as f:
    e = ELFFile(f)
    secs = {s.name: s for s in e.iter_sections()}
    stro = secs['.rodata.str1.1']
    blob = stro.data()
    sec_index = {s.name: i for i, s in enumerate(e.iter_sections())}
    target_sec = sec_index['.rodata.str1.1']
    offsets = {}
    for raw, label in TARGETS.items():
        off = blob.find(raw)
        if off >= 0:
            offsets[off] = label
    print('string offsets:', {hex(k): v for k, v in offsets.items()})

    refs = []
    for relname, txtname in (('.rel.text', '.text'), ('.rel.init.text', '.init.text')):
        if relname not in secs:
            continue
        td = secs[txtname].data()
        symtab = e.get_section(secs[relname]['sh_link'])
        for rel in secs[relname].iter_relocations():
            sym = symtab.get_symbol(rel['r_info_sym']) if rel['r_info_sym'] else None
            if sym is None or sym['st_shndx'] != target_sec:
                continue
            o = rel['r_offset']
            if o + 4 > len(td):
                continue
            add = struct.unpack_from('<I', td, o)[0]
            if add in offsets:
                refs.append({'label': offsets[add], 'text': txtname,
                             'literal_offset': hex(o), 'string_offset': hex(add)})
    for r in refs:
        print(r)
    (KO.parent / 'liro-loader-log-refs.json').write_text(json.dumps(refs, indent=2), encoding='utf-8')
