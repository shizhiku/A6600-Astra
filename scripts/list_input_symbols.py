"""List key-related symbols in the extracted input.ko (Windows-side pyelftools)."""
from pathlib import Path
from elftools.elf.elffile import ELFFile

KO = Path(r'<WORKSPACE>/03-证据/静态分析/input.ko')
with open(KO, 'rb') as f:
    e = ELFFile(f)
    print('sections:')
    for s in e.iter_sections():
        if s['sh_size']:
            print(f'  {s.name:16s} addr={s["sh_addr"]:#08x} off={s["sh_offset"]:#08x} size={s["sh_size"]:#08x}')
    symtab = e.get_section_by_name('.symtab')
    if symtab is None:
        raise SystemExit('no symtab')
    rows = []
    for s in symtab.iter_symbols():
        if s.name and s.entry.st_size and s.entry.st_info.type == 'STT_FUNC':
            rows.append((s.entry.st_value, s.entry.st_size, s.name))
    rows.sort()
    print(f'\n{len(rows)} functions; key/adc/gpio related:')
    for v, sz, n in rows:
        if any(k in n.lower() for k in ('key', 'adc', 'gpio', 'scan', 'poll', 'front', 'vgr')):
            print(f'  {v:#08x} size={sz:5d} {n}')
