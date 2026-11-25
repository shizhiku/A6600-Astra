"""Resolve the two thread-name format strings used by liro's kthread_create calls."""
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

KO = Path(r'<WORKSPACE>\03-证据\静态分析\liro-fault-static\liro.ko')
WANTED = {0x504: 'siteA_threadfn', 0x508: 'siteA_namefmt',
          0x8C0: 'siteB_threadfn', 0x8C4: 'siteB_namefmt'}

with open(KO, 'rb') as f:
    e = ELFFile(f)
    secs = {s.name: s for s in e.iter_sections()}
    td = secs['.text'].data()
    stro = secs['.rodata.str1.1'].data()
    symtab = e.get_section(secs['.rel.text']['sh_link'])

    resolved = {}
    for rel in secs['.rel.text'].iter_relocations():
        off = rel['r_offset']
        if off not in WANTED:
            continue
        sym = symtab.get_symbol(rel['r_info_sym']) if rel['r_info_sym'] else None
        addend = struct.unpack_from('<I', td, off)[0]
        entry = {'literal_offset': hex(off), 'role': WANTED[off],
                 'symbol': sym.name if sym else None}
        if sym is not None and sym['st_shndx'] == [i for i, s in enumerate(e.iter_sections())
                                                  if s.name == '.rodata.str1.1'][0]:
            end = stro.find(b'\x00', addend)
            entry['string_offset'] = hex(addend)
            entry['string'] = stro[addend:end].decode('latin1')
        else:
            entry['raw_value'] = hex(addend)
        resolved[WANTED[off]] = entry

    for k, v in resolved.items():
        print(k, '->', v)
