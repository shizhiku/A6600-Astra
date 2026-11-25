"""Find the code that references input.ko's 'input' string (proc entry name)."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

KO = Path(r'<WORKSPACE>/03-证据/静态分析/input.ko')
with open(KO, 'rb') as f:
    e = ELFFile(f)
    symtab = e.get_section_by_name('.symtab')
    ro = e.get_section_by_name('.rodata.str1.1')
    targets = {0x237: "'input'", 0x50: "'table'", 0x91: "'front'", 0x7e: "'adc'"}
    for sec in e.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        tgt = e.get_section(sec['sh_info'])
        for rel in sec.iter_relocations():
            sym = symtab.get_symbol(rel['r_info_sym'])
            if sym['st_shndx'] != e.get_section_index('.rodata.str1.1'):
                continue
            add = rel['r_addend'] if rel.is_RELA() else None
            # REL relocations on ARM store the addend in place
            off = rel['r_offset']
            if add is None:
                add = int.from_bytes(tgt.data()[off:off + 4], 'little')
            if add in targets:
                print(f'{sec.name} @ {off:#06x} -> {targets[add]} addend={add:#x}')
    # also dump the first bytes of kbd_init for manual inspection
    text = e.get_section_by_name('.text').data()
    print('\nkbd_init at 0x0, first 64 bytes:', text[:64].hex(' '))
