"""Find call sites in input.ko that reference OSAL send symbols."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

KO = Path(r'<WORKSPACE>/03-证据/静态分析/input.ko')
WANT = ('osal_snd_msg', 'osal_snd_sync_msg', 'osal_snd_sync_direct',
        'osal_valloc_msg_wait', 'osal_free_msg', 'osal_dynamic_id',
        'osal_reg_sync_msg_queue_cb')

with open(KO, 'rb') as f:
    e = ELFFile(f)
    symtab = e.get_section_by_name('.symtab')
    for sec in e.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        tgt = e.get_section(sec['sh_info'])
        for rel in sec.iter_relocations():
            sym = symtab.get_symbol(rel['r_info_sym'])
            if sym.name in WANT:
                print(f'{sec.name:16s} off={rel["r_offset"]:#06x} '
                      f'sym={sym.name} type={rel["r_info_type"]}')
