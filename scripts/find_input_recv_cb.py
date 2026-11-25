"""Locate the OSAL queue-callback registration in input.ko and the callback it passes."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

KO = Path(r'<WORKSPACE>/03-证据/静态分析/input.ko')
WANT = ('osal_reg_sync_msg_queue_cb', 'osal_reg_msg_queue_cb', 'osal_dynamic_id')

with open(KO, 'rb') as f:
    el = ELFFile(f)
    symtab = el.get_section_by_name('.symtab')
    text = el.get_section_by_name('.text')
    data = text.data()
    hits = []
    for sec in el.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        for rel in sec.iter_relocations():
            sym = symtab.get_symbol(rel['r_info_sym'])
            if sym.name in WANT:
                hits.append((sec.name, rel['r_offset'], sym.name))
    print('registration relocations:')
    for name, off, sym in hits:
        print(f'  {name} off={off:#06x} sym={sym}')

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.skipdata = True
    for name, off, sym in hits:
        if False:
            continue
        start = max(0, off - 0x40)
        print(f'\n=== around {off:#x} ({sym}) ===')
        for ins in md.disasm(data[start:off + 0x20], start):
            mark = ' <== reloc' if ins.address == off else ''
            print(f'{ins.address:06x} {ins.bytes.hex():10s} {ins.mnemonic:8s} {ins.op_str}{mark}')
