"""Disassemble the .init.text region around the 'input' string reference."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

KO = Path(r'<WORKSPACE>/03-证据/静态分析/input.ko')
with open(KO, 'rb') as f:
    e = ELFFile(f)
    sec = e.get_section_by_name('.init.text')
    data = sec.data()
    base = sec['sh_addr']
    print('init.text size', len(data), 'addr', hex(base))
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    start = 0x0ad0
    end = min(len(data), 0x0b90)
    for ins in md.disasm(data[start:end], start):
        print(f'{ins.address:06x} {ins.bytes.hex():10s} {ins.mnemonic:8s} {ins.op_str}')
    # relocations inside init.text
    from elftools.elf.relocation import RelocationSection
    print('\nrelocations in .init.text near 0xb00-0xb60:')
    sec_idx = e.get_section_index('.init.text')
    for rs in e.iter_sections():
        if isinstance(rs, RelocationSection) and rs['sh_info'] == sec_idx:
            for rel in rs.iter_relocations():
                off = rel['r_offset']
                if 0xb00 <= off < 0xb60:
                    print(f'  off={off:#06x} type={rel["r_info_type"]} sym={rel["r_info_sym"]}')
