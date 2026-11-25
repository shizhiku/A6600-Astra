"""Decode libc at VA 0x15796 correctly (VA -> segment -> file offset)."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

BASE = Path(r'<WORKSPACE>')
LIBC = BASE / '03-证据/静态分析/libc-2.11.2.so'
VA = 0x15796

with open(LIBC, 'rb') as f:
    e = ELFFile(f)
    seg = None
    for s in e.iter_segments():
        if s['p_type'] != 'PT_LOAD':
            continue
        vaddr, memsz, filesz = s['p_vaddr'], s['p_memsz'], s['p_filesz']
        if vaddr <= VA < vaddr + memsz:
            seg = (vaddr, filesz, memsz, s['p_offset'])
            break
    if seg is None:
        raise SystemExit('VA not in any LOAD segment')
    vaddr, filesz, memsz, p_off = seg
    print(f'LOAD seg vaddr={vaddr:#x} filesz={filesz:#x} memsz={memsz:#x} off={p_off:#x}')
    file_off = p_off + (VA - vaddr)
    print(f'VA {VA:#x} -> file offset {file_off:#x}')
    f.seek(file_off - 0x20)
    window = f.read(0x60)
    base_va = VA - 0x20
    print('bytes:', window[:16].hex(' '))

    # function symbols in VA space
    funcs = []
    symtab = e.get_section_by_name('.symtab')
    if symtab:
        for sym in symtab.iter_symbols():
            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_value']:
                funcs.append((sym['st_value'], sym['st_size'], sym.name))
    funcs.sort()
    owner = None
    for start, size, name in funcs:
        if start <= VA < start + max(size, 1):
            owner = (start, size, name)
    print('owner symbol:', owner if owner else 'none')

    for mode_name, mode in (('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)):
        md = Cs(CS_ARCH_ARM, mode)
        print(f'--- {mode_name} ---')
        for ins in md.disasm(window, base_va):
            mark = '   <== fault VA' if ins.address == VA else ''
            print(f'  {ins.address:06x} {ins.bytes.hex():10} {ins.mnemonic:10} {ins.op_str}{mark}')
