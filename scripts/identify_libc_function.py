"""Identify the function containing libc offset 0x15796 and disassemble around it."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIBC = BASE / '03-证据/静态分析/libc-2.11.2.so'
TARGET = 0x15796

with open(LIBC, 'rb') as f:
    e = ELFFile(f)
    # gather function symbols from both symtab and dynsym
    funcs = []
    for name in ('.symtab', '.dynsym'):
        s = e.get_section_by_name(name)
        if s is None:
            continue
        for sym in s.iter_symbols():
            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_value']:
                funcs.append((sym['st_value'], sym['st_size'], sym.name))
    funcs.sort()
    print('function symbols:', len(funcs))

    owner = None
    for start, size, name in funcs:
        end = start + (size if size else 0)
        if start <= TARGET < end or (size == 0 and start <= TARGET < start + 0x400):
            owner = (start, size, name)
            # keep the closest one
    if owner:
        print(f'target {TARGET:#x} in {owner[2]} (start={owner[0]:#x} size={owner[1]:#x})')
    else:
        print('no owning symbol found; nearest below:')
        below = [f for f in funcs if f[0] <= TARGET][-3:]
        for b in below:
            print('  ', hex(b[0]), b[2], 'size', b[1])

    # disassemble a window around the target (Thumb)
    code_sec = None
    for s in e.iter_sections():
        if s['sh_addr'] <= TARGET < s['sh_addr'] + s['sh_size']:
            code_sec = s
            break
    print('section:', code_sec.name if code_sec else None)
    data = code_sec.data()
    start = TARGET - 0x60
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    for ins in md.disasm(data[start:start + 0xA0], start):
        mark = '   <== target' if ins.address == TARGET else ''
        print(f'  {ins.address:06x} {ins.bytes.hex():10} {ins.mnemonic:10} {ins.op_str}{mark}')
