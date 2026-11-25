"""Identify the libc function that contains the failing syscall wrapper."""
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASE = Path(r'<WORKSPACE>')
LIBC = BASE / '03-证据/静态分析/nflasha7_libc-2.11.2.so'
TARGETS = [0x9AC2A, 0x9AC50]

with open(LIBC, 'rb') as f:
    e = ELFFile(f)
    funcs = []
    for name in ('.dynsym', '.symtab'):
        s = e.get_section_by_name(name)
        if s is None:
            continue
        for sym in s.iter_symbols():
            info = sym.entry.st_info
            if info['type'] == 'STT_FUNC' and sym.entry.st_value:
                funcs.append((sym.entry.st_value, sym.entry.st_size, sym.name))
    funcs = sorted(set(funcs))
    print('funcs:', len(funcs))
    for t in TARGETS:
        owner = None
        for start, size, name in funcs:
            if start <= t < start + max(size, 1):
                owner = (hex(start), hex(size), name)
        print(f'{t:#x} -> {owner}')
    near = [x for x in funcs if 0x9A800 <= x[0] <= 0x9B200]
    print('\nnearby symbols:')
    for s, sz, n in near:
        print(f'  {s:#08x} size={sz:#x} {n}')
