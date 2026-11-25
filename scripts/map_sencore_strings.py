"""Map libsencore string file offsets to virtual addresses via section/segment headers."""
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libsencore.so'
OFFS = {'Receive Pkt Err': 0x19be9, 'Trans(to Subsystem)': 0x19c92,
        'FileNotFound': 0x19abd, 'RECV_OSAL_PACKET': 0x19aec}

with open(LIB, 'rb') as f:
    e = ELFFile(f)
    print('sections of interest:')
    for s in e.iter_sections():
        so, sz = s['sh_offset'], s['sh_size']
        for name, off in OFFS.items():
            if so <= off < so + sz:
                va = s['sh_addr'] + (off - so)
                print(f'  {name:22s} file={off:#x} section={s.name} '
                      f'sh_addr={s["sh_addr"]:#x} -> VA={va:#x}')

    print('\nsegments:')
    for seg in e.iter_segments():
        print(f'  {seg["p_type"]:12s} vaddr={seg["p_vaddr"]:#x} off={seg["p_offset"]:#x} '
              f'filesz={seg["p_filesz"]:#x} memsz={seg["p_memsz"]:#x}')

    print('\nselected sections:')
    for s in e.iter_sections():
        if s['sh_size'] and s.name in ('.text', '.rodata', '.data', '.data.rel.ro',
                                       '.dynstr', '.dynsym', '.rel.dyn', '.plt', '.got'):
            print(f'  {s.name:14s} addr={s["sh_addr"]:#08x} off={s["sh_offset"]:#08x} '
                  f'size={s["sh_size"]:#08x}')
