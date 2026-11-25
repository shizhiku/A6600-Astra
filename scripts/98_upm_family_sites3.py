from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

for fn, ra, size in ((0x2b3571c, 0x2B359F7, 0x400),
                     (0x2b20810, 0x2B20821, 0x80),
                     (0x2b20ce0, 0x2B20DA9, 0x200)):
    print('==== fn', hex(fn), 'RA', hex(ra))
    insns = list(md.disasm(td[fn - tb: fn - tb + size], fn))
    for i in insns:
        mark = ''
        if i.address + i.size == ra:
            mark = '   <-- returns here (after BL notify?)'
        print(f'{i.address:08x} {i.mnemonic:8} {i.op_str}{mark}')
