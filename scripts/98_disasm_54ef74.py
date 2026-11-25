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
start = 0x54EF74
insns = list(md.disasm(td[start - tb:start - tb + 0x300], start))
for i in insns:
    print(f'{i.address:08x} {i.mnemonic:8} {i.op_str}')
