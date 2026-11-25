from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from pathlib import Path
import io

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

syms = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection) and sec.name in ('.dynsym', '.symtab'):
        for x in sec.iter_symbols():
            if x.name in ('Application_Start', '_Z16Application_Startv'):
                syms[x.name] = x['st_value']
print('symbols', {k: hex(v) for k, v in syms.items()})
start = (syms.get('_Z16Application_Startv') or syms.get('Application_Start'))
if not start:
    raise SystemExit('Application_Start not found')
start &= ~1
print('Application_Start', hex(start))
insns = list(md.disasm(td[start - tb: start - tb + 0x300], start))
for i in insns:
    print(f'{i.address:08x} {i.mnemonic:8} {i.op_str}')
