"""List tuning-related symbols in emmc.ko with sizes and disassemble the wrapper."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BASE = Path(r'<WORKSPACE>')
KO = BASE / '03-证据/静态分析/emmc.ko'
blob = KO.read_bytes()

with open(KO, 'rb') as f:
    e = ELFFile(f)
    symtab = e.get_section_by_name('.symtab')
    rows = []
    for s in symtab.iter_symbols():
        if s.name and s.entry.st_size:
            rows.append((s.entry.st_value, s.entry.st_size, s.entry.st_info.type, s.name))
rows.sort()
print('tuning-related symbols:')
for v, sz, typ, n in rows:
    if 'tuning' in n.lower() or 'exec_tuning' in n:
        print(f'  {v:#08x} size={sz:5d} {typ} {n}')

# disassemble mmc_hw_wrapper_exec_tuning if present
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.skipdata = True
targets = [r for r in rows if r[3] in ('mmc_hw_wrapper_exec_tuning', 'mmc_hw_wrapper_check_exec_tuning')]
for v, sz, typ, n in targets:
    print(f'\n=== {n} @ {v:#x} size={sz} ===')
    for x in md.disasm(blob[v:v + min(sz, 0x140)], v):
        print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:8} {x.op_str}')
