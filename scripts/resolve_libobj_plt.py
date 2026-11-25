"""Resolve which imported symbol libObj's PLT slot at 0xFF588 corresponds to."""
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'
TARGET = 0xFF588

data = LIB.read_bytes()

print('--- disassembly around PLT slot ---')
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
for ins in md.disasm(data[TARGET - 8:TARGET + 24], TARGET - 8):
    mark = '   <== target slot' if ins.address == TARGET else ''
    print(f'  {ins.address:06x} {ins.bytes.hex():8} {ins.mnemonic:9} {ins.op_str}{mark}')

# Some ARM PLT stubs compute a GOT address; try to parse common patterns:
#  add r12, pc ; add r12, r12 ; ldr pc,[r12, #imm]
got_addrs = set()
md2 = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md2.detail = True
for ins in md2.disasm(data[TARGET:TARGET + 16], TARGET):
    try:
        if ins.mnemonic.startswith('ldr') and len(ins.operands) >= 2:
            mem = ins.operands[1]
            if mem.type == 3:  # ARM_OP_MEM
                pass
    except Exception:
        pass

print('\n--- section layout near 0xFF588 ---')
with open(LIB, 'rb') as f:
    e = ELFFile(f)
    for s in e.iter_sections():
        if s['sh_addr'] <= TARGET < s['sh_addr'] + s['sh_size']:
            print(f'  section {s.name} addr={s["sh_addr"]:#x} size={s["sh_size"]:#x}')
    rel = e.get_section_by_name('.rel.plt') or e.get_section_by_name('.rela.plt')
    dynsym = e.get_section_by_name('.dynsym')
    if rel is not None and dynsym is not None:
        print(f'  {rel.name} entries: {rel.num_relocations()}')
        # print the symbol names in order with index, to later correlate with PLT slot order
        names = []
        for r in rel.iter_relocations():
            sym = dynsym.get_symbol(r['r_info_sym'])
            names.append((r['r_offset'], sym.name))
        print('  first 12 relocations:')
        for off, name in names[:12]:
            print(f'    got {off:#x} -> {name}')
        print('  last 6 relocations:')
        for off, name in names[-6:]:
            print(f'    got {off:#x} -> {name}')
