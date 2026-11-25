"""Disassemble the ARM PLT entry at 0xFF588 and resolve its GOT slot exactly."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'
SLOT = 0xFF588
data = LIB.read_bytes()

print('--- ARM disassembly from a bit earlier ---')
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
for ins in md.disasm(data[SLOT - 0x10: SLOT + 0x10], SLOT - 0x10):
    mark = '   <== slot' if ins.address == SLOT else ''
    print(f'  {ins.address:06x} {ins.bytes.hex():8} {ins.mnemonic:8} {ins.op_str}{mark}')

# ARM PLT entry: add ip,pc,#imm ; add ip,ip,#imm ; ldr pc,[ip,#imm]!
import re
entries = []
md2 = Cs(CS_ARCH_ARM, CS_MODE_ARM)
for ins in md2.disasm(data[SLOT - 8: SLOT + 12], SLOT - 8):
    entries.append((ins.address, ins.mnemonic, ins.op_str, ins.bytes.hex()))

# try to compute ip from the first add
ip = None
got = None
for addr, mn, ops, hx in entries:
    if mn == 'add' and 'ip, pc' in ops:
        m = re.search(r'#(-?0x[0-9a-f]+|\d+)', ops)
        if m:
            ip = ((addr + 8) & ~3) + int(m.group(1), 0)
    elif mn == 'add' and 'ip, ip' in ops:
        m = re.search(r'#(-?0x[0-9a-f]+|\d+)', ops)
        if m and ip is not None:
            ip += int(m.group(1), 0)
    elif mn == 'ldr' and 'pc,' in ops and 'ip' in ops:
        m = re.search(r'#(-?0x[0-9a-f]+|\d+)', ops)
        if m and ip is not None:
            got = ip + int(m.group(1), 0)
print(f'\ncomputed ip={ip:#x} got={got:#x}' if got else '\ncould not compute GOT')

if got:
    with open(LIB, 'rb') as f:
        e = ELFFile(f)
        rel = e.get_section_by_name('.rel.plt')
        dynsym = e.get_section_by_name('.dynsym')
        for r in rel.iter_relocations():
            if r['r_offset'] == got:
                sym = dynsym.get_symbol(r['r_info_sym'])
                print(f'  MATCH: got {got:#x} -> {sym.name}')
                break
        else:
            print('  no relocation at that GOT address')
