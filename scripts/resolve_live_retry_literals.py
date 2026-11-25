"""Resolve the live-build retry routine's pc-relative literals."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/av-cam-live.bin'
VA0 = 0x635C6000
ROUTINE = 0x63861584

d = IMG.read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True

print('--- disassembly around live retry routine ---')
code = [x for x in md.disasm(d[ROUTINE - VA0: ROUTINE - VA0 + 0xB0], ROUTINE)]
for x in code:
    print(f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:9} {x.op_str}')

print('\n--- resolved pc-relative literals ---')
import re
for x in code:
    if x.mnemonic == 'ldr' and '[pc' in x.op_str:
        m = re.search(r'\[pc, #(0x[0-9a-f]+|\d+)\]', x.op_str)
        if not m:
            continue
        imm = int(m.group(1), 0)
        rd = x.op_str.split(',')[0].strip()
        lit = ((x.address + 4) & ~3) + imm
        val = struct.unpack_from('<I', d, lit - VA0)[0]
        target = ((x.address + 6) + val) & 0xFFFFFFFF   # assume add follows (no align)
        print(f'  {x.address:08x} ldr {rd},[pc,#{imm:#x}] lit={lit:#010x} val={val:#010x} '
              f'-> add-resolved {target:#010x}')
