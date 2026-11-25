"""Try several kernel load bases to find code referencing the bad-syscall strings."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/nflasha3-Image'
d = IMG.read_bytes()

STR_OFFS = [0x33F34F, 0x33F469, 0x33F36E]
BASES = [0x60000000, 0x60008000, 0x60010000, 0x60004000, 0x60018000]

for kva in BASES:
    hits = []
    for so in STR_OFFS:
        pat = struct.pack('<I', kva + so)
        i = d.find(pat)
        while i >= 0:
            hits.append((so, i))
            i = d.find(pat, i + 1)
    print(f'base {kva:#010x}: {len(hits)} literal refs')
    if hits:
        for so, r in hits[:6]:
            print(f'   string {so:#x} referenced at file {r:#x} (VA {kva + r:#010x})')
        # disassemble around the first ref
        so, r = hits[0]
        start = max(0, r - 0x80)
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md.skipdata = True
        print('   --- window ---')
        for ins in md.disasm(d[start:r + 8], start):
            print(f'     {kva + ins.address:08x} {ins.bytes.hex():10} {ins.mnemonic:9} {ins.op_str}')
        break
