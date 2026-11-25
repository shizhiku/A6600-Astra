"""Locate the kernel code that prints 'Oops - bad syscall' and inspect its check."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/nflasha3-Image'
KVA = 0x60000000
d = IMG.read_bytes()

def find(term):
    i = -1
    out = []
    while True:
        i = d.find(term, i + 1)
        if i < 0:
            break
        out.append(i)
    return out

for term in (b'Oops - bad syscall', b'undefined instruction: pc=', b'complete system call'):
    offs = find(term)
    print(term.decode(), '->', [hex(o) for o in offs], 'VA', [hex(KVA + o) for o in offs])
    for o in offs[:2]:
        # look for a literal referencing this address
        target = KVA + o
        pat = struct.pack('<I', target)
        refs = find(pat)
        print(f'   literal refs to {target:#x}:', [hex(r) for r in refs][:8])
        for r in refs[:2]:
            start = max(0, r - 0x60)
            print(f'   --- code window before ref at {r:#x} ---')
            md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            md.skipdata = True
            for ins in md.disasm(d[start:r + 8], start):
                print(f'     {KVA + ins.address:08x} {ins.bytes.hex():10} {ins.mnemonic:9} {ins.op_str}')
