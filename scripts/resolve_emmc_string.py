"""Resolve the warning string VA in emmc.ko and find code referencing it (absolute literal)."""
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BASE = Path(r'<WORKSPACE>')
KO = BASE / '03-证据/静态分析/emmc.ko'
blob = KO.read_bytes()

with open(KO, 'rb') as f:
    e = ELFFile(f)
    off = blob.find(b'Software Tuning')
    va = None
    for s in e.iter_sections():
        so, sz = s['sh_offset'], s['sh_size']
        if so <= off < so + sz:
            va = s['sh_addr'] + (off - so)
            print(f'section {s.name}: sh_addr={s["sh_addr"]:#x} off={so:#x} -> VA={va:#x}')
    print('\nsections:')
    for s in e.iter_sections():
        if s['sh_size']:
            print(f'  {s.name:14s} addr={s["sh_addr"]:#08x} off={s["sh_offset"]:#08x} size={s["sh_size"]:#08x}')

    if va is None:
        raise SystemExit('string VA unresolved')

    # search dwords equal to the VA (absolute address literal)
    pat = struct.pack('<I', va)
    pos, i, n = [], 0, 0
    idx = blob.find(pat)
    while idx >= 0 and n < 10:
        pos.append(idx); n += 1
        idx = blob.find(pat, idx + 1)
    print(f'\ndword refs to VA {va:#x}: {[hex(p) for p in pos]}')

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.skipdata = True
    for p in pos[:3]:
        start = max(0, p - 0x40)
        print(f'\n=== code around literal {p:#x} ===')
        for x in md.disasm(blob[start:p + 0x20], start):
            print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:8} {x.op_str}')
