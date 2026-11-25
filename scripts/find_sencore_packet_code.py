"""Locate code in libsencore that references the packet-format strings (PIC literals)."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libsencore.so'
d = LIB.read_bytes()

TARGETS = {
    'Receive Pkt Err': 0x19be9,
    'Trans(to Subsystem)': 0x19c92,
    'FileNotFound': 0x19abd,
    'RECV_OSAL_PACKET': 0x19aec,
    'fin_send': None,
}
TARGETS.pop('fin_send')

# String literals in PIC code: at address A the 4-byte value V satisfies A+4+V == target
# For Thumb, PC = align(A+4,4). Scan both interpretations.
hits = []
for A in range(0, len(d) - 4, 2):
    V = struct.unpack_from('<I', d, A)[0]
    if V == 0 or V > 0x1000000:
        continue
    for name, tgt in TARGETS.items():
        for pc in ((A + 4) & ~3, (A + 4) & ~1):
            if pc + V == tgt:
                hits.append((A, name, V))
                break
print('literal references found:')
seen = set()
for A, name, V in hits:
    key = (name, A)
    if key in seen:
        continue
    seen.add(key)
    print(f'  literal@{A:#08x} -> {name} (V={V:#x})')

# disassemble a window around each referencing literal site
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
shown = set()
for A, name, V in hits:
    site = A - 6
    if name in shown:
        continue
    shown.add(name)
    print(f'\n=== code near literal for {name} ===')
    for x in md.disasm(d[max(0, site - 24): site + 26], max(0, site - 24)):
        print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:9} {x.op_str}')
