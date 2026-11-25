"""Correct scan: literal values V satisfy target = V + (add_pc), where add_pc lies in .text."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libsencore.so'
d = LIB.read_bytes()
TEXT_LO, TEXT_HI = 0x0F344, 0x18DE0
TARGETS = {'Receive Pkt Err': 0x19BE9, 'ReceivePkt2': 0x19C22,
           'Trans(to Subsystem)': 0x19C92, 'Trans2': 0x19CDF,
           'FileNotFound': 0x19ABD, 'RECV_OSAL_PACKET': 0x19AEC}

cands = []
for A in range(0, len(d) - 4, 2):
    V = struct.unpack_from('<I', d, A)[0]
    if V == 0 or V > 0x10000:
        continue
    for name, tgt in TARGETS.items():
        b_plus4 = tgt - V          # this should be the PC value used by add
        if TEXT_LO <= b_plus4 <= TEXT_HI and (b_plus4 % 2 == 0):
            cands.append((A, name, V, b_plus4 - 4))

print(f'candidates: {len(cands)}')
for A, name, V, b in cands[:25]:
    print(f'  literal@{A:#08x} V={V:#x} -> {name} (add at ~{b:#x})')

# show code near the first few add sites
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
shown = 0
for A, name, V, b in cands:
    if shown >= 3:
        break
    shown += 1
    start = max(TEXT_LO, b - 16)
    print(f'\n=== {name}: add@{b:#x} ===')
    for x in md.disasm(d[start:b + 24], start):
        mark = '   <== add pc' if x.address == b else ''
        print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:9} {x.op_str}{mark}')
