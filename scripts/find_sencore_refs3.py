"""Refined scan: literal V must pair with a real `add rX, pc` at target-V-4."""
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

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True

def decode_at(addr, count=1):
    out = []
    for x in md.disasm(d[addr:addr + 4 * count], addr):
        out.append(x)
        if len(out) >= count:
            break
    return out

found = []
for A in range(0, len(d) - 4, 2):
    V = struct.unpack_from('<I', d, A)[0]
    if V == 0 or V > 0x10000:
        continue
    for name, tgt in TARGETS.items():
        b = tgt - V - 4          # address of the add instruction
        if not (TEXT_LO <= b <= TEXT_HI) or (b % 2):
            continue
        ins = decode_at(b)
        if not ins or ins[0].mnemonic != 'add' or 'pc' not in ins[0].op_str:
            continue
        found.append((A, name, V, b, ins[0].op_str))

print(f'refined hits: {len(found)}')
for A, name, V, b, ops in found[:20]:
    print(f'  literal@{A:#08x} V={V:#x} add@{b:#x} ({ops}) -> {name}')

for A, name, V, b, ops in found[:2]:
    start = max(TEXT_LO, A - 8)
    print(f'\n=== literal {name} at {A:#x}; add at {b:#x} ===')
    for x in md.disasm(d[start:A + 32], start):
        print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:9} {x.op_str}')
