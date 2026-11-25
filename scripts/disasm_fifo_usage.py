"""Find and disassemble the code in libsencore that uses /var/fifo/sen_host_*."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libsencore.so'
d = LIB.read_bytes()

def find_all(term, limit=6):
    out, i = [], d.find(term)
    while i >= 0 and len(out) < limit:
        out.append(i)
        i = d.find(term, i + 1)
    return out

TARGETS = {}
for term in (b'/var/fifo/sen_host_req', b'/var/fifo/sen_host_res', b'/var/fifo'):
    for off in find_all(term):
        TARGETS[f'{term.decode()}@{off:#x}'] = off
print('string offsets:', TARGETS)

TEXT_LO, TEXT_HI = 0x0F344, 0x18DE0
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True

def decode_at(addr, count=1):
    out = []
    for x in md.disasm(d[addr:addr + 4 * count], addr):
        out.append(x)
        if len(out) >= count:
            break
    return out

refs = []
for A in range(0, len(d) - 4, 2):
    V = struct.unpack_from('<I', d, A)[0]
    if V == 0 or V > 0x20000:
        continue
    for name, tgt in TARGETS.items():
        b = tgt - V - 4
        if not (TEXT_LO <= b <= TEXT_HI) or (b % 2):
            continue
        ins = decode_at(b)
        if ins and ins[0].mnemonic == 'add' and 'pc' in ins[0].op_str:
            refs.append((b, name, A, V))

print(f'\nreferences: {len(refs)}')
for b, name, A, V in refs[:12]:
    print(f'  add@{b:#06x} (literal@{A:#06x} V={V:#x}) -> {name}')

for b, name, A, V in refs[:2]:
    start = max(TEXT_LO, b - 40)
    print(f'\n=== context around {b:#x} for {name} ===')
    for x in md.disasm(d[start:b + 60], start):
        mark = '   <== ref' if x.address == b else ''
        print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:9} {x.op_str}{mark}')
