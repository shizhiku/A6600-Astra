"""Find adr-style references (add rX,pc,#imm) to libsencore packet strings, plus raw dword pointers."""
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
    'resCode(dup)': 0x19c60,
}

print('=== raw dword occurrences of string addresses ===')
for name, tgt in TARGETS.items():
    pat = struct.pack('<I', tgt)
    idx, n = d.find(pat), 0
    pos = []
    while idx >= 0 and n < 5:
        pos.append(idx); n += 1
        idx = d.find(pat, idx + 1)
    print(f'  {name:22s} ptr-words at {[hex(p) for p in pos]}')

print('\n=== adr-style (add rX, pc, #imm) ===')
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
found = {}
for ins in md.disasm(d, 0):
    if ins.mnemonic != 'add' or 'pc' not in ins.op_str or '#' not in ins.op_str:
        continue
    try:
        imm = int(ins.op_str.split('#')[-1], 0)
    except ValueError:
        continue
    tgt = ((ins.address + 4) & ~3) + imm
    for name, s in TARGETS.items():
        if tgt == s:
            found.setdefault(name, []).append(ins.address)

for name, sites in found.items():
    print(f'  {name:22s} referenced at {[hex(x) for x in sites[:6]]}')
if not found:
    print('  none')

# show code context for the first hit of each
if found:
    for name, sites in list(found.items())[:3]:
        a = sites[0]
        print(f'\n=== context for {name} at {a:#x} ===')
        for x in md.disasm(d[max(0, a - 30): a + 40], max(0, a - 30)):
            print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:9} {x.op_str}')
