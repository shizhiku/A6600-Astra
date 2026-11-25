"""Find movw/movt pairs that materialize libsencore packet string addresses."""
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libsencore.so'
d = LIB.read_bytes()

TARGETS = {
    'Receive Pkt Err': 0x19be9,
    'Trans(to Subsystem)': 0x19c92,
    'FileNotFound': 0x19abd,
    'RECV_OSAL_PACKET': 0x19aec,
}
REV = {v: k for k, v in TARGETS.items()}

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
lo = {}
hits = []
for ins in md.disasm(d, 0):
    mn = ins.mnemonic
    if mn in ('movw', 'mov.w') and ins.op_str.startswith('r') and '#' in ins.op_str:
        try:
            reg = ins.op_str.split(',')[0].strip()
            val = int(ins.op_str.split('#')[-1], 0)
        except ValueError:
            continue
        lo[reg] = (val, ins.address)
    elif mn == 'movt' and '#' in ins.op_str:
        try:
            reg = ins.op_str.split(',')[0].strip()
            hi = int(ins.op_str.split('#')[-1], 0)
        except ValueError:
            continue
        if reg in lo:
            full = (hi << 16) | lo[reg][0]
            if full in REV:
                hits.append((ins.address, REV[full], full, lo[reg][1]))

print(f'movw/movt references: {len(hits)}')
for addr, name, val, waddr in hits:
    print(f'  {name:22s} materialized at {addr:#08x} (movw at {waddr:#08x}) value={val:#x}')

# context for first few
for addr, name, val, waddr in hits[:3]:
    start = max(0, addr - 40)
    print(f'\n=== context for {name} ===')
    for x in md.disasm(d[start:addr + 60], start):
        mark = '   <== movt' if x.address == addr else ''
        print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:9} {x.op_str}{mark}')
