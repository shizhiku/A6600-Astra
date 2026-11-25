"""Decode the literal used by the font-list helper and find callers of the node creator."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'
d = LIB.read_bytes()

print('=== bytes around the helper ===')
for off in range(0x54E7A8, 0x54E7D8, 4):
    w = struct.unpack_from('<I', d, off)[0]
    print(f'  {off:#08x}: {d[off:off+4].hex(" ")}  u32={w:#010x}')

print('\n=== compute candidate list-head addresses ===')
# ldr r4,[pc,#0x20] at 0x54E7AC -> literal at align(0x54E7B0)+0x20
lit_addr = (0x54E7AC + 4) + 0x20
lit = struct.unpack_from('<I', d, lit_addr)[0]
print(f'  literal at {lit_addr:#x} = {lit:#x}')
for pcbase in (0x54E7B4, 0x54E7B8):
    print(f'  if add pc base = {pcbase:#x}: head = {pcbase + lit:#x}')

print('\n=== scanning .text for bl targets == 0x54E7D4 ===')
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
hits = []
for ins in md.disasm(d, 0):
    if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
        try:
            tgt = int(ins.op_str[1:], 16)
        except ValueError:
            continue
        if tgt in (0x54E7D4, 0x54E79C, 0x54E7A8):
            hits.append((ins.address, ins.mnemonic, tgt))
print('hits:', len(hits))
for a, mn, t in hits[:20]:
    print(f'  {a:#08x} {mn} {t:#08x}')
