"""List libsencore imports related to fifos/open, then find bl sites calling open with a FIFO path."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
import struct

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libsencore.so'
d = LIB.read_bytes()

with open(LIB, 'rb') as f:
    e = ELFFile(f)
    print('=== imports matching fifo/open/pipe/read/write ===')
    for sym in e.get_section_by_name('.dynsym').iter_symbols():
        n = sym.name or ''
        if any(k in n for k in ('fifo', 'open', 'pipe', 'read', 'write', 'select', 'poll')):
            print(f'  {n}')

# find open's PLT entry (resolved earlier as 0xE6CC) and all bl sites to it
OPEN_PLT = 0xE6CC
FIFO_VA = {'req': 0x194F8, 'res': 0x1950F}

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
sites = []
for ins in md.disasm(d, 0):
    if ins.mnemonic == 'bl' and ins.op_str.startswith('#'):
        try:
            t = int(ins.op_str[1:], 16)
        except ValueError:
            continue
        if t == OPEN_PLT:
            sites.append(ins.address)
print(f'\nbl sites to open(): {len(sites)}')

# for each site, scan backwards for a FIFO string reference
def scan_back(site, window=0x80):
    found = []
    for A in range(max(0, site - window), site, 2):
        V = struct.unpack_from('<I', d, A)[0]
        if V == 0 or V > 0x20000:
            continue
        for name, tgt in FIFO_VA.items():
            b = tgt - V - 4
            if abs(b - site) <= window and (b % 2 == 0):
                found.append((name, A, b))
    return found

for s in sites[:40]:
    f2 = scan_back(s)
    if f2:
        print(f'  open@{s:#06x}: fifo refs {[(n, hex(b)) for n, A, b in f2]}')
