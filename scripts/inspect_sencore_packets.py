"""Inspect libsencore packet-format clues (header fields, fragmentation)."""
from pathlib import Path
import re

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libsencore.so'
d = LIB.read_bytes()

pats = [b'Receive Pkt Err', b'Trans(to Subsystem)', b'Offset', b'resCode', b'DataSize',
        b'/tmp/images', b'FileNotFound', b'RECV_OSAL_PACKET', b'Sonar_Packet']
for p in pats:
    i = d.find(p)
    print(f'{p.decode():22s} first={hex(i) if i >= 0 else "none"}')

print('\n--- strings in the packet-error region ---')
i = d.find(b'Receive Pkt Err')
if i >= 0:
    region = d[i - 600: i + 700]
    for s in re.findall(rb'[ -~]{6,}', region):
        print('   ', s.decode('latin1')[:120])

print('\n--- all format strings mentioning sizes/offsets ---')
seen = set()
for s in re.findall(rb'[ -~]{8,}', d):
    t = s.decode('latin1')
    if any(k in t for k in ('size', 'Size', 'offset', 'Offset', 'adrs', 'Adrs', 'resCode', 'pkt', 'Pkt')):
        if t not in seen:
            seen.add(t)
            print('   ', t[:130])
    if len(seen) > 45:
        break
