"""Locate the exception-monitor strings to understand trap_no semantics."""
from pathlib import Path

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/nflasha3-Image'
d = IMG.read_bytes()

TERMS = [b'Illeagle', b'Illegal Instruction', b'trap_no', b'Exception Syndrome',
         b'register dump', b'current task', b'Entering exception monitor']

for t in TERMS:
    idx = []
    i = d.find(t)
    while i >= 0 and len(idx) < 5:
        idx.append(i)
        i = d.find(t, i + 1)
    print(f'{t.decode():26s} -> {[hex(x) for x in idx]}')
    for x in idx[:2]:
        seg = d[max(0, x - 80): x + 120]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg)
        print(f'    ctx@{x:#x}: {printable}')
