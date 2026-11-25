"""Find 0x08249000 as a literal / immediate inside a5pFw.so and a5bObj.so.

The crash is a page-translation fault at 0x08249000 which maps to a `---p`
(no-access) anonymous region.  If the value appears as a hard-coded address in
the gen5 code, that tells us it expects a mapping there.
"""
import struct
from pathlib import Path

TARGETS = [
    Path('03-证据/静态分析/97_abi/a5pFw_upmfix_nonotify.so'),
    Path('03-证据/静态分析/grm/lib/libObj.so'),
]
VALUE = 0x08249000
LITTLE = struct.pack('<I', VALUE)
BIG = struct.pack('>I', VALUE)

for src in TARGETS:
    if not src.exists():
        print('MISSING', src)
        continue
    d = src.read_bytes()
    print('=== %s (%d bytes) ===' % (src.name, len(d)))
    for label, pat in (('LE', LITTLE), ('BE', BIG)):
        hits = []
        idx = 0
        while len(hits) < 20:
            idx = d.find(pat, idx)
            if idx < 0:
                break
            hits.append(idx)
            idx += 1
        print('  %s hits: %d %s' % (label, len(hits),
                                    [hex(h) for h in hits[:10]]))

    # also look for nearby page-aligned addresses 0x082x x000 (the same region)
    print('  --- all 0x0824xxxx-aligned LE values in .text-ish range ---')
    found = 0
    for off in range(0, len(d) - 4, 4):
        v = struct.unpack_from('<I', d, off)[0]
        if 0x08200000 <= v <= 0x08300000 and (v & 0xFFF) == 0:
            print('    off=%#x value=%#x' % (off, v))
            found += 1
            if found > 15:
                break
    if not found:
        print('    (none)')
