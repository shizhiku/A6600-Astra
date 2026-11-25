"""Diff image a5bObj.so vs reference libObj.so to find what differs.

Same size (3,931,624 B) but different SHA256.  Locate differing byte ranges.
"""
import importlib.util
import hashlib
from pathlib import Path

ROOT = Path('<WORKSPACE>')
spec = importlib.util.spec_from_file_location('u', str(ROOT / '02-脚本/97_ext2.py'))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)

fs = u.Ext2('/root/astra/97/m1-verified/astra-m1-astra7.img')
names = {p: i for p, i, d in fs.walk() if not d}
img = fs.read_file(names['/lib/a5bObj.so'])
ref = (ROOT / '03-证据/静态分析/grm/lib/libObj.so').read_bytes()

print('sizes', len(img), len(ref))
diffs = []
for i in range(0, min(len(img), len(ref))):
    if img[i] != ref[i]:
        diffs.append(i)

print('total differing bytes:', len(diffs))
if diffs:
    print('first:', hex(diffs[0]), 'last:', hex(diffs[-1]))
    # group into ranges
    ranges = []
    start = prev = diffs[0]
    for x in diffs[1:]:
        if x == prev + 1:
            prev = x
            continue
        ranges.append((start, prev))
        start = prev = x
    ranges.append((start, prev))
    print('ranges:', len(ranges))
    for a, b in ranges[:20]:
        print('  %#x..%#x (%d bytes)' % (a, b, b - a + 1))
        print('    img:', img[a:b + 1][:32].hex(' '))
        print('    ref:', ref[a:b + 1][:32].hex(' '))
