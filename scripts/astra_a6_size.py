"""Show where ZV-1M2 /usr space goes, to plan an ASTRA-lite image that fits 205 MB."""
from pathlib import Path
import importlib.util
from collections import defaultdict

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'

spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fs = m.Ext2(str(IMG))

sizes = defaultdict(int)
counts = defaultdict(int)
total = 0
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    mode, size, _ = fs.inode(ino)
    parts = path.strip('/').split('/')
    key = '/' + parts[0] if len(parts) > 1 else '(root)'
    sizes[key] += size
    counts[key] += 1
    total += size

print(f'total {total/1048576:.1f} MB in {sum(counts.values())} files\n')
for k in sorted(sizes, key=lambda x: -sizes[x]):
    print(f'  {k:16} {sizes[k]/1048576:8.1f} MB  {counts[k]:6d} files')

print('\n=== /lib biggest files ===')
libs = []
for path, ino, is_dir in fs.walk():
    if is_dir or not path.startswith('/lib/'):
        continue
    mode, size, _ = fs.inode(ino)
    libs.append((size, path))
for s, p in sorted(libs, reverse=True)[:15]:
    print(f'  {s/1048576:7.1f} MB  {p}')
