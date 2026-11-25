"""Inspect libsencore.so strings around the font/extraction references."""
from pathlib import Path
import importlib.util, re

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

data = None
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    if path == '/lib/libsencore.so':
        data = fs.read_file(ino)
        break
if data is None:
    raise SystemExit('libsencore.so not found')

out = BASE / '03-证据/静态分析/libsencore.so'
out.write_bytes(data)
print('size', len(data), '->', out.name)

# print printable strings in a window around the first /tmp/images reference
for m0 in re.finditer(rb'/tmp/images', data):
    off = m0.start()
    print(f'\n--- window around {off:#x} ---')
    seg = data[max(0, off - 400): off + 400]
    for s in re.findall(rb'[ -~]{5,}', seg):
        print('   ', s.decode('latin1')[:110])

# also print strings mentioning 'ltt', 'font', 'extract', 'images'
print('\n--- selected strings ---')
seen = 0
for s in re.findall(rb'[ -~]{6,}', data):
    t = s.decode('latin1')
    if any(k in t.lower() for k in ('ltt', 'font', '/tmp', 'extract', 'unpack', '.uz', 'images')):
        print('   ', t[:120])
        seen += 1
        if seen > 40:
            break
