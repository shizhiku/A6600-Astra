"""Read and decode /usr/share/app/fontlist.dat."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    if path == '/share/app/fontlist.dat':
        data = fs.read_file(ino)
        print('size', len(data))
        print('hex:', data.hex())
        print('ascii:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in data))
        out = BASE / '03-证据/静态分析/fontlist.dat'
        out.write_bytes(data)
        print('saved', out.name)
        break
