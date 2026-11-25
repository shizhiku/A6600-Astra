"""Dump /usr/share/app/lang_cmn.uxc (language resource naming the fonts)."""
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
    if path == '/share/app/lang_cmn.uxc':
        data = fs.read_file(ino)
        out = BASE / '03-证据/静态分析/lang_cmn.uxc'
        out.write_bytes(data)
        print('size', len(data), '-> saved as', out.name)
        print('hex head:', data[:64].hex(' '))
        cur = bytearray()
        for i, b in enumerate(data):
            if 32 <= b < 127 or b == 0:
                cur.append(b)
            else:
                if len(cur.strip(b'\x00')) >= 4:
                    print('  str:', cur.split(b'\x00')[0].decode('latin1'))
                cur = bytearray()
        if len(cur.strip(b'\x00')) >= 4:
            print('  str:', cur.split(b'\x00')[0].decode('latin1'))
        break
