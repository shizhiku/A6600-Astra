"""Extract libc from the a6600 rootfs and decode the faulting instruction."""
from pathlib import Path
import importlib.util

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
ROOTFS = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha7'
OFFSET = 0x15796

spec = importlib.util.spec_from_file_location('a6600_usr', BASE / '02-脚本/a6600_usr.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

fs = mod.Ext2(str(ROOTFS))
found = None
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    if path.endswith('libc-2.11.2.so') or path.endswith('libc.so.6'):
        found = (path, fs.read_file(ino))
        break
if found is None:
    raise SystemExit('libc not found')

path, data = found
print('found', path, len(data), 'bytes')
print('saved to', BASE / '03-证据/静态分析/libc-2.11.2.so')
(BASE / '03-证据/静态分析/libc-2.11.2.so').write_bytes(data)
print('bytes at', hex(OFFSET), ':', data[OFFSET:OFFSET + 16].hex(' '))

for name, mode in (('ARM', CS_MODE_ARM), ('Thumb', CS_MODE_THUMB)):
    md = Cs(CS_ARCH_ARM, mode)
    print(f'--- {name} ---')
    start = OFFSET - 8 if name == 'ARM' else OFFSET - 4
    for ins in md.disasm(data[start:OFFSET + 16], start):
        mark = '   <== faulting' if ins.address == OFFSET else ''
        print(f'  {ins.address:06x} {ins.bytes.hex():10} {ins.mnemonic:10} {ins.op_str}{mark}')
