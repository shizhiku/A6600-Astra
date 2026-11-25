"""Extract libObj.so and disassemble around the abort call site."""
from pathlib import Path
import importlib.util

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
PART = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev'
OFFSET = 0x64191F

spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

found = None
for part in ('nflasha15', 'nflasha7'):
    img = PART / part
    if not img.exists():
        continue
    fs = m.Ext2(str(img))
    for path, ino, is_dir in fs.walk():
        if is_dir:
            continue
        if path.rsplit('/', 1)[-1] == 'libObj.so':
            data = fs.read_file(ino)
            out = BASE / '03-证据/静态分析/libObj.so'
            out.write_bytes(data)
            print(f'found {path} in {part}: {len(data)} bytes -> {out.name}')
            found = data
            break
    if found:
        break

if not found:
    raise SystemExit('libObj.so not found')

print('bytes at offset:', found[OFFSET - 16: OFFSET + 16].hex(' '))
start = OFFSET - 0x60
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
for ins in md.disasm(found[start: OFFSET + 0x20], start):
    mark = '   <== abort call site' if ins.address == OFFSET - 2 else ''
    print(f'  {ins.address:06x} {ins.bytes.hex():10} {ins.mnemonic:9} {ins.op_str}{mark}')
