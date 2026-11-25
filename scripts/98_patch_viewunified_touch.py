"""Enable full touch capability gates in a6600 4th-gen viewUnified2.so.
Offsets match the a6600 library; verified against its dynamic symbols.
Writes a NEW file.
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io
SRC = Path('05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15')
OUT = Path('03-证据/静态分析/touch/viewUnified2_touch.so')
# read the library out of the ext2 image with the project reader
import importlib.util
spec = importlib.util.spec_from_file_location('u', '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(SRC)); idx = {p: i for p, i, d in fs.walk() if not d}
d = bytearray(fs.read_file(idx['/lib/viewUnified2.so']))
e = ELFFile(io.BytesIO(bytes(d)))
def off_of(va):
    for s in e.iter_sections():
        if s['sh_type'] != 'SHT_NOBITS' and s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + va - s['sh_addr']
    raise SystemExit('no section')
patches = [
    (0x2fbf90, bytes.fromhex('01207047'), 'isTouchToggleSupported -> return 1'),
    (0x2fbfa6, bytes.fromhex('04207047'), 'isTouchPanelPadSupported -> return 4'),
    (0x56f674, bytes.fromhex('0021'), 'MenuSelectMode setTouchable: movs r1,#0'),
    (0x5ba020, bytes.fromhex('0021'), 'BarCtrlDial setTouchable: movs r1,#0'),
]
for va, pat, desc in patches:
    o = off_of(va)
    old = bytes(d[o:o+len(pat)])
    d[o:o+len(pat)] = pat
    print(hex(va), desc, 'old', old.hex(), '->', pat.hex())
OUT.write_bytes(bytes(d))
print('wrote', OUT, len(d))
