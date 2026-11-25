from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io, struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

ex = e.get_section_by_name('.ARM.exidx')
ed, eb = ex.data(), ex['sh_addr']
starts = []
for k in range(0, len(ed), 8):
    w = struct.unpack_from('<I', ed, k)[0]
    pre = w & 0x7fffffff
    pre = pre if pre < 0x40000000 else pre - 0x80000000
    starts.append((eb + k + pre) & 0xffffffff)
starts = sorted(set(x & ~1 for x in starts))

for ra in (0x2B359F7, 0x2B20821, 0x2B20DA9):
    fn = max([s for s in starts if s <= ra], default=None)
    print('RA', hex(ra), 'fn_start', hex(fn) if fn else None,
          'delta', hex(ra - fn) if fn else None)

RA = 0x2B359F7
print('==== around RA')
off = RA - 4 - tb
for i in md.disasm(td[off - 0x120: off + 0x40], RA - 4 - 0x120):
    mark = ''
    if i.address == RA - 4:
        mark = ' <-- BL notify'
    if i.address == RA:
        mark = ' <-- RA'
    print(f'{i.address:08x} {i.mnemonic:8} {i.op_str}{mark}')
