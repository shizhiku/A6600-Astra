"""Resolve appFw return offsets using the actual library from the image."""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import struct, io
SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text'); tb = text['sh_addr']; td = text.data()
print('.text addr', hex(tb), 'size', hex(len(td)))
ex = e.get_section_by_name('.ARM.exidx'); ed = ex.data(); eb = ex['sh_addr']
starts = []
for k in range(0, len(ed), 8):
    w = struct.unpack_from('<I', ed, k)[0]
    v = w & 0x7fffffff
    pre = v if v < 0x40000000 else v - 0x80000000
    starts.append((eb + k + pre) & 0xffffffff)
starts = sorted(set(starts))
print('exidx functions', len(starts), 'first', hex(starts[0]), 'last', hex(starts[-1]))
def containing(a):
    c = None
    for st in starts:
        if (st & ~1) <= a: c = st
        else: break
    return c
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
RAS = [0x2bc318b, 0x2bba91f, 0x2b1e4d5, 0x2b4498d, 0x2c2e509, 0x2b4cb91,
       0x2b1756f, 0x2b20d11, 0x1d58fc1]
targets = []
for ra in RAS:
    fn = containing(ra)
    print('RA', hex(ra), 'func', hex(fn) if fn else None)
    for back in (4, 2):
        off = ra - back
        if off < tb or off + 4 > tb + len(td):
            continue
        ins = next(md.disasm(td[off - tb: off - tb + 4], off), None)
        if ins is None:
            continue
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                tgt = int(ins.op_str[1:], 16)
            except ValueError:
                continue
            print('   ', hex(off), ins.mnemonic, ins.op_str, '-> target', hex(tgt))
            targets.append((ra, tgt))
            break
print('targets', [(hex(a), hex(t)) for a, t in targets])
