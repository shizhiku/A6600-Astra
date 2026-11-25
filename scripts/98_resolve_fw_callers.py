"""Resolve appFw return offsets captured at notify_model_system_error abort,
then find the BL target (the assert function) and its call sites."""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import struct, io
SRC = Path('05-原始固件/zv1m2_fw/gen5/appFw.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text'); tb = text['sh_addr']; td = text.data()
ex = e.get_section_by_name('.ARM.exidx'); ed = ex.data(); eb = ex['sh_addr']
starts = []
for k in range(0, len(ed), 8):
    w = struct.unpack_from('<I', ed, k)[0]
    pre = w if w < 0x80000000 else w - 0x100000000
    starts.append((eb + k + pre) & 0xffffffff)
starts = sorted(set(starts))
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
    # The call instruction that produced RA is at RA-4 (32-bit BL) or RA-2.
    for back in (4, 2):
        off = ra - back
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
# scan for BL/BLX to the first plausible target
if targets:
    from collections import Counter
    cnt = Counter(t for _, t in targets)
    tgt, _ = cnt.most_common(1)[0]
    print('candidate notify function', hex(tgt))
    hits = []
    for ins in md.disasm(td, tb):
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                v = int(ins.op_str[1:], 16)
            except ValueError:
                continue
            if v == tgt:
                hits.append(ins.address)
    print('call sites', [hex(x) for x in hits][:40], 'count', len(hits))
