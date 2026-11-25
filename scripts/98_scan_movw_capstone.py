"""Scan appFw .text with capstone for MOVW/MOVT pairs materialising the
assertion strings; report code addresses and containing exidx function."""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io, struct, re, sys
SRC = Path('05-原始固件/zv1m2_fw/gen5/appFw.so')
TARGETS = {0x2fda84a, 0x2fda83b, 0x2fda85c}
e = ELFFile(io.BytesIO(SRC.read_bytes()))
text = e.get_section_by_name('.text'); tb = text['sh_addr']; td = text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
last = {}
found = []
for ins in md.disasm(td, tb):
    m = re.match(r'movw\s+(r\d+|ip|sb|sl|fp|lr), #(0x[0-9a-f]+|\d+)', ins.mnemonic + ' ' + ins.op_str)
    if m:
        last[m.group(1)] = (ins.address, int(m.group(2), 0)); continue
    m = re.match(r'movt\s+(r\d+|ip|sb|sl|fp|lr), #(0x[0-9a-f]+|\d+)', ins.mnemonic + ' ' + ins.op_str)
    if m and m.group(1) in last:
        lo_addr, lo = last.pop(m.group(1))
        val = (int(m.group(2), 0) << 16) | lo
        if val in TARGETS:
            found.append((lo_addr, ins.address, val))
        continue
print('found', [(hex(a), hex(b), hex(v)) for a, b, v in found])
ex = e.get_section_by_name('.ARM.exidx'); data = ex.data(); base = ex['sh_addr']; starts = []
for k in range(0, len(data), 8):
    w = struct.unpack_from('<I', data, k)[0]
    pre = w if w < 0x80000000 else w - 0x100000000
    starts.append((base + k + pre) & 0xffffffff)
starts = sorted(set(starts))
def containing(a):
    c = None
    for st in starts:
        if (st & ~1) <= a: c = st
        else: break
    return c
for a, b, v in found:
    print(hex(v), 'materialised at', hex(a), 'func', hex(containing(a) or 0))
