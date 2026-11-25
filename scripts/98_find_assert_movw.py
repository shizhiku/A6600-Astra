"""Find MOVW/MOVT materialisation of the notify_model_system_error strings in
appFw.so, map the code to its .ARM.exidx function, and patch that function to
return. Diagnostic-only; writes a NEW .so.
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io, struct
SRC = Path('05-原始固件/zv1m2_fw/gen5/appFw.so')
OUT = Path('03-证据/静态分析/97_abi/zv_appFw_assert_ret.so')
d = bytearray(SRC.read_bytes())
e = ELFFile(io.BytesIO(bytes(d)))
text = e.get_section_by_name('.text')
tb = text['sh_addr']; td = text.data()
print('.text', hex(tb), hex(len(td)))
# halfword scanner
cond = []
for off in range(0, len(td) - 16, 2):
    h1 = struct.unpack_from('<H', td, off)[0]
    if h1 not in (0xF64A, 0xF2C0):
        continue
    h2 = struct.unpack_from('<H', td, off + 2)[0]
    # look ahead up to 12 halfwords for the partner
    for k in range(4, 26, 2):
        if off + k + 4 > len(td):
            break
        g1 = struct.unpack_from('<H', td, off + k)[0]
        g2 = struct.unpack_from('<H', td, off + k + 2)[0]
        pair = None
        if h1 == 0xF64A and g1 == 0xF2C0:
            pair = (h2, g2)
        elif h1 == 0xF2C0 and g1 == 0xF64A:
            pair = (g2, h2)
        if not pair:
            continue
        lo, hi = pair
        rd_lo = (lo >> 8) & 0xf; rd_hi = (hi >> 8) & 0xf
        if rd_lo != rd_hi:
            continue
        imm_lo = ((lo & 0x00ff) | (((lo >> 12) & 0x7) << 8))
        # imm4 for movw is in h1's low nibble; recompute from the movw halfword
        if h1 == 0xF64A:
            imm4 = h1 & 0xf; movw_off = off
        else:
            imm4 = g1 & 0xf; movw_off = off + k
        va = (imm4 << 12) | (((0xF64A >> 10) & 1) << 11) | imm_lo
        # movt imm16 from the movt halfword and its second halfword
        movt_off = off + k if movw_off == off else off
        mt = struct.unpack_from('<H', td, movt_off)[0]
        mt2 = struct.unpack_from('<H', td, movt_off + 2)[0]
        imm_movt = ((mt & 0xf) << 12) | ((mt2 & 0x0fff))
        full = (imm_movt << 16) | va
        if full in (0x2fda85c, 0x2fda83b):
            cond.append((tb + movw_off, full))
print('materialisations', [(hex(a), hex(v)) for a, v in cond][:20])
# exidx
ex = e.get_section_by_name('.ARM.exidx'); starts = []
data = ex.data(); base = ex['sh_addr']
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
cands = []
for a, v in cond:
    st = containing(a)
    if st and (st, a) not in cands: cands.append((st, a))
print('functions', [(hex(s), hex(a)) for s, a in cands][:10])
if cands:
    st, a = cands[0]
    thumb = bool(st & 1); addr = st & ~1
    for s in e.iter_sections():
        if s['sh_type'] != 'SHT_NOBITS' and s['sh_addr'] <= addr < s['sh_addr'] + s['sh_size']:
            off = s['sh_offset'] + addr - s['sh_addr']; break
    if thumb:
        d[off:off+2] = b'\x70\x47'
    else:
        d[off:off+4] = b'\x1e\xff\x2f\xe1'
    OUT.write_bytes(bytes(d))
    print('patched', hex(addr), 'thumb', thumb, '->', OUT)
