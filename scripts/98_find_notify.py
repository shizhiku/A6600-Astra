"""Find notify_model_system_error's code and its callers in the actual
image appFw library using the __FILE__/__PRETTY_FUNCTION__ literals."""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import struct, io
SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text'); tb = text['sh_addr']; td = text.data()
def sec_of(va):
    for s in e.iter_sections():
        if s['sh_type'] != 'SHT_NOBITS' and s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s
    return None
# string VAs
def va_of_off(off):
    s = None
    for x in e.iter_sections():
        if x['sh_type'] != 'SHT_NOBITS' and x['sh_offset'] <= off < x['sh_offset'] + x['sh_size']:
            s = x; break
    return s['sh_addr'] + off - s['sh_offset'] if s else None
s1 = d.find(b'lib_assert.cpp')
s2 = d.find(b'notify_model_system_error')
va_file = va_of_off(s1); va_fn = va_of_off(s2)
print('strings', hex(va_file), hex(va_fn))
# occurrences of these VAs as 32-bit literals
lits = {}
for va in (va_file, va_fn):
    pat = struct.pack('<I', va)
    pos = []
    i = d.find(pat)
    while i >= 0:
        pos.append(i)
        i = d.find(pat, i + 1)
    lits[va] = pos
    print('literal occurrences of', hex(va), [hex(p) for p in pos][:8], len(pos))
lit_vas = set()
for va, pos in lits.items():
    for off in pos:
        sv = va_of_off(off)
        if sv: lit_vas.add(sv)
print('literal VAs', [hex(x) for x in lit_vas])
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
refs = []
for ins in md.disasm(td, tb):
    if ins.mnemonic.startswith('ldr') and '[pc' in ins.op_str:
        try:
            imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
        except Exception:
            continue
        tgt = ((ins.address + 4) & ~3) + imm
        if tgt in lit_vas:
            refs.append(ins.address)
print('code refs', [hex(x) for x in refs][:20])
# exidx function starts
ex = e.get_section_by_name('.ARM.exidx'); ed = ex.data(); eb = ex['sh_addr']
starts = []
for k in range(0, len(ed), 8):
    w = struct.unpack_from('<I', ed, k)[0]
    v = w & 0x7fffffff
    pre = v if v < 0x40000000 else v - 0x80000000
    starts.append((eb + k + pre) & 0xffffffff)
starts = sorted(set(starts))
def containing(a):
    c = None
    for st in starts:
        if (st & ~1) <= a: c = st
        else: break
    return c
funcs = []
for a in refs:
    f = containing(a)
    if f not in funcs: funcs.append(f)
print('candidate functions', [hex(x) for x in funcs])
if funcs:
    fn = funcs[0] & ~1
    # scan calls to fn
    hits = []
    for ins in md.disasm(td, tb):
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try: v = int(ins.op_str[1:], 16)
            except ValueError: continue
            if v == fn: hits.append(ins.address)
    print('call sites to', hex(fn), [hex(x) for x in hits][:40], 'count', len(hits))
    for h in hits[:12]:
        f2 = containing(h)
        print('  site', hex(h), 'in func', hex(f2) if f2 else None)
