"""Trace 0x54EF74's callees with CORRECT veneer resolution (V+12+word),
then for each callee scan its body for blocking primitives.

Blocking indicators inside a function body (via its own veneer calls):
  osal_rcv_msg_tmo / osal_wai_sem_tmo / pthread_cond_wait / sem_wait
  ioctl / open / poll / select / nanosleep / usleep / read / write
We identify these by resolving the callee's veneers to imported symbols in
.dynsym (through .rel.plt GOT slots).
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from pathlib import Path
import io
import struct
import bisect

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()


def sec_of(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s
    return None


def read_u32(va):
    s = sec_of(va)
    if s is None:
        return None
    off = s['sh_offset'] + (va - s['sh_addr'])
    if off + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, off)[0]


funcs = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            v = s['st_value']
            if v and s.name and s['st_info']['type'] == 'STT_FUNC':
                funcs.setdefault(v & ~1, s.name)
fa = sorted(funcs)

reloc_names = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            reloc_names[r['r_offset']] = st.get_symbol(r['r_info_sym']).name


def containing(va):
    i = bisect.bisect_right(fa, va) - 1
    if i < 0:
        return None
    return fa[i], funcs[fa[i]]


def resolve_veneer(v):
    if d[v:v + 4] != bytes.fromhex('04c09fe5'):
        return None
    word = struct.unpack_from('<i', d, v + 12)[0]
    return ((v + 12) + word) & 0xFFFFFFFF


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def calls_in(start, size):
    out = []
    for ins in md.disasm(td[start - tb:start - tb + size], start):
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16)
            except ValueError:
                continue
            real = resolve_veneer(t & ~1)
            out.append((ins.address, t, real if real else t))
    return out


BLOCK = ('osal_rcv_msg_tmo', 'osal_wai_sem_tmo', 'pthread_cond_wait',
         'sem_wait', 'sem_timedwait', 'ioctl', 'open', 'open64', 'poll',
         'select', 'nanosleep', 'usleep', 'read', 'write', 'recv', 'send',
         'osal_valloc_msg_wait', 'osal_snd_sync_msg', 'futex')

top = calls_in(0x54EF74, 0x90)
print('=== 0x54EF74 callees (corrected) ===')
for site, raw, real in top:
    c = containing(real)
    nm = funcs.get(real) or ('%s+%#x' % (c[1], real - c[0]) if c else '?')
    print('  %08x -> %#010x  %s' % (site, real, nm))

print()
print('=== scan each callee for blocking-style calls ===')
for site, raw, real in top:
    entry = real & ~1
    c = containing(entry)
    if c is None:
        continue
    nm = funcs.get(entry) or c[1]
    # scan a generous window from the entry
    subs = calls_in(entry, 0x600)
    hits = []
    for s2, r2, t2 in subs:
        name = funcs.get(t2 & ~1) or reloc_names.get(t2 & ~1) or ''
        if any(b in name for b in BLOCK):
            hits.append((s2, t2, name))
    if hits:
        print('  callee %#010x (%s):' % (entry, nm))
        for s2, t2, name in hits[:8]:
            print('      %08x -> %#010x %s' % (s2, t2, name))
