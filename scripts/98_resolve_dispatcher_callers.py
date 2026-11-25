"""Resolve the two callers of the model-status dispatcher found on the stack,
and print strings referenced by their functions."""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io, struct
SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes(); e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text'); tb = text['sh_addr']; td = text.data()
def va_to_off(va):
    for s in e.iter_sections():
        if s['sh_type'] != 'SHT_NOBITS' and s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + va - s['sh_addr']
    return None
def cstr(va):
    o = va_to_off(va)
    if o is None: return None
    end = d.find(b'\0', o)
    if end < 0 or end - o > 200: return None
    try: return d[o:end].decode('utf-8')
    except Exception: return d[o:end].decode('latin1')
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
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
def strings_in(start, size=0x200):
    off = start - tb
    insns = list(md.disasm(td[off:off + size], start))
    out = []
    for idx, ins in enumerate(insns):
        if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
            try:
                imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
                lva = ((ins.address + 4) & ~3) + imm
                o = va_to_off(lva)
                if o is None: continue
                val = struct.unpack_from('<I', d, o)[0]
            except Exception:
                continue
            reg = ins.op_str.split(',')[0].strip()
            for j in range(idx + 1, min(idx + 9, len(insns))):
                nxt = insns[j]
                if nxt.mnemonic.startswith('add') and nxt.op_str.startswith(reg + ', pc'):
                    try:
                        stimm = int(nxt.op_str.split('#')[-1], 0)
                        tgt = ((nxt.address + 4) & ~3) + val
                        if tgt != ((nxt.address + 4) & ~3) + val:
                            pass
                        tgt = ((nxt.address + 4) & ~3) + val
                        sv = cstr(tgt)
                        if sv:
                            out.append((nxt.address, tgt, sv))
                    except Exception:
                        pass
                    break
    return out
for ra in (0x2B1E4D5, 0x2B4498D):
    fn = containing(ra)
    print('RA', hex(ra), 'func', hex(fn) if fn else None)
    if fn:
        s = fn & ~1
        print('  strings:')
        seen = set()
        for a, t, sv in strings_in(s, 0x300):
            if sv not in seen:
                seen.add(sv)
                print(f'    {a:08x} 0x{t:08x} "{sv[:110]}"')
