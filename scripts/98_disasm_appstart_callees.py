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


def va_to_off(va):
    for s in e.iter_sections():
        if s['sh_type'] != 'SHT_NOBITS' and s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + va - s['sh_addr']
    return None


def cstr(va):
    o = va_to_off(va)
    if o is None:
        return None
    end = d.find(b'\x00', o)
    if end < 0 or end - o > 160:
        return None
    try:
        return d[o:end].decode('utf-8')
    except Exception:
        return d[o:end].decode('latin1')


def strs_in(start, size=0x300):
    off = start - tb
    insns = list(md.disasm(td[off:off + size], start))
    out = []
    for idx, ins in enumerate(insns):
        if ins.mnemonic == 'ldr' and '[pc' in ins.op_str:
            try:
                imm = int(ins.op_str.split('#')[-1].rstrip(']'), 0)
                lva = ((ins.address + 4) & ~3) + imm
                o = va_to_off(lva)
                if o is None:
                    continue
                val = struct.unpack_from('<I', d, o)[0]
            except Exception:
                continue
            reg = ins.op_str.split(',')[0].strip()
            for j in range(idx + 1, min(idx + 10, len(insns))):
                nxt = insns[j]
                if nxt.mnemonic.startswith('add') and nxt.op_str.startswith(reg + ', pc'):
                    try:
                        simm = int(nxt.op_str.split('#')[-1], 0)
                        tgt = ((nxt.address + 4) & ~3) + val
                        sv = cstr(tgt)
                        if sv:
                            out.append((ins.address, tgt, sv))
                    except Exception:
                        pass
                    break
    return out


for fn in (0x54D154, 0x54D2B0, 0x54F664, 0x54D538):
    print('====', hex(fn))
    insns = list(md.disasm(td[fn - tb:fn - tb + 0x1C0], fn))
    for i in insns:
        print(f'{i.address:08x} {i.mnemonic:8} {i.op_str}')
    print('  strings:')
    seen = set()
    for a, t, sv in strs_in(fn):
        if sv not in seen:
            seen.add(sv)
            print(f'    {a:08x} -> 0x{t:08x} "{sv[:120]}"')
