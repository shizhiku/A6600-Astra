"""Resolve blx targets like 0x2BA0FAC into imported symbol names.

Those addresses are ARM veneer stubs of the form:
    ldr ip, [pc]      ; or ldr ip,[pc,#4]
    add pc, pc, ip    ; tail-jump to the real PLT entry
Some are `ldr ip,[pc,#4]; add ip,pc,ip; bx ip` (normal veneer).

Approach: walk the stub, read the literal, compute the final address, and if
that lands in .got (or a PLT region) look up the relocation symbol name.
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io
import struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))


def sec_of(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s
    return None


def va_to_off(va):
    s = sec_of(va)
    return None if s is None else s['sh_offset'] + (va - s['sh_addr'])


def read_u32(va):
    o = va_to_off(va)
    if o is None or o + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, o)[0]


# All relocations: offset -> symbol name (covers .rel.plt and .rel.dyn)
reloc = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            sym = st.get_symbol(r['r_info_sym'])
            reloc[r['r_offset']] = sym.name
print('total relocations:', len(reloc))


def resolve_stub(va):
    """Follow an ARM veneer chain and return the final target VA."""
    seen = 0
    cur = va
    while seen < 4:
        seen += 1
        w0 = read_u32(cur)
        w1 = read_u32(cur + 4)
        if w0 is None:
            return None, 'no data'
        # pattern: ldr ip,[pc,#imm] ; add ip,pc,ip ; bx ip
        # 0xE59FC0xx = ldr ip,[pc,#imm12]
        if (w0 & 0xFFFFF000) == 0xE59FC000:
            imm = w0 & 0xFFF
            lit = (cur + 8) + imm
            val = read_u32(lit)
            if val is None:
                return None, 'bad literal'
            # add ip, pc, ip  -> pc = cur+4+8
            nxt = None
            if w1 is not None and (w1 & 0xFFFFF000) == 0xE08FC000:
                nxt = ((cur + 4) + 8 + val) & 0xFFFFFFFF
            # add pc, pc, ip then bx ip (tail)
            elif w1 is not None and (w1 & 0xFFFFF000) == 0xE08FF000:
                nxt = ((cur + 4) + 8 + val) & 0xFFFFFFFF
            if nxt is None:
                return None, 'unrecognized second insn'
            # if it lands in .got, report the symbol
            if nxt in reloc:
                return nxt, 'GOT-reloc'
            cur = nxt
            continue
        return None, 'not veneer (%08x)' % w0
    return None, 'too deep'


for va in (0x2BA0FAC, 0x2BA0E94, 0x2BA074C, 0x2BA1818, 0x2BA195C, 0x2BA0FE0, 0x2BA1260):
    tgt, why = resolve_stub(va)
    name = reloc.get(tgt) if tgt else None
    print('%#010x -> %s  [%s]  symbol=%s'
          % (va, ('%#010x' % tgt) if tgt else '?', why, name))
