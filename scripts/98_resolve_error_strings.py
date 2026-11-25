"""Resolve strings in the model-command handler's error branches and find
call sites of the handler."""
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
    if end < 0 or end - o > 300: return None
    try: return d[o:end].decode('utf-8')
    except Exception: return d[o:end].decode('latin1')
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
START = 0x2bba4cc
insns = list(md.disasm(td[START - tb: START - tb + 0x800], START))
print('=== add-pc strings in handler ===')
for i in insns:
    if not i.mnemonic.startswith('add'):
        continue
    if ', pc' not in i.op_str:
        continue
    try:
        imm = int(i.op_str.split('#')[-1], 0)
        tgt = ((i.address + 4) & ~3) + imm
        sv = cstr(tgt)
        if sv is not None and len(sv) > 2:
            print(f'{i.address:08x} {i.mnemonic} {i.op_str} -> 0x{tgt:08x} "{sv[:120]}"')
    except Exception:
        pass
print('=== ldr literal -> add pc strings ===')
for i in insns:
    if i.mnemonic == 'ldr' and '[pc' in i.op_str:
        try:
            imm = int(i.op_str.split('#')[-1].rstrip(']'), 0)
            lva = ((i.address + 4) & ~3) + imm
            o = va_to_off(lva)
            if o is None: continue
            val = struct.unpack_from('<I', d, o)[0]
            tgt = ((i.address + 4) & ~3) + val
            sv = cstr(tgt)
            if sv is not None and len(sv) > 2:
                print(f'{i.address:08x} ldr lit 0x{lva:08x}=0x{val:08x} -> 0x{tgt:08x} "{sv[:120]}"')
        except Exception:
            pass
print('=== call sites of handler 0x2bba4cc ===')
hits = []
for ins in md.disasm(td, tb):
    if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
        try: v = int(ins.op_str[1:], 16)
        except ValueError: continue
        if (v & ~1) == START:
            hits.append(ins.address)
print([hex(x) for x in hits][:20], 'count', len(hits))
