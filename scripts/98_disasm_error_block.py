"""Disassemble the block that leads to the notify_model_system_error call at
0x2BBA91A and resolve its string references."""
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
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
START = 0x2BBA7C0
insns = list(md.disasm(td[START - tb: START - tb + 0x170], START))
for i in insns:
    s = f'{i.address:08x} {i.mnemonic:8} {i.op_str}'
    if i.mnemonic == 'ldr' and '[pc' in i.op_str:
        try:
            imm = int(i.op_str.split('#')[-1].rstrip(']'), 0)
            lva = ((i.address + 4) & ~3) + imm
            o = va_to_off(lva)
            if o is not None:
                val = struct.unpack_from('<I', d, o)[0]
                s += f'   ; lit=0x{val:08x}'
        except Exception:
            pass
    print(s)
print('=== add/addw pc strings ===')
for i in insns:
    if i.mnemonic.startswith('add') and ', pc' in i.op_str:
        try:
            imm = int(i.op_str.split('#')[-1], 0)
            tgt = ((i.address + 4) & ~3) + imm
            sv = cstr(tgt)
            if sv: print(f'{i.address:08x} -> 0x{tgt:08x} "{sv[:120]}"')
        except Exception:
            pass
