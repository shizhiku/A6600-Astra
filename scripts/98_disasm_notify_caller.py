"""Disassemble the function that calls notify_model_system_error and resolve
nearby string references."""
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
    return d[o:end].decode('latin1')
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
START = 0x2bba4cc
off = START - tb
insns = list(md.disasm(td[off:off+0x300], START))
for i in insns:
    s = f'{i.address:08x} {i.mnemonic:8} {i.op_str}'
    if i.mnemonic == 'ldr' and '[pc' in i.op_str:
        try:
            imm = int(i.op_str.split('#')[-1].rstrip(']'), 0)
            lva = ((i.address + 4) & ~3) + imm
            lv = struct.unpack_from('<I', d, va_to_off(lva))[0] if va_to_off(lva) is not None else 0
            s += f'   ; lit@{lva:08x}=0x{lv:08x}'
        except Exception:
            pass
    print(s)
print('=== string refs in first 0x200 ===')
for i in insns:
    if i.mnemonic in ('add',) and ', pc' in i.op_str and i.address < START + 0x200:
        try:
            reg = i.op_str.split(',')[0].strip()
            imm = int(i.op_str.split('#')[-1], 0)
            tgt = ((i.address + 4) & ~3) + imm
            sv = cstr(tgt)
            if sv is not None:
                print(f'{i.address:08x} add {reg},pc -> 0x{tgt:08x} "{sv[:100]}"')
        except Exception:
            pass
