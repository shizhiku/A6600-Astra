from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io
import struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def resolve_veneer(v):
    if d[v:v + 4] != bytes.fromhex('04c09fe5'):
        return None
    word = struct.unpack_from('<i', d, v + 12)[0]
    return ((v + 12) + word) & 0xFFFFFFFF


# Disassemble 0x54F664 from the resume point onward with full call resolution
start = 0x54F664
insns = list(md.disasm(td[start - tb:start - tb + 0x600], start))
print('=== 0x54F664 call sites (after 0x54F678) ===')
for ins in insns:
    if ins.mnemonic not in ('bl', 'blx') or not ins.op_str.startswith('#'):
        continue
    try:
        t = int(ins.op_str[1:], 16)
    except ValueError:
        continue
    real = resolve_veneer(t & ~1)
    tag = 'veneer' if real else 'direct'
    print('  %08x -> %#010x (%s)  resolved=%s'
          % (ins.address, t, tag, ('%#010x' % real) if real else '-'))
