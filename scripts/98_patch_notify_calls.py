"""Patch every BL to notify_model_system_error (0x2BC3174) in the image's
appFw library to two Thumb NOPs, so error branches no longer abort.
Writes a NEW .so."""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io
SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
OUT = Path('03-证据/静态分析/97_abi/a5pFw_nonotify.so')
d = bytearray(SRC.read_bytes())
e = ELFFile(io.BytesIO(bytes(d)))
text = e.get_section_by_name('.text'); tb = text['sh_addr']; td = text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
TARGET = 0x2BC3174
hits = []
for ins in md.disasm(td, tb):
    if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
        try: v = int(ins.op_str[1:], 16)
        except ValueError: continue
        if (v & ~1) == TARGET:
            hits.append(ins.address)
print('call sites', [hex(x) for x in hits], 'count', len(hits))
for a in hits:
    off = a - tb + text['sh_offset']
    d[off:off+4] = b'\x00\xbf\x00\xbf'   # nop ; nop
OUT.write_bytes(bytes(d))
print('wrote', OUT, len(d))
