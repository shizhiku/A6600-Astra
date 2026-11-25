"""Recompute veneer targets with the correct ARM PC semantics.

ARM-state instructions read PC as (insn_addr + 8).

Veneer at V:
    V+0:  e59fc004   ldr ip, [pc, #4]   ; ip = *(u32*)(V + 8 + 4) = *(V+12)
    V+4:  e08fc00c   add ip, pc, ip     ; ip = (V+4+8) + ip = V+12 + ip
    V+8:  e12fff1c   bx  ip
    V+12: <word>

So: target = V + 12 + word.

Earlier I used V + 8 + word, which lands 4 bytes early; and since these are
Thumb targets the entry is at (target & ~1).  Let's verify with V+12.
"""
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

veneers = [0x925FB0, 0x9246B8, 0x923900, 0x9256A8, 0x9240D4,
           0x925B48, 0x924B48, 0x924B04, 0x923B34, 0x9243E4,
           0x925468, 0x9249C4, 0x92A2FC]

print('=== veneer resolution with target = V + 12 + word ===')
for v in veneers:
    raw = d[v:v + 16]
    if raw[:4] != bytes.fromhex('04c09fe5'):
        print('  %#010x not a standard veneer (%s)' % (v, raw[:4].hex()))
        continue
    word = struct.unpack_from('<i', d, v + 12)[0]
    tgt = ((v + 12) + word) & 0xFFFFFFFF
    entry = tgt & ~1
    body = list(md.disasm(td[entry - tb:entry - tb + 8], entry))
    txt = ' | '.join('%s %s' % (i.mnemonic, i.op_str) for i in body[:3])
    print('  %#010x word=%+#010x -> %#010x  %s' % (v, word, entry, txt))
