"""Resolve the ARM-state veneer used by gen5 appFw.

Raw bytes at 0x925FB0:  04 c0 9f e5 | 0c c0 8f e0 | 1c ff 2f e1 | <word>
That is ARM (not Thumb):
    0x925FB0: e59fc004   ldr ip, [pc, #4]      ; ip = *(u32*)(0x925FB0+8+4)
    0x925FB4: e08fc00c   add ip, pc, ip        ; ip = 0x925FB4+8 + value
    0x925FB8: e12fff1c   bx  ip
    0x925FBC: <word>     the pc-relative delta

So target = 0x925FB4 + 8 + word = 0x925FBC + word.

Note the veneer starts at an address that is 4-byte aligned in ARM state.
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import Path
import io
import struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()

funcs = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            v = s['st_value']
            if v and s.name and s['st_info']['type'] == 'STT_FUNC':
                funcs.setdefault(v & ~1, s.name)


def sec_of(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s
    return None


import bisect
fa = sorted(funcs)
fa_list = fa


def containing(va):
    i = bisect.bisect_right(fa_list, va) - 1
    if i < 0:
        return None
    return fa_list[i], funcs[fa_list[i]]


stubs = [0x925FB0, 0x9246B8, 0x923900, 0x9256A8, 0x9240D4,
         0x925B48, 0x924B48, 0x924B04, 0x923B34, 0x9243E4,
         0x925468, 0x9249C4]

for va in stubs:
    word = struct.unpack_from('<I', d, va + 12)[0]
    tgt = (va + 12 + word) & 0xFFFFFFFF
    s = sec_of(tgt)
    c = containing(tgt)
    print('%#08x word=%#010x target=%#010x sec=%-12s func=%s+%#x'
          % (va, word, tgt, s.name if s else '?',
             c[1] if c else '?', (tgt - c[0]) if c else 0))
