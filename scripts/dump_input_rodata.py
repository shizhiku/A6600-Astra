"""List every null-terminated string in input.ko's .rodata.str1.1, including short ones."""
from pathlib import Path
from elftools.elf.elffile import ELFFile

KO = Path(r'<WORKSPACE>/03-证据/静态分析/input.ko')
with open(KO, 'rb') as f:
    e = ELFFile(f)
    sec = e.get_section_by_name('.rodata.str1.1')
    data = sec.data()
    print('section size', len(data))
    off = 0
    n = 0
    while off < len(data):
        end = data.find(b'\x00', off)
        if end < 0:
            end = len(data)
        s = data[off:end]
        if s:
            try:
                txt = s.decode('utf-8')
            except Exception:
                txt = repr(s)
            print(f'  {off:#06x} {txt[:80]!r}')
            n += 1
        off = end + 1
    print('total', n)
