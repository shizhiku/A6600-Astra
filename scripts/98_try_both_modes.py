"""The veneer targets like 0x1C7E699 look invalid in Thumb mode.
Try ARM mode (and Thumb at aligned-1) to see which decodes sanely.

Arm/Thumb interworking: a veneer `bx ip` crosses to the state encoded in ip's
low bit.  For an ARM target, ip must be 4-byte aligned with bit0=0.  Our
target 0x1C7E699 is odd -> Thumb.  0x1C7E698 would be ARM.

Rather than guess, decode both and check plausibility (push/frame setup).
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()

targets = [0x01c7e699, 0x01d5a3d5, 0x01c7e6a9, 0x01c1b875,
           0x01c1b721, 0x01c1b741, 0x0165d63d, 0x02c2ea89,
           0x02ce6881, 0x02bdf571, 0x02bc326d]

for t in targets:
    print('=== target %#010x ===' % t)
    for label, mode, addr in (('THUMB', CS_MODE_THUMB, t & ~1),
                              ('ARM  ', CS_MODE_ARM, t & ~1),
                              ('THUMB-1', CS_MODE_THUMB, (t & ~1) - 2)):
        md = Cs(CS_ARCH_ARM, mode)
        ins = list(md.disasm(td[addr - tb:addr - tb + 12], addr))
        txt = ' | '.join('%s %s' % (i.mnemonic, i.op_str) for i in ins[:4])
        print('  %-8s %08x  %s' % (label, addr, txt))
    print()
