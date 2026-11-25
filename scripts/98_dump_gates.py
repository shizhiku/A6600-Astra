"""Dump the gate sites between the main loop and the frame-function call.

From doc 136 / verified disassembly:
  0x54FA3C  bl 0x54F2CA          ; state classify -> r8 ; r8==2 skips drawing
  0x54FA64..0x54FA72  time-diff vs 0x62F4 ; unsatisfied -> skip drawing
  0x54FA76  bl 0x54F2AE          ; gate -> 0 => skip drawing
  0x54FAA4..0x54FAA8  re-check r8 ; nonzero -> skip 0x54FAAE
  0x54FAAE  bl 0x54ED12          ; frame function  (B probe)

Dump this whole region so we can pick precise probe points and see the exact
compare/branch structure.
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
tb = text['sh_addr']
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def file_offset(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + (va - s['sh_addr'])
    return None


START = 0x54FA3C
off = file_offset(START)
print('=== 0x%08x .. (gates + frame call) ===' % START)
for ins in md.disasm(d[off:off + 0x90], START):
    mark = ''
    if ins.address in (0x54FA3C, 0x54FA76, 0x54FAA4, 0x54FAAE):
        mark = '   <== key'
    print('  %08x  %d  %-8s %s%s' % (ins.address, ins.size, ins.mnemonic,
                                     ins.op_str, mark))
