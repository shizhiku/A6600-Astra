"""Verify the three probe addresses are valid instruction boundaries, and
dump the surrounding code so the runtime probe is unambiguous.

Targets (appFw VMA; gen5 a5pFw_actual.so has .text addr==offset? check):
  0x54FB46  right after `bl GraphicsEngine::processSystemMessage`  -> r0 = its return
  0x54ED12  frame function entry
  0x54ED82  the BLX PLT drawFramebuffer call site
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, toff = text['sh_addr'], text['sh_offset']
print('.text addr=%#x off=%#x size=%#x' % (tb, toff, text['sh_size']))


def file_offset(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + (va - s['sh_addr'])
    return None


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def dump_around(va, back=0x20, fwd=0x40, title=''):
    start = va - back
    off = file_offset(start)
    print('=== %s  window %#x..%#x (file off %#x) ==='
          % (title, start, va + fwd, off))
    n = 0
    for ins in md.disasm(d[off:off + back + fwd], start):
        mark = ''
        if ins.address == va:
            mark = '   <===== PROBE'
        print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic,
                                     ins.op_str, mark))
        n += 1
        if n > 60:
            break
    print()


dump_around(0x54FB46, 0x18, 0x30, 'processSystemMessage return point')
dump_around(0x54ED12, 0x10, 0x90, 'frame function entry + drawFramebuffer call')
