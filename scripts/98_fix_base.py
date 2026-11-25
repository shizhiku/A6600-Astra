"""Fix base handling: print section layout and disassemble with correct
va->offset mapping (sh_addr may differ from sh_offset).
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io

SRC = Path('03-证据/静态分析/grm/lib/libObj.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))

print('=== sections ===')
for s in e.iter_sections():
    if s.name in ('.text', '.rodata', '.data', '.bss', '.dynamic',
                  '.dynsym', '.dynstr', '.plt', '.got'):
        print('  %-12s addr=%#010x off=%#010x size=%#x' %
              (s.name, s['sh_addr'], s['sh_offset'], s['sh_size']))

print()
print('=== program headers ===')
for p in e.iter_segments():
    print('  %-16s vaddr=%#010x off=%#010x filesz=%#x memsz=%#x' %
          (p['p_type'], p['p_vaddr'], p['p_offset'],
           p['p_filesz'], p['p_memsz']))

text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
print()
print('text: addr=%#x off=%#x size=%#x  (addr==off? %s)' %
      (tb, text['sh_offset'], text['sh_size'], tb == text['sh_offset']))

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for name, va in (('GRM_fbrmCheckUpdateFinished', 0x115619 & ~1),
                 ('GRM_fbrmSetScreenPreference', 0x1155AD & ~1),
                 ('GraphicsEngine::drawFramebuffer', 0xE565B & ~1)):
    off = va - tb
    print()
    print('=== %s @ %#x (text offset %#x) ===' % (name, va, off))
    if off < 0 or off >= len(td):
        print('  OUT OF RANGE')
        continue
    for ins in md.disasm(td[off:off + 48], va):
        print('  %08x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
