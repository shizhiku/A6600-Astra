"""Verify the exact instruction encodings in 0x54D154..0x54D16A.

We must know whether `add r4, pc` at 0x54D162 is a 16-bit or 32-bit Thumb
instruction, because that determines the PC value used:

  16-bit Thumb `add rX, pc` : PC = (insn_addr + 4) & ~3
  32-bit Thumb-2            : PC = insn_addr + 4   (aligned to 4 by spec)

Raw bytes are dumped and decoded both ways to settle it.
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

start = 0x54D154
raw = d[start:start + 0x20]
print('raw bytes 0x54D154..0x54D174:')
for i in range(0, 0x20, 4):
    print('  %08x: %s' % (start + i, raw[i:i + 4].hex(' ')))

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
print('\ndisassembly with sizes:')
addr = start
for ins in md.disasm(raw, start):
    print('  %08x  (%d bytes)  %-8s %s'
          % (ins.address, ins.size, ins.mnemonic, ins.op_str))
    if ins.address > start + 0x18:
        break

# Now decode `add r4, pc` and `ldr r3, [pc, #0x10]` by hand.
# Find the instruction at 0x54D162.
off = 0x54D162 - start
print('\nbytes at 0x54D162: %s' % raw[off:off + 4].hex(' '))
hw = struct.unpack_from('<H', d, 0x54D162)[0]
print('halfword = %#06x' % hw)
if (hw & 0xF800) == 0x4800:
    print('  -> 16-bit LDR (pc-relative)')
elif (hw & 0xFF80) == 0x4480 or (hw & 0xFF78) == 0x4478:
    print('  -> 16-bit ADD (pc)')
elif (hw & 0xFC00) == 0xF000:
    print('  -> 32-bit Thumb-2 prefix (0xF0xx)')
elif (hw & 0xFE00) == 0xE800:
    print('  -> 32-bit Thumb-2 (0xE8xx)')
elif (hw & 0xFF00) == 0xEB00:
    print('  -> 32-bit Thumb-2 ADD (0xEBxx)')
else:
    print('  -> other')
