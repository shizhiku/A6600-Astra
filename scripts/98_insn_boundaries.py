"""List every instruction boundary from 0x54F664 so probes only land on real
instruction starts.  Prints address, size (2 or 4), mnemonic."""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

start = 0x54F664
insns = list(md.disasm(td[start - tb:start - tb + 0x260], start))
calls = []
print('=== instruction boundaries 0x54F664.. (call sites marked) ===')
for ins in insns:
    is_call = ins.mnemonic in ('bl', 'blx')
    print('  %08x  %d  %-8s %s%s' % (ins.address, ins.size, ins.mnemonic,
                                     ins.op_str, '   <== CALL' if is_call else ''))
    if is_call:
        calls.append((ins.address, ins.size, ins.op_str))

print()
print('=== safe resume points (address right after each call) ===')
for a, sz, ops in calls:
    print('  after call at %08x -> resume %#010x' % (a, a + sz))
