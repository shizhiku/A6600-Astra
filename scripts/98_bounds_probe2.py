"""List instruction boundaries for the two suspect functions so probes land
on valid instruction starts:

  0x60E274  the reset loop (calls the infra_wrapper mumap wrapper)
  0x2B1B524 wrapper: sched_lock(0xf,0xf) -> bl 0x2B749CC -> sched_unlock
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
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def dump(start, size, title):
    print('=== %s: %#010x ===' % (title, start))
    for ins in md.disasm(td[start - tb:start - tb + size], start):
        tag = ' <== CALL' if ins.mnemonic in ('bl', 'blx') else ''
        print('  %08x  %d  %-8s %s%s'
              % (ins.address, ins.size, ins.mnemonic, ins.op_str, tag))
    print()


dump(0x60E274, 0x7A, '0x60E274 reset loop')
dump(0x2B1B524, 0x24, '0x2B1B524 sched_lock wrapper')
