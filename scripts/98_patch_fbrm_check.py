"""Patch gen5 libObj.so: force GRM_fbrmCheckUpdateFinished to report "finished".

file_off(va) = sh_offset + (va - sh_addr); here .text addr==off==0x3d080,
so file_off(0x115618) = 0x115618 (verified).

0x115618 GRM_fbrmCheckUpdateFinished:
    80 b5        push {r7,lr}
    00 af        add  r7, sp, #0
    0a f0 a3 f8  bl   0x11F766        <- returns (1 - status); caller needs 1
    02 4b        ldr  r3,[pc,#8]
    01 28        cmp  r0,#1
    14 bf        ite  ne
    18 46        movne r0,r3
    ...
Patch entry with: 00 20 70 47  (movs r0,#0 ; bx lr)
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io

SRC = Path('03-证据/静态分析/grm/lib/libObj.so')
OUT = Path('03-证据/静态分析/97_abi/a5bObj_fbrm.so')

raw = SRC.read_bytes()
d = bytearray(raw)
e = ELFFile(io.BytesIO(raw))


def file_offset(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + (va - s['sh_addr'])
    return None


ENTRY = 0x115618
off = file_offset(ENTRY)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

before = bytes(d[off:off + 16])
print('offset=%#x before=%s' % (off, before.hex(' ')))
for ins in md.disasm(before, ENTRY):
    print('  %08x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))

# correct prologue check: push {r7,lr} == 0xB580 -> little endian 80 b5
assert before[0:2] == bytes.fromhex('80b5'), 'unexpected prologue %s' % before[:2].hex()

d[off:off + 4] = bytes.fromhex('00207047')   # movs r0,#0 ; bx lr
print('after =', bytes(d[off:off + 4]).hex(' '))
for ins in md.disasm(bytes(d[off:off + 4]), ENTRY):
    print('  %08x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))

OUT.write_bytes(bytes(d))
print('wrote', OUT, len(d))
