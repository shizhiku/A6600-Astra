"""Scan Thumb-2 movw/movt pairs to find code referencing kernel strings."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/nflasha3-Image'
d = IMG.read_bytes()

STR_OFFS = {0x33F34F: 'bad_syscall_1', 0x33F469: 'bad_syscall_2', 0x33F36E: 'undefined_instr'}
BASES = [0x60000000, 0x60008000, 0x60010000, 0x60004000, 0x60018000]

def decode_movw_movt(hw1, hw2, is_movt):
    imm4 = hw1 & 0xF
    i = (hw1 >> 10) & 1
    imm3 = (hw2 >> 12) & 0x7
    rd = (hw2 >> 8) & 0xF
    imm8 = hw2 & 0xFF
    imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
    return rd, imm16

pairs = []
last_movw = {}
n = len(d)
for off in range(0, n - 4, 2):
    hw1 = struct.unpack_from('<H', d, off)[0]
    if (hw1 & 0xFFF0) == 0xF240 or (hw1 & 0xFFF0) == 0xF2C0:
        is_movt = (hw1 & 0xFFF0) == 0xF2C0
        hw2 = struct.unpack_from('<H', d, off + 2)[0]
        if hw2 & 0x8000:
            continue
        rd, imm16 = decode_movw_movt(hw1, hw2, is_movt)
        if not is_movt:
            last_movw[rd] = (off, imm16)
        else:
            prev = last_movw.get(rd)
            if prev and 0 < off - prev[0] < 0x40:
                value = (imm16 << 16) | prev[1]
                pairs.append((prev[0], off, rd, value))

print('movw/movt pairs found:', len(pairs))
hits = 0
for base in BASES:
    for off_w, off_t, rd, value in pairs:
        rel = value - base
        if rel in STR_OFFS:
            print(f'  base {base:#010x}: {STR_OFFS[rel]} <- movw@{off_w:#x} movt@{off_t:#x} '
                  f'(value {value:#010x}, VA {base + off_w:#010x})')
            hits += 1
print('total matches:', hits)

if hits:
    # disassemble around the first match
    for base in BASES:
        for off_w, off_t, rd, value in pairs:
            if value - base in STR_OFFS:
                start = max(0, off_w - 0x60)
                md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
                md.skipdata = True
                print(f'\n--- window at {base + off_w:#010x} ---')
                for ins in md.disasm(d[start:off_t + 8], start):
                    print(f'  {base + ins.address:08x} {ins.bytes.hex():10} {ins.mnemonic:9} {ins.op_str}')
                raise SystemExit
