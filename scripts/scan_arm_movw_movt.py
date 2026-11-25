"""Scan ARM-mode movw/movt pairs to find code referencing kernel strings."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/nflasha3-Image'
d = IMG.read_bytes()

STR_OFFS = {0x33F34F: 'bad_syscall_1', 0x33F469: 'bad_syscall_2', 0x33F36E: 'undefined_instr'}
BASES = [0x60000000, 0x60008000, 0x60010000, 0x60004000, 0x60018000]

pairs = []
last_movw = {}
for off in range(0, len(d) - 4, 4):
    w = struct.unpack_from('<I', d, off)[0]
    top = w & 0x0FF00000
    if top == 0x03000000:      # MOVW
        rd = (w >> 12) & 0xF
        imm16 = ((w >> 16) & 0xF) << 12 | (w & 0xFFF)
        last_movw[rd] = (off, imm16)
    elif top == 0x03400000:    # MOVT
        rd = (w >> 12) & 0xF
        imm16 = ((w >> 16) & 0xF) << 12 | (w & 0xFFF)
        prev = last_movw.get(rd)
        if prev and 0 < off - prev[0] <= 0x40:
            pairs.append((prev[0], off, rd, (imm16 << 16) | prev[1]))

print('ARM movw/movt pairs:', len(pairs))
found = []
for base in BASES:
    for off_w, off_t, rd, value in pairs:
        rel = value - base
        if rel in STR_OFFS:
            found.append((base, off_w, off_t, rd, value, STR_OFFS[rel]))
for f in found[:10]:
    base, off_w, off_t, rd, value, name = f
    print(f'  base {base:#010x}: {name} movw@{off_w:#x} movt@{off_t:#x} value={value:#010x}')
print('matches:', len(found))

if found:
    base, off_w, off_t, rd, value, name = found[0]
    start = max(0, off_w - 0x80)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.skipdata = True
    print(f'\n--- window around {base + off_w:#010x} ({name}) ---')
    for ins in md.disasm(d[start:off_t + 8], start):
        mark = '  <== movw' if ins.address == off_w else ('  <== movt' if ins.address == off_t else '')
        print(f'  {base + ins.address:08x} {ins.bytes.hex():8} {ins.mnemonic:9} {ins.op_str}{mark}')
