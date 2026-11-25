"""Find the enclosing function of a Thumb address and disassemble it with correct alignment."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/av-cam-live.bin'
VA0 = 0x635C6000
CALL_LR = 0x6386118D          # return address of the call of interest
TARGET = (CALL_LR - 1) & ~1   # 0x6386118C

d = IMG.read_bytes()

def at(va):
    return d[va - VA0: va - VA0 + 4]

# scan backwards for a plausible function prologue: push {..., lr}
start = None
va = TARGET - 2
while va > TARGET - 0x200:
    hw = struct.unpack_from('<H', d, va - VA0)[0]
    if (hw & 0xFF00) == 0xB500:          # push {.., lr}
        start = va
        break
    if hw == 0xE92D:                     # 32-bit push
        start = va
        break
    va -= 2
print('candidate function start:', hex(start) if start else None)

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.skipdata = True
begin = start if start else TARGET - 0x80
for ins in md.disasm(d[begin - VA0: begin - VA0 + 0x140], begin):
    mark = ''
    if ins.address == TARGET:
        mark = '   <== call returns here'
    if ins.address == TARGET - 4:
        mark = '   <== call instruction'
    print(f'{ins.address:08x} {ins.bytes.hex():10} {ins.mnemonic:9} {ins.op_str}{mark}')
