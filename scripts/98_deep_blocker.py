"""Deep-analyze the function containing 0x1C7E69C (the call that never returns).

The veneer 0x925FB0 resolves to 0x1C7E69C.  But 0x1C7E69C is a 6-instruction
stub ending in `pop {r7,pc}` -- so the real body must be reached by falling
through: at 0x1C7E6A6 `pop {r7,pc}` returns, meaning 0x1C7E69C RETURNS.

Wait: 0x1C7E69C is:
  1c7e69c ldr r3,[pc,#8]
  1c7e69e push {r7,lr}
  1c7e6a0 add r3, pc
  1c7e6a2 add r7, sp, #0
  1c7e6a4 str r3, [r0]
  1c7e6a6 pop {r7, pc}

That is a constructor-like setter.  If the call never returns, maybe our veneer
resolution is off by one function.  Enumerate ALL veneers that point into the
0x1C7E6xx neighborhood and print who calls them.
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from pathlib import Path
import io
import struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()


def sec_of(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s
    return None


def resolve_veneer(v):
    if d[v:v + 4] != bytes.fromhex('04c09fe5'):
        return None
    word = struct.unpack_from('<i', d, v + 12)[0]
    return ((v + 12) + word) & 0xFFFFFFFF


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# All the calls made inside 0x54EF74 with their resolved targets
print('=== 0x54EF74 calls (site -> veneer -> target, target+2) ===')
for ins in md.disasm(td[0x54EF74 - tb:0x54EF74 - tb + 0x90], 0x54EF74):
    if ins.mnemonic not in ('bl', 'blx') or not ins.op_str.startswith('#'):
        continue
    try:
        t = int(ins.op_str[1:], 16)
    except ValueError:
        continue
    real = resolve_veneer(t & ~1)
    if real:
        # also try +2 alignment variant
        print('  %08x -> veneer %#010x -> target %#010x (alt %#010x)'
              % (ins.address, t, real, (real + 2) & 0xFFFFFFFF))
    else:
        print('  %08x -> direct %#010x' % (ins.address, t))

print()
print('=== venv targets near 0x1C7E6xx with first instrs ===')
for t in (0x01c7e69c, 0x01c7e69d, 0x01c7e6a4, 0x01c7e6ac, 0x01c7e6b4):
    ent = t & ~1
    ins = list(md.disasm(td[ent - tb:ent - tb + 10], ent))
    print('  %#010x: %s' % (ent, ' | '.join('%s %s' % (i.mnemonic, i.op_str)
                                            for i in ins[:4])))

print()
print('=== who else references 0x1C7E6xx region? (veneer scan) ===')
# scan the .plt-adjacent veneer area for words resolving here
lo, hi = 0x920000, 0x92B000
found = 0
for v in range(lo, hi, 4):
    r = resolve_veneer(v)
    if r and 0x1C7E600 <= r <= 0x1C7E900:
        print('  veneer %#010x -> %#010x' % (v, r))
        found += 1
print('  total', found)
