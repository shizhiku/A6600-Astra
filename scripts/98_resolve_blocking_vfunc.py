"""Disassemble 0x54D05D (vtable[0], the suspected blocking virtual call)
and read the RTTI class-name strings to identify the class."""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()


def va_to_off(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + (va - s['sh_addr'])
    return None


def cstr(va, limit=200):
    o = va_to_off(va)
    if o is None:
        return None
    end = d.find(b'\x00', o)
    if end < 0 or end - o > limit:
        return None
    raw = d[o:end]
    try:
        return raw.decode('ascii')
    except UnicodeDecodeError:
        return repr(raw[:60])


print('=== vtable[0] target: 0x54D05D ===')
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
off = 0x54D05D - tb
for ins in md.disasm(td[off:off + 0x80], 0x54D05D):
    extra = ''
    if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
        try:
            tgt = int(ins.op_str[1:], 16)
            extra = '   ; -> %#x' % tgt
        except ValueError:
            pass
    print('  %08x  %-8s %s%s' % (ins.address, ins.mnemonic, ins.op_str, extra))

print()
print('=== RTTI strings from the vtable area ===')
for va in (0x02CEB040, 0x02CEB055, 0x02CEB062, 0x02CEB07A):
    s = cstr(va)
    print('  %#010x -> %r' % (va, s))

# Also dump a window of rodata around 0x2CEB000 to see the class name pool
print()
print('=== rodata window 0x02CEB000..0x02CEB100 ===')
o = va_to_off(0x02CEB000)
blob = d[o:o + 0x100]
parts = blob.split(b'\x00')
addr = 0x02CEB000
for p in parts:
    if p:
        try:
            print('  %#010x %r' % (addr, p.decode('ascii')))
        except UnicodeDecodeError:
            pass
    addr += len(p) + 1
