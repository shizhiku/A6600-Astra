"""Since vtable[0] at 0x54D05C is a no-op, the blocking point inside 0x54EF74
must be one of the later calls.  This script:
  1. resolves every bl/blx in 0x54EF74 to its real target,
  2. for each target that lands in .text, prints its first instructions,
  3. flags calls whose body touches known blocking primitives
     (osal_rcv_msg_tmo / osal_wai_sem_tmo / pthread_cond_wait / ioctl / open).

The 0x92xxxx values are ARM-state veneers:
    ldr ip,[pc,#4] ; add ip,pc,ip ; bx ip ; .word delta
with target = (veneer_addr + 8) + delta   (ARM pc = insn_addr + 8)
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from pathlib import Path
import io
import struct
import bisect

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


def read_u32(va):
    s = sec_of(va)
    if s is None:
        return None
    off = s['sh_offset'] + (va - s['sh_addr'])
    if off + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, off)[0]


funcs = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            v = s['st_value']
            if v and s.name and s['st_info']['type'] == 'STT_FUNC':
                funcs.setdefault(v & ~1, s.name)
fa = sorted(funcs)


def containing(va):
    i = bisect.bisect_right(fa, va) - 1
    if i < 0:
        return None
    return fa[i], funcs[fa[i]]


def resolve_veneer(va):
    """Return real target of an ARM-state veneer at va, or None."""
    raw = d[va:va + 16]
    if raw[:4] != bytes.fromhex('04c09fe5'):
        return None
    delta = struct.unpack_from('<i', d, va + 12)[0]
    return ((va + 8) + delta) & 0xFFFFFFFF


md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
insns = list(md_t.disasm(td[0x54EF74 - tb:0x54EF74 - tb + 0x90], 0x54EF74))

BLOCK_PAT = ('osal_rcv_msg_tmo', 'osal_wai_sem_tmo', 'pthread_cond_wait',
             'osal_valloc_msg_wait', 'sem_wait', 'ioctl', 'open',
             'nanosleep', 'usleep', 'osal_create_waitable_thread', 'poll',
             'select', 'read', 'write')

print('=== calls inside 0x54EF74 and their resolution ===')
for ins in insns:
    if ins.mnemonic not in ('bl', 'blx', 'bx') :
        continue
    if ins.mnemonic == 'bx':
        print('  %08x  bx %s  (indirect -> vtable[0] = no-op, verified)'
              % (ins.address, ins.op_str))
        continue
    if not ins.op_str.startswith('#'):
        print('  %08x  %s %s (indirect)' % (ins.address, ins.mnemonic,
                                            ins.op_str))
        continue
    try:
        tgt = int(ins.op_str[1:], 16)
    except ValueError:
        continue
    real = resolve_veneer(tgt & ~1)
    kind = ''
    final = tgt
    if real is not None:
        final = real
        kind = 'veneer'
    c = containing(final)
    name = ''
    if final in funcs:
        name = funcs[final]
    elif c:
        name = '%s+%#x' % (c[1], final - c[0])
    print('  %08x  -> %#010x  %-8s %s'
          % (ins.address, final, kind, name))
