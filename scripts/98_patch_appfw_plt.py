"""Patch the __assert_fail PLT entry in gen5 appFw.so to return (bx lr).
Diagnostic-only; writes a NEW .so. Prints the located slot.
"""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io, struct, sys
SRC = Path('05-原始固件/zv1m2_fw/gen5/appFw.so')
OUT = Path('03-证据/静态分析/97_abi/zv_appFw_assert_ret.so')
d = bytearray(SRC.read_bytes())
e = ELFFile(io.BytesIO(bytes(d)))
syms = e.get_section_by_name('.dynsym')
def symname(i):
    return syms.get_symbol(i).name
rel = None
for s in e.iter_sections():
    if s.name in ('.rel.plt', '.rel.dyn'):
        for r in s.iter_relocations():
            if symname(r['r_info_sym']) == '__assert_fail':
                rel = (s.name, r['r_offset'], r['r_info_type'])
                break
    if rel: break
print('reloc', rel)
assert rel, 'no __assert_fail relocation'
gotplt = e.get_section_by_name('.got.plt'); plt = e.get_section_by_name('.plt')
print('.plt', hex(plt['sh_addr']), hex(plt['sh_size']), '.got.plt', hex(gotplt['sh_addr']))
data = bytes(d[plt['sh_offset']:plt['sh_offset']+plt['sh_size']]); base = plt['sh_addr']
md = Cs(CS_ARCH_ARM, CS_MODE_ARM); md.detail = False
match = None
addrs = [ins.address for ins in md.disasm(data, base)]
# entries start after PLT0 (20 bytes); try 12-byte slots
for off in range(0, len(data) - 12, 4):
    chunk = data[off:off+12]
    try:
        ins = list(md.disasm(chunk, base + off))
    except Exception:
        continue
    if len(ins) != 3:
        continue
    if not (ins[0].mnemonic == 'add' and ins[0].op_str.startswith('ip, pc')):
        continue
    if not (ins[1].mnemonic == 'add' and ins[1].op_str.startswith('ip, ip')):
        continue
    if not (ins[2].mnemonic == 'ldr' and ins[2].op_str.startswith('pc, [ip')):
        continue
    def imm(op):
        try: return int(op.split('#')[-1].rstrip(']'), 0)
        except Exception: return None
    i1 = imm(ins[0].op_str); i2 = imm(ins[1].op_str); i3 = imm(ins[2].op_str)
    if i1 is None or i2 is None or i3 is None:
        continue
    target = (base + off + 8) + i1 + i2 + i3
    if target == rel[1]:
        match = base + off
        break
print('plt slot', hex(match) if match else None)
assert match
d[match - base + plt['sh_offset']: match - base + plt['sh_offset'] + 4] = struct.pack('<I', 0xE12FFF1E)
OUT.write_bytes(bytes(d))
print('wrote', OUT)
