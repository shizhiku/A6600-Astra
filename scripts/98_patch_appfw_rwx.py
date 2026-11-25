"""Make gen5 appFw's first PT_LOAD writable (emulator-only workaround: the app
patches const/rodata that its own loader apparently maps writable)."""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import struct, io
SRC = Path('05-原始固件/zv1m2_fw/gen5/appFw.so')
OUT = Path('03-证据/静态分析/97_abi/zv_appFw_rwx.so')
d = bytearray(SRC.read_bytes())
e = ELFFile(io.BytesIO(bytes(d)))
phoff = e['e_phoff']; phentsize = e['e_phentsize']; phnum = e['e_phnum']
changed = []
for i in range(phnum):
    off = phoff + i * phentsize
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from('<IIIIIIII', d, off)
    if p_type == 1 and not (p_flags & 2):
        new = p_flags | 2
        struct.pack_into('<I', d, off + 24, new)
        changed.append((i, hex(p_offset), p_flags, new))
OUT.write_bytes(bytes(d))
print('changed', changed, '->', OUT)
