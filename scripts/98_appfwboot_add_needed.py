"""Patch 5th-gen appFwBoot.so so that it depends on the renamed gen5
libObj (a5bObj.so) instead of libgcc_s.so.1.

appFwBoot imports 22 ux::gfxeng/resmgr/Kernel symbols that otherwise resolve
to the global 4th-gen libObj.so and crash.  Making a5bObj.so a NEEDED
dependency puts it into appFwBoot's local (DEEPBIND) lookup scope, so the
5th-gen implementations win.

The DT_NEEDED string is rewritten in place (same dynstr bytes, no layout
change): 'libgcc_s.so.1\\0' -> 'a5bObj.so\\0'.
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io

src = Path('03-证据/静态分析/97_abi/appFwBoot_a5.so')
out = Path('03-证据/静态分析/97_abi/appFwBoot_a5obj.so')
d = bytearray(src.read_bytes())
e = ELFFile(io.BytesIO(bytes(d)))

dyn = e.get_section_by_name('.dynamic')
strtab_hdr = None
for sec in e.iter_sections():
    if sec['sh_type'] == 'SHT_STRTAB':
        strtab_hdr = sec
        break
assert strtab_hdr is not None
strtab_off = strtab_hdr['sh_offset']

needed = []
for tag in dyn.iter_tags():
    if tag.entry.d_tag == 'DT_NEEDED':
        s_off = tag.entry.d_val
        end = d.find(b'\x00', strtab_off + s_off)
        name = bytes(d[strtab_off + s_off:end]).decode()
        needed.append((s_off, name))
print('NEEDED', needed)

target = None
for s_off, name in needed:
    if name == 'libgcc_s.so.1':
        target = (strtab_off + s_off, name)
        break
assert target is not None, 'libgcc_s.so.1 NEEDED not found'
pos, old = target
new = b'a5bObj.so\x00'
oldb = old.encode() + b'\x00'
assert len(new) <= len(oldb), 'new name longer than old'
d[pos:pos + len(oldb)] = new + b'\x00' * (len(oldb) - len(new))
out.write_bytes(bytes(d))
print('patched NEEDED', old, '-> a5bObj.so at file offset', hex(pos))
print('wrote', out, len(d))
