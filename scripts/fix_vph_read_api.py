"""Fix the VPH dump helper to use address_space_read (QEMU 11 API)."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/misc/cxd90014_vph.c')
s = p.read_text()
old = '    cpu_physical_memory_read(base, buf, total);'
new = ('    address_space_read(&address_space_memory, base, MEMTXATTRS_UNSPECIFIED,\n'
       '                       buf, total);')
if old in s:
    s = s.replace(old, new)
    if '#include "exec/cpu-common.h"' in s:
        s = s.replace('\n#include "exec/cpu-common.h"', '')
    p.write_text(s)
    print('switched to address_space_read')
else:
    print('already switched' if 'address_space_read(&address_space_memory' in s else 'anchor not found')
