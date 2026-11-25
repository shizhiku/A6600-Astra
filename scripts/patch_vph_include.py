"""Add the missing include for cpu_physical_memory_read to the VPH model."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/misc/cxd90014_vph.c')
s = p.read_text()
if 'exec/cpu-common.h' in s:
    print('already included')
else:
    anchor = '#include "system/memory.h"'
    assert anchor in s, 'anchor missing'
    s = s.replace(anchor, anchor + '\n#include "exec/cpu-common.h"', 1)
    p.write_text(s)
    print('include added')
