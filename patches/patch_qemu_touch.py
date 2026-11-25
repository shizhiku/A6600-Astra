#!/usr/bin/env python3
"""Add an interactive touch-write command to the sony-a6400 machine model.

FIFO protocol addition:
    'T' followed by 16 raw bytes = {addr:u32, magic:u32, x:u32, y:u32} (LE)
The machine model copies {magic,x,y} into guest physical `addr`, bypassing the
MMU, so the in-guest shim can poll its own page.
"""
import re
import sys
from pathlib import Path

SRC = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
text = SRC.read_text()

if 'rea_touch_state' in text:
    print('already patched')
    sys.exit(0)

# 1) include for address_space_memory
if '#include "system/address-spaces.h"' not in text:
    text = text.replace('#include "qemu/units.h"',
                        '#include "qemu/units.h"\n#include "system/address-spaces.h"', 1)

# 2) state + helper before sony_a6400_rea_ctl
anchor = 'static int sony_rea_ctl_fd = -1;'
helper = '''static int sony_rea_ctl_fd = -1;

/* REA: interactive touch mailbox write.
 * 'T' + 16 bytes {addr,magic,x,y} (LE) -> copy {magic,x,y} into guest phys addr. */
static int rea_touch_state;
static unsigned rea_touch_fill;
static uint8_t rea_touch_buf[16];

static void sony_rea_touch_write(const uint8_t *b)
{
    uint32_t addr, magic, x, y;
    uint8_t out[12];
    memcpy(&addr, b + 0, 4);
    memcpy(&magic, b + 4, 4);
    memcpy(&x, b + 8, 4);
    memcpy(&y, b + 12, 4);
    memcpy(out + 0, &magic, 4);
    memcpy(out + 4, &x, 4);
    memcpy(out + 8, &y, 4);
    address_space_write(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                        out, sizeof(out));
    fprintf(stderr, "[TOUCHINJ] addr=0x%08x seq=%u at (%u,%u)\\n",
            addr, magic, x, y);
}
'''
if anchor not in text:
    print('anchor1 missing')
    sys.exit(1)
text = text.replace(anchor, helper, 1)

# 3) hook into the byte loop
loop_anchor = """    for (i = 0; i < n; i++) {
        char c = buf[i];
        if (c == 's') {"""
loop_new = """    for (i = 0; i < n; i++) {
        char c = buf[i];
        if (rea_touch_state) {
            rea_touch_buf[rea_touch_fill++] = (uint8_t)c;
            if (rea_touch_fill >= sizeof(rea_touch_buf)) {
                rea_touch_state = 0;
                rea_touch_fill = 0;
                sony_rea_touch_write(rea_touch_buf);
            }
            continue;
        }
        if (c == 'T') {
            rea_touch_state = 1;
            rea_touch_fill = 0;
            continue;
        }
        if (c == 's') {"""
if loop_anchor not in text:
    print('anchor2 missing')
    sys.exit(1)
text = text.replace(loop_anchor, loop_new, 1)

SRC.write_text(text)
print('patched', SRC)
print('  has include :', '#include "system/address-spaces.h"' in text)
print('  has helper  :', 'sony_rea_touch_write' in text)
print('  has hook    :', "if (c == 'T')" in text)
