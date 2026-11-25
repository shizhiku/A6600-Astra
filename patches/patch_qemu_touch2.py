#!/usr/bin/env python3
"""Upgrade the machine-model touch command from tap-only to tap+drag.

New FIFO protocol:
    'T' + 28 raw bytes = {addr, seq, kind, x1, y1, x2, y2} (all u32 LE)
The machine model writes {seq, kind, x1, y1, x2, y2} (24 bytes) into guest
physical address `addr`.
      kind 1 = tap, 2 = drag
"""
import sys
from pathlib import Path

SRC = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
t = SRC.read_text()

if 'rea_touch_buf[28]' in t:
    print('already upgraded')
    sys.exit(0)

old_buf = 'static uint8_t rea_touch_buf[16];'
new_buf = 'static uint8_t rea_touch_buf[28];'
if old_buf not in t:
    print('buf decl missing'); sys.exit(1)
t = t.replace(old_buf, new_buf, 1)

old_fn_start = 'static void sony_rea_touch_write(const uint8_t *b)'
new_fn = '''static void sony_rea_touch_write(const uint8_t *b)
{
    uint32_t addr, seq, kind, x1, y1, x2, y2;
    uint8_t out[24];
    memcpy(&addr, b + 0, 4);
    memcpy(&seq,  b + 4, 4);
    memcpy(&kind, b + 8, 4);
    memcpy(&x1,   b + 12, 4);
    memcpy(&y1,   b + 16, 4);
    memcpy(&x2,   b + 20, 4);
    memcpy(&y2,   b + 24, 4);
    memcpy(out + 0,  &seq, 4);
    memcpy(out + 4,  &kind, 4);
    memcpy(out + 8,  &x1, 4);
    memcpy(out + 12, &y1, 4);
    memcpy(out + 16, &x2, 4);
    memcpy(out + 20, &y2, 4);
    address_space_write(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                        out, sizeof(out));
    fprintf(stderr, "[TOUCHINJ] addr=0x%08x seq=%u kind=%u (%u,%u)->(%u,%u)\\n",
            addr, seq, kind, x1, y1, x2, y2);
}
'''
# replace the whole old function body
start = t.find(old_fn_start)
if start < 0:
    print('fn missing'); sys.exit(1)
end = t.find('\n}\n', start) + 3
t = t[:start] + new_fn + t[end:]

SRC.write_text(t)
print('upgraded')
print('  buf28 :', 'rea_touch_buf[28]' in t)
print('  kind  :', 'uint32_t addr, seq, kind' in t)
