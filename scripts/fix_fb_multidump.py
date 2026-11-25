"""Rewrite the framebuffer dump trigger with correct one-shot-per-target logic."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/misc/cxd90014_vph.c')
s = p.read_text()

start_marker = '    {\n        static unsigned rea_n;'
end_marker = '    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);'

start = s.find(start_marker)
end = s.find(end_marker, start)
assert start > 0 and end > start, 'markers not found'

new_block = '''    {
        static unsigned rea_n;
        static unsigned targets[8];
        static int ntargets = -1, tidx;
        const char *want = getenv("REA_FB_PATH");

        rea_n++;
        if (ntargets < 0) {
            const char *list = getenv("REA_FB_VSYNC");
            ntargets = 0;
            tidx = 0;
            if (list) {
                while (*list && ntargets < 8) {
                    unsigned v = 0;
                    while (*list >= '0' && *list <= '9') {
                        v = v * 10 + (unsigned)(*list - '0');
                        list++;
                    }
                    if (v) {
                        targets[ntargets++] = v;
                    }
                    if (*list == ',') {
                        list++;
                    } else {
                        break;
                    }
                }
            }
            if (!ntargets) {
                targets[ntargets++] = 300;
            }
        }
        if (want && tidx < ntargets && rea_n >= targets[tidx] &&
            R(AIF(2) + 0x20)) {
            char path[512];
            snprintf(path, sizeof(path), "%s.%d.ppm", want, tidx);
            rea_fb_dump(R(AIF(2) + 0x20), R(AIF(2) + 0x24),
                        R(AIF(2) + 0x2C) + 1, path);
            tidx++;
        }
    }
'''
s = s[:start] + new_block + s[end:]
p.write_text(s)
print('rewrote dump trigger')
