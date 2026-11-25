"""Add REA_FB_FORMAT=rgba4444 support to the QEMU framebuffer dump."""
from pathlib import Path
p=Path('/root/qemu-11.1.3/hw/misc/cxd90014_vph.c')
t=p.read_text()
old='''    uint32_t w, h, x, y;

    if (!path || !base || !lb || !lines) {
        return;
    }'''
new='''    uint32_t w, h, x, y;
    const char *fmt = getenv("REA_FB_FORMAT");
    int rgba4444 = fmt && !strcmp(fmt, "rgba4444");

    if (!path || !base || !lb || !lines) {
        return;
    }'''
assert old in t
t=t.replace(old,new,1)
old2='''            for (x = 0; x < w; x++) {
                uint16_t v = row[x];
                fputc(((v >> 11) & 0x1f) << 3, f);
                fputc(((v >> 5) & 0x3f) << 2, f);
                fputc((v & 0x1f) << 3, f);
            }'''
new2='''            for (x = 0; x < w; x++) {
                uint16_t v = row[x];
                if (rgba4444) {
                    fputc(((v >> 12) & 0xf) * 17, f);
                    fputc(((v >> 8) & 0xf) * 17, f);
                    fputc(((v >> 4) & 0xf) * 17, f);
                } else {
                    fputc(((v >> 11) & 0x1f) << 3, f);
                    fputc(((v >> 5) & 0x3f) << 2, f);
                    fputc((v & 0x1f) << 3, f);
                }
            }'''
assert old2 in t
t=t.replace(old2,new2,1)
p.write_text(t)
print('patched',p)
