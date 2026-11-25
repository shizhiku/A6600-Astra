"""Add a one-shot framebuffer dump to the VPH model (ch53 scanout -> PPM)."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/misc/cxd90014_vph.c')
s = p.read_text()

helper = '''
/* REA: dump the panel framebuffer (ch53 scanout) to a PPM file once. */
static void rea_fb_dump(uint32_t base, uint32_t lb, uint32_t lines)
{
    const char *path = getenv("REA_FB_PATH");
    size_t total;
    uint8_t *buf;
    FILE *f;
    uint32_t w, h, x, y;

    if (!path || !base || !lb || !lines) {
        return;
    }
    total = (size_t)lb * lines;
    if (total == 0 || total > 64u * 1024 * 1024) {
        return;
    }
    buf = g_malloc(total);
    cpu_physical_memory_read(base, buf, total);
    w = lb / 2;
    h = lines;
    f = fopen(path, "wb");
    if (f) {
        fprintf(f, "P6\\n%u %u\\n255\\n", w, h);
        for (y = 0; y < h; y++) {
            const uint16_t *row = (const uint16_t *)(buf + (size_t)y * lb);
            for (x = 0; x < w; x++) {
                uint16_t v = row[x];
                fputc(((v >> 11) & 0x1f) << 3, f);
                fputc(((v >> 5) & 0x3f) << 2, f);
                fputc((v & 0x1f) << 3, f);
            }
        }
        fclose(f);
        fprintf(stderr, "[REA_FB] dumped %ux%u from 0x%08x to %s\\n",
                w, h, base, path);
    }
    g_free(buf);
}

'''

anchor = 'static void vph_tick(void *opaque)\n{'
if 'rea_fb_dump' in s:
    print('already patched')
else:
    assert anchor in s, 'vph_tick not found'
    s = s.replace(anchor, helper + anchor, 1)

    # insert the dump trigger right after the opening brace of vph_tick
    body_anchor = 'static void vph_tick(void *opaque)\n{\n    VphState *s = opaque;'
    trigger = '''static void vph_tick(void *opaque)
{
    VphState *s = opaque;
    {
        static unsigned rea_n;
        static int rea_done, rea_inited;
        static unsigned rea_target;
        const char *want = getenv("REA_FB_PATH");
        rea_n++;
        if (want && !rea_inited) {
            const char *v = getenv("REA_FB_VSYNC");
            rea_target = v ? (unsigned)atoi(v) : 300;
            rea_inited = 1;
        }
        if (want && !rea_done && rea_n >= rea_target && R(AIF(2) + 0x20)) {
            rea_done = 1;
            rea_fb_dump(R(AIF(2) + 0x20), R(AIF(2) + 0x24),
                        R(AIF(2) + 0x2C) + 1);
        }
    }'''
    assert body_anchor in s, 'vph_tick body not found'
    s = s.replace(body_anchor, trigger, 1)
    p.write_text(s)
    print('patched framebuffer dump')
