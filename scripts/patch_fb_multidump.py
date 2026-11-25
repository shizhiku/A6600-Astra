"""Allow REA_FB_VSYNC to be a comma-separated list; each dump gets a numbered file."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/misc/cxd90014_vph.c')
s = p.read_text()

old = '''        if (want && !rea_done && rea_n >= rea_target && R(AIF(2) + 0x20)) {
            rea_done = 1;
            rea_fb_dump(R(AIF(2) + 0x20), R(AIF(2) + 0x24),
                        R(AIF(2) + 0x2C) + 1);
        }'''

new = '''        if (want && R(AIF(2) + 0x20)) {
            static const char *list;
            static int idx;
            const char *p2;
            unsigned tgt;
            if (!list) {
                list = getenv("REA_FB_VSYNC");
                if (!list) {
                    list = "300";
                }
            }
            p2 = list;
            tgt = 0;
            for (int k = 0; k <= idx; k++) {
                tgt = (unsigned)atoi(p2);
                {
                    const char *c = strchr(p2, ',');
                    if (!c) {
                        break;
                    }
                    p2 = c + 1;
                }
            }
            if (rea_n >= tgt && tgt) {
                char path[512];
                snprintf(path, sizeof(path), "%s.%d.ppm", want, idx);
                rea_fb_dump(R(AIF(2) + 0x20), R(AIF(2) + 0x24),
                            R(AIF(2) + 0x2C) + 1, path);
                idx++;
                if (!strchr(p2, ',')) {
                    /* nothing more */
                }
            }
        }'''

if 'rea_fb_dump(R(AIF(2) + 0x20), R(AIF(2) + 0x24),\n                            R(AIF(2) + 0x2C) + 1, path)' in s:
    print('already patched')
else:
    assert old in s, 'anchor missing'
    s = s.replace(old, new, 1)
    # make rea_fb_dump take an explicit path
    s = s.replace('static void rea_fb_dump(uint32_t base, uint32_t lb, uint32_t lines)\n{\n    const char *path = getenv("REA_FB_PATH");',
                  'static void rea_fb_dump(uint32_t base, uint32_t lb, uint32_t lines, const char *path)\n{', 1)
    p.write_text(s)
    print('patched multi-dump')
