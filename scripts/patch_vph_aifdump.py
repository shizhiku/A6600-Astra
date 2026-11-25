"""Dump all VPH AIF channels once (base/ctrl/line bytes/lines) at a chosen vsync."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/misc/cxd90014_vph.c')
s = p.read_text()
anchor = '    {\n        static unsigned rea_n;'
if 'REA_DUMP_AIF' in s:
    print('already patched')
else:
    assert anchor in s, 'anchor missing'
    block = '''    {
        static int rea_aif_done;
        const char *wa = getenv("REA_DUMP_AIF");
        if (wa && !rea_aif_done) {
            static unsigned rea_aif_at;
            static int rea_aif_init;
            static unsigned rea_tick;
            if (!rea_aif_init) {
                rea_aif_at = (unsigned)atoi(wa);
                rea_aif_init = 1;
            }
            rea_tick++;
            if (rea_tick >= rea_aif_at) {
                rea_aif_done = 1;
                for (int k = 0; k < 8; k++) {
                    fprintf(stderr,
                            "[AIF] ch%d ctrl=0x%08x base=0x%08x lb=0x%x "
                            "skip=0x%x lines=%u\\n",
                            k, R(AIF(k)), R(AIF(k) + 0x20),
                            R(AIF(k) + 0x24), R(AIF(k) + 0x28),
                            R(AIF(k) + 0x2C) + 1);
                }
                fprintf(stderr, "[AIF] en144=0x%08x\\n", R(0x144));
            }
        }
    }
''' + anchor
    s = s.replace(anchor, block, 1)
    p.write_text(s)
    print('patched aif dump')
