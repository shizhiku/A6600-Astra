"""Add REA_ADC_HOLD=1 to keep the injected ADC level asserted after T0."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()

anchor = '    if (chosen_ch >= 0 && phase < 1500) {'
new = '''    if (getenv("REA_ADC_HOLD")) {
        static int hold_done;
        chosen_ch = -1;
        {
            /* single entry form: "ch:level" held forever after T0 */
            int ch = 0, lvl = 0;
            char b2[64];
            g_strlcpy(b2, v, sizeof(b2));
            if (sscanf(b2, "%d:%d", &ch, &lvl) == 2) {
                if (!hold_done) {
                    cxd90014_adc_set(sony_a6400_rear_adc, ch, lvl);
                    hold_done = 1;
                    fprintf(stderr, "[ADCINJ] HOLD ch%d level %d at %lld ms\\n",
                            ch, lvl, (long long)t);
                }
            }
        }
        return;
    }
    if (chosen_ch >= 0 && phase < 1500) {'''

if 'REA_ADC_HOLD' in s:
    print('already patched')
else:
    assert anchor in s, 'anchor missing'
    s = s.replace(anchor, new, 1)
    p.write_text(s)
    print('hold mode added')
