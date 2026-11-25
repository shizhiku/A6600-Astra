"""Add an ADC key injector (REA_ADC_SEQ) that sweeps rear-control ADC levels."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()

if 'REA_ADC_SEQ' in s:
    print('already patched')
else:
    anchor = 'static uint16_t sony_a6400_wheel_count;'
    assert anchor in s, 'state var anchor missing'
    fn = anchor + '''

/* REA_ADC_SEQ="ch:level,ch:level,..." sweeps rear-control ADC keys, 5 s each. */
static void sony_a6400_adc_inject(void)
{
    const char *v = getenv("REA_ADC_SEQ");
    const char *t0s = getenv("REA_ADC_T0");
    int64_t t = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000;
    int64_t t0 = t0s ? g_ascii_strtoll(t0s, NULL, 0) : 20000;
    int64_t slot = (t - t0) / 5000;
    int64_t phase = (t - t0) % 5000;
    char buf[128];
    char *tok, *save = NULL;
    unsigned idx = 0;
    int chosen_ch = -1, chosen_lvl = 0;

    if (!v || t < t0 || !sony_a6400_rear_adc) {
        return;
    }
    g_strlcpy(buf, v, sizeof(buf));
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        int ch = 0, lvl = 0;
        if (sscanf(tok, "%d:%d", &ch, &lvl) == 2 && (int64_t)idx == slot) {
            chosen_ch = ch;
            chosen_lvl = lvl;
        }
        idx++;
    }
    if (chosen_ch >= 0 && phase < 1500) {
        static int cur_ch = -1, cur_lvl = -1;
        if (cur_ch != chosen_ch || cur_lvl != chosen_lvl) {
            cxd90014_adc_set(sony_a6400_rear_adc, chosen_ch, chosen_lvl);
            cur_ch = chosen_ch;
            cur_lvl = chosen_lvl;
            fprintf(stderr, "[ADCINJ] ch%d level %d slot %u at %lld ms\\n",
                    chosen_ch, chosen_lvl, (unsigned)slot, (long long)t);
        }
    } else {
        static int released;
        if (!released) {
            if (sony_a6400_rear_adc) {
                cxd90014_adc_set(sony_a6400_rear_adc, 0, 1023);
                cxd90014_adc_set(sony_a6400_rear_adc, 3, 1023);
            }
            released = 1;
        }
    }
}
'''
    s = s.replace(anchor, fn, 1)

    tick_anchor = '    sony_a6400_front_inject();'
    assert tick_anchor in s
    s = s.replace(tick_anchor, tick_anchor + '\n    sony_a6400_adc_inject();', 1)

    decl_anchor = 'static void sony_a6400_front_inject(void);'
    s = s.replace(decl_anchor, decl_anchor + '\nstatic void sony_a6400_adc_inject(void);', 1)
    p.write_text(s)
    print('patched adc injector')
