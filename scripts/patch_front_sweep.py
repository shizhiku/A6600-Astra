"""Extend the front-button injector to sweep a list of bitmasks on a schedule."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()

start = s.index('static void sony_a6400_front_inject(void)\n{')
end = s.index('\n}\n', start) + 3
new_fn = '''static void sony_a6400_front_inject(void)
{
    const char *v = getenv("REA_FRONT_BTN");
    const char *t0s = getenv("REA_FRONT_T0");
    int64_t t = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000;
    int64_t t0 = t0s ? g_ascii_strtoll(t0s, NULL, 0) : 20000;
    int64_t slot = (t - t0) / 5000;             /* 5 s per candidate */
    int64_t phase = (t - t0) % 5000;
    char buf[128];
    char *tok, *save = NULL;
    unsigned idx = 0, chosen = 0, want;
    bool pressed = false;

    if (!v || t < t0) {
        return;
    }
    g_strlcpy(buf, v, sizeof(buf));
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        unsigned bits = (unsigned)g_ascii_strtoull(tok, NULL, 0);
        if ((int64_t)idx == slot) {
            chosen = bits;
            want = idx;
            pressed = phase < 1500;
            (void)want;
        }
        idx++;
    }
    if (pressed) {
        if (sony_a6400_front_pressed != (uint16_t)chosen) {
            sony_a6400_front_pressed = (uint16_t)chosen;
            fprintf(stderr, "[KEYINJ] press 0x%04x slot %u at %lld ms\\n",
                    chosen, (unsigned)slot, (long long)t);
        }
    } else if (sony_a6400_front_pressed) {
        sony_a6400_front_pressed = 0;
        fprintf(stderr, "[KEYINJ] release at %lld ms\\n", (long long)t);
    }
}
'''
s = s[:start] + new_fn + s[end:]
p.write_text(s)
print('sweep injector installed')
