"""Inject a front-panel button press on a virtual-time schedule (REA_FRONT_BTN)."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()

if 'REA_FRONT_BTN' in s:
    print('already patched')
else:
    anchor = """static void sony_a6400_submicro_tick(void *opaque)
{"""
    inject = """static void sony_a6400_front_inject(void)
{
    const char *v = getenv("REA_FRONT_BTN");
    const char *t0s = getenv("REA_FRONT_T0");
    const char *t1s = getenv("REA_FRONT_T1");
    int64_t t = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000;
    int64_t t0 = t0s ? g_ascii_strtoll(t0s, NULL, 0) : 20000;
    int64_t t1 = t1s ? g_ascii_strtoll(t1s, NULL, 0) : 22000;
    unsigned bits;

    if (!v) {
        return;
    }
    bits = (unsigned)g_ascii_strtoull(v, NULL, 0);
    if (t >= t0 && t < t1) {
        if (sony_a6400_front_pressed != (uint16_t)bits) {
            sony_a6400_front_pressed = (uint16_t)bits;
            fprintf(stderr, "[KEYINJ] front_pressed=0x%04x at %lld ms\\n",
                    bits, (long long)t);
        }
    } else if (sony_a6400_front_pressed) {
        sony_a6400_front_pressed = 0;
        fprintf(stderr, "[KEYINJ] front released at %lld ms\\n", (long long)t);
    }
}

""" + anchor
    assert anchor in s, 'anchor missing'
    s = s.replace(anchor, inject, 1)

    old_tick = """    qemu_set_irq(qdev_get_gpio_in(sony_a6400_gpio, CXD90045_SM_REQ_LINE), 0);"""
    assert old_tick in s
    s = s.replace(old_tick, """    sony_a6400_front_inject();
""" + old_tick, 1)
    p.write_text(s)
    print('patched front button injector')
