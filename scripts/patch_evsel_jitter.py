"""Add optional timing jitter to the evsel frame timer in the local QEMU tree."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/misc/cxd90014_evsel.c')
s = p.read_text()

helper = '''
/* Optional deterministic-jitter injection for phase experiments.
 * REA_EVSEL_JITTER_US=0 (default) keeps the stock timing exactly.
 */
static uint32_t evsel_jitter_seed = 0x12345678u;
static int evsel_jitter_us(void)
{
    const char *e = getenv("REA_EVSEL_JITTER_US");
    int j = e ? atoi(e) : 0;
    if (j <= 0) {
        return 0;
    }
    evsel_jitter_seed = evsel_jitter_seed * 1103515245u + 12345u;
    return (int)((evsel_jitter_seed >> 16) % (2u * (uint32_t)j + 1u)) - j;
}

'''

anchor = 'static void ev_vd(void *opaque)'
assert anchor in s
s = s.replace(anchor, helper + anchor, 1)

old1 = """    timer_mod(s->vd, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              FRAME_US * SCALE_US);
}"""
new1 = """    timer_mod(s->vd, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              (FRAME_US + evsel_jitter_us()) * SCALE_US);
}"""
assert old1 in s
s = s.replace(old1, new1, 1)

old2 = """        timer_mod(s->vd, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  FRAME_US * SCALE_US);"""
new2 = """        timer_mod(s->vd, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  (FRAME_US + evsel_jitter_us()) * SCALE_US);"""
assert old2 in s
s = s.replace(old2, new2, 1)

p.write_text(s)
print('patched evsel jitter')
