"""Offline patch: add a runtime control FIFO and live framebuffer dump to the
QEMU sony-a6400 model used by this workspace. Idempotent; keeps .bak files.
Run in WSL: python3 98_patch_qemu_interactive.py
"""
from pathlib import Path
import sys
SRC=Path('/root/qemu-11.1.3')
ARM=SRC/'hw/arm/sony_a6400.c';VPH=SRC/'hw/misc/cxd90014_vph.c'
def patch(p,edits):
    t=p.read_text()
    if '.bak-interactive' not in t and not Path(str(p)+'.bak-interactive').exists():
        Path(str(p)+'.bak-interactive').write_text(t)
    for old,new in edits:
        if new in t:
            print('already:',p.name,old[:40].replace('\n','\\n'))
            continue
        if old not in t:
            raise SystemExit('anchor not found in %s: %r'%(p,old[:80]))
        t=t.replace(old,new,1)
    p.write_text(t)
    print('patched',p)
CTL_FN=r'''
/* REA: interactive control FIFO.  Commands: m=front MENU, e=ADC ENTER,
 * 1..5 = selector unit1/ch4 levels, 6..0 = unit1/ch5 levels. */
static int sony_rea_ctl_fd = -1;
static int64_t sony_rea_front_until;
static int64_t sony_rea_adc_until;
static int sony_rea_adc_ch = -1;

static void sony_a6400_rea_ctl(void)
{
    const char *p = getenv("REA_CTL_FIFO");
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000;
    char buf[64];
    ssize_t n;
    int i;

    if (!p || !*p) {
        return;
    }
    if (sony_rea_ctl_fd < 0) {
        sony_rea_ctl_fd = open(p, O_RDONLY | O_NONBLOCK);
        if (sony_rea_ctl_fd < 0) {
            return;
        }
    }
    n = read(sony_rea_ctl_fd, buf, sizeof(buf));
    for (i = 0; i < n; i++) {
        char c = buf[i];
        if (c == 'm') {
            sony_a6400_front_pressed |= 4;      /* front bit2 = MENU */
            sony_rea_front_until = now + 1200;
            fprintf(stderr, "[CTL] MENU press\n");
        } else if (c == 'e') {
            if (sony_a6400_rear_adc) {
                cxd90014_adc_set(sony_a6400_rear_adc, 3, 32);
                sony_rea_adc_ch = 3;
                sony_rea_adc_until = now + 1200;
            }
            fprintf(stderr, "[CTL] ENTER press\n");
        } else if (c >= '1' && c <= '5') {
            static const int lv[5] = {0x00, 0x5b, 0x112, 0x1b7, 0x258};
            if (sony_a6400_rear_adc) {
                cxd90014_adc_set(sony_a6400_rear_adc, 4, lv[c - '1']);
                sony_rea_adc_ch = 4;
                sony_rea_adc_until = now + 1200;
            }
            fprintf(stderr, "[CTL] SEL1-%c\n", c);
        } else if ((c >= '6' && c <= '9') || c == '0') {
            static const int lv[5] = {0x00, 0x5b, 0x112, 0x1b7, 0x258};
            int k = (c == '0') ? 4 : (c - '6');
            if (sony_a6400_rear_adc) {
                cxd90014_adc_set(sony_a6400_rear_adc, 5, lv[k]);
                sony_rea_adc_ch = 5;
                sony_rea_adc_until = now + 1200;
            }
            fprintf(stderr, "[CTL] SEL2-%c\n", c);
        }
    }
    if (sony_rea_front_until && now >= sony_rea_front_until) {
        sony_a6400_front_pressed &= ~4;
        sony_rea_front_until = 0;
    }
    if (sony_rea_adc_until && now >= sony_rea_adc_until) {
        if (sony_a6400_rear_adc && sony_rea_adc_ch >= 0) {
            cxd90014_adc_set(sony_a6400_rear_adc, sony_rea_adc_ch, 1023);
        }
        sony_rea_adc_until = 0;
        sony_rea_adc_ch = -1;
    }
}
'''
patch(ARM,[
 ('#include "ui/input.h"\n','#include "ui/input.h"\n#include <fcntl.h>\n#include <unistd.h>\n'),
 ('static void sony_a6400_front_inject(void);\nstatic void sony_a6400_adc_inject(void);\n',
  'static void sony_a6400_front_inject(void);\nstatic void sony_a6400_adc_inject(void);\nstatic void sony_a6400_rea_ctl(void);\n'),
 ('static void sony_a6400_submicro_tick(void *opaque)\n{\n    sony_a6400_front_inject();',
  'static void sony_a6400_submicro_tick(void *opaque)\n{\n    sony_a6400_rea_ctl();\n    sony_a6400_front_inject();'),
 ('static uint64_t sony_a6400_wheel_read(void *opaque, hwaddr offset, unsigned size)',
  CTL_FN+'\nstatic uint64_t sony_a6400_wheel_read(void *opaque, hwaddr offset, unsigned size)'),
])
patch(VPH,[
 ('            tidx++;\n        }\n    }\n    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);',
  '            tidx++;\n        }\n    }\n    {\n        const char *live = getenv("REA_FB_LIVE");\n        static unsigned liven;\n        if (live && R(AIF(2) + 0x20)) {\n            liven++;\n            if ((liven % 30) == 0) {\n                rea_fb_dump(R(AIF(2) + 0x20), R(AIF(2) + 0x24),\n                            R(AIF(2) + 0x2C) + 1, live);\n            }\n        }\n    }\n    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);'),
])
print('done')
