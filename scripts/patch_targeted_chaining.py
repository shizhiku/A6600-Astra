"""Disable TB chaining only for the TB that starts at REA_BP_VA."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/translate-all.c')
s = p.read_text()

old = """    /* REA_BP disable chaining so the VA hook observes every TB */
    if (getenv("REA_BP_VA")) {
        s.cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR;
    }
"""
new = """    /* REA_BP: only the TB that starts exactly at the watched VA loses
     * chaining, so the VA hook observes it without slowing the whole VM. */
    {
        static int rea_ready;
        static unsigned long long rea_target;
        if (!rea_ready) {
            const char *e = getenv("REA_BP_VA");
            rea_target = e ? strtoull(e, NULL, 0) : 0;
            rea_ready = 1;
        }
        if (rea_target && (unsigned long long)s.pc == rea_target) {
            s.cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR;
        }
    }
"""
if new in s:
    print('already patched')
elif old in s:
    s = s.replace(old, new)
    p.write_text(s)
    print('patched targeted chaining disable')
else:
    print('anchor not found')
