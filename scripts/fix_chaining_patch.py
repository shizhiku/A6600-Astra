"""Fix the chaining-disable patch to use s.cflags."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/translate-all.c')
s = p.read_text()
bad = """    /* REA_BP disable chaining so the VA hook observes every TB */
    if (getenv("REA_BP_VA")) {
        cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR;
    }
"""
good = """    /* REA_BP disable chaining so the VA hook observes every TB */
    if (getenv("REA_BP_VA")) {
        s.cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR;
    }
"""
if bad in s:
    s = s.replace(bad, good)
    p.write_text(s)
    print('fixed to s.cflags')
elif good in s:
    print('already correct')
else:
    print('pattern not found')
