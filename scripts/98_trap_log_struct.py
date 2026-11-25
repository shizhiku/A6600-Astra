from pathlib import Path
p = Path('04-产物/98_trap_preload.c')
s = p.read_text()
old = '''        snprintf(b, sizeof(b),
                 "[ENTRYTRAP] hit r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx "
                 "sp=0x%08lx lr=0x%08lx",
                 r0, r1, r2, r3, sp, lr);
        logline(b);'''
new = '''        snprintf(b, sizeof(b),
                 "[ENTRYTRAP] hit r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx "
                 "sp=0x%08lx lr=0x%08lx",
                 r0, r1, r2, r3, sp, lr);
        logline(b);
        if (r1 >= 0x1000UL && r1 < 0x40000000UL) {
            unsigned long *q = (unsigned long *)r1;
            int k;
            for (k = 0; k < 8; k++) {
                snprintf(b, sizeof(b),
                         "[ENTRYTRAP]   msg[%d]=0x%08lx", k, q[k]);
                logline(b);
            }
        }'''
assert old in s
s = s.replace(old, new, 1)
p.write_text(s)
print('patched')
