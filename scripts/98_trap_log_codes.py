from pathlib import Path
p = Path('04-产物/98_trap_preload.c')
s = p.read_text()
old = '''        snprintf(b, sizeof(b),
                 "[ENTRYTRAP] hit r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx "
                 "sp=0x%08lx lr=0x%08lx",
                 r0, r1, r2, r3, sp, lr);
        logline(b);'''
new = '''        {
            unsigned long r6 = sc[9], r10 = sc[13], r7 = sc[10];
            snprintf(b, sizeof(b),
                     "[ENTRYTRAP] hit r6=0x%08lx sl=0x%08lx r7=0x%08lx "
                     "r0=0x%08lx r1=0x%08lx sp=0x%08lx lr=0x%08lx",
                     r6, r10, r7, r0, r1, sp, lr);
            logline(b);
            if (r7 >= 0x1000UL && r7 < 0x40000000UL) {
                unsigned long sp2 = *(unsigned long *)(r7 + 0x34);
                snprintf(b, sizeof(b),
                         "[ENTRYTRAP]   r7[+0x34]=0x%08lx", sp2);
                logline(b);
                if (sp2 >= 0x1000UL && sp2 < 0x40000000UL) {
                    int k;
                    unsigned long *q = (unsigned long *)sp2;
                    for (k = 0; k < 8; k++) {
                        snprintf(b, sizeof(b),
                                 "[ENTRYTRAP]   msg[%d]=0x%08lx", k, q[k]);
                        logline(b);
                    }
                }
            }
        }'''
assert old in s
s = s.replace(old, new, 1)
p.write_text(s)
print('patched')
