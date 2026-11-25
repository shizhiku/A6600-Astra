from pathlib import Path
p = Path('04-产物/98_trap_preload.c')
s = p.read_text()
s = s.replace('#define TRAP_OFF  0x2BBA52CUL', '#define TRAP_OFF  0x2BBA8F0UL')
start = s.index('    if (trap_armed && (pc & ~1UL) == trap_va) {')
end = s.index('    snprintf(b, sizeof(b),\n             "[CRASHTRACE] sig=%d')
new = r'''    if (trap_armed && (pc & ~1UL) == trap_va) {
        unsigned short *p = (unsigned short *)trap_va;
        unsigned long r4 = sc[7], r5 = sc[8], r6 = sc[9], r7 = sc[10];
        unsigned long r8 = sc[11], sb = sc[12], sl = sc[13], fp = sc[14];
        int k;
        snprintf(b, sizeof(b),
                 "[ENTRYTRAP] hit r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx "
                 "r4=0x%08lx r5=0x%08lx r6=0x%08lx r7=0x%08lx",
                 r0, r1, r2, r3, r4, r5, r6, r7);
        logline(b);
        snprintf(b, sizeof(b),
                 "[ENTRYTRAP]   r8=0x%08lx sb=0x%08lx sl=0x%08lx fp=0x%08lx "
                 "sp=0x%08lx lr=0x%08lx",
                 r8, sb, sl, fp, sp, lr);
        logline(b);
        if (r7 >= 0x1000UL && r7 < 0x40000000UL) {
            unsigned long *q = (unsigned long *)r7;
            for (k = 0; k < 16; k++) {
                snprintf(b, sizeof(b), "[ENTRYTRAP]   r7[%02d]=0x%08lx",
                         k, q[k]);
                logline(b);
            }
        }
        *p = trap_orig;
        __builtin___clear_cache((char *)p, (char *)p + 2);
        trap_armed = 0;
        sc[18] = trap_va;
        return;
    }
'''
s = s[:start] + new + s[end:]
p.write_text(s)
print('patched')
