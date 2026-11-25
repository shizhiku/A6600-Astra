from pathlib import Path
p = Path('04-产物/98_trap_preload.c')
s = p.read_text()
s = s.replace('#define TRAP_OFF  0x2BBA91AUL', '#define TRAP_OFF  0x2BBA4ECUL')
start = s.index('    if (trap_armed && (pc & ~1UL) == trap_va) {')
end = s.index('    snprintf(b, sizeof(b),\n             "[CRASHTRACE] sig=%d')
new = r'''    if (trap_armed && (pc & ~1UL) == trap_va) {
        unsigned short *p = (unsigned short *)trap_va;
        unsigned long r7 = sc[10];
        int k;
        snprintf(b, sizeof(b),
                 "[MSGDUMP] hit r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx "
                 "r7=0x%08lx lr=0x%08lx",
                 r0, r1, r2, r3, r7, lr);
        logline(b);
        if (r7 >= 0x1000UL && r7 < 0x40000000UL) {
            unsigned long sp2 = *(unsigned long *)(r7 + 0x34);
            snprintf(b, sizeof(b), "[MSGDUMP] msg_ptr=0x%08lx", sp2);
            logline(b);
            if (sp2 >= 0x1000UL && sp2 < 0x40000000UL) {
                unsigned long *q = (unsigned long *)sp2;
                for (k = 0; k < 12; k++) {
                    snprintf(b, sizeof(b), "[MSGDUMP]   msg[%02x]=0x%08lx",
                             k * 4, q[k]);
                    logline(b);
                }
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
