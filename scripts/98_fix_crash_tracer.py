from pathlib import Path
p = Path('04-产物/98_crash_trace_preload.c')
s = p.read_text()
s = s.replace('#include <ucontext.h>\n', '')
start = s.index('static void crash_handler')
end = s.index('static void install_handlers')
new = r'''static void crash_handler(int sig, siginfo_t *si, void *ucv)
{
    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);
    unsigned long r0 = sc[0], r1 = sc[1], r2 = sc[2], r3 = sc[3];
    unsigned long fp = sc[11], ip = sc[12], sp = sc[13];
    unsigned long lr = sc[14], pc = sc[15];
    char b[256];
    int i;
    (void)si;
    (void)ip;
    snprintf(b, sizeof(b),
             "[CRASHTRACE] sig=%d pc=0x%08lx lr=0x%08lx sp=0x%08lx fp=0x%08lx "
             "r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx",
             sig, pc, lr, sp, fp, r0, r1, r2, r3);
    logline(b);
    for (i = 0; i < 12 && fp; i++) {
        unsigned long *p = (unsigned long *)fp;
        unsigned long nfp = p[0], ra = p[1];
        snprintf(b, sizeof(b), "[CRASHTRACE]   frame%d fp=0x%08lx ra=0x%08lx",
                 i, fp, ra);
        logline(b);
        if (nfp <= fp || (nfp & 3)) break;
        fp = nfp;
    }
    _exit(0);
}

'''
s = s[:start] + new + s[end:]
p.write_text(s)
print('patched')
