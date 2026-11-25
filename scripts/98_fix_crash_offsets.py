from pathlib import Path
p = Path('04-产物/98_crash_trace_preload.c')
s = p.read_text()
start = s.index('static void crash_handler')
end = s.index('static void install_handlers')
new = r'''static void crash_handler(int sig, siginfo_t *si, void *ucv)
{
    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);
    unsigned long r0 = sc[3], r1 = sc[4], r2 = sc[5], r3 = sc[6];
    unsigned long r7 = sc[10];
    unsigned long fp = sc[14], ip = sc[15], sp = sc[16];
    unsigned long lr = sc[17], pc = sc[18];
    unsigned long *st = (unsigned long *)sp;
    char b[256];
    int i;
    FILE *f;
    (void)si;
    (void)ip;
    (void)r7;
    snprintf(b, sizeof(b),
             "[CRASHTRACE] sig=%d pc=0x%08lx lr=0x%08lx sp=0x%08lx fp=0x%08lx "
             "r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx",
             sig, pc, lr, sp, fp, r0, r1, r2, r3);
    logline(b);
    f = fopen("/dev/console", "w");
    if (f) {
        FILE *m = fopen("/proc/self/maps", "r");
        char line[256];
        if (m) {
            while (fgets(line, sizeof(line), m)) {
                if (strstr(line, "a5pFw") || strstr(line, "a5pFwBoot") ||
                    strstr(line, "libObj") || strstr(line, "im.elf")) {
                    fprintf(f, "[CRASHTRACE] map %s", line);
                }
            }
            fclose(m);
        }
        for (i = 0; i < 64; i++) {
            fprintf(f, "[CRASHTRACE] st[%02d]=0x%08lx\n", i, st[i]);
        }
        fclose(f);
    }
    _exit(0);
}

'''
s = s[:start] + new + s[end:]
p.write_text(s)
print('patched')
