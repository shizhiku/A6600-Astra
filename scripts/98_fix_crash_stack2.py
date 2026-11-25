from pathlib import Path
p = Path('04-产物/98_crash_trace_preload.c')
s = p.read_text()
start = s.index('static void crash_handler')
end = s.index('static void install_handlers')
new = r'''static unsigned long parse_hex8(const char *p)
{
    unsigned long v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned long)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned long)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned long)(c - 'A' + 10);
        else break;
    }
    return v;
}

static void crash_handler(int sig, siginfo_t *si, void *ucv)
{
    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);
    unsigned long sp = sc[16], lr = sc[17], pc = sc[18];
    unsigned long *st = (unsigned long *)sp;
    unsigned long fw_base = 0;
    char b[256], line[256];
    FILE *f, *m;
    int i;
    (void)si;
    snprintf(b, sizeof(b), "[CRASHTRACE] sig=%d pc=0x%08lx lr=0x%08lx sp=0x%08lx",
             sig, pc, lr, sp);
    logline(b);
    m = fopen("/proc/self/maps", "r");
    if (m) {
        while (fgets(line, sizeof(line), m)) {
            if (strstr(line, "a5pFw.so") && strstr(line, "rwx")) {
                fw_base = parse_hex8(line);
                break;
            }
        }
        fclose(m);
    }
    f = fopen("/dev/console", "w");
    if (!f) { _exit(0); }
    fprintf(f, "[CRASHTRACE] a5pFw_base=0x%08lx\n", fw_base);
    if (fw_base) {
        unsigned long lo = fw_base + 0x52ab00UL;
        unsigned long hi = fw_base + 0x2ce8ac8UL;
        for (i = 0; i < 512; i++) {
            unsigned long v = st[i];
            if (v >= lo && v < hi) {
                fprintf(f, "[CRASHTRACE] FWRA st[%02d]=0x%08lx off=0x%lx\n",
                        i, v, v - fw_base);
            }
        }
        for (i = 0; i < 512; i++) {
            unsigned long v = st[i];
            if (v >= fw_base && v < fw_base + 0x343f000UL &&
                !(v >= lo && v < hi)) {
                fprintf(f, "[CRASHTRACE] FWDATA st[%02d]=0x%08lx off=0x%lx\n",
                        i, v, v - fw_base);
            }
        }
    }
    fclose(f);
    _exit(0);
}

'''
s = s[:start] + new + s[end:]
p.write_text(s)
print('patched')
