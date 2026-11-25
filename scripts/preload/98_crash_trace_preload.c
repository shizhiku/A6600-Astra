/* Emulator-only crash tracer for the ASTRA bring-up.
 *
 * - interposes pthread_attr_init to enlarge thread stacks to 6 MiB
 *   (the 5th-gen init frame is ~3.4 MiB; the 4th-gen libc default is 2 MiB)
 * - installs SIGILL/SIGABRT/SIGSEGV handlers that log registers, LR/PC and a
 *   frame-pointer walk to /dev/console, then _exit() the process so the
 *   guest stays alive for shell inspection.
 * GLIBC_2.4-only symbols.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define MIN_STACK (6UL * 1024 * 1024)

extern int real_attr_init_sym(pthread_attr_t *);
extern int real_setstacksize_sym(pthread_attr_t *, size_t);
extern int real_getstacksize_sym(const pthread_attr_t *, size_t *);
extern void *real_dlvsym_sym(void *, const char *, const char *);
__asm__(".symver real_attr_init_sym,pthread_attr_init@GLIBC_2.4");
__asm__(".symver real_setstacksize_sym,pthread_attr_setstacksize@GLIBC_2.4");
__asm__(".symver real_getstacksize_sym,pthread_attr_getstacksize@GLIBC_2.4");
__asm__(".symver real_dlvsym_sym,dlvsym@GLIBC_2.4");

static int (*real_init)(pthread_attr_t *);
static int (*real_set)(pthread_attr_t *, size_t);
static int (*real_get)(const pthread_attr_t *, size_t *);

static void resolve(void)
{
    if (real_init) return;
    real_init = (int (*)(pthread_attr_t *))
        real_dlvsym_sym(RTLD_NEXT, "pthread_attr_init", "GLIBC_2.4");
    real_set = (int (*)(pthread_attr_t *, size_t))
        real_dlvsym_sym(RTLD_NEXT, "pthread_attr_setstacksize", "GLIBC_2.4");
    real_get = (int (*)(const pthread_attr_t *, size_t *))
        real_dlvsym_sym(RTLD_NEXT, "pthread_attr_getstacksize", "GLIBC_2.4");
    if (!real_init) real_init = real_attr_init_sym;
    if (!real_set) real_set = real_setstacksize_sym;
    if (!real_get) real_get = real_getstacksize_sym;
}

int pthread_attr_init(pthread_attr_t *a)
{
    int rc;
    size_t sz = 0;
    resolve();
    if (!real_init) return -1;
    rc = real_init(a);
    if (rc) return rc;
    if (real_get && real_set) {
        real_get(a, &sz);
        if (sz < MIN_STACK) real_set(a, MIN_STACK);
    }
    return 0;
}

static void logline(const char *s)
{
    FILE *f = fopen("/dev/console", "w");
    if (f) { fputs(s, f); fputc('\n', f); fclose(f); }
}

static unsigned long parse_hex8(const char *p)
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

static void install_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}

__attribute__((constructor)) static void init(void)
{
    resolve();
    install_handlers();
}
