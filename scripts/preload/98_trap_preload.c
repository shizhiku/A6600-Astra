/* Emulator-only instrumentation for the ASTRA bring-up.
 *
 * 1) interposes pthread_attr_init -> 6 MiB stacks (5th-gen init frame ~3.4 MiB)
 * 2) after /usr/lib/a5pFw.so is mapped, patches the entry of the model-status
 *    dispatcher (file offset 0x2BBA4CC) with a Thumb UDF and logs the incoming
 *    r0..r3 when SIGILL fires, then restores the original halfword and resumes
 *    at the function entry.
 * 3) any other fatal signal logs registers and exits the process.
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
#define TRAP_OFF  0x2BBA4ECUL

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

static volatile unsigned long trap_va;
static volatile unsigned short trap_orig;
static volatile int trap_armed;

static void *trap_thread(void *arg)
{
    int i;
    (void)arg;
    for (i = 0; i < 1200; i++) {
        FILE *m = fopen("/proc/self/maps", "r");
        if (m) {
            char line[256];
            while (fgets(line, sizeof(line), m)) {
                if (strstr(line, "a5pFw.so") &&
                    (strstr(line, "rwx") || strstr(line, "r-x"))) {
                    unsigned long base = parse_hex8(line);
                    unsigned long va = base + TRAP_OFF;
                    unsigned short *p = (unsigned short *)va;
                    trap_orig = *p;
                    *p = 0xDE00;      /* Thumb UDF #0 */
                    __builtin___clear_cache((char *)p, (char *)p + 2);
                    trap_va = va;
                    trap_armed = 1;
                    {
                        char b[128];
                        snprintf(b, sizeof(b),
                                 "[ENTRYTRAP] patched 0x%08lx orig=0x%04x",
                                 va, trap_orig);
                        logline(b);
                    }
                    fclose(m);
                    return NULL;
                }
            }
            fclose(m);
        }
        usleep(5000);
    }
    logline("[ENTRYTRAP] a5pFw mapping not found");
    return NULL;
}

static void crash_handler(int sig, siginfo_t *si, void *ucv)
{
    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);
    unsigned long r0 = sc[3], r1 = sc[4], r2 = sc[5], r3 = sc[6];
    unsigned long sp = sc[16], lr = sc[17], pc = sc[18];
    char b[256];
    (void)si;

    if (trap_armed && (pc & ~1UL) == trap_va) {
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
    snprintf(b, sizeof(b),
             "[CRASHTRACE] sig=%d pc=0x%08lx lr=0x%08lx sp=0x%08lx "
             "r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx",
             sig, pc, lr, sp, r0, r1, r2, r3);
    logline(b);
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
    pthread_t th;
    resolve();
    install_handlers();
    if (pthread_create(&th, NULL, trap_thread, NULL) == 0)
        pthread_detach(th);
}
