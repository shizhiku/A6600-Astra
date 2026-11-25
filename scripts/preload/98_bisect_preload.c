/* Emulator-only bisection probe over 0x54F664's resume points.

All these are the instruction AFTER a call in 0x54F664. Hitting point k means
calls 0..#k  returned.  We arm MANY at once (each independent) and see which is
the highest one that fires -- that pinpoints the first non-returning call.
*/
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

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

#define N 12
static const unsigned long offs[N] = {
    0x54F690, 0x54F6A0, 0x54F6AA, 0x54F6B4, 0x54F6C2, 0x54F6D2,
    0x54F6E6, 0x54F716, 0x54F72E, 0x54F752, 0x54F760, 0x54F76C
};
static const char *labels[N] = {
    "01_54F690", "02_54F6A0", "03_54F6AA", "04_54F6B4", "05_54F6C2",
    "06_54F6D2", "07_54F6E6", "08_54F716", "09_54F72E", "10_54F752",
    "11_54F760", "12_54F76C"
};

static volatile unsigned long addrs[N];
static volatile unsigned short origs[N];
static volatile int armed[N];
static volatile int hits[N];
static volatile unsigned long cnts[N];

static void *thread(void *arg)
{
    int i;
    (void)arg;
    for (i = 0; i < 2400; i++) {
        void *fw = dlopen("/usr/lib/a5pFw.so", RTLD_LAZY | RTLD_NOLOAD);
        if (fw) {
            Dl_info info;
            void *sym = dlsym(fw, "Application_Start");
            if (sym && dladdr(sym, &info) && info.dli_fbase) {
                unsigned long base = (unsigned long)info.dli_fbase;
                int k;
                for (k = 0; k < N; k++) {
                    unsigned short *p;
                    unsigned long pg;
                    void *pa;
                    addrs[k] = base + offs[k];
                    origs[k] = *(unsigned short *)addrs[k];
                    p = (unsigned short *)addrs[k];
                    pg = (unsigned long)sysconf(_SC_PAGESIZE);
                    pa = (void *)((unsigned long)p & ~(pg - 1));
                    mprotect(pa, pg * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
                    *p = 0xDE00;
                    __builtin___clear_cache((char *)p, (char *)p + 2);
                    armed[k] = 1;
                }
                logline("[BISECT] armed 12 resume points");
                break;
            }
        }
        usleep(50000);
    }
    for (;;) {
        int k;
        for (k = 0; k < N; k++) {
            if (hits[k]) {
                usleep(15000);
                if (addrs[k]) {
                    unsigned short *p = (unsigned short *)addrs[k];
                    *p = 0xDE00;
                    __builtin___clear_cache((char *)p, (char *)p + 2);
                    armed[k] = 1;
                }
                hits[k] = 0;
            }
        }
        usleep(1500);
    }
    return NULL;
}

static void handler(int sig, siginfo_t *si, void *ucv)
{
    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);
    unsigned long pc = sc[18], lr = sc[17];
    int k;
    char b[160];
    (void)si;
    for (k = 0; k < N; k++) {
        if (armed[k] && (pc & ~1UL) == (addrs[k] & ~1UL)) {
            unsigned short *p = (unsigned short *)addrs[k];
            cnts[k]++;
            if (cnts[k] <= 2) {
                snprintf(b, sizeof(b), "[BISECT] HIT %s #%lu lr=0x%08lx",
                         labels[k], cnts[k], lr);
                logline(b);
            }
            *p = origs[k];
            __builtin___clear_cache((char *)p, (char *)p + 2);
            armed[k] = 0;
            hits[k] = 1;
            sc[18] = addrs[k];
            return;
        }
    }
    snprintf(b, sizeof(b), "[BISECT] fatal sig=%d pc=0x%08lx lr=0x%08lx",
             sig, pc, lr);
    logline(b);
    _exit(0);
}

__attribute__((constructor)) static void init(void)
{
    pthread_t th;
    struct sigaction sa;
    resolve();
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    if (pthread_create(&th, NULL, thread, NULL) == 0)
        pthread_detach(th);
}
