/* Emulator-only probe: trace the calls inside the blocking function
 * 0x54F664 (Application_Start -> ... -> blocks) of gen5 appFw.
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
#define NT 16

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

static unsigned long offs[NT] = {
    0x54EF74, 0x54833C, 0x925FB0, 0x9256A8, 0x547EB8, 0x548146,
    0x924A4C, 0x52BF6C, 0x54ED00, 0x54DAE4, 0x54DCAC, 0x54DBE0,
    0x9245A8, 0x52A490, 0x52A0D0, 0x9236A0
};
static volatile unsigned long addr[NT];
static volatile unsigned short orig[NT];
static volatile int armed[NT];
static volatile int hit[NT];

static void arm(int i)
{
    unsigned short *p = (unsigned short *)addr[i];
    unsigned long pg = (unsigned long)sysconf(_SC_PAGESIZE);
    void *pa = (void *)((unsigned long)p & ~(pg - 1));
    mprotect(pa, pg * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    *p = 0xDE00;
    __builtin___clear_cache((char *)p, (char *)p + 2);
    armed[i] = 1;
}

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
                for (i = 0; i < NT; i++) {
                    addr[i] = base + offs[i];
                    orig[i] = *(unsigned short *)addr[i];
                    arm(i);
                }
                logline("[DEEP2] armed 16 calls in 0x54F664");
                break;
            }
        }
        usleep(50000);
    }
    for (;;) {
        int i;
        for (i = 0; i < NT; i++) {
            if (hit[i]) {
                usleep(15000);
                if (addr[i]) arm(i);
                hit[i] = 0;
            }
        }
        usleep(2000);
    }
    return NULL;
}

static void handler(int sig, siginfo_t *si, void *ucv)
{
    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);
    unsigned long pc = sc[18], lr = sc[17];
    int i;
    char b[160];
    (void)si;
    for (i = 0; i < NT; i++) {
        if (armed[i] && (pc & ~1UL) == addr[i]) {
            static unsigned long cnt[NT];
            unsigned short *p = (unsigned short *)addr[i];
            cnt[i]++;
            snprintf(b, sizeof(b), "[DEEP2] 0x%08lx #%lu lr=0x%08lx",
                     offs[i], cnt[i], lr);
            logline(b);
            *p = orig[i];
            __builtin___clear_cache((char *)p, (char *)p + 2);
            armed[i] = 0;
            hit[i] = 1;
            sc[18] = addr[i];
            return;
        }
    }
    snprintf(b, sizeof(b), "[DEEP2] fatal sig=%d pc=0x%08lx lr=0x%08lx",
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
