/* Emulator-only staircase probe.

Traps a sequence of "resume points" inside gen5 appFw's Application_Start
chain.  Each trap is placed AFTER a call that might block: if the trap hits,
that previous call returned.  This lets us bisect the blocking call without
instrumenting the calls themselves (which proved unstable).

Sequence (offset in a5pFw.so):
  0x54EF90   after  blx r3            (vtable[0] - already known no-op)
  0x54EF96   after  bl 0x925FB0
  0x54EF9C   after  bl 0x923900
  0x54EFA2   after  bl 0x9246B8
  0x54EFA6   after  bl 0x9240D4
  0x54EFB8   after  bl 0x723AAC
  0x54EFD0   after  bl 0x558CBC
  0x54EFEE   after  bl 0x60E228
  0x54F678   after  bl 0x54EF74   (0x54EF74 returned)
  0x54F690   after  bl 0x54833C   (0x54833C returned)

Only ONE trap is armed at a time; on hit we log and arm the next.  This keeps
the disturbance minimal.
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
#define NT 10

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

static const unsigned long offs[NT] = {
    0x54EF90, 0x54EF96, 0x54EF9C, 0x54EFA2, 0x54EFA6,
    0x54EFB8, 0x54EFD0, 0x54EFEE, 0x54F678, 0x54F690
};
static const char *labels[NT] = {
    "after_blx_r3", "after_925FB0", "after_923900", "after_9246B8",
    "after_9240D4", "after_723AAC", "after_558CBC", "after_60E228",
    "after_54EF74", "after_54833C"
};

static volatile unsigned long addr;
static volatile unsigned short orig;
static volatile int armed, hit;
static volatile int cur;          /* index currently armed */

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
                addr = base + offs[0];
                orig = *(unsigned short *)addr;
                {
                    unsigned short *p = (unsigned short *)addr;
                    unsigned long pg = (unsigned long)sysconf(_SC_PAGESIZE);
                    void *pa = (void *)((unsigned long)p & ~(pg - 1));
                    mprotect(pa, pg * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
                    *p = 0xDE00;
                    __builtin___clear_cache((char *)p, (char *)p + 2);
                }
                cur = 0;
                armed = 1;
                logline("[STAIR] armed after_blx_r3");
                break;
            }
        }
        usleep(50000);
    }
    for (;;) {
        if (hit) {
            unsigned long base = 0;
            void *fw = dlopen("/usr/lib/a5pFw.so", RTLD_LAZY | RTLD_NOLOAD);
            Dl_info info;
            void *sym = fw ? dlsym(fw, "Application_Start") : NULL;
            if (sym && dladdr(sym, &info))
                base = (unsigned long)info.dli_fbase;
            usleep(30000);
            if (cur + 1 < NT && base) {
                cur++;
                addr = base + offs[cur];
                orig = *(unsigned short *)addr;
                {
                    unsigned short *p = (unsigned short *)addr;
                    unsigned long pg = (unsigned long)sysconf(_SC_PAGESIZE);
                    void *pa = (void *)((unsigned long)p & ~(pg - 1));
                    mprotect(pa, pg * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
                    *p = 0xDE00;
                    __builtin___clear_cache((char *)p, (char *)p + 2);
                }
                armed = 1;
            }
            hit = 0;
        } else {
            usleep(2000);
        }
    }
    return NULL;
}

static void handler(int sig, siginfo_t *si, void *ucv)
{
    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);
    unsigned long pc = sc[18], lr = sc[17];
    char b[160];
    (void)si;
    if (armed && (pc & ~1UL) == (addr & ~1UL)) {
        unsigned short *p = (unsigned short *)addr;
        snprintf(b, sizeof(b), "[STAIR] HIT %s lr=0x%08lx", labels[cur], lr);
        logline(b);
        *p = orig;
        __builtin___clear_cache((char *)p, (char *)p + 2);
        armed = 0;
        hit = 1;
        sc[18] = addr;
        return;
    }
    snprintf(b, sizeof(b), "[STAIR] fatal sig=%d pc=0x%08lx lr=0x%08lx",
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
