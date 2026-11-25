/* Emulator-only probe: determine whether 0x54EF90 (the resume point after
 * `blx 0x925FB0`) is EVER reached.

 * Arms BOTH 0x54EF90 and 0x54EF96 at once (two independent traps).  If only
 * 0x54EF90 fires, the call before it (blx r3) is fine but the call at 0x54EF90
 * (-> 0x925FB0) blocks.  If neither fires, we never got into 0x54EF74.
 * If both fire, the block is later.
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

#define N 4
static const unsigned long offs[N] = {0x60E288, 0x60E2AE, 0x60E2C2, 0x60E2E8};
static const char *labels[N] = {"i_loop_start", "ii_after_9257D8", "iii_after_924500", "iv_loop_exit"};

static volatile unsigned long addrs[N];
static volatile unsigned short origs[N];
static volatile int armed[N];
static volatile int hits[N];

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
                logline("[MULTI] armed P,Q,R,S");
                break;
            }
        }
        usleep(50000);
    }
    for (;;) {
        int k;
        for (k = 0; k < N; k++) {
            if (hits[k]) {
                usleep(20000);
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
            static unsigned long cnt[N];
            unsigned short *p = (unsigned short *)addrs[k];
            cnt[k]++;
            snprintf(b, sizeof(b), "[MULTI] %s #%lu lr=0x%08lx",
                     labels[k], cnt[k], lr);
            logline(b);
            *p = origs[k];
            __builtin___clear_cache((char *)p, (char *)p + 2);
            armed[k] = 0;
            hits[k] = 1;
            sc[18] = addrs[k];
            return;
        }
    }
    snprintf(b, sizeof(b), "[MULTI] fatal sig=%d pc=0x%08lx lr=0x%08lx",
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
