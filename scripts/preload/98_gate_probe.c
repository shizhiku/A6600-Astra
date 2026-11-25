/* Emulator-only probe: report the gate values that stop the frame call.

Probe points (all verified instruction boundaries):
  0x54FA40  cmp r0,#2        -> r0 = 0x54F2CA() state-classify result
  0x54FA6C  cmp r0,r2        -> r2:r3 = 64-bit elapsed, r0 = 0x62F4 threshold
  0x54FA7A  cmp r0,#0        -> r0 = 0x54F2AE() gate result
  0x54FAA4  cmp.w r8,#0      -> r8 = gate re-check (r8 == state from 54F2CA)

Interpretation:
  * 54FA44 beq 0x54FAF0 fires when state == 2          -> drawing skipped
  * 54FA72 bhs 0x54FAD4 fires when threshold >= delta  -> drawing skipped
  * 54FA7C beq 0x54FAE6 fires when gate == 0           -> drawing skipped
  * 54FAA8 bne 0x54FACC fires when r8 != 0             -> frame call skipped
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
#define NT 4

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

static const unsigned long offs[NT] = {0x54FA40, 0x54FA6C, 0x54FA7A, 0x54FAA4};
static const char *labels[NT] = {
    "G1_state", "G2_timediff", "G3_gate", "G4_r8check"
};

static volatile unsigned long addrs[NT];
static volatile unsigned short origs[NT];
static volatile int armed[NT];
static volatile int hit[NT];
static volatile unsigned long cnts[NT];

static void arm(int k)
{
    unsigned short *p = (unsigned short *)addrs[k];
    unsigned long pg = (unsigned long)sysconf(_SC_PAGESIZE);
    void *pa = (void *)((unsigned long)p & ~(pg - 1));
    mprotect(pa, pg * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    *p = 0xDE00;
    __builtin___clear_cache((char *)p, (char *)p + 2);
    armed[k] = 1;
}

static void *thread(void *arg)
{
    int i, k;
    (void)arg;
    for (i = 0; i < 2400; i++) {
        void *fw = dlopen("/usr/lib/a5pFw.so", RTLD_LAZY | RTLD_NOLOAD);
        if (fw) {
            Dl_info info;
            void *sym = dlsym(fw, "Application_Start");
            if (sym && dladdr(sym, &info) && info.dli_fbase) {
                unsigned long base = (unsigned long)info.dli_fbase;
                for (k = 0; k < NT; k++) {
                    addrs[k] = base + offs[k];
                    origs[k] = *(unsigned short *)addrs[k];
                    arm(k);
                }
                logline("[GATE] armed state/timediff/gate/r8");
                break;
            }
        }
        usleep(50000);
    }
    for (;;) {
        for (k = 0; k < NT; k++) {
            if (hit[k]) {
                usleep(12000);
                if (addrs[k]) arm(k);
                hit[k] = 0;
            }
        }
        usleep(1500);
    }
    return NULL;
}

static void handler(int sig, siginfo_t *si, void *ucv)
{
    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);
    unsigned long r0 = sc[3], r1 = sc[4], r2 = sc[5], r3 = sc[6];
    unsigned long r8 = sc[11];
    unsigned long pc = sc[18], lr = sc[17];
    int k;
    char b[220];
    (void)si;
    for (k = 0; k < NT; k++) {
        if (armed[k] && (pc & ~1UL) == (addrs[k] & ~1UL)) {
            unsigned short *p = (unsigned short *)addrs[k];
            cnts[k]++;
            if (cnts[k] <= 6) {
                snprintf(b, sizeof(b),
                         "[GATE] HIT %s #%lu r0=%#lx r1=%#lx r2=%#lx r3=%#lx "
                         "r8=%#lx lr=%#lx",
                         labels[k], cnts[k], r0, r1, r2, r3, r8, lr);
                logline(b);
            }
            *p = origs[k];
            __builtin___clear_cache((char *)p, (char *)p + 2);
            armed[k] = 0;
            hit[k] = 1;
            sc[18] = addrs[k];
            return;
        }
    }
    snprintf(b, sizeof(b), "[GATE] fatal sig=%d pc=%#lx lr=%#lx", sig, pc, lr);
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
