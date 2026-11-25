/* Emulator-only probe: count 5th-gen WidgetSystem frame-loop calls
 * (updateFrame / notifyDraw / processEvent) via re-armable UDF traps.
 * Also keeps 6 MiB thread stacks. GLIBC_2.4-only symbols.
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
#define NTRAP 3

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

static const char *trap_names[NTRAP] = {
    "updateFrame", "notifyDraw", "processEvent"
};
static const char *trap_syms[NTRAP] = {
    "_ZN2ux6wgtsys12WidgetSystem11updateFrameEv",
    "_ZN2ux6wgtsys12WidgetSystem10notifyDrawEv",
    "_ZN2ux6wgtsys12WidgetSystem12processEventEv"
};
static volatile unsigned long trap_addr[NTRAP];
static volatile unsigned short trap_orig[NTRAP];
static volatile int armed[NTRAP];
static volatile int hit[NTRAP];
static volatile unsigned long cnt[NTRAP];

static void arm(int i)
{
    unsigned short *p = (unsigned short *)trap_addr[i];
    unsigned long pg = (unsigned long)sysconf(_SC_PAGESIZE);
    void *pa = (void *)((unsigned long)p & ~(pg - 1));
    mprotect(pa, pg * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    *p = 0xDE00;
    __builtin___clear_cache((char *)p, (char *)p + 2);
    armed[i] = 1;
}

static void *trap_thread(void *arg)
{
    int i, j;
    (void)arg;
    for (i = 0; i < 2400; i++) {
        void *h = dlopen("/usr/lib/a5bObj.so", RTLD_LAZY | RTLD_NOLOAD);
        if (h) {
            int n = 0;
            for (j = 0; j < NTRAP; j++) {
                void *sym = dlsym(h, trap_syms[j]);
                char b[160];
                if (!sym) {
                    snprintf(b, sizeof(b), "[RENDERTRAP] %s not found",
                             trap_names[j]);
                    logline(b);
                    continue;
                }
                trap_addr[j] = (unsigned long)sym & ~1UL;
                trap_orig[j] = *(unsigned short *)trap_addr[j];
                arm(j);
                n++;
            }
            {
                char b[128];
                snprintf(b, sizeof(b), "[RENDERTRAP] armed %d traps", n);
                logline(b);
            }
            break;
        }
        usleep(50000);
    }
    if (!trap_addr[0]) return NULL;
    for (;;) {
        int any = 0;
        for (j = 0; j < NTRAP; j++) {
            if (hit[j]) {
                any = 1;
                usleep(3000);
                if (trap_addr[j]) arm(j);
                hit[j] = 0;
            }
        }
        if (!any) usleep(1000);
    }
    return NULL;
}

static void handler(int sig, siginfo_t *si, void *ucv)
{
    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);
    unsigned long pc = sc[18], lr = sc[17];
    int j;
    char b[192];
    (void)si;
    for (j = 0; j < NTRAP; j++) {
        if (armed[j] && (pc & ~1UL) == trap_addr[j]) {
            unsigned short *p = (unsigned short *)trap_addr[j];
            cnt[j]++;
            if (cnt[j] <= 3 || (cnt[j] % 200) == 0) {
                snprintf(b, sizeof(b),
                         "[RENDERTRAP] %s #%lu lr=0x%08lx", trap_names[j],
                         cnt[j], lr);
                logline(b);
            }
            *p = trap_orig[j];
            __builtin___clear_cache((char *)p, (char *)p + 2);
            armed[j] = 0;
            hit[j] = 1;
            sc[18] = trap_addr[j];
            return;
        }
    }
    snprintf(b, sizeof(b), "[RENDERTRAP] fatal sig=%d pc=0x%08lx", sig, pc);
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
    if (pthread_create(&th, NULL, trap_thread, NULL) == 0)
        pthread_detach(th);
}
