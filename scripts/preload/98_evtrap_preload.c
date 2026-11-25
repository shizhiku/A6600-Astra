/* Emulator-only probe: re-armable UDF trap on 4th-gen libObj
 * InputService::createEvent(m, h), logging its arguments on every hit.
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

static volatile unsigned long trap_addr;
static volatile unsigned short trap_orig;
static volatile int armed, hit;

static void *trap_thread(void *arg)
{
    int i;
    (void)arg;
    for (i = 0; i < 2400; i++) {
        void *sym = dlsym(RTLD_DEFAULT,
                          "_ZN12InputService11createEventEmh");
        if (sym) {
            unsigned long addr = (unsigned long)sym & ~1UL;
            unsigned short *p = (unsigned short *)addr;
            {
                unsigned long pg = (unsigned long)sysconf(_SC_PAGESIZE);
                void *pa = (void *)((unsigned long)p & ~(pg - 1));
                mprotect(pa, pg * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
            }
            trap_orig = *p;
            *p = 0xDE00;
            __builtin___clear_cache((char *)p, (char *)p + 2);
            trap_addr = addr;
            armed = 1;
            {
                char b[128];
                snprintf(b, sizeof(b), "[EVTRAP] patched 0x%08lx orig=0x%04x",
                         addr, trap_orig);
                logline(b);
            }
            break;
        }
        usleep(100000);
    }
    if (!trap_addr) { logline("[EVTRAP] createEvent not found"); return NULL; }
    for (;;) {
        if (hit) {
            usleep(150000);
            if (trap_addr) {
                unsigned short *p = (unsigned short *)trap_addr;
                {
                    unsigned long pg = (unsigned long)sysconf(_SC_PAGESIZE);
                    void *pa = (void *)((unsigned long)p & ~(pg - 1));
                    mprotect(pa, pg * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
                }
                *p = 0xDE00;
                __builtin___clear_cache((char *)p, (char *)p + 2);
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
    unsigned long r0 = sc[3], r1 = sc[4], r2 = sc[5], r3 = sc[6];
    unsigned long lr = sc[17], pc = sc[18];
    char b[200];
    (void)si;
    if (armed && (pc & ~1UL) == trap_addr) {
        static unsigned long count;
        unsigned short *p = (unsigned short *)trap_addr;
        count++;
        snprintf(b, sizeof(b),
                 "[EVTRAP] #%lu r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx lr=0x%08lx",
                 count, r0, r1, r2, r3, lr);
        logline(b);
        *p = trap_orig;
        __builtin___clear_cache((char *)p, (char *)p + 2);
        armed = 0;
        hit = 1;
        sc[18] = trap_addr;
        return;
    }
    snprintf(b, sizeof(b), "[EVTRAP] fatal sig=%d pc=0x%08lx lr=0x%08lx",
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
    if (pthread_create(&th, NULL, trap_thread, NULL) == 0)
        pthread_detach(th);
}
