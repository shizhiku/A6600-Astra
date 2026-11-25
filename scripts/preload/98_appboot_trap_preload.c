/* Emulator-only probe: trap the 5th-gen app startup chain entries
 *   appFwBoot Main (file offset 0x14d8) -> uxengine_init2 (a5bObj)
 *   -> Application_Start (a5pFw)
 * and log the order in which they are reached.  Also keeps 6 MiB stacks.
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
#define NT 3

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

static const char *names[NT] = {"appFwBoot_Main", "uxengine_init2",
                                "Application_Start"};
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
        void *obj = dlopen("/usr/lib/a5bObj.so", RTLD_LAZY | RTLD_NOLOAD);
        void *boot = dlopen("/usr/lib/a5pFwBoot.so", RTLD_LAZY | RTLD_NOLOAD);
        void *s1, *s2;
        if (fw && obj && boot) {
            s1 = dlsym(obj, "uxengine_init2");
            s2 = dlsym(fw, "Application_Start");
            if (s1 && s2) {
                Dl_info info;
                addr[0] = 0;
                if (dladdr(boot, &info) && info.dli_fbase)
                    addr[0] = (unsigned long)info.dli_fbase + 0x14d8;
                addr[1] = (unsigned long)s1 & ~1UL;
                addr[2] = (unsigned long)s2 & ~1UL;
                for (i = 0; i < NT; i++) {
                    if (!addr[i]) continue;
                    orig[i] = *(unsigned short *)addr[i];
                    arm(i);
                }
                logline("[APPTRAP] armed appFwBoot_Main/uxengine_init2/Application_Start");
                break;
            }
        }
        usleep(50000);
    }
    for (;;) {
        int i;
        for (i = 0; i < NT; i++) {
            if (hit[i]) {
                usleep(20000);
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
            snprintf(b, sizeof(b), "[APPTRAP] %s #%lu lr=0x%08lx",
                     names[i], cnt[i], lr);
            logline(b);
            *p = orig[i];
            __builtin___clear_cache((char *)p, (char *)p + 2);
            armed[i] = 0;
            hit[i] = 1;
            sc[18] = addr[i];
            return;
        }
    }
    snprintf(b, sizeof(b), "[APPTRAP] fatal sig=%d pc=0x%08lx lr=0x%08lx",
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
