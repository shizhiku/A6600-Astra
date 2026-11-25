/* Emulator-only diagnostic preload: enlarge pthread stacks for ASTRA bring-up.
 * GLIBC_2.4 compatible; no UI calls, no signal handlers.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MIN_STACK (6UL*1024*1024)

extern int real_pthread_create(pthread_t *, const pthread_attr_t *,
                               void *(*)(void *), void *);
__asm__(".symver real_pthread_create,pthread_create@GLIBC_2.4");
extern int real_getstacksize(const pthread_attr_t *, size_t *);
extern int real_setstacksize(pthread_attr_t *, size_t);
extern int real_getstack(const pthread_attr_t *, void **, size_t *);
extern int real_getguardsize(const pthread_attr_t *, size_t *);
extern int real_setguardsize(pthread_attr_t *, size_t);
__asm__(".symver real_getstacksize,pthread_attr_getstacksize@GLIBC_2.4");
__asm__(".symver real_setstacksize,pthread_attr_setstacksize@GLIBC_2.4");
__asm__(".symver real_getstack,pthread_attr_getstack@GLIBC_2.4");
__asm__(".symver real_getguardsize,pthread_attr_getguardsize@GLIBC_2.4");
__asm__(".symver real_setguardsize,pthread_attr_setguardsize@GLIBC_2.4");

static void logline(const char *s)
{
    FILE *f = fopen("/dev/console", "w");
    if (f) { fputs(s, f); fputc('\n', f); fclose(f); }
}

__attribute__((constructor)) static void init(void)
{
    char comm[32] = {0};
    FILE *f = fopen("/proc/self/comm", "r");
    pthread_attr_t a;
    size_t sz = 0;
    if (!f) return;
    if (fgets(comm, sizeof(comm), f)) {
        if (strncmp(comm, "im.elf", 6) == 0) {
            if (pthread_attr_init(&a) == 0) {
                real_getstacksize(&a, &sz);
                char buf[96];
                snprintf(buf, sizeof(buf), "[ASTRAPRE] default_stack=%lu", (unsigned long)sz);
                logline(buf);
                pthread_attr_destroy(&a);
            }
        }
    }
    fclose(f);
}

int pthread_create(pthread_t *t, const pthread_attr_t *attr,
                   void *(*fn)(void *), void *arg)
{
    pthread_attr_t a;
    size_t sz = 0;
    void *addr = NULL;
    int detach = PTHREAD_CREATE_JOINABLE;
    int policy = SCHED_OTHER;
    struct sched_param sp;
    size_t guard = 0;
    int rc;

    if (pthread_attr_init(&a) != 0)
        return real_pthread_create(t, attr, fn, arg);
    if (attr) {
        real_getstacksize(attr, &sz);
        real_getstack(attr, &addr, &sz);
        pthread_attr_getdetachstate(attr, &detach);
        real_getguardsize(attr, &guard);
        pthread_attr_getschedpolicy(attr, &policy);
        pthread_attr_getschedparam(attr, &sp);
    } else {
        real_getstack(&a, &addr, &sz);
    }
    if (addr && sz >= 65536) {          /* caller supplied its own stack */
        pthread_attr_destroy(&a);
        return real_pthread_create(t, attr, fn, arg);
    }
    if (sz < MIN_STACK) sz = MIN_STACK;
    real_setstacksize(&a, sz);
    pthread_attr_setdetachstate(&a, detach);
    real_setguardsize(&a, guard);
    pthread_attr_setschedpolicy(&a, policy);
    pthread_attr_setschedparam(&a, &sp);
    rc = real_pthread_create(t, &a, fn, arg);
    pthread_attr_destroy(&a);
    return rc;
}
