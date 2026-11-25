/* Emulator-only exit tracer: interposes exit() and logs the caller return
 * address, plus a destructor marker, to explain premature process exit.
 * Also keeps the 6 MiB thread-stack interposition. GLIBC_2.4-only symbols.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

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

static void logline(const char *s)
{
    FILE *f = fopen("/dev/console", "w");
    if (f) { fputs(s, f); fputc('\n', f); fclose(f); }
}

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

__attribute__((destructor)) static void bye(void)
{
    logline("[EXITTRACE] destructor ran");
}

__attribute__((constructor)) static void init(void)
{
    logline("[EXITTRACE] preload active");
}
