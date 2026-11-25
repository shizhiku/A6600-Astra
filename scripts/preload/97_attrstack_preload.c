/* Emulator-only preload: enlarge pthread attr stack size at attr_init time.
 * This avoids interposing pthread_create (a previous attempt recursed).
 * GLIBC_2.4 only; no UI calls and no signal handlers.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MIN_STACK (6UL * 1024 * 1024)
static void patch_libc_assert(void);
static void rea_assert_shim(const char *, const char *, unsigned int, const char *);

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
    if (real_init)
        return;
    real_init = (int (*)(pthread_attr_t *))
        real_dlvsym_sym(RTLD_NEXT, "pthread_attr_init", "GLIBC_2.4");
    real_set = (int (*)(pthread_attr_t *, size_t))
        real_dlvsym_sym(RTLD_NEXT, "pthread_attr_setstacksize", "GLIBC_2.4");
    real_get = (int (*)(const pthread_attr_t *, size_t *))
        real_dlvsym_sym(RTLD_NEXT, "pthread_attr_getstacksize", "GLIBC_2.4");
    if (!real_init)
        real_init = real_attr_init_sym;
    if (!real_set)
        real_set = real_setstacksize_sym;
    if (!real_get)
        real_get = real_getstacksize_sym;
}

static void logline(const char *s)
{
    FILE *f = fopen("/dev/console", "w");
    if (f) {
        fputs(s, f);
        fputc('\n', f);
        fclose(f);
    }
}

__attribute__((constructor)) static void init(void)
{
    char comm[32] = {0};
    FILE *f = fopen("/proc/self/comm", "r");
    pthread_attr_t a;
    size_t sz = 0;
    resolve();
    patch_libc_assert();
    if (!f)
        return;
    if (fgets(comm, sizeof(comm), f) && strncmp(comm, "im.elf", 6) == 0) {
        if (real_init && real_init(&a) == 0) {
            if (real_get)
                real_get(&a, &sz);
            {
                char buf[96];
                snprintf(buf, sizeof(buf), "[ASTRAPRE] default_stack=%lu",
                         (unsigned long)sz);
                logline(buf);
            }
            pthread_attr_destroy(&a);
        }
    }
    fclose(f);
}

int pthread_attr_init(pthread_attr_t *a)
{
    int rc;
    size_t sz = 0;
    resolve();
    if (!real_init)
        return -1;
    rc = real_init(a);
    if (rc != 0)
        return rc;
    if (real_get && real_set) {
        real_get(a, &sz);
        if (sz < MIN_STACK)
            real_set(a, MIN_STACK);
    }
    return 0;
}

/* Diagnostic only: let a failed app assert continue instead of aborting. */
void __assert_fail(const char *assertion, const char *file, unsigned int line,
                   const char *function)
{
    char buf[256];
    FILE *f = fopen("/dev/console", "w");
    if (f) {
        snprintf(buf, sizeof(buf), "[ASSERT-BYPASS] %s:%u: %s: %s",
                 file ? file : "?", line, function ? function : "?",
                 assertion ? assertion : "?");
        fputs(buf, f);
        fputc('\n', f);
        fclose(f);
    }
}

#include <stdint.h>
#include <sys/mman.h>

static void patch_libc_assert(void)
{
    void *h;
    void (*f)(void);
    unsigned long a, pg;
    h = dlopen("libc.so.6", RTLD_LAZY);
    if (!h)
        return;
    f = (void (*)(void))dlsym(h, "__assert_fail");
    if (!f)
        return;
    a = (unsigned long)f & ~1UL;
    pg = (unsigned long)sysconf(_SC_PAGESIZE);
    if (mprotect((void *)(a & ~(pg - 1)), pg * 2,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        logline("[ASTRAPATCH] mprotect libc text failed");
        return;
    }
    {
        uint16_t insn0 = 0xF8DF, insn1 = 0xF000;
        uint32_t target = (uint32_t)(uintptr_t)&rea_assert_shim | 1u;
        memcpy((void *)a, &insn0, 2);
        memcpy((void *)(a + 2), &insn1, 2);
        memcpy((void *)(a + 4), &target, 4);
    }
    __builtin___clear_cache((char *)a, (char *)a + 8);
    logline("[ASTRAPATCH] libc __assert_fail redirected to trace shim");
}

/* Diagnostic: redirect libc __assert_fail to a shim that logs call-site and
 * a small frame-pointer walk before returning to the caller. */
static void rea_assert_shim(const char *ass, const char *file, unsigned int line,
                            const char *func)
{
    unsigned long fp = 0, ra = 0;
    char buf[256];
    FILE *f;
    int i;

    __asm__ volatile("mov %0, r7" : "=r"(fp));
    __asm__ volatile("mov %0, lr" : "=r"(ra));
    f = fopen("/dev/console", "w");
    if (f) {
        snprintf(buf, sizeof(buf), "[ASSERT-TRACE] file=%s line=%u func=%s ass=%s lr=0x%08lx",
                 file ? file : "?", line, func ? func : "?",
                 ass ? ass : "?", ra);
        fputs(buf, f);
        fputc('\n', f);
        for (i = 0; i < 8 && fp; i++) {
            unsigned long *p2 = (unsigned long *)fp;
            unsigned long nfp = p2[0], nra = p2[1];
            snprintf(buf, sizeof(buf), "[ASSERT-TRACE]   frame%d fp=0x%08lx ra=0x%08lx",
                     i, fp, nra);
            fputs(buf, f);
            fputc('\n', f);
            if (nfp <= fp) break;
            fp = nfp;
        }
        fclose(f);
    }
}
