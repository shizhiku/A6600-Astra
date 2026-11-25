/* Emulator-only probe: read the framebuffer dimensions and the +0x23a flag
 * seen in GraphicsEngine::drawFramebuffer.
 *
 * Disassembly (libObj+0xE565A):
 *   0xe5676  ldrb.w r3,[r4,#0x23a]   ; flag
 *   0xe567a  cbnz   r3,0xe5698
 *   0xe56a2  bl 0x1c943a ; cmp r0,#0 ; beq 0xe5720   -> early out
 *   0xe56be  r6=0x280 (640) ; r8=0x1e0 (480)
 *   0xe56d0  bl 0x3bc9c ; cmp r0,r8 ; bne 0xe5746    -> size mismatch out
 *   0xe56da  bl 0x3a9e0 ; cmp r0,r6 ; bne 0xe5746
 *
 * So we probe right before the size compares to capture the ACTUAL width/height.
 * Probe points (instruction boundaries):
 *   0xE56D6  cmp r0, r8    -> r0 = height (should be 480=r8)
 *   0xE56E0  cmp r0, r6    -> r0 = width  (should be 640=r6)
 *   0xE56A6  cmp r0, #0    -> r0 = result of 0x1c943a
 *   0xE567A  cbnz r3       -> r3 = flag at obj+0x23a
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

/* offsets relative to the 5th-gen libObj (a5bObj) load base */
static const unsigned long offs[NT] = {0x0E567A, 0x0E56A6, 0x0E56D6, 0x0E56E0};
static const char *labels[NT] = {
    "D1_flag_23a", "D2_bl_1c943a", "D3_height", "D4_width"
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
        void *h = dlopen("/usr/lib/a5bObj.so", RTLD_LAZY | RTLD_NOLOAD);
        if (h) {
            Dl_info info;
            void *s = dlsym(h, "_ZN2ux6gfxeng14GraphicsEngine15drawFramebufferEv");
            if (s && dladdr(s, &info) && info.dli_fbase) {
                unsigned long base = (unsigned long)info.dli_fbase;
                for (k = 0; k < NT; k++) {
                    addrs[k] = base + offs[k];
                    origs[k] = *(unsigned short *)addrs[k];
                    arm(k);
                }
                {
                    char b[128];
                    snprintf(b, sizeof(b), "[DRAW] base=%#lx armed 4 points",
                             base);
                    logline(b);
                }
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
    unsigned long r0 = sc[3], r1 = sc[4], r6 = sc[9], r8 = sc[11];
    unsigned long pc = sc[18], lr = sc[17];
    int k;
    char b[220];
    (void)si;
    for (k = 0; k < NT; k++) {
        if (armed[k] && (pc & ~1UL) == (addrs[k] & ~1UL)) {
            unsigned short *p = (unsigned short *)addrs[k];
            cnts[k]++;
            if (cnts[k] <= 4) {
                snprintf(b, sizeof(b),
                         "[DRAW] HIT %s #%lu r0=%#lx r1=%#lx r6=%#lx r8=%#lx "
                         "lr=%#lx",
                         labels[k], cnts[k], r0, r1, r6, r8, lr);
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
    snprintf(b, sizeof(b), "[DRAW] fatal sig=%d pc=%#lx lr=%#lx", sig, pc, lr);
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
