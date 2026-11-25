/* Emulator-only probe: register a callback on the 4th-gen libObj InfraInput
 * instance and log every _InfraInputEvent it receives (id + struct words).
 * Also keeps 6 MiB thread stacks. GLIBC_2.4-only symbols.
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

static unsigned long ev_count;

static void input_cb(int id, void *evp)
{
    char b[240];
    unsigned long *w = (unsigned long *)evp;
    ev_count++;
    if (evp && (unsigned long)evp > 0x1000UL) {
        snprintf(b, sizeof(b),
                 "[INHOOK] #%lu id=0x%x ev=0x%08lx w=%08lx %08lx %08lx %08lx "
                 "%08lx %08lx %08lx %08lx",
                 ev_count, id, (unsigned long)evp,
                 w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
    } else {
        snprintf(b, sizeof(b), "[INHOOK] #%lu id=0x%x ev=0x%08lx",
                 ev_count, id, (unsigned long)evp);
    }
    logline(b);
}

static void *hook_thread(void *arg)
{
    typedef void *(*get_inst_fn)(void);
    typedef int (*set_cb_fn)(void *, int *, void (*)(int, void *));
    get_inst_fn get_inst = NULL;
    set_cb_fn set_cb = NULL;
    int i;
    (void)arg;
    for (i = 0; i < 2400 && !(get_inst && set_cb); i++) {
        get_inst = (get_inst_fn)dlsym(RTLD_DEFAULT,
                        "_ZN10InfraInput11GetInstanceEv");
        set_cb = (set_cb_fn)dlsym(RTLD_DEFAULT,
                        "_ZN10InfraInput11SetCallbackEPiPFviP16_InfraInputEventE");
        if (!get_inst || !set_cb) usleep(100000);
    }
    if (!get_inst || !set_cb) {
        logline("[INHOOK] InfraInput symbols not found");
        return NULL;
    }
    for (i = 0; i < 600; i++) {
        void *inst = get_inst();
        if (inst) {
            static int cb_id;
            int rc = set_cb(inst, &cb_id, (void (*)(int, void *))input_cb);
            char b[160];
            snprintf(b, sizeof(b),
                     "[INHOOK] registered inst=0x%08lx cb_id=%d rc=%d",
                     (unsigned long)inst, cb_id, rc);
            logline(b);
            return NULL;
        }
        usleep(100000);
    }
    logline("[INHOOK] InfraInput instance timeout");
    return NULL;
}

__attribute__((constructor)) static void init(void)
{
    pthread_t th;
    resolve();
    if (pthread_create(&th, NULL, hook_thread, NULL) == 0)
        pthread_detach(th);
}
