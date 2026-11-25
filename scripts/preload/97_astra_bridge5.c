/* Emulator-only Application-route bridge v5:
 * runs the 5th-gen init entry points each in its own thread with a timeout
 * so a hanging init (grm_init) does not block the rest of the boot, then
 * invokes appFwBoot::Application_System_Init.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern void *old_dlopen(const char *, int);
extern void *old_dlsym(void *, const char *);
extern char *old_dlerror(void);
__asm__(".symver old_dlopen,dlopen@GLIBC_2.4");
__asm__(".symver old_dlsym,dlsym@GLIBC_2.4");
__asm__(".symver old_dlerror,dlerror@GLIBC_2.4");

static void logmsg(const char *msg)
{
    FILE *f = fopen("/dev/console", "w");
    if (f) { fputs(msg, f); fputc('\n', f); fclose(f); }
}

struct init_job {
    void *fn;
    const char *name;
    volatile int done;
    int rc;
};

static void *init_thread(void *p)
{
    struct init_job *j = (struct init_job *)p;
    j->rc = ((int (*)(const char *))j->fn)(NULL);
    j->done = 1;
    return NULL;
}

static void run_init(void *h, const char *name, const char *ignored)
{
    char b[200];
    void *p = old_dlsym(h, name);
    struct init_job *j;
    pthread_t th;
    int waited;
    (void)ignored;
    if (!p) {
        snprintf(b, sizeof(b), "[ASTRA97] init %s: not exported", name);
        logmsg(b);
        return;
    }
    j = (struct init_job *)old_dlsym(h, "__never__");   /* placeholder */
    (void)j;
    {
        static struct init_job jobs[64];
        static int jobn;
        if (jobn >= 64) jobn = 0;
        j = &jobs[jobn++];
    }
    j->fn = p; j->name = name; j->done = 0; j->rc = -999;
    snprintf(b, sizeof(b), "[ASTRA97] init %s start", name);
    logmsg(b);
    if (pthread_create(&th, NULL, init_thread, j) != 0) {
        logmsg("[ASTRA97] init thread create failed");
        return;
    }
    pthread_detach(th);
    for (waited = 0; waited < 250 && !j->done; waited++)
        usleep(10000);
    if (!j->done) {
        snprintf(b, sizeof(b), "[ASTRA97] init %s TIMEOUT (still running)", name);
        logmsg(b);
    } else {
        snprintf(b, sizeof(b), "[ASTRA97] init %s returned %d", name, j->rc);
        logmsg(b);
    }
}

void Application_System_Init(const char *config)
{
    const char *translated = config;
    int flags = RTLD_LAZY | RTLD_GLOBAL | RTLD_DEEPBIND;
    void *fw, *obj, *mwf, *boot, *sym;
    void (*entry)(const char *);

    if (config && !strcmp(config, "AdjChkConfig.so"))
        translated = "a5jChkConfig.so";
    logmsg("[ASTRA97] bridge5 enter");

    fw = old_dlopen("/usr/lib/a5pFw.so", flags);
    if (!fw) { logmsg("[ASTRA97] a5pFw dlopen failed"); return; }
    logmsg("[ASTRA97] a5pFw loaded");

    obj = old_dlopen("/usr/lib/a5bObj.so", flags);
    if (!obj) {
        logmsg("[ASTRA97] a5bObj dlopen failed");
    } else {
        run_init(obj, "dmp_allocator_lib_init", translated);
        run_init(obj, "dmp_allocator_mmap_init", translated);
        run_init(obj, "DDSUserInit", translated);
        run_init(obj, "uxengine_init", translated);
        run_init(obj, "_ZN2ux6wgtlay14WidgetLayouter14sys_initializeEv",
                 translated);
        run_init(obj, "infra_input_init", translated);
    }

    mwf = old_dlopen("/usr/lib/a5bMWF.so", flags);
    if (mwf)
        run_init(mwf, "MWF_Init", translated);
    else
        logmsg("[ASTRA97] a5bMWF dlopen failed");

    run_init(obj, "grm_init", translated);

    boot = old_dlopen("/usr/lib/a5pFwBoot.so", flags);
    if (!boot) { logmsg("[ASTRA97] appFwBoot dlopen failed"); return; }
    sym = old_dlsym(boot, "Application_System_Init");
    if (!sym) { logmsg("[ASTRA97] entry lookup failed"); return; }
    entry = (void (*)(const char *))sym;
    logmsg("[ASTRA97] call appFwBoot entry");
    entry(translated);
    logmsg("[ASTRA97] appFwBoot entry returned");
}
