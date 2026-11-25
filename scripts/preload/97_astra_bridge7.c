/* Emulator-only bridge v7: original-order pre-inits (MWF -> InfraInput ->
 * grm -> DDS -> uxengine), each in its own thread with a timeout, then the
 * 5th-gen appFwBoot::Application_System_Init (which starts the ASTRA app).
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

struct job { void *fn; const char *name; volatile int done; int rc; };
static struct job jobs[32];
static int jobn;

static void *run(void *p)
{
    struct job *j = (struct job *)p;
    j->rc = ((int (*)(const char *))j->fn)(NULL);
    j->done = 1;
    return NULL;
}

static void call_init(void *h, const char *name)
{
    void *p = h ? old_dlsym(h, name) : NULL;
    struct job *j;
    pthread_t th;
    int i;
    char b[192];
    if (!p) {
        snprintf(b, sizeof(b), "[ASTRA97] init %s: not exported", name);
        logmsg(b);
        return;
    }
    if (jobn >= 32) jobn = 0;
    j = &jobs[jobn++];
    j->fn = p; j->name = name; j->done = 0; j->rc = -999;
    snprintf(b, sizeof(b), "[ASTRA97] init %s start", name);
    logmsg(b);
    if (pthread_create(&th, NULL, run, j) != 0) {
        logmsg("[ASTRA97] init thread create failed");
        return;
    }
    pthread_detach(th);
    for (i = 0; i < 250 && !j->done; i++)
        usleep(10000);
    if (!j->done) {
        snprintf(b, sizeof(b), "[ASTRA97] init %s TIMEOUT", name);
    } else {
        snprintf(b, sizeof(b), "[ASTRA97] init %s returned %d", name, j->rc);
    }
    logmsg(b);
}

void Application_System_Init(const char *config)
{
    const char *translated = config;
    int flags = RTLD_LAZY | RTLD_GLOBAL | RTLD_DEEPBIND;
    void *fw, *obj, *mwf, *boot, *sym;
    void (*entry)(const char *);

    if (config && !strcmp(config, "AdjChkConfig.so"))
        translated = "a5jChkConfig.so";
    logmsg("[ASTRA97] bridge7 enter");

    fw = old_dlopen("/usr/lib/a5pFw.so", flags);
    logmsg(fw ? "[ASTRA97] a5pFw loaded" : "[ASTRA97] a5pFw dlopen failed");
    obj = old_dlopen("/usr/lib/a5bObj.so", flags);
    logmsg(obj ? "[ASTRA97] a5bObj loaded" : "[ASTRA97] a5bObj dlopen failed");
    mwf = old_dlopen("/usr/lib/a5bMWF.so", flags);

    call_init(mwf, "MWF_Init");
    call_init(obj, "infra_input_init");
    call_init(obj, "grm_init");
    call_init(obj, "DDSUserInit");
    call_init(obj, "uxengine_init");

    boot = old_dlopen("/usr/lib/a5pFwBoot.so", flags);
    if (!boot) { logmsg("[ASTRA97] appFwBoot dlopen failed"); return; }
    sym = old_dlsym(boot, "Application_System_Init");
    if (!sym) { logmsg("[ASTRA97] entry lookup failed"); return; }
    entry = (void (*)(const char *))sym;
    logmsg("[ASTRA97] call appFwBoot entry");
    entry(translated);
    logmsg("[ASTRA97] appFwBoot entry returned");
}
