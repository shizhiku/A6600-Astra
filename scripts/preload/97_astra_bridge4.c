/* Emulator-only Application-route bridge v4.
 * Loads the 5th-gen appFw group, calls the init entry points that the 5th-gen
 * IMDB would normally run before Application (they live inside libObj / MWF),
 * then invokes appFwBoot::Application_System_Init.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

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

static int call_init(void *h, const char *name, const char *cfg)
{
    void *p = old_dlsym(h, name);
    char b[192];
    int rc;
    if (!p) {
        snprintf(b, sizeof(b), "[ASTRA97] init %s: not exported", name);
        logmsg(b);
        return -1;
    }
    snprintf(b, sizeof(b), "[ASTRA97] init %s = %p", name, p);
    logmsg(b);
    rc = ((int (*)(const char *))p)(cfg);
    snprintf(b, sizeof(b), "[ASTRA97] init %s returned %d", name, rc);
    logmsg(b);
    return rc;
}

void Application_System_Init(const char *config)
{
    const char *translated = config;
    int flags = RTLD_LAZY | RTLD_GLOBAL | RTLD_DEEPBIND;
    void *fw, *obj, *mwf, *boot, *sym;
    void (*entry)(const char *);

    if (config && !strcmp(config, "AdjChkConfig.so"))
        translated = "a5jChkConfig.so";
    logmsg("[ASTRA97] bridge4 enter");

    fw = old_dlopen("/usr/lib/a5pFw.so", flags);
    if (!fw) { logmsg("[ASTRA97] a5pFw dlopen failed"); return; }
    logmsg("[ASTRA97] a5pFw loaded");

    obj = old_dlopen("/usr/lib/a5bObj.so", flags);
    if (!obj) {
        char b[160];
        snprintf(b, sizeof(b), "[ASTRA97] a5bObj dlopen failed: %s",
                 old_dlerror());
        logmsg(b);
    } else {
        call_init(obj, "dmp_allocator_lib_init", translated);
        call_init(obj, "dmp_allocator_mmap_init", translated);
        call_init(obj, "grm_init", translated);
        call_init(obj, "DDSUserInit", translated);
        call_init(obj, "uxengine_init", translated);
        call_init(obj, "_ZN2ux6wgtlay14WidgetLayouter14sys_initializeEv",
                  translated);
        call_init(obj, "infra_input_init", translated);
    }

    mwf = old_dlopen("/usr/lib/a5bMWF.so", flags);
    if (mwf)
        call_init(mwf, "MWF_Init", translated);
    else
        logmsg("[ASTRA97] a5bMWF dlopen failed");

    boot = old_dlopen("/usr/lib/a5pFwBoot.so", flags);
    if (!boot) { logmsg("[ASTRA97] appFwBoot dlopen failed"); return; }
    sym = old_dlsym(boot, "Application_System_Init");
    if (!sym) { logmsg("[ASTRA97] entry lookup failed"); return; }
    entry = (void (*)(const char *))sym;
    logmsg("[ASTRA97] call appFwBoot entry");
    entry(translated);
    logmsg("[ASTRA97] appFwBoot entry returned");
}
