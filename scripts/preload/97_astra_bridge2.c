/* Emulator-only Application route bridge v2: pre-initialise 5th-gen MWF
 * before invoking appFwBoot::Application_System_Init.
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

static void logf_(const char *msg, const char *a1, void *a2)
{
    FILE *f = fopen("/dev/console", "w");
    if (f) {
        fprintf(f, "[ASTRA97] ");
        fprintf(f, msg, a1, a2);
        fputc('\n', f);
        fclose(f);
    }
}

void Application_System_Init(const char *config)
{
    const char *translated = config;
    void *fw, *boot, *sym;
    void (*entry)(const char *);
    void (*init_fn)(void);
    int flags = RTLD_LAZY | RTLD_GLOBAL | RTLD_DEEPBIND;

    if (config && !strcmp(config, "AdjChkConfig.so"))
        translated = "a5jChkConfig.so";
    logf_("bridge2 enter config=%s translated=%s", config ? config : "(null)",
          (void *)translated);

    fw = old_dlopen("/usr/lib/a5pFw.so", flags);
    logf_("a5pFw handle=%p", "", fw);
    if (fw) {
        sym = old_dlsym(fw, "MWF_Init");
        if (sym) {
            init_fn = (void (*)(void))sym;
            logf_("call MWF_Init=%p", "", sym);
            init_fn();
            logf_("MWF_Init returned", "", 0);
        } else {
            logf_("MWF_Init not found: %s", old_dlerror(), 0);
        }
    } else {
        logf_("a5pFw dlopen failed: %s", old_dlerror(), 0);
    }

    boot = old_dlopen("/usr/lib/a5pFwBoot.so", flags);
    if (!boot) {
        logf_("appFwBoot dlopen failed: %s", old_dlerror(), 0);
        return;
    }
    entry = (void (*)(const char *))old_dlsym(boot, "Application_System_Init");
    if (!entry) {
        logf_("entry lookup failed: %s", old_dlerror(), 0);
        return;
    }
    logf_("call appFwBoot entry=%p", "", (void *)entry);
    entry(translated);
    logf_("appFwBoot entry returned", "", 0);
}
