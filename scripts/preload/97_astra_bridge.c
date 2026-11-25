/* Offline emulator-only Application route bridge. No camera deployment. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
extern void *old_dlopen(const char*,int);
extern void *old_dlsym(void*,const char*);
extern char *old_dlerror(void);
__asm__(".symver old_dlopen,dlopen@GLIBC_2.4");
__asm__(".symver old_dlsym,dlsym@GLIBC_2.4");
__asm__(".symver old_dlerror,dlerror@GLIBC_2.4");
#ifndef ASTRA97_BIND_MODE
#define ASTRA97_BIND_MODE RTLD_NOW
#endif
/* Application entry prototype verified in a6600 im.elf and gen5 appFwBoot.so. */
void Application_System_Init(const char *config)
{
    const char *translated = config;
    void *handle;
    void (*entry)(const char*);
    if (config && !strcmp(config,"AdjChkConfig.so")) translated="a5jChkConfig.so";
    fprintf(stderr,"[ASTRA97] bridge enter config=%s translated=%s\n",config?config:"(null)",translated?translated:"(null)");
    handle=old_dlopen("/usr/lib/a5pFwBoot.so",ASTRA97_BIND_MODE|RTLD_LOCAL|RTLD_DEEPBIND);
    if (!handle) { fprintf(stderr,"[ASTRA97] appFwBoot dlopen failed: %s\n",old_dlerror()); return; }
    fprintf(stderr,"[ASTRA97] appFwBoot handle=%p\n",handle);
    entry=(void(*)(const char*))old_dlsym(handle,"Application_System_Init");
    if (!entry) { fprintf(stderr,"[ASTRA97] entry lookup failed: %s\n",old_dlerror()); return; }
    fprintf(stderr,"[ASTRA97] call appFwBoot entry=%p\n",(void*)entry);
    entry(translated);
    fprintf(stderr,"[ASTRA97] appFwBoot entry returned\n");
}
