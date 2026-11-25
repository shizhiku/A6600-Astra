/* a6600 最小引导垫片（验证注入链用，不加载任何五代代码）
 *
 * 作用：模块表被重定向到 appFwBoot.so 之后，这个库只做一件事——
 *       把控制权交回四代原来的 Application_System_Init。
 *
 * 目的：在不引入五代 UI 的前提下，验证
 *       im.elf 补丁 + libIMDB 重定向 + 动态库加载 这条链是否成立。
 *       相机行为应当与打补丁前完全一致。
 */
#define _GNU_SOURCE
#include <dlfcn.h>

typedef int (*init_fn)(void *);

static void *open_libobj(void)
{
    void *h = dlopen("libObj.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!h)
        h = dlopen("/usr/lib/libObj.so", RTLD_LAZY | RTLD_GLOBAL);
    return h;
}

int Application_System_Init(void *arg)
{
    void *h = open_libobj();
    if (!h)
        return -1;

    init_fn fn = (init_fn)dlsym(h, "Application_System_Init");
    if (!fn)
        fn = (init_fn)dlsym(h, "Application_System_InjS");
    if (!fn)
        return -2;

    return fn(arg);
}
