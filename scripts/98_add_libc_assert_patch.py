from pathlib import Path
p = Path('04-产物/97_attrstack_preload.c')
s = p.read_text()
fn = r'''
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
    *(uint16_t *)a = 0x4770;            /* bx lr */
    __builtin___clear_cache((char *)a, (char *)a + 4);
    logline("[ASTRAPATCH] libc __assert_fail patched to return");
}
'''
if 'patch_libc_assert' not in s:
    s = s.replace('#define MIN_STACK (6UL * 1024 * 1024)',
                  '#define MIN_STACK (6UL * 1024 * 1024)\nstatic void patch_libc_assert(void);', 1)
    s = s.rstrip() + '\n' + fn
    s = s.replace('    resolve();\n    if (!f)', '    resolve();\n    patch_libc_assert();\n    if (!f)', 1)
    p.write_text(s)
print('ok')
