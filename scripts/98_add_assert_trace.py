from pathlib import Path
p = Path('04-产物/97_attrstack_preload.c')
s = p.read_text()
add = r'''
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
'''
if 'rea_assert_shim' not in s:
    s = s.replace('static void patch_libc_assert(void);',
                  'static void patch_libc_assert(void);\nstatic void rea_assert_shim(const char *, const char *, unsigned int, const char *);', 1)
    s = s.rstrip() + '\n' + add
    s = s.replace('''    *(uint16_t *)a = 0x4770;            /* bx lr */
    __builtin___clear_cache((char *)a, (char *)a + 4);
    logline("[ASTRAPATCH] libc __assert_fail patched to return");''',
'''    {
        uint16_t insn0 = 0xF8DF, insn1 = 0xF000;
        uint32_t target = (uint32_t)(uintptr_t)&rea_assert_shim | 1u;
        memcpy((void *)a, &insn0, 2);
        memcpy((void *)(a + 2), &insn1, 2);
        memcpy((void *)(a + 4), &target, 4);
    }
    __builtin___clear_cache((char *)a, (char *)a + 8);
    logline("[ASTRAPATCH] libc __assert_fail redirected to trace shim");''', 1)
    p.write_text(s)
print('ok')
