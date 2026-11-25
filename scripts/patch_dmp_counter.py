"""Remove the shared 24-entry DMP log budget and count draw kicks per kind."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/display/dmp_smaph.c')
s = p.read_text()

old = '''static void dmp_job_log(const char *kind, uint64_t addr, uint64_t n)
{
    static int left = 24;
    if (left <= 0) {
        return;
    }
    left--;
    fprintf(stderr, "[DMP] %s addr=0x%08" PRIx64 " n=%" PRIu64 "\\n",
            kind, addr, n);
}'''

new = '''static void dmp_job_log(const char *kind, uint64_t addr, uint64_t n)
{
    static int left = 24;
    static unsigned long n_draw, n_ppf, n_psc, n_list, n_copy;

    if (g_str_equal(kind, "p3d-draw")) {
        n_draw++;
    } else if (g_str_equal(kind, "ppf-transfer")) {
        n_ppf++;
    } else if (g_str_equal(kind, "ppf-copy")) {
        n_copy++;
    } else if (g_str_equal(kind, "psc-fill")) {
        n_psc++;
    } else if (g_str_equal(kind, "p3d-list")) {
        n_list++;
    }
    if ((n_draw + n_ppf + n_psc + n_list + n_copy) == 1 ||
        (n_draw && (n_draw % 50) == 0)) {
        fprintf(stderr, "[DMPCOUNT] draw=%lu list=%lu ppf=%lu copy=%lu psc=%lu\\n",
                n_draw, n_list, n_ppf, n_copy, n_psc);
    }
    if (left <= 0) {
        return;
    }
    left--;
    fprintf(stderr, "[DMP] %s addr=0x%08" PRIx64 " n=%" PRIu64 "\\n",
            kind, addr, n);
}'''

if 'DMPCOUNT' in s:
    print('already patched')
else:
    assert old in s, 'anchor missing'
    s = s.replace(old, new, 1)
    p.write_text(s)
    print('patched dmp counter')
