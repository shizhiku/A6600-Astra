from pathlib import Path
p = Path('04-产物/97_attrstack_preload.c')
s = p.read_text()
add = r'''
/* Diagnostic only: let a failed app assert continue instead of aborting. */
void __assert_fail(const char *assertion, const char *file, unsigned int line,
                   const char *function)
{
    char buf[256];
    FILE *f = fopen("/dev/console", "w");
    if (f) {
        snprintf(buf, sizeof(buf), "[ASSERT-BYPASS] %s:%u: %s: %s",
                 file ? file : "?", line, function ? function : "?",
                 assertion ? assertion : "?");
        fputs(buf, f);
        fputc('\n', f);
        fclose(f);
    }
}
'''
if '__assert_fail' not in s:
    p.write_text(s.rstrip() + '\n' + add)
print('ok')
