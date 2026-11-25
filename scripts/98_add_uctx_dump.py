from pathlib import Path
p = Path('04-产物/98_crash_trace_preload.c')
s = p.read_text()
if 'uc[%02d..]' not in s:
    s = s.replace(
        '    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);',
        '    unsigned long *uc = (unsigned long *)ucv;\n'
        '    unsigned long *sc = (unsigned long *)((char *)ucv + 0x14);\n'
        '    int wi;', 1)
    s = s.replace(
        '    logline(b);\n    for (i = 0; i < 12 && fp; i++) {',
        '    logline(b);\n'
        '    for (wi = 0; wi < 48; wi += 4) {\n'
        '        snprintf(b, sizeof(b),\n'
        '                 "[CRASHTRACE] uc[%02d..] = %08lx %08lx %08lx %08lx",\n'
        '                 wi, uc[wi], uc[wi+1], uc[wi+2], uc[wi+3]);\n'
        '        logline(b);\n'
        '    }\n'
        '    for (i = 0; i < 12 && fp; i++) {', 1)
    p.write_text(s)
print('ok')
