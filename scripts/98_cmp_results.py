import glob
import re
from pathlib import Path

BASE = Path('<WORKSPACE>/03-证据/ASTRA-97')

for tag in ('unpatched', 'fbrm2'):
    ds = sorted(glob.glob(str(BASE / ('m1-cmp-%s-*' % tag))))
    dirs = [Path(d) for d in ds if Path(d).is_dir()]
    if not dirs:
        print(tag, 'no run dir')
        continue
    p = dirs[-1]
    err = (p / 'stderr.log').read_text(errors='replace') if (p / 'stderr.log').exists() else ''
    print('=' * 60)
    print(tag, p.name)
    dmp = [l for l in err.splitlines() if 'DMPCOUNT' in l]
    print('  DMPCOUNT lines:', len(dmp))
    for l in dmp[-4:]:
        print('   ', l.strip()[:110])
    regs = {}
    for m in re.finditer(r'\[GPETRACE\] w ([0-9a-f]{4})', err):
        regs[m.group(1)] = regs.get(m.group(1), 0) + 1
    print('  GPETRACE writes total:', sum(regs.values()))
    print('  key registers: draw(0202)=%s list(1800)=%s ppf(0c18)=%s psc(001c)=%s'
          % (regs.get('0202', 0), regs.get('1800', 0),
             regs.get('0c18', 0), regs.get('001c', 0)))
    ch53 = [l for l in err.splitlines() if 'ch53' in l]
    print('  ch53 lines:', len(ch53))
    for l in ch53[-3:]:
        print('   ', l.strip()[:110])
    # also look at serial for gemini/draw hints
    ser = (p / 'serial.log').read_text(errors='replace') if (p / 'serial.log').exists() else ''
    for kw in ('gemini', 'Gemini', 'drawFramebuffer', 'fbrm', 'ASTRA_FB'):
        n = ser.count(kw)
        if n:
            print('  serial contains %r x%d' % (kw, n))
