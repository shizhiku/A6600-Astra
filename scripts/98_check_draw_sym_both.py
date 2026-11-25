"""Does the 4th-gen a6600 libObj ALSO export the C++ drawFramebuffer symbol?

If yes, appFw's GOT slot for drawFramebuffer may bind to the 4th-gen
implementation instead of the 5th-gen one, which would explain:
  - call site 0x54ED82 reached (probe C hits)
  - but no P3D draw kick issued (draw=0, ch53=0)
because the 4th-gen implementation targets the 4th-gen framebuffer path.

Symbols of interest:
  _ZN2ux6gfxeng14GraphicsEngine15drawFramebufferEv
  _ZN2ux6gfxeng14GraphicsEngine20processSystemMessageEv
  _ZN2ux6wgtsys12WidgetSystem12processEventEv
  _ZN2ux6wgtsys12WidgetSystem11updateFrameEv
  _ZN2ux6wgtsys12WidgetSystem10notifyDrawEv
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import Path
import io

ROOT = Path(__file__).resolve().parent.parent

TARGETS = [
    '_ZN2ux6gfxeng14GraphicsEngine15drawFramebufferEv',
    '_ZN2ux6gfxeng14GraphicsEngine20processSystemMessageEv',
    '_ZN2ux6wgtsys12WidgetSystem12processEventEv',
    '_ZN2ux6wgtsys12WidgetSystem11updateFrameEv',
    '_ZN2ux6wgtsys12WidgetSystem10notifyDrawEv',
    'GRM_fbrmCheckUpdateFinished',
]

CASES = [
    ('gen5 appFw', ROOT / '03-证据/静态分析/97_abi/a5pFw_upmfix_nonotify.so'),
    ('gen5 a5bObj', ROOT / '03-证据/静态分析/grm/lib/libObj.so'),
    ('gen4 a6600 libObj', ROOT / '03-证据/静态分析/97_abi/a6_libObj.so'),
]

for label, path in CASES:
    if not path.exists():
        print('%-20s MISSING %s' % (label, path.name))
        continue
    d = path.read_bytes()
    e = ELFFile(io.BytesIO(d))
    syms = {}
    for sec in e.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        for s in sec.iter_symbols():
            if s.name in TARGETS:
                key = (s.name, sec.name)
                if key not in syms:
                    syms[key] = (s['st_value'], s['st_size'], s['st_shndx'])
    print('=== %-20s %-30s %d B ===' % (label, path.name, len(d)))
    for t in TARGETS:
        rows = [(k[1], v) for k, v in syms.items() if k[0] == t]
        if not rows:
            print('   %-56s ABSENT' % t[:56])
            continue
        for secname, (val, size, shndx) in rows:
            kind = 'IMPORT' if shndx == 'SHN_UNDEF' else 'DEFINED'
            print('   %-56s %-8s %s value=%#010x size=%d'
                  % (t[:56], secname, kind, val, size))
    print()
