"""Locate the 5th-gen software framebuffer ("gemini") inside a5bObj.so / a5pFw.

The reference project hooks a software canvas (g_gemini_fb) and a swap/present
pair.  Find the corresponding symbols/strings in our gen5 libraries so we can
locate the canvas at runtime and dump it.
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import Path
import io
import re

TARGETS = [
    Path('03-证据/静态分析/97_abi/a5pFw_actual.so'),
]

# also the renamed gen5 libObj used in the image
alt = Path('03-证据/静态分析/grm/lib/libObj.so')
if alt.exists():
    TARGETS.append(alt)
g5obj = Path('05-原始固件/zv1m2_fw/gen5/libObj.so')
if g5obj.exists():
    TARGETS.append(g5obj)

PATTERNS = [b'gemini', b'GEMINI', b'Gemini', b'swap_buffers', b'SwapBuffers',
            b'present', b'Present', b'framebuffer', b'Framebuffer',
            b'src_phys', b'dst_phys']

for src in TARGETS:
    print('=' * 70)
    print('FILE', src, src.stat().st_size if src.exists() else 'MISSING')
    if not src.exists():
        continue
    d = src.read_bytes()
    e = ELFFile(io.BytesIO(d))

    # 1) symbol scan
    print('--- dynsym/symtab hits ---')
    seen = set()
    for sec in e.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        for s in sec.iter_symbols():
            if not s.name:
                continue
            low = s.name.lower()
            if any(p in low for p in (b'gemini'.decode(), 'swap_buffer',
                                      'present', 'framebuffer', 'fbrm',
                                      'swapbuf')):
                key = (s.name, s['st_value'])
                if key in seen:
                    continue
                seen.add(key)
                print('  %-60s %#x size=%d' % (s.name[:60], s['st_value'],
                                               s['st_size']))
    if not seen:
        print('  (none)')

    # 2) string scan for gemini
    print('--- string hits (gemini/present/swap) ---')
    for pat in (b'gemini', b'Gemini', b'GEMINI'):
        idx = 0
        n = 0
        while n < 8:
            idx = d.find(pat, idx)
            if idx < 0:
                break
            start = d.rfind(b'\x00', max(0, idx - 80), idx) + 1
            end = d.find(b'\x00', idx)
            if 0 < end - start < 160:
                try:
                    txt = d[start:end].decode('ascii')
                    if all(32 <= ord(c) < 127 for c in txt):
                        print('  @%#x %r' % (idx, txt))
                        n += 1
                except UnicodeDecodeError:
                    pass
            idx = end + 1 if end > idx else idx + 1
        if n == 0:
            print('  %r: none' % pat)
