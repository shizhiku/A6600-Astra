"""Check which library DEFINES vs IMPORTS GRM_fbrmCheckUpdateFinished.

Run with:  python 02-脚本/98_check_binding.py
Paths are resolved relative to the repository root (parent of this script's dir).
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import Path
import io
import sys

# repo root = parent of 02-脚本
ROOT = Path(__file__).resolve().parent.parent
TARGET = 'GRM_fbrmCheckUpdateFinished'

CASES = [
    ('gen5 appFw (patched)', ROOT / '03-证据/静态分析/97_abi/a5pFw_upmfix_nonotify.so'),
    ('gen5 a5bObj (patched)', ROOT / '03-证据/静态分析/97_abi/a5bObj_fbrm2.img.so'),
    ('gen5 a5bObj (pristine)', ROOT / '03-证据/静态分析/grm/lib/libObj.so'),
    ('gen4 a6600 libObj', ROOT / '03-证据/静态分析/97_abi/a6_libObj.so'),
]

print('ROOT =', ROOT)
for label, path in CASES:
    if not path.exists():
        print('%-24s MISSING: %s' % (label, path.name))
        continue
    d = path.read_bytes()
    e = ELFFile(io.BytesIO(d))
    print('=== %-24s %-32s %d B ===' % (label, path.name, len(d)))
    hits = 0
    for sec in e.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        for s in sec.iter_symbols():
            if s.name != TARGET:
                continue
            hits += 1
            sh = s['st_shndx']
            where = ('IMPORT (undefined)' if sh == 'SHN_UNDEF'
                     else 'DEFINED (shndx=%s)' % sh)
            print('   %-10s value=%#010x size=%-4d %s'
                  % (sec.name, s['st_value'], s['st_size'], where))
    if not hits:
        print('   symbol not present')
    print()
