# -*- coding: utf-8 -*-
"""
92_plt3.py : 正确解析 .plt (12 字节桩) -> GOT -> 符号, 并输出 InfraInput API 的调用点
"""
import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import libobj92_tools as T
from elftools.elf.elffile import ELFFile

elf = ELFFile(open(T.LIB, 'rb'))
dynsym = elf.get_section_by_name('.dynsym')
syms = [s for s in dynsym.iter_symbols()]

def armimm(w):
    imm12 = w & 0xFFF
    imm8 = imm12 & 0xFF
    rot = (imm12 >> 8) & 0xF
    if rot == 0:
        return imm8
    return ((imm8 >> (2 * rot)) | (imm8 << (32 - 2 * rot))) & 0xFFFFFFFF

o = T.va2off(0xF7CC0)
got2sym = {}
for i in range(0x4F98 // 8):
    ro, ri = struct.unpack_from('<II', T.DATA, o + 8 * i)
    si = ri >> 8
    got2sym[ro] = syms[si].name if si < len(syms) else '?'

def w32(va):
    return struct.unpack_from('<I', T.DATA, T.va2off(va))[0]

stub2sym = {}
a = 0xFCC78
end = 0xFCC64 + 0x7DC8
while a + 12 <= end:
    w1, w2, w3 = w32(a), w32(a + 4), w32(a + 8)
    if (w1 & 0xFFFFF000) == 0xE28FC000 and (w2 & 0xFFFFF000) == 0xE28CC000 \
       and (w3 & 0xFFFFF000) == 0xE5BCF000:
        got = (a + 8) + armimm(w1) + armimm(w2) + (w3 & 0xFFF)
        if got in got2sym:
            stub2sym[a] = got2sym[got]
            a += 12
            continue
    a += 4
print('stubs resolved:', len(stub2sym), ' got slots:', len(got2sym))

name2stub = {}
for st, nm in stub2sym.items():
    name2stub.setdefault(nm, []).append(st)

bmap = T.build_bl_map()
def callers(nm):
    out = []
    for st in name2stub.get(nm, []):
        out.extend(bmap.get(st, []))
    return sorted(out)

NAMES = ['_ZN10InfraInput15SetEventKeyListEiP18_InfraInputKeyListi',
         '_ZN10InfraInput14RmEventKeyListEiP18_InfraInputKeyListi',
         '_ZN10InfraInput17SendEventInitDataEi',
         '_ZN10InfraInput14GetEventStatusEiiP16_InfraInputEvent',
         '_ZN10InfraInput9SetKeyInhEib',
         '_ZN10InfraInput10SetCallbackEPiPFviP16_InfraInputEventE',
         '_ZN10InfraInput9SetOsalIdEPii',
         '_ZN10InfraInput11GetInstanceEv',
         '_ZN10InfraInput15GetPhyKeyStatusEiP21_InfraInputPhyKeyData',
         '_ZN10InfraInput10RmCallbackEi']
print('\n=== call sites (through PLT) ===')
for nm in NAMES:
    cs = callers(nm)
    print('%-58s stubs=%s n=%d' % (nm.replace('_ZN10InfraInput', 'InfraInput::'),
                                   [hex(x) for x in name2stub.get(nm, [])], len(cs)))
    for c in cs[:24]:
        print('        call 0x%08X  func 0x%08X' % (c, T.func_of(c)))

if len(sys.argv) > 1:
    # 额外: 任意符号名的调用点
    for nm in sys.argv[1:]:
        print('\n%s stubs=%s' % (nm, [hex(x) for x in name2stub.get(nm, [])]))
        for c in callers(nm)[:40]:
            print('        call 0x%08X  func 0x%08X' % (c, T.func_of(c)))
