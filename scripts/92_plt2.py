# -*- coding: utf-8 -*-
"""
92_plt2.py : 逐 4 字节(容错)扫描 .plt, 建立 stub->符号 映射并打印关键符号调用点
"""
import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import libobj92_tools as T
from capstone import *
from elftools.elf.elffile import ELFFile

elf = ELFFile(open(T.LIB, 'rb'))
dynsym = elf.get_section_by_name('.dynsym')
syms = [s for s in dynsym.iter_symbols()]

o = T.va2off(0xF7CC0)
got2sym = {}
for i in range(0x4F98 // 8):
    ro, ri = struct.unpack_from('<II', T.DATA, o + 8 * i)
    si = ri >> 8
    got2sym[ro] = syms[si].name if si < len(syms) else '?'

mda = Cs(CS_ARCH_ARM, CS_MODE_ARM)
PLT_A, PLT_SZ = 0xFCC64, 0x7DC8
ins_at = {}
ob = T.va2off(PLT_A)
for off in range(0, PLT_SZ, 4):
    for ins in mda.disasm(T.DATA[ob + off:ob + off + 4], PLT_A + off):
        ins_at[ins.address] = (ins.mnemonic, ins.op_str, ins)

stub2sym = {}
for a in sorted(ins_at):
    mn, ops, ins = ins_at[a]
    if mn == 'ldr' and ops.startswith('pc, [ip'):
        a1 = ins_at.get(a - 8)
        a2 = ins_at.get(a - 4)
        if not a1 or not a2:
            continue
        try:
            v = (a - 8 + 8) + a1[2].operands[2].imm
            v += a2[2].operands[2].imm
            got = v + ins.operands[1].mem.disp
            if got in got2sym:
                stub2sym[a - 8] = got2sym[got]
        except Exception:
            pass
print('plt stubs resolved:', len(stub2sym))

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
         '_ZN10InfraInput15GetPhyKeyStatusEiP21_InfraInputPhyKeyData']
print('\n=== call sites (PLT) ===')
for nm in NAMES:
    cs = callers(nm)
    short = nm.replace('_ZN10InfraInput', 'InfraInput::')
    print('%-56s stubs=%s n=%d' % (short, [hex(x) for x in name2stub.get(nm, [])], len(cs)))
    for c in cs[:24]:
        print('        call 0x%08X in func 0x%08X' % (c, T.func_of(c)))
