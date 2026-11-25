# -*- coding: utf-8 -*-
"""
92_plt_xref.py : 解析 .plt 桩 -> 符号, 并统计各导出符号的真实调用点
只读。
"""
import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import libobj92_tools as T
from capstone import *
from elftools.elf.elffile import ELFFile

elf = ELFFile(open(T.LIB, 'rb'))
dynsym = elf.get_section_by_name('.dynsym')
dynstr = elf.get_section_by_name('.dynstr')
syms = [s for s in dynsym.iter_symbols()]

# .rel.plt: Elf32_Rel { r_offset, r_info }
relplt_a, relplt_sz = 0xF7CC0, 0x4F98
o = T.va2off(relplt_a)
got2sym = {}
for i in range(relplt_sz // 8):
    r_off, r_info = struct.unpack_from('<II', T.DATA, o + 8 * i)
    si = r_info >> 8
    typ = r_info & 0xFF
    nm = syms[si].name if si < len(syms) else '?'
    got2sym[r_off] = (nm, typ, si)
print('rel.plt entries:', len(got2sym), 'sample:', list(got2sym.items())[:2])

# 解析 .plt (ARM, 12 字节/条)
mda = Cs(CS_ARCH_ARM, CS_MODE_ARM)
plt_a, plt_e = 0xFCC64, 0xFCC64 + 0x7DC8
stub2sym = {}
insns = list(mda.disasm(T.DATA[T.va2off(plt_a):T.va2off(plt_e)], plt_a))
i = 0
while i < len(insns):
    ins = insns[i]
    if ins.mnemonic == 'ldr' and ins.op_str.startswith('pc, [ip'):
        # 前两条是 add ip, pc, #i1 / add ip, ip, #i2
        a1, a2 = insns[i - 2], insns[i - 1]
        try:
            v = (a1.address + 8) + a1.operands[1].imm
            v = v + a2.operands[2].imm
            got = v + ins.operands[1].mem.disp
            if got in got2sym:
                stub2sym[a1.address] = got2sym[got][0]
        except Exception:
            pass
    i += 1
print('plt stubs resolved:', len(stub2sym))

# 反查: 符号名 -> 桩地址
name2stub = {}
for st, nm in stub2sym.items():
    name2stub.setdefault(nm, []).append(st)

bmap = T.build_bl_map()
def callers_of_symbol(nm):
    out = []
    for st in name2stub.get(nm, []):
        out.extend((c, st) for c in bmap.get(st, []))
    return sorted(out)

TARGETS = [
    '_ZN10InfraInput15SetEventKeyListEiP18_InfraInputKeyListi',
    '_ZN10InfraInput14RmEventKeyListEiP18_InfraInputKeyListi',
    '_ZN10InfraInput17SendEventInitDataEi',
    '_ZN10InfraInput14GetEventStatusEiiP16_InfraInputEvent',
    '_ZN10InfraInput9SetKeyInhEib',
    '_ZN10InfraInput10SetCallbackEPiPFviP16_InfraInputEventE',
    '_ZN10InfraInput9SetOsalIdEPii',
    '_ZN10InfraInput11GetInstanceEv',
]
print('\n=== call sites of InfraInput APIs (through PLT) ===')
for t in TARGETS:
    cs = callers_of_symbol(t)
    print('%-58s n=%d' % (t.replace('_ZN10InfraInput', 'InfraInput::'), len(cs)))
    for c, st in cs[:20]:
        print('        call 0x%08X (stub 0x%X) func=0x%X' % (c, st, T.func_of(c)))

print('\n=== who references the "unknown key_code"/dump strings ? ===')
T.build_index()
for s in (0x1012D55, 0x1012D8D, 0x1012FB2, 0x101303E, 0x101307B, 0x10130AF):
    r = T.find_refs(s)
    print('0x%X n=%d' % (s, len(r)), ['0x%X/%s/f=0x%X' % (a, k, T.func_of(a)) for a, k in r[:8]])
