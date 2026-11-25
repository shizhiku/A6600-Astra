# -*- coding: utf-8 -*-
"""
92_infra_key_map_scan2.py
libObj.so: (a) 更多 INFRAINPUT 字符串 (b) 扫 0x1AC 引用点 (c) 字符串字面量引用者反汇编
只读。
"""
import sys, struct, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

LIB = r'<WORKSPACE>\03-证据\静态分析\libObj.so'
data = open(LIB, 'rb').read()

from elftools.elf.elffile import ELFFile
from capstone import *

elf = ELFFile(open(LIB, 'rb'))
segs = []
for sec in elf.iter_sections():
    if sec['sh_type'] == 'SHT_NOBITS' or sec['sh_size'] == 0:
        continue
    segs.append((sec['sh_addr'], sec['sh_offset'], sec['sh_size'], sec.name))

# va <-> file offset. 注意: 第一个 PT_LOAD vadelta=0, 第二个 vadelta=0x8000
def va2off(va):
    for a, o, s, n in segs:
        if a <= va < a + s:
            return o + (va - a)
    return None

def r32(va):
    o = va2off(va)
    if o is None or o + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, o)[0]

def cstr(va, maxlen=300):
    o = va2off(va)
    if o is None:
        return None
    z = data.find(b'\x00', o, o + maxlen)
    if z < 0:
        z = o + maxlen
    return data[o:z].decode('utf-8', 'replace')

TEXT_A = 0x104A30
TEXT_E = 0x104A30 + 0xD3A6F0

print('=== more strings 0x1013200..0x1013700 ===')
base = 0x1013200
o = va2off(base)
n = 0x500
blob = data[o:o + n]
cur = base
for t in blob.split(b'\x00'):
    if t.strip() and all(32 <= c < 127 or c in (9, 10, 13) for c in t):
        print('  0x%08X  %s' % (cur, t.decode('ascii', 'replace')))
    cur += len(t) + 1

# ---------------------------------------------------------------- 0x1AC scan
print('\n=== raw scan for 0x1AC (ac 01 00 00) ===')
needle = struct.pack('<I', 0x1AC)
hits = []
i = 0
while True:
    i = data.find(needle, i)
    if i < 0:
        break
    hits.append(i)
    i += 1
print('total hits:', len(hits))

def secname_off(off):
    for a, o, s, n in segs:
        if o <= off < o + s:
            return n
    return '?'

hdr = '%-9s %-14s %-12s %s'
print(hdr % ('VA', 'section', 'prev_word', 'context(+/-32B)'))

def looks_keycode(v):
    if v is None:
        return False
    return 1 <= v <= 0x800 or 0x7000 <= v <= 0x7100

interesting = []
for off in hits:
    sec = secname_off(off)
    va = None
    for a, o, s, n in segs:
        if o <= off < o + s:
            va = a + (off - o)
            break
    if va is None:
        continue
    prev = struct.unpack_from('<I', data, off - 4)[0] if off >= 4 else None
    ctx = data[max(0, off - 16):off + 32]
    print('0x%08X  %-14s 0x%08X  %s' % (va, sec, prev if prev is not None else 0,
                                        ctx.hex(' ')))
    if sec in ('.rodata', '.data.rel.ro', '.data', '.text') and looks_keycode(prev):
        interesting.append((va, sec, prev))

print('\n--- candidates where prev word looks like a key_code ---')
for va, sec, prev in interesting:
    print(' 0x%08X [%s] prev=0x%X' % (va, sec, prev))

# ---------------------------------------------------------------- literal xref
MD_T = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
MD_A = Cs(CS_ARCH_ARM, CS_MODE_ARM)
for md in (MD_T, MD_A):
    md.detail = True

def find_refs(target_va):
    """找把 target_va 作为字面量加载的指令地址。"""
    res = []
    pat = struct.pack('<I', target_va)
    start = 0
    while True:
        off = data.find(pat, start)
        if off < 0:
            break
        start = off + 1
        # 字面量所在 VA
        lva = None
        for a, o, s, n in segs:
            if o <= off < o + s:
                lva = a + (off - o)
                secn = n
                break
        if lva is None:
            continue
        # 字面量池必须在 .text (或 .rodata 里的指针表)
        if not (TEXT_A <= lva < TEXT_E or secn == '.data.rel.ro'):
            continue
        cands = []
        # Thumb T1/T2: 指令必须在奇数地址(Thumb)且 (A+4)&~3 == lva
        for A in (lva - 4, lva - 2):
            for odd in (1,):
                a2 = A & ~1
                c = []
                for ins in MD_T.disasm(data[va2off(a2):va2off(a2) + 4], a2):
                    c.append(ins)
                # 取前两条 16bit? capstone 一次可能解出 1 条 16 位
                if c:
                    ins = c[0]
                    tgt = None
                    if ins.mnemonic == 'ldr' and 'pc' in ins.op_str:
                        try:
                            base = ((a2 + 4) & ~3)
                            # 解析内存操作数
                            mem = ins.operands[1].mem
                            tgt = base + mem.disp
                        except Exception:
                            tgt = None
                    elif ins.mnemonic == 'add' and 'pc' in ins.op_str:
                        try:
                            base = ((a2 + 4) & ~3)
                            imm = ins.operands[2].imm
                            tgt = base + imm
                        except Exception:
                            tgt = None
                    if tgt == lva:
                        cands.append((a2, 1))
        # ARM: A = lva - 8
        A = lva - 8
        if A >= TEXT_A and A % 4 == 0:
            for ins in MD_A.disasm(data[va2off(A):va2off(A) + 4], A):
                tgt = None
                try:
                    if ins.mnemonic == 'ldr' and 'pc' in ins.op_str:
                        mem = ins.operands[1].mem
                        tgt = A + 8 + mem.disp
                except Exception:
                    tgt = None
                if tgt == lva:
                    cands.append((A, 0))
        for a2, is_thumb in cands:
            res.append((lva, a2, is_thumb))
    return res

STR_TARGETS = {
    0x1012D8D: 'InputEventList {',
    0x1012DAB: 'InfraInputKeyList event {',
    0x1012DD3: 'key_code   =',
    0x1012DFD: 'event_code =',
    0x1012E27: 'status     =',
    0x1012FB2: 'key_code, event_code line',
    0x1012E6F: 'InputPhyKeyInternal phy_data {',
    0x1012D55: 'unknown key_code',
    0x1012CEB: '%s(callback_id, list_no)',
    0x1012D1A: 'new callback_table',
    0x1012C27: 'InfraInput::ChangeEventStatus',
    0x1012C51: 'max_on/max_off/max_invalid',
    0x101302C: 'event inh',
    0x1012FF9: 'no group',
    0x1013002: 'do not',
    0x1013009: 'repeat key',
    0x1013014: 'keep_unknown',
    0x1013021: 'same event',
    0x1013036: 'no_send',
    0x101303E: '%s, chg/rep/inh/flags',
    0x10130AF: 'KeyConfigInfraInput {',
    0x101307B: 'display config_tableI',
}

print('\n=== literal xrefs of INFRAINPUT strings ===')
for va, nm in STR_TARGETS.items():
    refs = find_refs(va)
    print('0x%08X  %-32s refs=%d %s' % (va, nm, len(refs),
          ' '.join('[0x%X%s]' % (a, 'T' if t else 'A') for a, t in refs)))
