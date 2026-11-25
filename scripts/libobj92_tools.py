# -*- coding: utf-8 -*-
"""
libobj92_tools.py  —— libObj.so 静态分析工具库（只读）

va2off / r32 / cstr / secname
FUNCS          : .ARM.exidx 恢复的函数入口表
func_of(addr)
build_index()  : 一次遍历全部函数, 建立 "引用目标VA -> [引用点]" 索引
                 (支持惯用式 ldr rD,=imm ; add rD,pc,  以及直接字面量)
find_refs(tgt) : 取引用点
build_bl_map() : {callee: [call site]}
dis / show     : 反汇编
"""
import struct
from capstone import *
from capstone.arm import ARM_REG_PC

LIB = r'<WORKSPACE>\03-证据\静态分析\libObj.so'
DATA = open(LIB, 'rb').read()

from elftools.elf.elffile import ELFFile
_elf = ELFFile(open(LIB, 'rb'))
SECS = []
for sec in _elf.iter_sections():
    if sec['sh_type'] == 'SHT_NOBITS' or sec['sh_size'] == 0:
        continue
    SECS.append((sec['sh_addr'], sec['sh_offset'], sec['sh_size'], sec.name))

TEXT_A, TEXT_SZ = 0x104A30, 0xD3A6F0
TEXT_E = TEXT_A + TEXT_SZ
RO_A, RO_E = 0xE3F128, 0xE3F128 + 0x3567A2

def va2off(va):
    for a, o, s, n in SECS:
        if a <= va < a + s:
            return o + (va - a)
    return None

def off2va(off):
    for a, o, s, n in SECS:
        if o <= off < o + s:
            return a + (off - o), n
    return None, None

def r32(va):
    o = va2off(va)
    if o is None or o + 4 > len(DATA):
        return None
    return struct.unpack_from('<I', DATA, o)[0]

def cstr(va, n=300):
    o = va2off(va)
    if o is None:
        return None
    z = DATA.find(b'\x00', o, min(o + n, len(DATA)))
    if z < 0:
        z = o + n
    return DATA[o:z].decode('utf-8', 'replace')

def secname(va):
    for a, o, s, n in SECS:
        if a <= va < a + s:
            return n
    return '?'

MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
MD.detail = True

# ------------------------------------------------------------------ .ARM.exidx
FUNCS = []
def _load_funcs():
    global FUNCS
    if FUNCS:
        return
    ent_a, ent_sz = 0x1287E10, 0x74770
    o = va2off(ent_a)
    for i in range(ent_sz // 8):
        w0 = struct.unpack_from('<I', DATA, o + 8 * i)[0]
        if w0 == 1:
            continue
        prel = w0 & 0x7FFFFFFF
        if prel & 0x40000000:
            prel -= 0x80000000
        f = ent_a + 8 * i + prel
        FUNCS.append(f & ~1)
    FUNCS = sorted(set(f for f in FUNCS if TEXT_A <= f < TEXT_E))

def func_of(addr):
    _load_funcs()
    lo, hi, best = 0, len(FUNCS) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if FUNCS[mid] <= addr:
            best = FUNCS[mid]; lo = mid + 1
        else:
            hi = mid - 1
    return best

# ------------------------------------------------------------------ index
INDEX = None      # target_va -> [(site, kind)]
LITS = {}         # insn addr -> (dest reg, literal va, value)

def build_index(verbose=False):
    """遍历全部函数, 建立引用索引。约 10-25 秒。"""
    global INDEX
    if INDEX is not None:
        return INDEX
    _load_funcs()
    idx = {}
    lits = {}
    fs = FUNCS
    n = len(fs)
    for i, f in enumerate(fs):
        end = fs[i + 1] if i + 1 < n else TEXT_E
        sz = end - f
        if sz <= 0 or sz > 0x40000:
            continue
        o = va2off(f)
        if o is None:
            continue
        lastldr = {}   # reg -> (addr, literal value)
        for ins in MD.disasm(DATA[o:o + sz], f):
            mn = ins.mnemonic
            a = ins.address
            if mn.startswith('ldr') and len(ins.operands) >= 2 and ins.operands[1].type == CS_OP_MEM:
                m = ins.operands[1].mem
                if m.base == ARM_REG_PC:
                    lt = ((a + 4) & ~3) + m.disp
                    v = r32(lt)
                    if v is not None:
                        lastldr[ins.operands[0].reg] = (a, v)
                        lits[a] = (ins.operands[0].reg, lt, v)
                        # 直接字面量引用
                        if RO_A <= v < RO_E or v >= 0x1300000:
                            idx.setdefault(v, []).append((a, 'lit'))
                continue
            if mn in ('add', 'add.w') and len(ins.operands) == 2:
                if ins.operands[1].type == CS_OP_REG and ins.operands[1].reg == ARM_REG_PC:
                    rd = ins.operands[0].reg
                    if rd in lastldr:
                        la, v = lastldr[rd]
                        if a - la <= 0x100:
                            # 实测: Thumb-2 的 add rD,pc 基址 = 指令地址+4, 不做 4 字节对齐
                            tgt = (a + 4) + v
                            idx.setdefault(tgt, []).append((a, 'pcadd'))
                            continue
            elif mn in ('add', 'add.w') and len(ins.operands) == 3:
                if ins.operands[1].type == CS_OP_REG and ins.operands[1].reg == ARM_REG_PC:
                    try:
                        tgt = ((a + 4) & ~3) + ins.operands[2].imm
                        idx.setdefault(tgt, []).append((a, 'addimm'))
                    except Exception:
                        pass
    INDEX = idx
    LITS.clear(); LITS.update(lits)
    if verbose:
        print('# index entries: %d, literals: %d' % (len(idx), len(lits)))
    return INDEX

def find_refs(tgt):
    return build_index().get(tgt, [])

# ------------------------------------------------------------------ BL map
BLMAP = None
def build_bl_map():
    """Thumb-2 BL / BLX 直接调用边。返回 {callee: [call_site,...]}
    说明: BL/BLX 的第二半字高两位恒为 11, bit12 在两种编码里含义不同,
    故同时按 BL(imm11) 与 BLX(imm10L) 两种公式生成候选目标(取并集),
    调用点如需精确判定再单独反汇编确认。"""
    global BLMAP
    if BLMAP is not None:
        return BLMAP
    m = {}
    base = va2off(TEXT_A)
    o = base
    end = base + TEXT_SZ - 4
    while o < end:
        hw1 = struct.unpack_from('<H', DATA, o)[0]
        if (hw1 & 0xF800) == 0xF000:
            hw2 = struct.unpack_from('<H', DATA, o + 2)[0]
            if (hw2 & 0xC000) == 0xC000:
                S = (hw1 >> 10) & 1
                imm10 = hw1 & 0x3FF
                J1 = (hw2 >> 13) & 1
                J2 = (hw2 >> 11) & 1
                I1 = (~(J1 ^ S)) & 1
                I2 = (~(J2 ^ S)) & 1
                va = TEXT_A + (o - base)
                # --- BL 公式
                imm11 = hw2 & 0x7FF
                off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
                if off & 0x1000000:
                    off -= 0x2000000
                m.setdefault(va + 4 + off, []).append(va)
                # --- BLX 公式
                imm10L = (hw2 >> 1) & 0x3FF
                off2 = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm10L << 2)
                if off2 & 0x1000000:
                    off2 -= 0x2000000
                t2 = ((va + 4) & ~3) + off2
                if t2 != va + 4 + off:
                    m.setdefault(t2, []).append(va)
                o += 4
                continue
        o += 2
    BLMAP = m
    return m

def callers(tgt):
    return build_bl_map().get(tgt, [])

# ------------------------------------------------------------------ disasm
def dis(va, size):
    out = []
    o = va2off(va)
    if o is None:
        return out
    for ins in MD.disasm(DATA[o:o + size], va):
        note = ''
        if len(ins.operands) >= 2 and ins.operands[-1].type == CS_OP_MEM:
            mm = ins.operands[-1].mem
            if mm.base == ARM_REG_PC:
                lt = ((ins.address + 4) & ~3) + mm.disp
                v = r32(lt)
                note = '; 0x%X=0x%X' % (lt, v if v is not None else 0)
                if v is not None:
                    if RO_A <= v < RO_E:
                        s = cstr(v, 80)
                        if s and s.isprintable():
                            note += ' "%s"' % s
                    else:
                        note += ' %d' % v
        out.append((ins.address, ins.mnemonic, ins.op_str, note))
    return out

def show(va, size, title=''):
    print('\n===== %s  VA=0x%X size=%d =====' % (title, va, size))
    for a, mn, ops, note in dis(va, size):
        print('%08X  %-10s %-40s %s' % (a, mn, ops, note))
