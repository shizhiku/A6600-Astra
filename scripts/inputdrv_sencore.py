# -*- coding: utf-8 -*-
"""inputdrv_sencore.py — libsencore.so 中 0x8F013A/0x8F0313/0x910042 的引用点与上下文。"""
import io
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'
LIB = OUT / 'g4_libsencore.so'
QIDS = [0x8F013A, 0x8F0313, 0x910042, 0x910041]


def main():
    d = LIB.read_bytes()
    e = ELFFile(io.BytesIO(d))
    secs = []
    for s in e.iter_sections():
        if int(s['sh_size']) == 0 or s['sh_type'] == 'SHT_NOBITS':
            continue
        secs.append((int(s['sh_addr']), int(s['sh_offset']), int(s['sh_size']), s.name))
    syms = []
    ds = e.get_section_by_name('.dynsym')
    for s in ds.iter_symbols():
        if s.name and isinstance(s['st_shndx'], int):
            syms.append((int(s['st_value']) & ~1, int(s['st_size']), s.name))
    syms.sort()

    def off2va(o):
        for a, of, sz, n in secs:
            if of <= o < of + sz:
                return a + (o - of), n
        return None, None

    def va2off(va):
        for a, of, sz, n in secs:
            if a <= va < a + sz:
                return of + (va - a)
        return None

    def func_of(va):
        best = None
        for v, sz, n in syms:
            if v <= va and (best is None or v > best[0]):
                best = (v, n, sz)
        return best

    # PLT map
    got = {}
    for sec in e.iter_sections():
        if sec.name == '.rel.plt':
            for r in sec.iter_relocations():
                got[int(r['r_offset'])] = ds.get_symbol(r['r_info_sym']).name
    plt = {}
    p = e.get_section_by_name('.plt')
    if p:
        def imm(w):
            r = ((w >> 8) & 15) * 2
            b = w & 255
            return ((b >> r) | (b << (32 - r))) & 0xffffffff if r else b
        for o in range(int(p['sh_offset']), int(p['sh_offset']) + int(p['sh_size']) - 11, 4):
            a, b, c = struct.unpack_from('<III', d, o)
            if a & 0xfffff000 == 0xe28fc000 and b & 0xfffff000 == 0xe28cc000 and \
                    c & 0xfffff000 == 0xe5bcf000:
                va = o - int(p['sh_offset']) + int(p['sh_addr'])
                g = va + 8 + imm(a) + imm(b) + (c & 4095)
                if g in got:
                    plt[va] = got[g]

    L = [f'FILE {LIB.name}  qids={[hex(q) for q in QIDS]}']
    for q in QIDS:
        pat = struct.pack('<I', q)
        start = 0
        while True:
            i = d.find(pat, start)
            if i < 0:
                break
            start = i + 1
            va, sn = off2va(i)
            fn = func_of(va) if va else None
            L.append(f'\n== qid 0x{q:x} literal @ file 0x{i:x} va={hex(va) if va else "?"} sec={sn} '
                     f'func={hex(fn[0]) if fn else "?"} {fn[1] if fn else ""}')
            # 找引用该 literal 的指令：向前 0x400 内扫描 ARM/Thumb 解码
            lo = max(0, i - 0x400)
            for mode, md in (('arm', Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)),
                             ('thumb', Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN))):
                md.detail = True
                for cand in range(lo, i, 2):
                    for ins in md.disasm(d[cand:cand + 4], cand):
                        ops = ins.operands
                        if ins.mnemonic.startswith('ldr') and len(ops) >= 2 and \
                                ops[1].type == 3 and ins.reg_name(ops[1].mem.base) == 'pc':
                            if mode == 'thumb':
                                la = ((ins.address + 4) & ~3) + ops[1].mem.disp
                            else:
                                la = ins.address + 8 + ops[1].mem.disp
                            if la == i:
                                refva, _ = off2va(ins.address)
                                L.append(f'   ref {mode} @ file 0x{ins.address:x} '
                                         f'({ins.mnemonic} {ins.op_str}) va={hex(refva) if refva else "?"}')
            # 反汇编字面量所在函数附近
            if fn:
                o = va2off(fn[0])
                sz = min(fn[2] if fn[2] else 0x200, 0x600)
                md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
                md.detail = True
                pos = 0
                code = d[o:o + sz]
                while pos < len(code) - 1:
                    got2 = list(md.disasm(code[pos:pos + 4], fn[0] + pos))
                    if not got2:
                        pos += 2
                        continue
                    x = got2[0]
                    note = ''
                    if x.mnemonic in ('bl', 'blx') and x.operands and x.operands[0].type == 2:
                        t = x.operands[0].imm & ~1
                        note = '-> ' + plt.get(t, hex(t))
                    L.append(f'   {x.address:08x} {x.bytes.hex():10s} {x.mnemonic:8s} '
                             f'{x.op_str:38s} {note}')
                    pos += x.size
    (OUT / 'inputdrv_sencore_qid_ctx.txt').write_text('\n'.join(L), encoding='utf-8')
    print(f'wrote {len(L)} lines')


if __name__ == '__main__':
    main()
