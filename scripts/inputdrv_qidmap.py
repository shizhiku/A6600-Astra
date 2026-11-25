# -*- coding: utf-8 -*-
"""inputdrv_qidmap.py — 定向：目标 qid 字面量 -> 引用指令 -> 所在函数 -> 该函数的 osal 调用。

比全量扫描快得多：只反汇编"确实引用了目标 qid 字面量"的那批函数。
产物 03-证据/静态分析/input_drv/：
  inputdrv_qidmap_<gen>.json    qid -> [{func,name,refs,osal_calls}]
  inputdrv_qidmap_<gen>.txt     人读
"""
import importlib.util
import json
import re
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'
_spec = importlib.util.spec_from_file_location('q', BASE / '02-脚本/inputdrv_queue.py')
qmod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qmod)
_spec2 = importlib.util.spec_from_file_location('c', BASE / '02-脚本/inputdrv_consumers.py')
cmod = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(cmod)

TARGET_QIDS = [0x7A804C, 0x7A0020, 0x8F013A, 0x8F0313, 0x910042, 0x910041, 0x920021,
               0x410025, 0x720018, 0x280132, 0x18A04D1]
_MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
_MD.detail = True


def off2va(elf, off):
    for s in elf.segs:
        po, pv, pf = int(s['p_offset']), int(s['p_vaddr']), int(s['p_filesz'])
        if po <= off < po + pf:
            return pv + (off - po)
    for sec in elf.secs:
        so, sv, ss = int(sec['sh_offset']), int(sec['sh_addr']), int(sec['sh_size'])
        if ss and so <= off < so + ss and sec['sh_type'] != 'SHT_NOBITS':
            return sv + (off - so)
    return None


def find_refs(elf, lit_va, lo=None, hi=None):
    """返回引用 lit_va 的 Thumb ldr 字面量指令的 VA 集合（按文件偏移定位字面量）。"""
    refs = set()
    data = elf.data
    lv_off = elf.off(lit_va)
    if lv_off is None:
        return []
    start = max(0, lv_off - 0x1000) & ~1
    for a_off in range(start, lv_off, 2):
        a = off2va(elf, a_off)
        if a is None:
            continue
        hw = struct.unpack_from('<H', data, a_off)[0]
        # 16-bit LDR Rt,[PC,#imm8*4]
        if (hw & 0xF800) == 0x4800:
            imm = (hw & 0xFF) * 4
            tgt = ((a + 4) & ~3) + imm
            if tgt == lit_va:
                refs.add(a)
                continue
        # 32-bit LDR.W Rt,[PC,#imm12]
        got = list(_MD.disasm(data[a_off:a_off + 4], a))
        if got:
            ins = got[0]
            ops = ins.operands
            if ins.mnemonic.startswith('ldr') and len(ops) >= 2 and ops[1].type == ARM_OP_MEM and \
                    ins.reg_name(ops[1].mem.base) == 'pc':
                tgt = ((a + 4) & ~3) + ops[1].mem.disp
                if tgt == lit_va:
                    refs.add(a)
    return sorted(refs)


def analyze_funcs(elf, func_starts, funcs, plt):
    """只分析给定函数集合（funcs 为 start 列表）。"""
    fs = func_starts
    thi = int(elf.e.get_section_by_name('.text')['sh_addr']) + \
        int(elf.e.get_section_by_name('.text')['sh_size'])
    calls = []
    for start in sorted(set(funcs)):
        i = fs.index(start) if start in fs else None
        if i is None:
            continue
        end = fs[i + 1] if i + 1 < len(fs) else thi
        if end - start > 0x8000:
            end = start + 0x8000
        insns = cmod.thumb_dis(elf, start, end - start)
        leaders = {start}
        for ins in insns:
            ops = ins.operands
            if (ins.mnemonic.startswith('b') and ins.mnemonic not in (
                    'bic', 'bics', 'bfc', 'bfi', 'bkpt')) or ins.mnemonic in ('cbz', 'cbnz'):
                if ops and ops[0].type == ARM_OP_IMM:
                    t = ops[0].imm & ~1
                    if start <= t < end:
                        leaders.add(t)
                leaders.add(ins.address + ins.size)
        leaders = sorted(a for a in leaders if start <= a <= end)
        if not leaders or leaders[0] != start:
            leaders.insert(0, start)
        ri, state = 1, {}
        for ins in insns:
            while ri < len(leaders) and ins.address >= leaders[ri]:
                state = {}
                ri += 1
            mn, ops = ins.mnemonic, ins.operands
            if mn.startswith('ldr') and len(ops) >= 2 and ops[1].type == ARM_OP_MEM and \
                    ins.reg_name(ops[1].mem.base) == 'pc':
                la = ((ins.address + 4) & ~3) + ops[1].mem.disp
                v = elf.r32(la)
                if v is not None:
                    state[ins.reg_name(ops[0].reg)] = ('imm', v)
                continue
            if mn in ('mov', 'movs', 'mov.w', 'movw', 'movt', 'mvn') and \
                    len(ops) >= 2 and ops[0].type == ARM_OP_REG:
                if ops[1].type == ARM_OP_IMM:
                    v = ops[1].imm & 0xffffffff
                    if mn == 'movt':
                        old = state.get(ins.reg_name(ops[0].reg))
                        if old and old[0] == 'imm':
                            v = (old[1] & 0xffff) | (v << 16)
                    state[ins.reg_name(ops[0].reg)] = ('imm', v)
                    continue
                if ops[1].type == ARM_OP_REG:
                    state[ins.reg_name(ops[0].reg)] = state.get(ins.reg_name(ops[1].reg))
                    continue
            if mn in ('add', 'add.w') and len(ops) == 3 and ops[0].type == ARM_OP_REG and \
                    ops[1].type == ARM_OP_REG and ins.reg_name(ops[1].reg) == 'pc' and \
                    ops[2].type == ARM_OP_IMM:
                state[ins.reg_name(ops[0].reg)] = ('imm', (ins.address + 4 + ops[2].imm) & 0xffffffff)
                continue
            if mn in ('bl', 'blx') and ops and ops[0].type == ARM_OP_IMM:
                t = ops[0].imm & ~1
                name = plt.get(t)
                if name:
                    calls.append(dict(func=start, site=ins.address, callee=name,
                                      args={r: (state.get(r)[1] if state.get(r) and
                                                state.get(r)[0] == 'imm' else None)
                                            for r in ('r0', 'r1', 'r2', 'r3')}))
                state = {}
                continue
            if ops and ops[0].type == ARM_OP_REG:
                d = ins.reg_name(ops[0].reg)
                if d in ('r0', 'r1', 'r2', 'r3') and mn not in ('cmp', 'cmn', 'tst', 'teq'):
                    state[d] = None
    return calls


def main():
    gens = sys.argv[1:] or ['g4', 'g5']
    libs = {'g4': OUT / 'g4_libObj.so', 'g5': OUT / 'g5_libObj.so'}
    for gen in gens:
        p = libs[gen]
        if not p.exists():
            continue
        elf = qmod.Dso(p)
        funcs = cmod.exidx_funcs(elf)
        print(f'[{gen}] {len(funcs)} funcs, {len(elf.plt)} plt')
        # 函数名
        fsym = {}
        for n, v, sz, t, idx in elf.syms:
            if t == 'STT_FUNC' and isinstance(idx, int) and n:
                fsym.setdefault(v & ~1, n)
        rep = {}
        for qid in TARGET_QIDS:
            pat = struct.pack('<I', qid)
            lit_vas = []
            start = 0
            while True:
                i = elf.data.find(pat, start)
                if i < 0:
                    break
                start = i + 1
                va = off2va(elf, i)
                if va is not None:
                    lit_vas.append(va)
            if not lit_vas:
                continue
            # 每个 literal 的引用
            all_refs = {}
            for lv in lit_vas:
                refs = find_refs(elf, lv, None, None)
                if refs:
                    all_refs[lv] = refs
            if not all_refs:
                continue
            # ref -> 函数
            func_hit = {}
            for lv, refs in all_refs.items():
                for r in refs:
                    fn = cmod_func_of(funcs, r)
                    if fn is not None:
                        func_hit.setdefault(fn, []).append((lv, r))
            calls = analyze_funcs(elf, funcs, list(func_hit), elf.plt)
            entries = []
            for fn, hits in sorted(func_hit.items()):
                fcalls = [c for c in calls if c['func'] == fn]
                entries.append(dict(func=f'0x{fn:x}', name=fsym.get(fn, f'static_0x{fn:x}'),
                                    refs=[dict(lit=f'0x{lv:x}', site=f'0x{r:x}')
                                          for lv, r in hits],
                                    osal_calls=[dict(site=f'0x{c["site"]:x}', callee=c['callee'],
                                                     args={k: (f'0x{v:x}' if v is not None else None)
                                                           for k, v in c['args'].items()})
                                                for c in fcalls]))
            rep[f'0x{qid:08x}'] = entries
        (OUT / f'inputdrv_qidmap_{gen}.json').write_text(json.dumps(rep, indent=1), encoding='utf-8')
        L = [f'== {gen} qid 引用函数（{len(rep)} 个 qid 命中）==']
        for q, entries in rep.items():
            L.append(f'\n## qid {q}')
            for e in entries:
                L.append(f'  func {e["name"]} {e["func"]} refs={[r["site"] for r in e["refs"]]}')
                for c in e['osal_calls']:
                    L.append(f'      {c["callee"]} @{c["site"]} r0={c["args"].get("r0")} '
                             f'r1={c["args"].get("r1")} r2={c["args"].get("r2")}')
        (OUT / f'inputdrv_qidmap_{gen}.txt').write_text('\n'.join(L), encoding='utf-8')
        print(f'[{gen}] qidmap done')


def cmod_func_of(funcs, addr):
    lo, hi, best = 0, len(funcs) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid] <= addr:
            best = funcs[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return best


if __name__ == '__main__':
    main()
