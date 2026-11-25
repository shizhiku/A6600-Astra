# -*- coding: utf-8 -*-
"""inputdrv_consumers.py — 四代/五代 libObj 中 UIPC 队列消费点与 InfraInput 线程队列还原。

方法：.ARM.exidx 恢复函数入口 -> Thumb 反汇编 -> 基本块内前向常量跟踪
      -> 记录 (a) 每处 PLT 调 osal_*/u_osal_* 的 r0..r3；(b) 每个 PC 相对字面量加载。
产物（03-证据/静态分析/input_drv/）：
  inputdrv_consumers_<gen>_osal_calls.tsv   所有 osal 调用点（函数/地址/callee/r0..r3）
  inputdrv_consumers_<gen>_qid_use.json     目标 qid -> 引用函数 & 该函数的 osal 调用
  inputdrv_consumers_<gen>_sig_funcs.json   InfraInput 自证字符串 -> 引用它的函数
  inputdrv_consumers_<gen>_summary.txt      人读汇总
只读，不执行。
"""
import importlib.util
import json
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

TARGET_QIDS = [0x7A804C, 0x7A0020, 0x8F013A, 0x8F0313, 0x910042, 0x910041, 0x920021,
               0x410025, 0x720018, 0x280132, 0x18A04D1]
SIG_STRS = [b'InfraInput::MainThread', b'InfraInput::RecvThread', b'InfraInput::EventThread',
            b'InfraInput::RepeatThread', b'InfraInput::SendAttachEvent',
            b'InfraInput::GetInstance', b'InputService', b'_InfraInputEvent']


def exidx_funcs(elf):
    sec = elf.e.get_section_by_name('.ARM.exidx')
    if sec is None:
        return []
    addr, off, size = int(sec['sh_addr']), int(sec['sh_offset']), int(sec['sh_size'])
    out = set()
    for i in range(size // 8):
        w0 = struct.unpack_from('<I', elf.data, off + 8 * i)[0]
        if w0 == 1:
            continue
        prel = w0 & 0x7FFFFFFF
        if prel & 0x40000000:
            prel -= 0x80000000
        f = (addr + 8 * i + prel) & ~1
        out.add(f)
    # 只保留 .text 内
    t = elf.e.get_section_by_name('.text')
    lo, hi = int(t['sh_addr']), int(t['sh_addr']) + int(t['sh_size'])
    return sorted(f for f in out if lo <= f < hi)


_MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
_MD.detail = True


def thumb_dis(elf, va, size):
    off = elf.off(va)
    if off is None:
        return []
    code = elf.data[off:off + size]
    md = _MD
    out, pos = [], 0
    while pos < len(code) - 1:
        last = None
        for ins in md.disasm(code[pos:], va + pos):
            out.append(ins)
            last = ins
        if last is None:
            pos += 2
        else:
            pos = (last.address + last.size) - va
    return out


def analyze(elf, func_starts, plt):
    """扫描全部函数；返回 (osal_calls, lit_loads)。"""
    osal_calls = []
    lit_loads = []
    text = elf.e.get_section_by_name('.text')
    tlo, thi = int(text['sh_addr']), int(text['sh_addr']) + int(text['sh_size'])
    fs = func_starts
    sym_names = {}
    for n, v, sz, t, idx in elf.syms:
        if t == 'STT_FUNC' and isinstance(idx, int) and n:
            sym_names.setdefault(v & ~1, n)
    for i, start in enumerate(fs):
        end = fs[i + 1] if i + 1 < len(fs) else thi
        if end - start > 0x20000:
            end = start + 0x20000
        insns = thumb_dis(elf, start, end - start)
        if not insns:
            continue
        # 基本块 leader
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
        ri = 1
        state = {}
        for ins in insns:
            while ri < len(leaders) and ins.address >= leaders[ri]:
                state = {}
                ri += 1
            mn, ops = ins.mnemonic, ins.operands
            # ---- 字面量 ldr ----
            if mn.startswith('ldr') and len(ops) >= 2 and ops[1].type == ARM_OP_MEM and \
                    ins.reg_name(ops[1].mem.base) == 'pc':
                la = ((ins.address + 4) & ~3) + ops[1].mem.disp
                v = elf.r32(la)
                if v is not None:
                    lit_loads.append(dict(func=start, site=ins.address, lit=la, value=v,
                                          reg=ins.reg_name(ops[0].reg)))
                    state[ins.reg_name(ops[0].reg)] = ('imm', v)
                continue
            # ---- mov/movw/movt ----
            if mn in ('mov', 'movs', 'mov.w', 'movw', 'movt', 'mvn') and \
                    len(ops) >= 2 and ops[0].type == ARM_OP_REG:
                if ops[1].type == ARM_OP_IMM:
                    v = ops[1].imm & 0xffffffff
                    if mn == 'movt':
                        old = state.get(ins.reg_name(ops[0].reg))
                        if old and old[0] == 'imm':
                            v = (old[1] & 0xffff) | (v << 16)
                    if mn == 'mvn':
                        v = (~v) & 0xffffffff
                    state[ins.reg_name(ops[0].reg)] = ('imm', v)
                    continue
                if ops[1].type == ARM_OP_REG:
                    state[ins.reg_name(ops[0].reg)] = state.get(ins.reg_name(ops[1].reg))
                    continue
            # ---- add rd, pc, #imm ----
            if mn in ('add', 'add.w') and len(ops) == 3 and ops[0].type == ARM_OP_REG and \
                    ops[1].type == ARM_OP_REG and ins.reg_name(ops[1].reg) == 'pc' and \
                    ops[2].type == ARM_OP_IMM:
                state[ins.reg_name(ops[0].reg)] = (
                    'imm', (ins.address + 4 + ops[2].imm) & 0xffffffff)
                continue
            # ---- 调用 ----
            if mn in ('bl', 'blx') and ops and ops[0].type == ARM_OP_IMM:
                t = ops[0].imm & ~1
                name = plt.get(t)
                if name and ('osal' in name or name.startswith('u_')):
                    args = {r: state.get(r) for r in ('r0', 'r1', 'r2', 'r3')}
                    osal_calls.append(dict(func=start, site=ins.address, callee=name,
                                           args={k: (v[1] if v and v[0] == 'imm' else None)
                                                 for k, v in args.items()}))
                state = {}
                continue
            # ---- 其它写寄存器则失效 ----
            if ops and ops[0].type == ARM_OP_REG:
                d = ins.reg_name(ops[0].reg)
                if d in ('r0', 'r1', 'r2', 'r3') and mn not in ('cmp', 'cmn', 'tst', 'teq'):
                    state[d] = None
    return osal_calls, lit_loads


def main():
    gens = sys.argv[1:] or ['g4', 'g5']
    libs = {'g4': OUT / 'g4_libObj.so', 'g5': OUT / 'g5_libObj.so'}
    for gen in gens:
        path = libs[gen]
        if not path.exists():
            print('[missing]', path)
            continue
        elf = qmod.Dso(path)
        funcs = exidx_funcs(elf)
        print(f'[{gen}] {path.name}: {len(funcs)} exidx functions, {len(elf.plt)} plt')
        osal_calls, lit_loads = analyze(elf, funcs, elf.plt)
        print(f'[{gen}] osal call sites: {len(osal_calls)}, literal loads: {len(lit_loads)}')
        # --- 函数名 ---
        fsym = {}
        for n, v, sz, t, idx in elf.syms:
            if t == 'STT_FUNC' and isinstance(idx, int) and n:
                fsym.setdefault(v & ~1, n)
        start_set = set(funcs)

        def func_of(addr):
            lo, hi = 0, len(funcs) - 1
            best = None
            while lo <= hi:
                mid = (lo + hi) // 2
                if funcs[mid] <= addr:
                    best = funcs[mid]
                    lo = mid + 1
                else:
                    hi = mid - 1
            return best

        def fname(a):
            if a is None:
                return '?'
            return fsym.get(a, f'static_0x{a:x}')

        with open(OUT / f'inputdrv_consumers_{gen}_osal_calls.tsv', 'w', encoding='utf-8') as f:
            f.write('func\tsite\tcallee\tr0\tr1\tr2\tr3\n')
            for c in osal_calls:
                a = c['args']
                fmt = lambda v: '' if v is None else f'0x{v:x}' if isinstance(v, int) else str(v)
                f.write(f'0x{c["func"]:x}\t0x{c["site"]:x}\t{c["callee"]}\t'
                        f'{fmt(a["r0"])}\t{fmt(a["r1"])}\t{fmt(a["r2"])}\t{fmt(a["r3"])}\n')
        # --- qid -> 引用 ----
        rep = {}
        for qid in TARGET_QIDS:
            sites = [l for l in lit_loads if l['value'] == qid]
            funcs_hit = []
            per_func = {}
            for s in sites:
                fn = func_of(s['site'])
                per_func.setdefault(fn, []).append(s)
            for fn, ss in sorted(per_func.items()):
                calls = [c for c in osal_calls if c['func'] == fn]
                funcs_hit.append(dict(func=f'0x{fn:x}', name=fname(fn),
                                      sites=[hex(s['site']) for s in ss],
                                      osal_calls=[dict(site=hex(c['site']), callee=c['callee'],
                                                       args={k: (hex(v) if isinstance(v, int) else v)
                                                             for k, v in c['args'].items()})
                                                  for c in calls]))
            if funcs_hit:
                rep[f'0x{qid:08x}'] = funcs_hit
        (OUT / f'inputdrv_consumers_{gen}_qid_use.json').write_text(
            json.dumps(rep, indent=1), encoding='utf-8')
        # --- 自证字符串 -> 函数 ---
        sig = {}
        for pat in SIG_STRS:
            p = pat
            offs = []
            start = 0
            while True:
                i = elf.data.find(p, start)
                if i < 0:
                    break
                # string 必须后跟 \0
                if elf.data[i + len(p):i + len(p) + 1] == b'\x00':
                    offs.append(i)
                start = i + 1
            for o in offs:
                va = None
                for s in elf.segs:
                    if int(s['p_offset']) <= o < int(s['p_offset']) + int(s['p_filesz']):
                        va = int(s['p_vaddr']) + (o - int(s['p_offset']))
                        break
                if va is None:
                    continue
                refs = [l for l in lit_loads if l['value'] == va]
                hits = []
                for r in refs:
                    fn = func_of(r['site'])
                    calls = [dict(site=hex(c['site']), callee=c['callee'],
                                  args={k: (hex(v) if isinstance(v, int) else v)
                                        for k, v in c['args'].items()})
                             for c in osal_calls if c['func'] == fn]
                    hits.append(dict(ref=hex(r['site']), func=f'0x{fn:x}', name=fname(fn),
                                     osal_calls=calls))
                if hits:
                    sig.setdefault(p.decode(), []).append(dict(string_va=f'0x{va:x}', hits=hits))
        (OUT / f'inputdrv_consumers_{gen}_sig_funcs.json').write_text(
            json.dumps(sig, indent=1), encoding='utf-8')
        # --- 汇总 ---
        L = [f'== {gen} libObj UIPC 消费点汇总 ==',
             f'osidx functions={len(funcs)} osal_calls={len(osal_calls)} literal_loads={len(lit_loads)}', '']
        L.append('-- qid 引用（值 -> 函数 -> 该函数的 osal 调用）--')
        for q, hits in rep.items():
            L.append(f'{q}:')
            for h in hits:
                L.append(f'  {h["name"]} {h["func"]} sites={h["sites"]}')
                for c in h['osal_calls']:
                    L.append(f'      {c["callee"]} @{c["site"]} r0={c["args"].get("r0")} '
                             f'r1={c["args"].get("r1")} r2={c["args"].get("r2")}')
        L.append('')
        L.append('-- InfraInput 自证字符串 -> 函数 --')
        for k, v in sig.items():
            for item in v:
                for h in item['hits']:
                    L.append(f'"{k}" @{item["string_va"]} -> {h["name"]} {h["func"]} (ref {h["ref"]})')
                    for c in h['osal_calls']:
                        L.append(f'      {c["callee"]} @{c["site"]} r0={c["args"].get("r0")}')
        (OUT / f'inputdrv_consumers_{gen}_summary.txt').write_text('\n'.join(L), encoding='utf-8')
        print(f'[{gen}] wrote consumer evidence')
    print('done')


if __name__ == '__main__':
    main()
