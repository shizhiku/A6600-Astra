# -*- coding: utf-8 -*-
"""inputdrv_infra.py — 对比四代/五代 InfraInput 关键导出函数与线程创建。"""
import importlib.util
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'
_spec = importlib.util.spec_from_file_location('q', BASE / '02-脚本/inputdrv_queue.py')
q = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(q)

FUNCS = ['infra_input_init', 'infra_input_res', 'infra_input_sus', 'infra_input_exit',
         '_ZN10InfraInput11GetInstanceEv', '_ZN10InfraInput9SetOsalIdEPii',
         '_ZN10InfraInput11SetCallbackEPiPFviP16_InfraInputEventE',
         '_ZN10InfraInput17SendEventInitDataEi',
         '_ZN10InfraInput9SetKeyInhEib', '_ZN10InfraInput14GetEventStatusEiiP16_InfraInputEvent']

# InfraInput 构造函数（由 GetInstance 调用）：四代 0x860554 起；五代按 GetInstance 内 call 目标取
CTOR = {'g4': (0x860554, 0x320), 'g5': None}


def main():
    for gen, p in (('g4', OUT / 'g4_libObj.so'), ('g5', OUT / 'g5_libObj.so')):
        if not p.exists():
            continue
        ds = q.Dso(p)
        L = [f'== {gen} libObj InfraInput 关键导出 ==', f'file={p.name}']
        for fn in FUNCS:
            v = ds.func_by_name(fn)
            if v is None:
                L.append(f'-- {fn}: MISSING')
                continue
            sz = next((s for n, vv, s, t, i in ds.syms if n == fn), 0)
            L.append(f'-- {fn} @0x{v:x} size={sz}')
            L.extend('   ' + x for x in ds.dis(v, sz if sz else 0x200))
        # 构造函数窗口
        ctor = CTOR.get(gen)
        if ctor:
            L.append(f'-- InfraInput ctor @0x{ctor[0]:x} size=0x{ctor[1]:x}')
            L.extend('   ' + x for x in ds.dis(ctor[0], ctor[1]))
        (OUT / f'inputdrv_infra_{gen}_funcs.txt').write_text('\n'.join(L), encoding='utf-8')
        print('wrote', len(L))


if __name__ == '__main__':
    main()
