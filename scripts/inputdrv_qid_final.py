# -*- coding: utf-8 -*-
"""inputdrv_qid_final.py — 从 qidmap/ko 调用表提炼"确证 qid 使用"清单。

过滤规则：只有在同一函数里 qid 被作为 osal_* 调用的 r0（队列参数）时才计为"确证使用"，
          避免把 `ldr rX,=offset ; add rX,pc` 惯用法里的普通 32 位常量误判为 qid。
产物：inputdrv_qid_confirmed.json / .txt
"""
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'
QUEUE_CALLS = ('osal_rcv_msg_tmo', 'osal_snd_msg', 'osal_snd_sync_msg', 'osal_snd_sync_direct',
               'osal_valloc_msg_wait', 'osal_free_msg', 'osal_reg_msg_queue_cb',
               'osal_reg_sync_msg_queue_cb', 'osal_unreg_msg_queue_cb',
               'osal_set_msgq_broadcast_mode', 'osal_stat_msgq')


def main():
    final = {}
    for gen in ('g4', 'g5'):
        p = OUT / f'inputdrv_qidmap_{gen}.json'
        if not p.exists():
            continue
        d = json.load(open(p, encoding='utf-8'))
        genrep = {}
        for q, entries in d.items():
            qv = int(q, 16)
            hits = []
            for e in entries:
                def is_q(v):
                    try:
                        return v is not None and int(v, 16) == qv
                    except (TypeError, ValueError):
                        return False
                used = [c for c in e['osal_calls']
                        if c['callee'] in QUEUE_CALLS and is_q(c['args'].get('r0'))]
                if used:
                    hits.append(dict(func=e['name'], func_addr=e['func'],
                                     literal_files=[r['lit'] for r in e['refs']],
                                     calls=[dict(site=c['site'], callee=c['callee'],
                                                 r0=c['args'].get('r0'),
                                                 r1=c['args'].get('r1'),
                                                 r2=c['args'].get('r2'),
                                                 r3=c['args'].get('r3')) for c in used]))
            if hits:
                genrep[q] = hits
        final[gen] = genrep
    (OUT / 'inputdrv_qid_confirmed.json').write_text(json.dumps(final, indent=1), encoding='utf-8')
    L = ['== 确证 qid 使用（qid 被直接作为 osal_* 的 r0）==']
    for gen, rep in final.items():
        L.append(f'\n### {gen}')
        for q, hits in rep.items():
            L.append(f'  qid {q}')
            for h in hits:
                L.append(f'    - {h["func"]} @{h["func_addr"]}  literal_pool={h["literal_files"]}')
                for c in h['calls']:
                    L.append(f'        {c["callee"]} @{c["site"]} r0={c["r0"]} r1={c["r1"]} '
                             f'r2={c["r2"]} r3={c["r3"]}')
    (OUT / 'inputdrv_qid_confirmed.txt').write_text('\n'.join(L), encoding='utf-8')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
