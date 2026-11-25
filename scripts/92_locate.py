# -*- coding: utf-8 -*-
"""
92_locate.py : 通过字符串引用定位 InfraInput 各函数
"""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import libobj92_tools as T

T.build_index()
T._load_funcs()

STR = {
    0x101354E: 'bool InfraInput::RmCallback(int)',
    0x101356F: 'static void InfraInput::MainThread(void*)',
    0x1013599: 'static void InfraInput::RecvThread(void*)',
    0x10135C3: 'static void InfraInput::EventThread(void*)',
    0x1013626: 'static void InfraInput::ILogThread(void*)',
    0x1013650: 'void InfraInput::iLogReboot(int,int)',
    0x10132FD: 'received InputPhyKeyInternal',
    0x101332A: 'InputPhyKeyInternal data {',
    0x1013302: '? near phykeydata',
    0x1012C27: 'InfraInput::ChangeEventStatus',
    0x1012C51: 'max_on/off/invalid',
    0x101303E: 'chg/rep/inh/flags',
    0x10132F4: 'rep over',
    0x1013522: 'start repeat',
    0x101352F: 'exit repeat',
    0x101353B: 'SKeyRep',
    0x1013543: 'SKeyRepRst',
    0x10135EE: 'init key_conf',
    0x101360A: 'get key_conf',
    0x10135FC: 'exit key_conf',
    0x1013617: 'alloc key_conf',
    0x1012D1A: 'new callback_table',
    0x1012CEB: '%s(cb_id,list_no)',
    0x1012FF2: 'set key_list',
    0x1013130: '? ',
    0x1012CC0: 'rm key_list',
    0x1012CD9: 'new key_list',
    0x1012CCC: 'set same_key',
}
print('%-10s %-32s %-12s %s' % ('string', 'name', 'refs', 'containing funcs'))
for va, nm in sorted(STR.items()):
    refs = T.find_refs(va)
    fs = sorted(set('0x%X(size~0x%X)' % (T.func_of(a), 0)
                    for a, k in refs))
    addrs = sorted(set(T.func_of(a) for a, k in refs))
    print('0x%08X %-32s n=%-3d %s' % (va, nm, len(refs),
          ' '.join('0x%X' % a for a in addrs[:6])))

print('\n=== 每个候选函数的起始地址处打印的自述字符串 (前 0x120 字节内的引用) ===')
# 反查: 各函数开头引用了哪条 "签名" 字符串
SIGS = [0x101354E, 0x101356F, 0x1013599, 0x10135C3, 0x1013626, 0x1013650, 0x1013676, 0x10136AA,
        0x10136CF, 0x10136FD]
for s in SIGS:
    for a, k in T.find_refs(s):
        f = T.func_of(a)
        print('  sig 0x%X "%s" -> func 0x%X (ref site 0x%X)' % (s, T.cstr(s, 60), f, a))
