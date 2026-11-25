# -*- coding: utf-8 -*-
"""inputdrv_findings.py — 输出本轮 112 的机器可读关键结论（只读汇总，不重新分析）。"""
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'

FINDINGS = {
    'task': 'a6600 input.ko 用户态事件通道 / 四代·五代 InfraInput 队列争用',
    'report': '01-文档/112-input驱动事件通道分析.md',
    'inputs': {
        'g4_image': '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15',
        'g5_image': '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15',
        'g4_input_ko_sha256': '71cbca3d5a1bb2c2f35b4ba1ca296f717cbc4eb63a78b900b30d1a87df48cc32',
        'g4_g5_input_ko_diff': '36 bytes (.note.gnu.build-id 20B + .comment 16B); .text/.init.text/.rodata/.data identical',
    },
    'driver_interface': {
        'proc_path': '/proc/udm/input (udif/udm framework; descriptor name "input" at .data+0x18)',
        'proc_write_commands': ['table', 'get', 'adc', 'front', 'gpio', 'vgrip', 'multi_selector_soft'],
        'module_params': ['key_tbl', 'Input_debug', 'multi_selector_soft', 'is_representative_entry'],
        'own_queue_registration': {
            'qid': '0x00410025', 'handler': 'getkey_cb (.text+0x121C)',
            'api': 'osal_reg_sync_msg_queue_cb', 'register_site': '.text+0x3C5C',
            'unregister_site': '.text+0x3A98 (kbd_close)',
        },
        'event_channel': {
            'qid': '0x007A0020', 'size': 16, 'api': 'osal_snd_msg (async)',
            'sender': 'static .text+0x0BA0', 'callers_in_timer': ['0x2764', '0x2ADC', '0x2FA4', '0x3744'],
            'layout': ['+0x00 u32 code', '+0x04 u32 0', '+0x08 u32 value', '+0x0C u32 opt'],
            'msg_minus4_tag': '0x00410025 (driver queue id, candidate sender/reply tag)',
            'debug_log': 'kbd send osal type:%d code:%x value:%x opt:%x',
        },
        'pull_channels_sync': [
            {'qid': '0x00720018', 'size': 0x28, 'role': 'ADC/liro_adc', 'helper': '.text+0x0000'},
            {'qid': '0x00280132', 'size': 0x18, 'role': 'front(CA)', 'helper': '.text+0x00BC'},
            {'qid': '0x018A04D1', 'size': 8, 'role': 'vgrip', 'helper': '.text+0x0154'},
        ],
        'log_channels_not_events': [
            {'qid': '0x008F013A', 'envelope': 'u16 2/0x41 + u32 len + u64 ts(0x00910042) + payload', 'fallback': '0x008F0313'},
            {'qid': '0x00910042', 'role': 'timestamp source (snd_sync_direct, 32B)'},
        ],
    },
    'uipc_queue_semantics': {
        'qid_bits': '[group 12][bit15 local][index 15]; libosal_uipc: bit15=1 -> in-process queue, bit15=0 -> /dev/uipc kernel queue',
        'kernel_osal_requires': 'bit15 == 0 (else -1024)',
        'queue_object': 'single priority-ordered msg chain (head/tail) + waiter chain; one msg consumed per rcv_msg_tmo',
        'delivery': 'point-to-point; no fan-out; broadcast mode requires explicit osal_set_msgq_broadcast_mode (not used by driver/InfraInput)',
        'registration': 'reg_sync_msg_queue_cb single slot per queue (second returns 0xFFFFFC00); reg_msg_queue_cb attaches cb list',
        'qid_allocation': 'fixed compile-time constants (not allocated by open order)',
        'answer_if_two_consumers': 'both register/poll same qid -> each message delivered to exactly one consumer; no duplication; winner = scheduling/start order',
    },
    'consumers': {
        'g4_libObj': {
            'file': 'g4_libObj.so', 'sha256_prefix': 'ebb6cd0475ebfdb5',
            'MainThread': {'addr': '0x862430', 'reads': '0x007A804C', 'calls': 'osal_rcv_msg_tmo@0x862464'},
            'RecvThread': {'addr': '0x862D60', 'reads': '0x007A0020', 'calls': 'osal_rcv_msg_tmo@0x862D94',
                           'forwards_to_Main_via': '0x85F398(this, qid=0x7A804C, &event24, 24) @0x86313E; qid literal 0x863150'},
            'event_size': 24,
            'event_layout': {'+0x00': 'event_code', '+0x04': 'tp_x u16', '+0x06': 'tp_y u16',
                             '+0x08': 'status', '+0x0C': 'prev_status', '+0x10': 'ex_info', '+0x14': 'repeat'},
            'dispatch_gate': 'MainThread requires key_code registered in key_list (this+0x9c) else drops',
        },
        'g5_libObj(a5bObj)': {
            'file': 'g5_libObj.so', 'size': 3931624,
            'MainThread': {'addr': '0x209C58', 'reads': '0x007A804C', 'similarity_to_g4': 0.64},
            'RecvThread': {'addr': '0x20A588', 'reads': '0x007A0020', 'forward_literal': '0x20A978 (0x7A804C)', 'similarity_to_g4': 0.52},
            'infra_input_init': {'addr': '0x208134', 'tail': 'b.w 0x3A5A0 = InfraInput::GetInstance PLT (creates instance+4 I-Input* threads)'},
        },
        'g4_infra_input_init': {'addr': '0x8603A5', 'nature': 'log-only stub (does not create instance)'},
    },
    'dual_consumer_judgement': {
        'same_queue': True,
        'mechanism': 'both generations poll the same two qids (0x7A0020 cross, 0x7A804C process-local); single delivery by design',
        'who_wins': 'scheduler/start order; 4th-gen usually created earlier by 4th-gen modules (libBizFw2/libNetRemote/libUsbChargingApp import InfraInput::GetInstance)',
        'even_without_g5': '4th-gen MainThread consumes and drops events when InputService key_list is absent (ASTRA createEvent=0)',
        'runtime_check': ['count I-Input* threads (4 per instance)', 'breakpoints 0x862464 / 0x209C8C', '/proc/osal/uipc queue waiters'],
    },
    'fix_options_priority': [
        {
            'priority': 'A1', 'name': 'disable 4th-gen I-Input threads',
            'artifact': '03-证据/静态分析/imdb4/imdb4_libObj_noInputThreads.so',
            'patches': ['0x8606A0', '0x8606E4', '0x860728', '0x86076C: BLX osal_create_waitable_thread -> 00 BF 00 BF'],
            'note': 'keeps singleton/APIs; runtime side effects untested; blocks all 4th-gen event consumption',
        },
        {
            'priority': 'A2', 'name': 'retarget 4th-gen InfraInput queue ids',
            'patches': [
                {'offset': '0x86270C', 'old': '0x007A804C', 'new': '0x007A8060 (suggested)', 'role': 'MainThread rcv'},
                {'offset': '0x86301C', 'old': '0x007A0020', 'new': '0x007A0030 (suggested)', 'role': 'RecvThread rcv'},
                {'offset': '0x863150', 'old': '0x007A804C', 'new': '0x007A8060 (suggested)', 'role': 'RecvThread post-to-Main'},
            ],
            'note': 'libObj .text VA==file offset; 4th-gen instance becomes permanently idle; 5th-gen untouched',
        },
        {
            'priority': 'B', 'name': 'private queue for 5th gen (driver + a5bObj patch)',
            'patches': [
                {'file': 'g4/g5 /kmod/input.ko', 'offset': '0x0D24', 'old': '0x007A0020', 'new': 'new cross qid e.g. 0x007A0030'},
                {'file': 'a5bObj', 'offset': '0x20A844', 'old': '0x007A0020', 'new': 'same new cross qid'},
                {'file': 'a5bObj', 'offset': '0x209F34', 'old': '0x007A804C', 'new': 'new local qid e.g. 0x007A8060'},
                {'file': 'a5bObj', 'offset': '0x20A978', 'old': '0x007A804C', 'new': 'same new local qid'},
            ],
            'note': 'requires usr image repack (historically risky)',
        },
        {
            'priority': 'C', 'name': 'in-process direct dispatch to 5th-gen instance (LD_PRELOAD)',
            'steps': ['dlopen a5bObj RTLD_NOLOAD', 'dlsym InfraInput::GetInstance (g5 0x208005)',
                      'build 24B _InfraInputEvent (MENU=0x1AC, ENTER=0x1AD)',
                      'call g5 internal dispatch/post helper (g4 analogue 0x86092C SendAttachEvent / 0x85F398 post helper)'],
            'note': 'diagnostic; posting into 0x7A804C alone still races with 4th-gen MainThread unless A/B applied',
        },
        {'priority': 'D', 'name': 'driver second-target qid / subscription list', 'note': 'most invasive; not recommended'},
        {'priority': 'E', 'name': 'start 4th-gen InputService', 'note': 'wrong direction: makes 4th-gen consume even more'},
    ],
    'uncertainties': [
        '16B record -> _InfraInputEvent field-level binding (value/opt semantics; msg+0x04=0 role)',
        'owners of 0x720018 / 0x280132 / 0x18A04D1 (ADC/front/vgrip providers)',
        'whether both instances are actually created at runtime (thread-count/breakpoint check needed)',
        'status values for press/release (no static enum in firmware)',
        'side effects of A1 noInputThreads patch (threads/waits in 4th-gen code)',
        'g5 SendAttachEvent-equivalent address for option C',
    ],
}

if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=True)
    p = OUT / 'inputdrv_key_findings.json'
    p.write_text(json.dumps(FINDINGS, ensure_ascii=False, indent=1), encoding='utf-8')
    print('wrote', p, p.stat().st_size, 'bytes')
