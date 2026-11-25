"""Map known addresses from the update-package av-cam to the camera's av-cam.

Each old address is located in the new image by searching a 48-byte code snippet
and requiring a unique hit.
"""
from pathlib import Path
import json

BASE = Path(r'<WORKSPACE>')
OLD = BASE / '05-原始固件/qemu_in/av-cam.bin'
NEW = BASE / '05-原始固件/qemu_in/av-cam-live.bin'
OLD_BASE = 0x635C6000

# addresses of interest in the old build (runtime VA == base + file offset)
TARGETS = {
    'fatal_store_pc':      0x63849F30,
    'retry_routine':       0x638529D8,
    'retry_counter_write': 0x63852A32,
    'retry_clear_write':   0x63852A20,
    'getter_638516C8':     0x638516C8,
    'init_entry':          0x635E1A6C,
    'checkpoint_helper':   0x635E19D0,
    'callback_trampoline': 0x63CEFCAA,
    'loop_entry':          0x63D3B556,
}

old = OLD.read_bytes()
new = NEW.read_bytes()
rows = []
for name, va in TARGETS.items():
    off = va - OLD_BASE
    for span in (48, 32, 24):
        snippet = old[off:off + span]
        if len(snippet) < span:
            continue
        pos = new.find(snippet)
        if pos < 0:
            continue
        if new.find(snippet, pos + 1) >= 0:
            rows.append({'name': name, 'old_va': hex(va), 'span': span, 'result': 'ambiguous'})
            break
        rows.append({'name': name, 'old_va': hex(va), 'span': span,
                     'new_file_offset': hex(pos), 'new_va': hex(OLD_BASE + pos),
                     'delta': f'{pos - off:+#x}'})
        print(f'{name:22s} old={va:#010x} new={OLD_BASE + pos:#010x} delta={pos - off:+#x} (span {span})')
        break
    else:
        rows.append({'name': name, 'old_va': hex(va), 'result': 'not found'})
        print(f'{name:22s} old={va:#010x} NOT FOUND')

(BASE / '03-证据/静态分析/avcam-address-map.json').write_text(
    json.dumps(rows, indent=2), encoding='utf-8')
