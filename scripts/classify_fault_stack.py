"""Classify words in the recorded kernel stack dump by owning module range."""
from pathlib import Path
import re, json

BASE = Path(r'<WORKSPACE>')
LOG = BASE / '03-证据/模拟器运行/captured-stock-20261120T151942Z-27058/serial.log'

# module ranges observed in the same boot log
MODULES = [
    ('devno',        0x5f000000, 0x5f000724 + 2161),
    ('dmac',         0x5f004000, 0x5f004000 + 12460),
    ('ldec',         0x5f00b000, 0x5f00b000 + 10134),
    ('osal_uipc',    0x5f046000, 0x5f046000 + 37433),
    ('osal_ulogio',  0x5f070000, 0x5f070000 + 29859),
    ('liro',         0x5f4e0000, 0x5f4e0000 + 51420),
    ('usbg_buspower',0x5f4f3000, 0x5f4f3000 + 9293),
    ('usb_darwin',   0x5f4f9000, 0x5f4f9000 + 21440),
    ('av-cam',       0x635c6000, 0x635c6000 + 16825940),
    ('kernel',       0x60000000, 0x60400000),
    ('stack/heap',   0x60a00000, 0x60b00000),
    ('av-cam data',  0x64000000, 0x645c8b44),
]

def classify(v):
    for name, lo, hi in MODULES:
        if lo <= v < hi:
            return name, v - lo
    return None, None

def main():
    lines = []
    for raw in LOG.read_text(errors='replace').splitlines():
        m = re.match(r'^(0x[0-9a-f]{8}):\s+(.*)$', raw.strip())
        if m:
            addr = int(m.group(1), 16)
            words = [int(w, 16) for w in re.findall(r'0x[0-9a-f]{8}', m.group(2))]
            for i, w in enumerate(words):
                lines.append((addr + 4 * i, w))
    # keep only the fault-time window seen in the log
    window = [(a, w) for a, w in lines if 0x60a6bd88 <= a < 0x60a6c000]
    out = []
    for a, w in window:
        mod, off = classify(w)
        if mod:
            out.append({'stack_addr': hex(a), 'value': hex(w), 'module': mod, 'offset': hex(off)})
    print(f'stack words in window: {len(window)}, classified as code/data pointers: {len(out)}')
    for e in out:
        print(f"  {e['stack_addr']} -> {e['value']}  {e['module']}+{e['offset']}")
    (BASE / '03-证据/静态分析/liro-fault-static/fault-stack-classified.json').write_text(
        json.dumps({'window': ['0x60a6bd88', '0x60a6c000'], 'classified': out}, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
