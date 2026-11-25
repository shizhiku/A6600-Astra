"""Read two bounded 4 KiB pages from the camera to compare live av-cam state bytes.

Read-only. No file, RAM or settings writes. Two pages only.
Page A: PA 0x040D2000  (contains VA 0x640D26A3 -> predicate buffer byte)
Page B: PA 0x044AE000  (contains VA 0x644AE3A5 -> expected-value global)
"""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-avcam-state-20261121'
PAGES = [('A', 0x040D2000), ('B', 0x044AE000)]
SIZE = 4096

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Two bounded read-only 4 KiB physical pages; no writes of any kind',
               'pages': [{'label': l, 'physical': hex(p)} for l, p in PAGES],
               'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        for label, pa in PAGES:
            data = cam.readMemory(pa, SIZE)
            if len(data) != SIZE:
                raise RuntimeError(f'page {label}: expected {SIZE}, got {len(data)}')
            name = f'page-{label}-{pa:08X}.bin'
            (OUT / name).write_bytes(data)
            entry = {'label': label, 'physical': hex(pa), 'bytes': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
            if label == 'A':
                off = 0x040D26A3 - pa
                entry['shared_byte_640D26A3'] = hex(data[off])
                entry['bytes_around'] = data[off-3:off+5].hex()
            else:
                off = 0x044AE3A5 - pa
                entry['global_byte_644AE3A5'] = hex(data[off])
                entry['bytes_around'] = data[off-3:off+5].hex()
            receipt.setdefault('reads', []).append(entry)
            print(json.dumps(entry), flush=True)

    try:
        senserShellCommand(driverName='libusb', complete=cb)
    except Exception as exc:
        receipt['session_error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    if not receipt['callback_entered']:
        raise SystemExit('capture callback not reached; no data assumed')
    print('CAPTURE ' + str(OUT), flush=True)

if __name__ == '__main__':
    main()
