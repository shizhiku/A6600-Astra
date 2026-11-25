"""Capture av-cam pages with data retained, for offline comparison against the local image."""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-avcam-pages-20261121'
PA0 = 0x035C6000
SIZE = 4096
OFFSETS = [0x000000, 0x100000, 0x200000, 0x400000, 0x600000,
           0x800000, 0x900000, 0xA00000, 0xAC0000, 0xB00000,
           0xC00000, 0xE00000, 0x1000000]

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only capture of bounded av-cam pages, data retained for comparison',
               'load_address': hex(PA0), 'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        rows = []
        for off in OFFSETS:
            pa = PA0 + off
            data = cam.readMemory(pa, SIZE)
            if len(data) != SIZE:
                raise RuntimeError(f'page {off:#x}: short read {len(data)}')
            name = f'page-{off:08X}.bin'
            (OUT / name).write_bytes(data)
            rows.append({'file_offset': hex(off), 'physical': hex(pa), 'local': name,
                         'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
            print(f'OK {off:#010x} {name}', flush=True)
        receipt['pages'] = rows

    try:
        senserShellCommand(driverName='libusb', complete=cb)
    except Exception as exc:
        receipt['session_error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    if not receipt['callback_entered']:
        raise SystemExit('callback not reached')
    print('CAPTURE ' + str(OUT), flush=True)

if __name__ == '__main__':
    main()
