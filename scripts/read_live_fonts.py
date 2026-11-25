"""Try reading the Chinese .ltt font files from the camera (read-only)."""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-fonts-20261121'
PATHS = [
    '/usr/share/app/MYingHeiC-GB18030-SJ_wIcon.ltt',
    '/tmp/images/MYingHeiC-GB18030-SJ_wIcon.ltt',
]

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only font file probe', 'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        rows = []
        for path in PATHS:
            try:
                data = cam.readFile(path)
                name = path.strip('/').replace('/', '_')
                (OUT / name).write_bytes(data)
                rows.append({'path': path, 'bytes': len(data),
                             'sha256': hashlib.sha256(data).hexdigest()})
                print('OK', path, len(data), 'bytes')
            except Exception as exc:
                rows.append({'path': path, 'error': f'{type(exc).__name__}: {exc}'})
                print('ERR', path, type(exc).__name__)
        receipt['files'] = rows

    try:
        senserShellCommand(driverName='libusb', complete=cb)
    finally:
        (OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    if not receipt['callback_entered']:
        raise SystemExit('camera not reached')

if __name__ == '__main__':
    main()
