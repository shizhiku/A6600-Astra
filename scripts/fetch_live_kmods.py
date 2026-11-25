"""Fetch the missing kernel modules (msen_drv.ko, sata_drv.ko) from the camera (read-only)."""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-kmod-20261121'
PATHS = [
    '/usr/kmod/msen_drv.ko',
    '/usr/kmod/sata_drv.ko',
    '/usr/kmod/kikilog.ko',
]

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only kernel module capture', 'callback_entered': False,
               'files': []}

    def cb(cam):
        receipt['callback_entered'] = True
        for path in PATHS:
            try:
                data = cam.readFile(path)
                name = path.strip('/').replace('/', '_')
                (OUT / name).write_bytes(data)
                receipt['files'].append({'path': path, 'bytes': len(data),
                                         'sha256': hashlib.sha256(data).hexdigest()})
                print(f'OK   {path}  {len(data)} bytes')
            except Exception as exc:
                receipt['files'].append({'path': path, 'error': type(exc).__name__})
                print(f'ERR  {path}  {type(exc).__name__}')

    try:
        senserShellCommand(driverName='libusb', complete=cb)
    finally:
        (OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    if not receipt['callback_entered']:
        raise SystemExit('camera not reached')

if __name__ == '__main__':
    main()
