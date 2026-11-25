"""Fetch every font listed in fontlist.dat from the camera's /tmp/images (read-only)."""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-fonts-20261121'
NAMES = [
    'UniversOTS-SJ_wIcon.ltt',
    'HeiseiKakuGothW5-SJ_wIcon.ltt',
    'MYingHeiC-KSX1001-SJ_wIcon.ltt',
    'MYingHeiC-GB18030-SJ_wIcon.ltt',
    'MYingHeiC-Big5-SJ_wIcon.ltt',
    'MYingHeiC-GB2312-SJ_wIcon.ltt',
    'MYingHeiC-Big5HKSCS-SJ_wIcon.ltt',
    'Sony_DI_Icons.ttf',
]
PATHS = [f'/tmp/images/{n}' for n in NAMES]

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only font set capture from /tmp/images', 'callback_entered': False,
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
        (OUT / 'receipt-fontset.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    if not receipt['callback_entered']:
        raise SystemExit('camera not reached')

if __name__ == '__main__':
    main()
