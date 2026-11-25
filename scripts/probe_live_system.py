"""Probe the camera for /system structure and mount info (read-only)."""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-system-20261121'
PATHS = [
    '/proc/mounts',
    '/proc/self/mountinfo',
    '/system',
    '/system/version.txt',
    '/system/sabin/ssboot.bin',
    '/system/lib/libMWF.so',
    '/system/lib',
]

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only /system and mount probe', 'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        rows = []
        for path in PATHS:
            try:
                data = cam.readFile(path)
                name = path.strip('/').replace('/', '_') or 'root'
                (OUT / name).write_bytes(data)
                info = {'path': path, 'bytes': len(data),
                        'sha256': hashlib.sha256(data).hexdigest()}
                head = data[:400]
                if path.startswith('/proc'):
                    info['text'] = head.decode('latin1', 'replace')
                rows.append(info)
                print(f'OK   {path}  {len(data)} bytes')
                if path.startswith('/proc'):
                    print(head.decode('latin1', 'replace')[:800])
            except Exception as exc:
                rows.append({'path': path, 'error': f'{type(exc).__name__}: {exc}'})
                print(f'ERR  {path}  {type(exc).__name__}')
        receipt['files'] = rows

    try:
        senserShellCommand(driverName='libusb', complete=cb)
    finally:
        (OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    if not receipt['callback_entered']:
        raise SystemExit('camera not reached')

if __name__ == '__main__':
    main()
