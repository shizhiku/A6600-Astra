"""Read the camera's own libc (read-only) and compare bytes at the syscall site."""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-libc-20261121'
PATHS = ['/lib/libc-2.11.2.so']
OFFSET = 0x9AC2A

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only read of the camera libc via the file API',
               'paths': PATHS, 'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        rows = []
        for path in PATHS:
            try:
                data = cam.readFile(path)
            except Exception as exc:
                rows.append({'path': path, 'error': f'{type(exc).__name__}: {exc}'})
                print(f'ERR {path} {type(exc).__name__}', flush=True)
                continue
            name = path.strip('/').replace('/', '_')
            (OUT / name).write_bytes(data)
            row = {'path': path, 'bytes': len(data),
                   'sha256': hashlib.sha256(data).hexdigest(),
                   'site_hex': data[OFFSET:OFFSET + 8].hex(' ') if len(data) > OFFSET + 8 else None}
            rows.append(row)
            print(json.dumps(row), flush=True)
        receipt['files'] = rows

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
