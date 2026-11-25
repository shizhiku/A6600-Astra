"""Read tiny sysfs/proc text files to learn the live av-cam load address and module bases.

Read-only, a handful of small text files. No memory pages, no writes.
"""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-layout-20261121'
FILES = [
    '/sys/module/liro/parameters/adr',
    '/proc/modules',
    '/proc/cmdline',
]

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only small text files (sysfs parameter, module list, cmdline)',
               'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        got = []
        for path in FILES:
            try:
                data = cam.readFile(path)
            except Exception as exc:
                got.append({'path': path, 'error': f'{type(exc).__name__}: {exc}'})
                print(f'ERR {path} {type(exc).__name__}', flush=True)
                continue
            name = path.strip('/').replace('/', '_')
            (OUT / name).write_bytes(data)
            entry = {'path': path, 'bytes': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
            text = data.decode('latin1', 'replace')
            entry['head'] = text[:400]
            got.append(entry)
            print(f'OK {path} {len(data)}B', flush=True)
        receipt['files'] = got

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
