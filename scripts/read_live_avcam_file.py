"""Try to read the camera's own av-cam.bin through the Senser file API.

Read-only. Probes a few likely paths and saves whatever exists.
"""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-avcam-file-20261121'
CANDIDATES = ['/system/av-cam.bin', '/av-cam.bin', '/system/AV-CAM.BIN']
LIMIT = 24 * 1024 * 1024

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only read of the camera av-cam file via the file API',
               'candidates': CANDIDATES, 'limit': LIMIT, 'callback_entered': False}

    class Bounded:
        def __init__(self, limit):
            self.buf = bytearray()
            self.limit = limit
        def write(self, b):
            if len(self.buf) + len(b) > self.limit:
                raise RuntimeError('read limit exceeded')
            self.buf.extend(b)
            return len(b)
        def getvalue(self):
            return bytes(self.buf)

    def cb(cam):
        receipt['callback_entered'] = True
        rows = []
        for path in CANDIDATES:
            buf = Bounded(LIMIT)
            try:
                cam.readFile(path, buf)
                data = buf.getvalue()
                name = path.strip('/').replace('/', '_')
                (OUT / name).write_bytes(data)
                entry = {'path': path, 'bytes': len(data),
                         'sha256': hashlib.sha256(data).hexdigest(),
                         'head': data[:32].hex()}
            except Exception as exc:
                entry = {'path': path, 'error': f'{type(exc).__name__}: {exc}'}
            rows.append(entry)
            print(json.dumps(entry), flush=True)
        receipt['results'] = rows

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
