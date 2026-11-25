"""Verify Senser page reads by comparing the live av-cam image head with the local file."""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-avcam-head-20261121'
PA = 0x035C6000
SIZE = 4096
LOCAL = BASE / '05-原始固件/qemu_in/av-cam.bin'

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'One bounded read-only 4 KiB page at the documented av-cam load address',
               'physical': hex(PA), 'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        data = cam.readMemory(PA, SIZE)
        if len(data) != SIZE:
            raise RuntimeError(f'expected {SIZE}, got {len(data)}')
        (OUT / 'page-avcam-head.bin').write_bytes(data)
        local = LOCAL.read_bytes()[:SIZE]
        match = sum(1 for a, b in zip(data, local) if a == b)
        receipt.update({
            'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'local_sha256': hashlib.sha256(local).hexdigest(),
            'identical_bytes': match,
            'total': SIZE,
            'live_head': data[:64].hex(),
            'local_head': local[:64].hex(),
        })
        print(json.dumps(receipt, indent=2), flush=True)

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
