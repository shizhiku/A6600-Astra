"""Read several larger contiguous blocks from the live av-cam image.

Purpose: obtain dense coverage to locate where the file-to-memory offset changes.
Read-only, bounded: 4 blocks x 128 KiB = 512 KiB.
"""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-avcam-blocks-20261121'
PA0 = 0x035C6000
BLOCK = 0x20000
OFFSETS = [0x000000, 0x600000, 0xA00000, 0x1000000]

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only bounded blocks of the live av-cam image',
               'block_bytes': BLOCK, 'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        rows = []
        for off in OFFSETS:
            pa = PA0 + off
            data = cam.readMemory(pa, BLOCK)
            if len(data) != BLOCK:
                print(f'SHORT {off:#x}: {len(data)}', flush=True)
                rows.append({'file_offset': hex(off), 'got': len(data), 'error': 'short read'})
                continue
            name = f'block-{off:08X}.bin'
            (OUT / name).write_bytes(data)
            rows.append({'file_offset': hex(off), 'physical': hex(pa), 'local': name,
                         'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            print(f'OK {off:#010x} {name}', flush=True)
        receipt['blocks'] = rows

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
