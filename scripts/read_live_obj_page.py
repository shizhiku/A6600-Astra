"""Read one page from the live camera at the predicate object's physical address.

Read-only, single 4 KiB page.
"""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-obj-page-20261121'
PA = 0x040E4000          # page containing VA 0x640E46A0
OBJ_OFF = 0x040E46A0 - PA
SIZE = 4096

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'One bounded read-only 4 KiB page at the predicate object physical address',
               'physical': hex(PA), 'object_offset_in_page': hex(OBJ_OFF),
               'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        data = cam.readMemory(PA, SIZE)
        if len(data) != SIZE:
            raise RuntimeError(f'short read {len(data)}')
        (OUT / 'page-040E4000.bin').write_bytes(data)
        obj = data[OBJ_OFF:OBJ_OFF + 32]
        receipt.update({
            'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'object_hex': obj.hex(),
            'object_ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in obj),
            'object_word0': obj[:4].hex(),
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
