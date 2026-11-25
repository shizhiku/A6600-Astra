"""Map how much of the av-cam image is actually resident, with bounded page reads.

One Senser session, a fixed list of pages. Read-only.
"""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
OUT = BASE / '03-证据/相机采集/live-avcam-extent-20261121'
LOCAL = BASE / '05-原始固件/qemu_in/av-cam.bin'
PA0 = 0x035C6000
SIZE = 4096
OFFSETS = [0x000000, 0x200000, 0x400000, 0x600000, 0x800000,
           0x900000, 0xA00000, 0xAC0000, 0xB00000, 0xB0C000,
           0xC00000, 0xE00000, 0x1000000]

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    local = LOCAL.read_bytes()
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Bounded read-only page sampling to locate the resident extent of av-cam',
               'load_address': hex(PA0), 'local_bytes': len(local),
               'offsets': [hex(o) for o in OFFSETS], 'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        rows = []
        for off in OFFSETS:
            pa = PA0 + off
            data = cam.readMemory(pa, SIZE)
            if len(data) != SIZE:
                raise RuntimeError(f'page at {off:#x}: got {len(data)}')
            ref = local[off:off + SIZE]
            same = sum(1 for a, b in zip(data, ref) if a == b)
            all_ff = all(b == 0xFF for b in data)
            all_00 = all(b == 0 for b in data)
            row = {'file_offset': hex(off), 'physical': hex(pa),
                   'identical_bytes': same, 'all_0xff': all_ff, 'all_0x00': all_00,
                   'live_head': data[:16].hex(), 'local_head': ref[:16].hex()}
            rows.append(row)
            print(json.dumps(row), flush=True)
        receipt['pages'] = rows

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
