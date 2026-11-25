"""One-shot verification: read the camera's libc and compare it with the update-package copy.

Usage (when the camera is connected, MSC mode is fine):
    python3 verify_live_libc.py

Prints a clear verdict about whether the two builds differ at the syscall site.
"""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<WORKSPACE>')
LOCAL = BASE / '03-证据/静态分析/nflasha7_libc-2.11.2.so'
OUT = BASE / '03-证据/相机采集/live-libc-20261121'
PATH_ON_CAM = '/lib/libc-2.11.2.so'
SITE = 0x9AC2A          # mov.w ip,#0xbf ; bl syscall stub
SITE_LEN = 8


def compare(live: bytes, local: bytes):
    n = min(len(live), len(local))
    same = sum(1 for i in range(0, n, 4096) if live[i:i + 4096] == local[i:i + 4096])
    total = (n + 4095) // 4096
    first = next((i for i in range(n) if live[i] != local[i]), None)
    return {
        'live_bytes': len(live), 'local_bytes': len(local),
        'identical_4k_blocks': same, 'total_4k_blocks': total,
        'first_diff': hex(first) if first is not None else None,
        'same_size': len(live) == len(local),
    }


def main():
    if not LOCAL.exists():
        raise SystemExit(f'local libc missing: {LOCAL}')
    local = LOCAL.read_bytes()
    OUT.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only single-file capture of the camera libc',
               'callback_entered': False}

    def cb(cam):
        receipt['callback_entered'] = True
        data = cam.readFile(PATH_ON_CAM)
        (OUT / 'system_libc-2.11.2.so').write_bytes(data)
        receipt['live_bytes'] = len(data)
        receipt['live_sha256'] = hashlib.sha256(data).hexdigest()
        receipt['site_live'] = data[SITE:SITE + SITE_LEN].hex(' ')
        receipt['site_local'] = local[SITE:SITE + SITE_LEN].hex(' ')
        receipt['comparison'] = compare(data, local)
        print(json.dumps(receipt, indent=2), flush=True)

    try:
        senserShellCommand(driverName='libusb', complete=cb)
    finally:
        receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    if not receipt['callback_entered']:
        raise SystemExit('camera not reached; nothing verified')

    same_site = receipt['site_live'] == receipt['site_local']
    print('\n=== VERDICT ===')
    if same_site and receipt['comparison']['same_size']:
        print('libc 与更新包一致 → 问题 B 不是构建差异造成的，需要查内核判定分支')
    elif same_site:
        print('syscall 现场一致但文件大小不同 → 需分别看待（系统调用号相同，B 另有原因）')
    else:
        print('syscall 现场不同 → 真机 libc 是另一构建，应改用真机 libc 重测')


if __name__ == '__main__':
    main()
