#!/usr/bin/env python3
"""Remove only the previously installed probe preload artefacts from the camera.

Scope: delete /etc/ld.so.preload and the probe library copies created by the
earlier experiment. No other file is touched. Every step is recorded.
"""
from pathlib import Path
import sys, json, datetime, hashlib

BASE = Path('<LEGACY_WORKSPACE>')
OUT = BASE / 'a6600_port/captures/cleanup-20261121'
TARGETS = ['/etc/ld.so.preload', '/etc/astra_probe.so', '/setting/mode/astra_probe.so']

def main():
    if OUT.exists():
        raise SystemExit(f'refusing to overwrite {OUT}')
    OUT.mkdir(parents=True)
    sys.path.insert(0, '/root/a6600/pmca-vendor')
    sys.path.insert(0, '/root/a6600/probe')
    from pmca.commands.usb import senserShellCommand
    receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Delete only probe preload artefacts; no settings, partitions, or other files',
               'targets': TARGETS, 'steps': [], 'callback_entered': False}

    def record(step, **kw):
        entry = {'step': step, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        entry.update(kw)
        receipt['steps'].append(entry)
        (OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(json.dumps(entry), flush=True)

    def cb(cam):
        receipt['callback_entered'] = True
        # 1. pre-state
        for path in TARGETS:
            try:
                data = cam.readFile(path)
                record('read_before', path=path, bytes=len(data),
                       sha256=hashlib.sha256(data).hexdigest(),
                       preview=data[:64].decode('latin1', 'replace'))
            except Exception as exc:
                record('read_before_absent', path=path, error=f'{type(exc).__name__}: {exc}')
        # 2. delete only the ones that exist
        for path in TARGETS:
            try:
                cam.deleteFile(path)
                record('deleted', path=path)
            except Exception as exc:
                record('delete_failed', path=path, error=f'{type(exc).__name__}: {exc}')
        # 3. verify
        for path in TARGETS:
            try:
                data = cam.readFile(path)
                record('verify_still_present', path=path, bytes=len(data))
            except Exception as exc:
                record('verify_absent', path=path, error=f'{type(exc).__name__}: {exc}')
        # 4. responsiveness
        for attempt in (1, 2):
            try:
                up = cam.readFile('/proc/uptime')
                record('uptime', attempt=attempt, bytes=len(up),
                       text=up[:48].decode('latin1', 'replace'))
            except Exception as exc:
                record('uptime_failed', attempt=attempt, error=f'{type(exc).__name__}: {exc}')

    try:
        senserShellCommand(driverName='libusb', complete=cb)
    except Exception as exc:
        receipt['session_error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')

    if not receipt['callback_entered']:
        raise SystemExit('cleanup callback not reached; no change assumed')
    print('CLEANUP ' + str(OUT), flush=True)

if __name__ == '__main__':
    main()
