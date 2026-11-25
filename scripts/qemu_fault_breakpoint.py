#!/usr/bin/env python3
"""Bounded, offline QEMU observations of original a6600 firmware.

Hardware breakpoints and data reads only. --watch executes one original
store after removing its watchpoint. No firmware/register/memory patches.
"""
from pathlib import Path
import argparse
import collections
import datetime
import hashlib
import json
import os
import resource
import shutil
import socket
import subprocess
import time

BASE = Path('<WORKSPACE>')
DATA = BASE / '05-原始固件/qemu_in'
EMMC = Path('/root/qemu_in/emmc.img')
QEMU = Path('/root/qemu-11.1.3/build')
CONTROL = Path('/root/a6600-emulation/captured-stock-20261120T151942Z-27058')
FATAL_PC = 0x63849f30
STATE = 0x64437e98
LOG_LIMIT = 32 * 1024 * 1024

class RSP:
    def __init__(self, connection):
        self.s = connection

    def exact(self, n):
        result = bytearray()
        while len(result) < n:
            chunk = self.s.recv(n - len(result))
            if not chunk:
                raise EOFError('GDB connection closed')
            result.extend(chunk)
        return bytes(result)

    def receive(self):
        while self.exact(1) != b'$':
            pass
        raw = bytearray()
        while True:
            b = self.exact(1)
            if b == b'#':
                break
            raw.extend(b)
        if int(self.exact(2), 16) != (sum(raw) & 255):
            self.s.sendall(b'-')
            raise RuntimeError('GDB packet checksum mismatch')
        self.s.sendall(b'+')
        result = bytearray()
        i = 0
        while i < len(raw):
            if raw[i] == 125:
                i += 1
                result.append(raw[i] ^ 32)
            elif raw[i] == 42:
                i += 1
                result.extend(bytes([result[-1]]) * (raw[i] - 29))
            else:
                result.append(raw[i])
            i += 1
        return result.decode('ascii')

    def command(self, text):
        data = text.encode()
        self.s.sendall(b'$' + data + b'#' + f'{sum(data) & 255:02x}'.encode())
        return self.receive()

    def memory(self, address, size):
        answer = self.command(f'm{address:x},{size:x}')
        if answer.startswith('E'):
            return {'address': hex(address), 'error': answer}
        value = bytes.fromhex(answer)
        if len(value) != size:
            raise RuntimeError('Short GDB memory observation')
        return {'address': hex(address), 'bytes': size, 'hex': answer}

    def registers(self):
        raw = self.command('g')
        if raw.startswith('E'):
            raise RuntimeError('ARM core register packet unavailable')
        data = bytes.fromhex(raw)
        # 32-bit ARM: this QEMU returns 4 bytes per core register (16 regs).
        if len(data) < 64:
            raise RuntimeError(f'Short register packet: {len(data)} bytes')
        return [int.from_bytes(data[i*4:(i+1)*4], 'little') for i in range(16)]

def parse_read_reg(spec):
    reg, _, size = spec.partition(':')
    reg = reg.strip().lower()
    if not reg.startswith('r'):
        raise ValueError(f'bad register {reg!r}')
    return int(reg[1:]), int(size or '4', 0)


def file_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LOG_LIMIT, LOG_LIMIT))

def prepare(run):
    subprocess.run([str(QEMU/'qemu-img'), 'create', '-q', '-f', 'qcow2', '-F', 'raw', '-b', str(EMMC), str(run/'overlay.qcow2')], check=True)
    for name in ('stock-usr.bin', 'setting.img'):
        shutil.copyfile(CONTROL/name, run/name)
    with (run/'overlay.log').open('wb') as log:
        subprocess.run([str(QEMU/'qemu-io'), '-f', 'qcow2', '-c', 'write -s stock-usr.bin 771751936 215517184', '-c', 'write -s setting.img 16777216 20971520', 'overlay.qcow2'], cwd=run, stdout=log, stderr=log, check=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--watch', action='store_true')
    ap.add_argument('--trace-sio', action='store_true')
    ap.add_argument('--submicro-frames', type=Path)
    ap.add_argument('--trace-predicate', action='store_true')
    ap.add_argument('--watch-target', type=lambda x: int(x, 0))
    ap.add_argument('--evsel-late-us', type=int)
    ap.add_argument('--entry-breakpoint', type=lambda x: int(x, 0))
    ap.add_argument('--count-breakpoint', type=lambda x: int(x, 0))
    ap.add_argument('--count-limit', type=int, default=40)
    ap.add_argument('--clear-breakpoint', type=lambda x: int(x, 0))
    ap.add_argument('--read-address', type=lambda x: int(x, 0), action='append', default=[])
    ap.add_argument('--sequence-breakpoint', type=lambda x: int(x, 0), action='append', default=[])
    ap.add_argument('--read-reg', action='append', default=[],
                    help='reg:size, e.g. r0:8 reads memory at the address held in r0')
    ap.add_argument('--wall-seconds', type=int, default=120)
    ap.add_argument('--seq-filter-reg', type=int)
    ap.add_argument('--seq-filter-value', type=lambda x: int(x, 0))
    args = ap.parse_args()
    name = 'observe-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + f'-{os.getpid()}'
    run = Path('/root/a6600-emulation')/name
    run.mkdir(parents=True)
    report = {'scope': 'Offline stock firmware; no bypass or firmware mutation', 'observer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'mode': {'watch': args.watch, 'trace_sio': args.trace_sio, 'submicro_frames': str(args.submicro_frames) if args.submicro_frames else None, 'trace_predicate': args.trace_predicate, 'watch_target': hex(args.watch_target) if args.watch_target is not None else None, 'evsel_late_us': args.evsel_late_us, 'entry_breakpoint': hex(args.entry_breakpoint) if args.entry_breakpoint is not None else None}, 'wall_seconds_limit': args.wall_seconds, 'max_log_file_bytes': LOG_LIMIT}
    prepare(run)
    machine = 'sony-a6400'
    if args.submicro_frames:
        frame_data = args.submicro_frames.read_bytes()
        if len(frame_data) != 384:
            raise ValueError(f'submicro frame input must be 384 bytes, got {len(frame_data)}')
        machine += ',submicro-frames=' + str(args.submicro_frames)
        report['submicro_input'] = {'path': str(args.submicro_frames), 'bytes': len(frame_data), 'sha256': hashlib.sha256(frame_data).hexdigest()}
    argv = [str(QEMU/'qemu-system-arm'), '-M', machine, '-m', '1G', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-kernel', str(DATA/'nflasha3-Image'), '-initrd', os.environ.get('INITRD_IMG', str(DATA / 'nflasha3-initrd')), '-append', (CONTROL/'cmdline.txt').read_text() + os.environ.get('CMDLINE_EXTRA', ''), '-drive', f'if=sd,format=qcow2,file={run}/overlay.qcow2', '-device', f'loader,file={os.environ.get('BACKUP_IMG', str(CONTROL / 'Backup.bin'))},addr=0x02E80000,force-raw=on', '-device', f'loader,file={os.environ.get('AVCAM_IMG', str(DATA / 'av-cam-live.bin'))},addr=0x035C6000,force-raw=on', '-icount', 'shift=0,sleep=on', '-S', '-gdb', f'unix:{run}/gdb.sock,server=on,wait=off']
    if args.evsel_late_us is not None:
        if not 0 <= args.evsel_late_us <= 100000:
            raise ValueError('EVSEL delay outside bounded range')
        argv += ['-global', 'cxd90014-evsel.late-src=30', '-global', f'cxd90014-evsel.late-us={args.evsel_late_us}']
    if args.trace_sio:
        argv += ['-d', 'unimp', '-D', str(run/'unimplemented.log')]
    report['command'] = argv
    env = os.environ.copy()
    env.pop('A6400_SIO_MARKER', None)
    report['environment_policy'] = 'A6400_SIO_MARKER unset; authentic static frame replay only when explicitly supplied'
    process = None
    connection = None
    try:
        with (run/'serial.log').open('wb') as serial, (run/'stderr.log').open('wb') as err:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=serial, stderr=err, env=env, preexec_fn=file_limit)
            deadline = time.monotonic() + 120
            while not (run/'gdb.sock').exists():
                if process.poll() is not None:
                    raise RuntimeError('QEMU exited before GDB attach')
                if time.monotonic() > deadline:
                    raise TimeoutError('GDB socket unavailable')
                time.sleep(0.05)
            connection = socket.socket(socket.AF_UNIX)
            connection.settimeout(max(1, deadline-time.monotonic()))
            connection.connect(str(run/'gdb.sock'))
            rsp = RSP(connection)
            report['supported'] = rsp.command('qSupported')
            report['initial_stop'] = rsp.command('?')
            report['breakpoint_set'] = rsp.command(f'Z1,{FATAL_PC:x},2')
            if report['breakpoint_set'] != 'OK':
                raise RuntimeError('Hardware breakpoint refused')
            if args.entry_breakpoint is not None:
                report['entry_breakpoint_set'] = rsp.command(f'Z1,{args.entry_breakpoint:x},2')
                if report['entry_breakpoint_set'] != 'OK':
                    raise RuntimeError('Entry breakpoint refused')
            if args.count_breakpoint is not None:
                report['count_breakpoint_set'] = rsp.command(f'Z1,{args.count_breakpoint:x},2')
                if report['count_breakpoint_set'] != 'OK':
                    raise RuntimeError('Count breakpoint refused')
            if args.clear_breakpoint is not None:
                report['clear_breakpoint_set'] = rsp.command(f'Z1,{args.clear_breakpoint:x},2')
                if report['clear_breakpoint_set'] != 'OK':
                    raise RuntimeError('Clear breakpoint refused')
            if args.sequence_breakpoint:
                report['sequence_breakpoints_set'] = []
                for addr in args.sequence_breakpoint:
                    reply = rsp.command(f'Z1,{addr:x},2')
                    if reply != 'OK':
                        raise RuntimeError(f'Sequence breakpoint refused at {addr:#x}')
                    report['sequence_breakpoints_set'].append(hex(addr))
            if args.trace_predicate:
                report['predicate_breakpoint_set'] = rsp.command('Z1,63849efc,2')
                if report['predicate_breakpoint_set'] != 'OK':
                    raise RuntimeError('Predicate breakpoint refused')
            if args.watch_target is not None:
                report['watch_target_set'] = rsp.command(f'Z2,{args.watch_target:x},4')
                if report['watch_target_set'] != 'OK':
                    raise RuntimeError('Target data watchpoint refused')
            if args.watch:
                report['watchpoint_set'] = rsp.command(f'Z2,{STATE+2:x},1')
                if report['watchpoint_set'] != 'OK':
                    raise RuntimeError('Data watchpoint refused')
            print('OBSERVATION_ARMED', flush=True)
            connection.settimeout(max(1, deadline-time.monotonic()))
            if args.sequence_breakpoint:
                events = []
                status = 'sequence_budget_exhausted'
                matched = 0
                max_iter = max(args.count_limit * 500, 1000)
                for _iteration in range(max_iter):
                    if matched >= args.count_limit:
                        break
                    stop = rsp.command('c')
                    regs = rsp.registers()
                    pc = regs[15]
                    reads = {hex(a): rsp.memory(a, 4).get('hex') for a in args.read_address}
                    # step off the breakpoint so the next continue makes real progress
                    for addr in args.sequence_breakpoint:
                        rsp.command(f'z1,{addr:x},2')
                    rsp.command('s')
                    if args.seq_filter_reg is not None and \
                            regs[args.seq_filter_reg] != args.seq_filter_value:
                        for addr in args.sequence_breakpoint:
                            rsp.command(f'Z1,{addr:x},2')
                        continue
                    index = matched
                    matched += 1
                    for spec in args.read_reg:
                        idx, size = parse_read_reg(spec)
                        addr = regs[idx]
                        reads[f'{spec}@{addr:#x}'] = rsp.memory(addr, size).get('hex')
                    events.append({'index': index, 'pc': hex(pc),
                                   'r0': hex(regs[0]), 'r1': hex(regs[1]),
                                   'r2': hex(regs[2]), 'r3': hex(regs[3]),
                                   'thread': stop.split('thread:')[1].rstrip(';') if 'thread:' in stop else None,
                                   'reads': reads})
                    print(f'SEQ {index} pc={pc:#x} ' + json.dumps(reads), flush=True)
                    if pc == FATAL_PC:
                        status = 'fatal_pc_reached'
                        break
                    for addr in args.sequence_breakpoint:
                        rsp.command(f'Z1,{addr:x},2')
                report['sequence_events'] = events
                report['sequence_first_hits'] = {}
                for bp in args.sequence_breakpoint:
                    report['sequence_first_hits'][hex(bp)] = next(
                        (e['index'] for e in events if e['pc'] == hex(bp)), None)
                report['status'] = status
                report['stop_reply'] = stop
            elif args.watch_target is not None:
                report['target_write_events'] = []
                for index in range(max(32, args.count_limit)):
                    stop = rsp.command('c')
                    regs = rsp.registers()
                    before = rsp.memory(args.watch_target, 4)
                    event = {'index': index, 'stop': stop, 'pc': hex(regs[15]), 'registers': {f'r{i}': hex(v) for i, v in enumerate(regs)}, 'target_before_or_at_stop': before, 'instructions': rsp.memory(regs[15]-4, 12)}
                    if regs[15] == FATAL_PC:
                        event['kind'] = 'fatal_pc'
                        report['target_write_events'].append(event)
                        report['status'] = 'fatal_pc_before_target_write'
                        break
                    if rsp.command(f'z2,{args.watch_target:x},4') != 'OK':
                        raise RuntimeError('Cannot remove target watchpoint for one original step')
                    event['single_step_reply'] = rsp.command('s')
                    event['target_after_single_step'] = rsp.memory(args.watch_target, 4)
                    event['kind'] = 'watchpoint_stop_then_one_original_instruction_step'
                    report['target_write_events'].append(event)
                    if regs[15] == FATAL_PC:
                        report['status'] = 'fatal_pc_after_step'
                        break
                    if rsp.command(f'Z2,{args.watch_target:x},4') != 'OK':
                        raise RuntimeError('Cannot re-arm target watchpoint')
                    print('WATCH '+str(index)+' PC='+hex(regs[15])+' LR='+hex(regs[14])+' VALUE='+event['target_after_single_step'].get('hex','?'), flush=True)
                else:
                    report['status'] = 'target_watchpoint_budget_exhausted'
                report['stop_reply'] = stop
            elif args.sequence_breakpoint:
                events = []
                status = 'sequence_budget_exhausted'
                target = args.sequence_breakpoint[0]
                watch_slot = args.watch_target if args.watch_target is not None else None
                for index in range(args.count_limit):
                    stop = rsp.command('c')
                    regs = rsp.registers()
                    pc = regs[15]
                    slot = rsp.memory(watch_slot, 4).get('hex') if watch_slot else None
                    events.append({'index': index, 'pc': hex(pc), 'slot_hex': slot,
                                   'thread': stop.split('thread:')[1].rstrip(';') if 'thread:' in stop else None})
                    print(f'SEQ {index} pc={pc:#x} slot={slot}', flush=True)
                    if pc == FATAL_PC:
                        status = 'fatal_pc_reached'
                        break
                    for addr in args.sequence_breakpoint:
                        rsp.command(f'Z1,{addr:x},2')
                report['sequence_events'] = events
                report['sequence_first_copy_index'] = next((e['index'] for e in events if e['pc'] == hex(target)), None)
                report['sequence_first_increment_index'] = next((e['index'] for e in events if e['pc'] == '0x63852a32'), None)
                report['status'] = status
                report['stop_reply'] = stop
            elif args.count_breakpoint is not None:
                hits = []
                status = 'count_budget_exhausted'
                counts = []
                clears = 0
                counter_addr = args.watch_target if args.watch_target is not None else 0x644ae3aa
                for index in range(args.count_limit):
                    stop = rsp.command('c')
                    regs = rsp.registers()
                    pc = regs[15]
                    value = rsp.memory(counter_addr, 1).get('hex')
                    thread = ''
                    if 'thread:' in stop:
                        thread = stop.split('thread:')[1].rstrip(';')
                    if pc == FATAL_PC:
                        status = 'fatal_pc_reached'
                        hits.append({'index': index, 'pc': hex(pc), 'kind': 'fatal_pc', 'thread': thread})
                        break
                    kind = 'unknown'
                    if args.clear_breakpoint is not None and pc == args.clear_breakpoint:
                        kind = 'clear'
                        clears += 1
                    elif pc == args.count_breakpoint:
                        kind = 'increment'
                        counts.append(int(value, 16) if value else None)
                    hits.append({'index': index, 'pc': hex(pc), 'kind': kind, 'thread': thread,
                                 'counter_value_hex': value, 'r2': hex(regs[2]),
                                 'reads': {hex(a): rsp.memory(a, 4).get('hex') for a in args.read_address}})
                    print(f'{kind.upper()} {index} pc={pc:#x} counter={value} thread={thread} '
                          f'reads=' + json.dumps({hex(a): rsp.memory(a, 4).get("hex") for a in args.read_address}), flush=True)
                report['count_hits'] = hits
                report['increment_count'] = len(counts)
                report['clear_count'] = clears
                report['counter_values_after_increment'] = counts
                report['max_counter_observed'] = max([c for c in counts if c is not None], default=None)
                report['status'] = status
                report['stop_reply'] = stop
            elif args.entry_breakpoint is not None:
                report['entry_stop_reply'] = rsp.command('c')
                regs = rsp.registers()
                report['entry_registers'] = {f'r{i}': hex(v) for i, v in enumerate(regs)}
                report['entry_pc_matches'] = regs[15] == args.entry_breakpoint
                report['caller_lr'] = hex(regs[14])
                report['return_site_bytes'] = rsp.memory((regs[14] & ~1)-8, 16)
                report['entry_stack'] = rsp.memory(regs[13], 96)
                report['status'] = 'routine_entry_observed' if report['entry_pc_matches'] else 'unexpected_entry_stop'
                report['stop_reply'] = report['entry_stop_reply']
                print('ENTRY '+report['status']+' LR='+hex(regs[14]), flush=True)
            elif args.trace_predicate:
                report['predicate_stop_reply'] = rsp.command('c')
                predicate_regs = rsp.registers()
                report['predicate_registers'] = {f'r{i}': hex(v) for i, v in enumerate(predicate_regs)}
                report['predicate_cmp_r0'] = hex(predicate_regs[0])
                report['predicate_cmp_r1'] = hex(predicate_regs[1])
                report['predicate_cmp_r2'] = hex(predicate_regs[2])
                report['predicate_cmp_r3'] = hex(predicate_regs[3])
                report['predicate_instructions'] = rsp.memory(predicate_regs[15], 8)
                if predicate_regs[15] != 0x63849efc:
                    raise RuntimeError(f'Unexpected predicate PC {predicate_regs[15]:#x}')
                if rsp.command('z1,63849efc,2') != 'OK':
                    raise RuntimeError('Cannot remove predicate breakpoint')
                report['stop_reply'] = rsp.command('c')
            else:
                report['stop_reply'] = rsp.command('c')
            if args.watch_target is None and args.entry_breakpoint is None and args.count_breakpoint is None:
                regs = rsp.registers()
                report['registers'] = {f'r{i}': hex(v) for i, v in enumerate(regs)}
                report['pc_matches'] = regs[15] == FATAL_PC
                report['instructions'] = rsp.memory(regs[15]-8, 24)
                report['state'] = rsp.memory(STATE, 64)
                pointer_slot = rsp.memory(0x645ca930, 4)
                pointer = int.from_bytes(bytes.fromhex(pointer_slot['hex']), 'little')
                report['predicate_flags_at_fault'] = {'global_6384cc94_target': rsp.memory(0x644ae302, 1), 'global_6384cca0_target': rsp.memory(0x644ae326, 1), 'getter_638516c8_pointer_slot': pointer_slot, 'getter_638516c8_dereferenced_value': rsp.memory(pointer, 4)}
                report['status'] = 'stopped_before_fault' if report['pc_matches'] else 'unexpected_stop'
                print('STOP '+report['status'], flush=True)
            else:
                report['status'] = report.get('status', 'target_watchpoint_observed')
                print('WATCH_STATUS '+report['status'], flush=True)
    except Exception as exc:
        report['status'] = 'error'
        report['error'] = f'{type(exc).__name__}: {exc}'
        print(report['error'], flush=True)
    finally:
        if connection:
            connection.close()
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        report['qemu_exit'] = process.returncode if process else None
        destination = BASE/'03-证据/模拟器运行'/name
        destination.mkdir(parents=True)
        if args.trace_sio and (run/'unimplemented.log').exists():
            counts = collections.Counter()
            samples = []
            with (run/'unimplemented.log').open(errors='replace') as log:
                for line in log:
                    if 'sony-a6400 sio ch' in line:
                        counts[line.split(' tx:')[0]] += 1
                        if len(samples) < 20:
                            samples.append(line.strip())
            report['sio'] = {'log_bytes': (run/'unimplemented.log').stat().st_size, 'transfer_counts': dict(counts), 'first_transfers': samples, 'raw_log': str(run/'unimplemented.log')}
        (run/'observation.json').write_text(json.dumps(report, indent=2))
        for name in ('observation.json', 'serial.log', 'stderr.log', 'overlay.log'):
            if (run/name).exists():
                shutil.copyfile(run/name, destination/name)
        print(json.dumps(report, indent=2), flush=True)
        print('RESULT '+str(destination), flush=True)

if __name__ == '__main__':
    main()
