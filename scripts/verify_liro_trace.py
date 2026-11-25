"""Verify bounded fault and state-copy observations against immutable local inputs."""
from pathlib import Path
import json,hashlib
r=Path(__file__).resolve().parent
av=(r/'qemu_in/av-cam.bin').read_bytes()
backup=(r/'a6600_port/captures/boot-20261120T151656Z-26869/05-setting__Backup.bin').read_bytes()
fault=json.loads((r/'a6600_port/emulation/breakpoint-20261120T153013Z-27606/breakpoint.json').read_text())
copy=json.loads((r/'a6600_port/emulation/breakpoint-20261120T153907Z-28123/breakpoint.json').read_text())
source=bytes.fromhex(copy['copy_source_before_store']['hex'])
after=bytes.fromhex(copy['state_after_original_store']['hex'])
checks={
 'fault_pc_matches':fault['registers']['r15']=='0x63849f30',
 'fault_base_register_zero':fault['registers']['r3']=='0x0',
 'fault_instruction_matches_original':av[0x283f28:0x283f38]==bytes.fromhex(fault['fault_instruction']['hex']),
 'explicit_null_store':av[0x283f2e:0x283f32]==bytes.fromhex('00231b60'),
 'state_byte_at_fault_is_3':bytes.fromhex(fault['state_r7']['hex'])[2]==3,
 'live_copy_source_matches_backup':source==backup[0x67f54:0x67f54+96],
 'original_store_copies_32_bytes':after[:32]==source[:32],
 'store_changes_destination_state_to_3':after[2]==3,
 'observed_copy_pc_advanced_one_arm_instruction':copy['registers']['r15']=='0x60258bd4',
 'no_instruction_skip':copy['original_store_single_step'].startswith('T05'),
}
result={'checks':checks,'all_checks_pass':all(checks.values()),'input_sha256':{'av-cam.bin':hashlib.sha256(av).hexdigest(),'Backup.bin':hashlib.sha256(backup).hexdigest()},'limits':'These observations establish the state source and fatal store, not the semantic meaning of property 0x170000 or why the broader condition occurs.'}
(r/'a6600_port/analysis/liro-fault-static/verified-trace.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
if not all(checks.values()):raise SystemExit(1)
