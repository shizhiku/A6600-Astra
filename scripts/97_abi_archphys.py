"""Evidence for original gen5 kernel arch_phys_to_cache; does not emit a shim."""
from pathlib import Path
import hashlib,struct,json
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_abi';p=O/'zv_system_VMLINUX.BIN';d=p.read_bytes()
assert hashlib.sha256(d).hexdigest()=='fc6009d3a77057a56abf543c6882f905c447c5b7075d7b70ac55b533e57bad94'
base=0x60108000;export=0x32b588;fn,name=struct.unpack_from('<II',d,export)
assert (fn,name)==(0x6011f21c,0x6043ae25)
assert d[name-base:name-base+19]==b'arch_phys_to_cache\0'
limits=list(struct.unpack_from('<5I',d,0x60495c20-base));assert limits==[0x40000000,0x90000000,0xa0000000,0xb0000000,0xffffffff]
lines=[f'{i.address:08x}: {i.mnemonic:9} {i.op_str}' for i in Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(d[fn-base:fn-base+0xa4],fn)]
r={'source':str(p),'sha256':hashlib.sha256(d).hexdigest(),'mapping_base':hex(base),'mapping_evidence':['export name pointer minus exact name file offset equals base','error format literal0x6040c9be maps to file string <3>ERROR:%s:pa=0x%08lx','function-name literal0x60391bd8 maps to exact file string arch_phys_to_cache'],'export_entry_file_offset':hex(export),'function_va':hex(fn),'function_file_offset':hex(fn-base),'name_va':hex(name),'name_file_offset':hex(name-base),'limits_va':'0x60495c20','limits':[hex(x) for x in limits],'argument_return_evidence':'One 32-bit pa arrives in r0; result returns in r0. Literal printf format uses %08lx, supporting unsigned long on this ARM32 target. Source-level exact type remains inferred.','semantics':['If pa==0 and runtime word[0x604b3540]!=0, return0 without translation.','Otherwise if unsigned pa<0x40000000, return pa+0x60000000.','Otherwise if signed(pa)<0 and unsigned pa<0x90000000, return pa+0x20000000.','Otherwise log ERROR with pa; runtime word[0x604b3544] controls extra diagnostics/panic. Nonpanic path returns0.'],'runtime_unknowns':['BSS words0x604b3540/44 values at function call','Whether user-space caller is allowed to dereference the resulting kernel alias','Whether user-space should instead invoke a DMM mmap/ioctl contract'],'no_shim_emitted':True,'instructions':lines}
(O/'archphys_kernel_evidence.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf8');(O/'archphys_kernel_disasm.txt').write_text('\n'.join(lines),encoding='utf8');print(json.dumps({k:v for k,v in r.items() if k!='instructions'},ensure_ascii=False,indent=2))
