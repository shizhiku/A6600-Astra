"""Locate lib::assert::notify_model_system_error in gen5 appFw.so via its
__PRETTY_FUNCTION__ string and .ARM.exidx, then optionally patch its entry to
return. Diagnostic only; writes a NEW file under 03-证据/静态分析/97_abi/.
Run in WSL (elftools + capstone available).
"""
from elftools.elf.elffile import ELFFile
from capstone import *
import struct, sys
from pathlib import Path
SRC=Path('05-原始固件/zv1m2_fw/gen5/appFw.so')
OUT=Path('03-证据/静态分析/97_abi/zv_appFw_noassert.so')
d=bytearray(SRC.read_bytes());e=ELFFile(__import__('io').BytesIO(bytes(d)))
def sec_by_off(off):
    for s in e.iter_sections():
        if s['sh_type']!='SHT_NOBITS' and s['sh_offset']<=off<s['sh_offset']+s['sh_size']:return s
    return None
pat=b'notify_model_system_error'
fo=d.find(pat);assert fo>=0,pat
s=sec_by_off(fo);va=s['sh_addr']+fo-s['sh_offset']
print('string file',hex(fo),'va',hex(va),'sec',s.name)
# find 4-byte literals of va
hits=[]
for i in range(0,len(d)-4):
    if struct.unpack_from('<I',d,i)[0]==va:
        ss=sec_by_off(i)
        if ss is not None and ss['sh_addr']:
            hits.append((i,ss['sh_addr']+i-ss['sh_offset'],ss.name))
print('literal hits',[(hex(a),hex(b),c) for a,b,c in hits][:20])
# find thumb ldr literal referencing those literal addresses in .text
text=[x for x in e.iter_sections() if x.name=='.text'][0]
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=False
tdata=text.data();tbase=text['sh_addr'];lit_vas={b for _,b,_ in hits}
code_refs=[]
for ins in md.disasm(tdata,tbase):
    if ins.mnemonic.startswith('ldr') and '[pc' in ins.op_str:
        try:imm=int(ins.op_str.split('#')[-1].rstrip(']'),0)
        except:continue
        tgt=((ins.address+4)&~3)+imm
        if tgt in lit_vas:code_refs.append((ins.address,tgt))
print('code refs',[(hex(a),hex(b)) for a,b in code_refs][:20])
# find containing function via exidx
ex=e.get_section_by_name('.ARM.exidx');starts=[]
if ex:
    data=ex.data();base=ex['sh_addr']
    for k in range(0,len(data),8):
        w=struct.unpack_from('<I',data,k)[0]
        pre=w if w<0x80000000 else w-0x100000000
        addr=(base+k+pre)&0xffffffff
        starts.append(addr)
    starts=sorted(set(starts))
def containing(addr):
    cand=None
    for st in starts:
        if (st&~1)<=addr:cand=st
        else:break
    return cand
for a,b in code_refs[:6]:
    st=containing(a);print('ref',hex(a),'func',hex(st) if st else None)
if len(sys.argv)>1 and sys.argv[1]=='patch' and code_refs:
    a,b=code_refs[0];st=containing(a);thumb=bool(st&1);st&=~1
    off=None
    for x in e.iter_sections():
        if x['sh_type']!='SHT_NOBITS' and x['sh_addr']<=st<x['sh_addr']+x['sh_size']:
            off=x['sh_offset']+st-x['sh_addr'];break
    assert off is not None
    if thumb:
        d[off:off+2]=b'\x70\x47'   # bx lr
    else:
        d[off:off+4]=b'\x1e\xff\x2f\xe1'  # bx lr (ARM)
    OUT.write_bytes(bytes(d))
    print('patched function',hex(st),'thumb',thumb,'->',OUT)
