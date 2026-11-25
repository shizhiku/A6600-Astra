"""QEMU-only SDM migration planner, default strictly read-only.
No camera APIs; no firmware DAT output; input is never opened for write.
python 02-脚本/97_flash_m2_plan.py --plan-out 03-证据/静态分析/97_flash/97_flash_m2_plan.json
Optional --output must be NEW regular image file with 97_flash in name.
It clones the input, zeroes/repositions the original tail in the new file only,
patches the single observed SDM table, and verifies copied regions byte-for-byte by SHA256.
Does not resize or inject ext2; caller must do that on another new copy.
"""
from pathlib import Path
import argparse,hashlib,struct,json
P=argparse.ArgumentParser();P.add_argument('--input',default=r'\\wsl.localhost\Ubuntu\root\qemu_in\emmc.img');P.add_argument('--plan-out');P.add_argument('--output');P.add_argument('--usr-mib',type=int,default=512);A=P.parse_args()
src=Path(A.input); MiB=1<<20; USER=8*MiB;TARGET=A.usr_mib*MiB
if not 300<A.usr_mib<=1024:raise ValueError('QEMU-only /usr target must be >300 and <=1024 MiB')
if not src.is_file() or str(src).startswith(('\\\\.\\','/dev/')):
 raise ValueError('Only a regular offline image file is permitted')
EXPECTED='8305fdf72050570811c15943a835bee7a0f935f15203e3aaadf14ec290782f01'
def hash_range(f,off,n):
 f.seek(off);h=hashlib.sha256()
 while n:
  b=f.read(min(n,8*MiB))
  if not b:raise ValueError('short read')
  h.update(b);n-=len(b)
 return h.hexdigest()
def copy(f,o,off,dest,n):
 f.seek(off);o.seek(dest)
 while n:
  b=f.read(min(n,8*MiB))
  if not b:raise ValueError('short read')
  o.write(b);n-=len(b)
with src.open('rb') as f:
 size=src.stat().st_size;digest=hash_range(f,0,size)
 if digest!=EXPECTED:raise ValueError('Input hash not audited baseline')
 f.seek(USER);sdm=f.read(512)
 if sdm[:8]!=b'82461.00' or struct.unpack_from('<I',sdm,8)[0]!=30:raise ValueError('Unexpected SDM')
 rows=[list(struct.unpack_from('<IIII',sdm,32+16*i)) for i in range(30)]
 if rows[14]!=[0x2d800000,0x12c00000,0,0xffffffff]:raise ValueError('Unexpected p15')
 delta=TARGET-rows[14][1];oldtail=USER+rows[15][0];oldend=USER+max(r[0]+r[1] for r in rows);newend=oldend+delta
 if newend>size:raise ValueError('Migration exceeds medium')
 # Complete byte scan records exact SDM copies, not just magic-string candidates.
 f.seek(0);pos=0;overlap=b'';copies=[];magic=[]
 while True:
  b=f.read(8*MiB)
  if not b:break
  data=overlap+b;base=pos-len(overlap);j=0
  while True:
   j=data.find(b'82461.00',j)
   if j<0:break
   loc=base+j
   if loc>=pos-len(overlap) and loc not in magic:
    magic.append(loc)
    if data[j:j+512]==sdm:copies.append(loc)
   j+=1
  overlap=data[-511:];pos+=len(b)
 if copies!=[USER]:raise ValueError('Ambiguous/redundant SDM copies '+repr(copies))
 f.seek(oldend);n=newend-oldend
 while n:
  b=f.read(min(n,8*MiB))
  if any(b):raise ValueError('Nonzero unallocated destination area; refuse overwrite')
  n-=len(b)
 newrows=[r.copy() for r in rows];newrows[14][1]=TARGET
 for r in newrows[15:]:r[0]+=delta
 modified=bytearray(sdm)
 for i,r in enumerate(newrows):struct.pack_into('<IIII',modified,32+16*i,*r)
 assert modified[:32]==sdm[:32]
 assert all(r[2:]==n[2:] for r,n in zip(rows,newrows))
 report={'purpose':'QEMU-only; not proof of updater/hardware acceptance','input':str(src),'input_size':size,'input_sha256':digest,'sdm_offset':USER,'sdm_sha256':hashlib.sha256(sdm).hexdigest(),'sdm_reserved_12_32':sdm[12:32].hex(),'sdm_exact_copies':copies,'sdm_magic_occurrences':magic,'sdm_crc':'No checksum field in primary fwtool SDM structure; reserved bytes all zero. Actual kernel checks still require verification.','delta':delta,'new_usr_size':TARGET,'old_tail_start':oldtail,'new_tail_start':oldtail+delta,'old_last_end':oldend,'new_last_end':newend,'remaining_medium_bytes':size-newend,'destination_unallocated_zero_checked':[oldend,newend],'rows':[{'partition':i+1,'old':o,'new':n,'old_disk_start':USER+o[0],'new_disk_start':USER+n[0]} for i,(o,n) in enumerate(zip(rows,newrows))]}
 if A.output:
  out=Path(A.output)
  if '97_flash' not in out.name or out.resolve()==src.resolve():raise ValueError('Output must be new 97_flash image')
  with out.open('xb+') as o:
   copy(f,o,0,0,size)
   o.seek(oldtail);n=newend-oldtail;zero=bytes(8*MiB)
   while n:k=min(n,len(zero));o.write(zero[:k]);n-=k
   copy(f,o,oldtail,oldtail+delta,oldend-oldtail)
   o.seek(USER);o.write(modified);o.flush()
   source_hash=hash_range(f,oldtail,oldend-oldtail);dest_hash=hash_range(o,oldtail+delta,oldend-oldtail)
   if source_hash!=dest_hash:raise ValueError('Moved tail hash mismatch')
   for i in list(range(14))+list(range(15,30)):
    r,nr=rows[i],newrows[i]
    if r[1] and hash_range(f,USER+r[0],r[1])!=hash_range(o,USER+nr[0],nr[1]):raise ValueError('Partition copy mismatch '+str(i+1))
   report['output']=str(out);report['output_sha256']=hash_range(o,0,size);report['tail_verified_sha256']=source_hash
  if hash_range(f,0,size)!=digest:raise ValueError('Input changed during build')
 if A.plan_out:
  path=Path(A.plan_out)
  if '97_flash' not in path.name:raise ValueError('Report name needs 97_flash')
  with path.open('x',encoding='utf-8') as o:json.dump(report,o,indent=2)
 print(json.dumps(report,indent=2))
