"""Offline only a6600 input/sen ELF extraction, inventory and disassembly. No camera I/O."""
from pathlib import Path
import sys, io, re, json, struct, hashlib, importlib.util
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
BASE=Path(__file__).resolve().parents[1]
OUT=BASE/'03-证据/静态分析/input_sen'
OUT.mkdir(exist_ok=True)
IMAGE=BASE/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
def extract():
 spec=importlib.util.spec_from_file_location('usr', BASE/'02-脚本/a6600_usr.py'); m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 fs=m.Ext2(str(IMAGE)); targets=['/bin/sen.elf','/kmod/input.ko','/kmod/osal_uipc.ko','/lib/libosal_uipc.so','/lib/libsencore.so','/lib/libObj.so','/lib/libosal.so','/lib/libosal_ulogio.so']
 found=[]
 for p,ino,d in fs.walk():
  if p in targets:
   b=fs.read_file(ino); dest=OUT/Path(p).name
   if dest.exists() and dest.read_bytes()!=b: raise RuntimeError('Existing output differs '+str(dest))
   if not dest.exists():dest.write_bytes(b)
   found.append(dict(path=p,file=str(dest.relative_to(BASE)),size=len(b),sha256=hashlib.sha256(b).hexdigest(),inode=ino))
 (OUT/'input_sen_manifest.json').write_text(json.dumps(found,ensure_ascii=False,indent=2),encoding='utf-8')
 return found
class Elf:
 def __init__(self,path):
  self.path=Path(path);self.data=self.path.read_bytes();self.e=ELFFile(io.BytesIO(self.data)); self.segs=[s for s in self.e.iter_segments() if s['p_type']=='PT_LOAD'];self.syms=[]
  for sec in self.e.iter_sections():
   if sec['sh_type'] in ('SHT_DYNSYM','SHT_SYMTAB'):
    self.syms += [(s.name,int(s['st_value']),int(s['st_size']),s['st_info']['type'],s['st_shndx']) for s in sec.iter_symbols() if s.name]
  self.funcs=sorted(set((v&~1,n,z,v&1) for n,v,z,t,idx in self.syms if t=='STT_FUNC' and isinstance(idx,int)))
  self.plt={}; dyn=self.e.get_section_by_name('.dynsym'); got={}
  for sec in self.e.iter_sections():
   if sec.name=='.rel.plt':
    for r in sec.iter_relocations():got[r['r_offset']]=dyn.get_symbol(r['r_info_sym']).name
  plt=self.e.get_section_by_name('.plt')
  def imm(w):
   r=((w>>8)&15)*2;b=w&255
   return ((b>>r)|(b<<(32-r)))&0xffffffff if r else b
  if plt:
   for o in range(plt['sh_offset'],plt['sh_offset']+plt['sh_size']-11,4):
    a,b,c=struct.unpack_from('<III',self.data,o)
    if a&0xfffff000==0xe28fc000 and b&0xfffff000==0xe28cc000 and c&0xfffff000==0xe5bcf000:
     va=o-plt['sh_offset']+plt['sh_addr'];g=va+8+imm(a)+imm(b)+(c&4095)
     if g in got:self.plt[va]=got[g]
 def off(self,va):
  for s in self.segs:
   if s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz']:return s['p_offset']+va-s['p_vaddr']
  for s in self.e.iter_sections():
   if s['sh_addr']<=va<s['sh_addr']+s['sh_size'] and s['sh_type']!='SHT_NOBITS':return s['sh_offset']+va-s['sh_addr']
  return None
 def string(self,va):
  o=self.off(va)
  if o is None:return ''
  b=self.data[o:o+180].split(b'\0')[0]
  return b.decode('ascii') if len(b)>2 and all(32<=c<127 or c in [9,10,13] for c in b) else ''
 def name(self,va):
  va &= ~1
  if va in self.plt:return self.plt[va]+'@plt'
  matches=[(v,n) for v,n,z,t in self.funcs if v==va or (v<va<v+z)]
  return (max(matches)[1]+'+0x%x'%(va-max(matches)[0])) if matches else ''
 def dis(self,start,size,thumb=True):
  cs=Cs(CS_ARCH_ARM,(CS_MODE_THUMB if thumb else CS_MODE_ARM)|CS_MODE_LITTLE_ENDIAN);cs.detail=True
  off=self.off(start)
  if off is None:raise RuntimeError('No VA '+hex(start))
  lines=[];regs={}
  for ins in cs.disasm(self.data[off:off+size],start):
   notes=[];ops=ins.operands
   if ins.mnemonic.startswith(('bl','b.w')) and ops and ops[0].type==2:notes.append(self.name(ops[0].imm))
   if ins.mnemonic.startswith('ldr') and len(ops)>1 and ops[1].type==3 and ins.reg_name(ops[1].mem.base)=='pc':
    a=((ins.address+4)&~3)+ops[1].mem.disp if thumb else ins.address+8+ops[1].mem.disp
    o=self.off(a)
    if o is not None and o+4<=len(self.data):
     v=struct.unpack_from('<I',self.data,o)[0];regs[ops[0].reg]=v;notes.append('literal@%x=%08x %s'%(a,v,self.string(v)))
   if ins.mnemonic in ('add','add.w') and ops and ops[0].type==1:
    dest=ops[0].reg
    if len(ops)==2 and ops[1].type==1 and ins.reg_name(ops[1].reg)=='pc' and dest in regs:
     v=(regs[dest]+ins.address+(4 if thumb else 8))&0xffffffff;regs[dest]=v;notes.append('PCREL=%08x %s'%(v,self.string(v)))
   lines.append('%08x off=%08x %-12s %-8s %-34s %s'%(ins.address,self.off(ins.address),ins.bytes.hex(),ins.mnemonic,ins.op_str,' ; '.join(x for x in notes if x)))
  return '\n'.join(lines)
 def inventory(self):
  lines=['FILE '+str(self.path.relative_to(BASE)),'SHA256 '+hashlib.sha256(self.data).hexdigest(),str(self.e.header)]
  lines+=['SECTION '+s.name+' '+str(dict(s.header)) for s in self.e.iter_sections()]
  lines+=['SYMBOL %08x size=%x %s %s %s'%(v,z,t,str(idx),n) for n,v,z,t,idx in self.syms]
  lines+=['PLT %08x %s'%(a,n) for a,n in self.plt.items()]
  for m in re.finditer(rb'[ -~]{4,}',self.data):
   if any(x in m.group().lower() for x in [b'/dev/',b'key',b'dial',b'button',b'sen',b'ioctl',b'uipc',b'input',b'handshake',b'osal']):lines.append('STRING off=%08x %s'%(m.start(),m.group().decode()))
  return '\n'.join(lines)
def main():
 if len(sys.argv)<2 or sys.argv[1]=='inventory':
  found=extract()
  for f in found:
   e=Elf(BASE/f['file']);(OUT/(e.path.name+'.inventory.txt')).write_text(e.inventory(),encoding='utf-8')
  print(json.dumps(found,indent=2));return
 e=Elf(OUT/sys.argv[1])
 if len(sys.argv)<4:print(e.inventory());return
 start=int(sys.argv[2],0);size=int(sys.argv[3],0);thumb=not(len(sys.argv)>4 and sys.argv[4]=='arm')
 print(e.dis(start,size,thumb))
if __name__=='__main__':main()
