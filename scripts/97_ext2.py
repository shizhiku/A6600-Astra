"""Read-only ext2 reader for the ASTRA experiments.
Preserves sparse logical blocks and handles fast symlinks, unlike the legacy
reader which concatenated allocated blocks and could invalidate ELF hashes.
"""
from pathlib import Path
import importlib.util,struct,math
_spec=importlib.util.spec_from_file_location('_astra_legacy_ext2',Path(__file__).with_name('a6600_usr.py'))
_legacy=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_legacy)
class Ext2(_legacy.Ext2):
 def read_file(self,ino):
  mode,size,blocks=self.inode(ino)
  if (mode&0xf000)==0xa000 and size<=60:
   g,idx=divmod(ino-1,self.ipg);off=self.inode_tables[g]*self.bs+idx*self.inode_size+40;self.f.seek(off);return self.f.read(size)
  need=(size+self.bs-1)//self.bs;per=self.bs//4;out=bytearray()
  def pointers(ptr,level,count):
   if count<=0:return
   if not ptr:
    for _ in range(count):yield 0
   elif level==0:yield ptr
   else:
    raw=self._block(ptr)
    if len(raw)!=self.bs:raise ValueError('Short indirect block')
    vals=struct.unpack('<%dI'%per,raw);chunk=per**(level-1)
    for v in vals:
     take=min(count,chunk)
     if not take:break
     yield from pointers(v,level-1,take);count-=take
  logical=[]
  for b in blocks[:12]:
   if not need:break
   logical.append(b);need-=1
  for ptr,level in zip(blocks[12:],[1,2,3]):
   take=min(need,per**level)
   if take:logical.extend(pointers(ptr,level,take));need-=take
  if need:raise ValueError('File exceeds ext2 indirect capacity')
  for b in logical:
   data=self._block(b) if b else bytes(self.bs)
   if len(data)!=self.bs:raise ValueError('Short data block')
   out.extend(data)
  return bytes(out[:size])
