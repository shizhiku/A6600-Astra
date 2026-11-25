"""Read-only ARM ELF frame caller audit. No firmware execution or mutation.
Usage: python 02-脚本/136b_frame_callers.py ELF [START:END ...] [--xref=ADDR ...]
Addresses are ELF virtual addresses, Thumb code addresses normalized to even.
Raw branch candidates are verified by Capstone but may be data unless function flow confirms.
"""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM
import io,struct,hashlib,sys,bisect
p=Path(sys.argv[1]); data=p.read_bytes(); elf=ELFFile(io.BytesIO(data))
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
ma=Cs(CS_ARCH_ARM,CS_MODE_ARM);ma.detail=True
secs=list(elf.iter_sections()); rels={}; symbols={}; funcs=[]
for sec in secs:
 if sec['sh_type'] in ('SHT_SYMTAB','SHT_DYNSYM'):
  for s in sec.iter_symbols():
   if s['st_shndx']!='SHN_UNDEF' and s['st_value']:
    symbols.setdefault(s['st_value']&~1,[]).append(s.name)
    if s['st_info']['type']=='STT_FUNC': funcs.append((s['st_value']&~1,s['st_size'],s.name))
 if sec['sh_type'] in ('SHT_REL','SHT_RELA'):
  tab=elf.get_section(sec['sh_link'])
  for r in sec.iter_relocations():
   name=tab.get_symbol(r['r_info_sym']).name
   if r['r_offset'] not in rels or name: rels[r['r_offset']]=(name,r['r_info_type'])
def at(a,n):
 for s in secs:
  if s['sh_type']!='SHT_NOBITS' and s['sh_addr']<=a and a+n<=s['sh_addr']+s['sh_size']:
   o=s['sh_offset']+a-s['sh_addr']; return data[o:o+n]
 return b''
def u32(a):
 b=at(a,4);return struct.unpack('<I',b)[0] if len(b)==4 else None
plt={}
s=elf.get_section_by_name('.plt')
if s:
 for i in range(0,s['sh_size']-11,4):
  a=s['sh_addr']+i; ins=list(ma.disasm(at(a,12),a))
  if len(ins)==3 and ins[0].mnemonic=='add' and ins[1].mnemonic=='add' and ins[2].mnemonic.startswith('ldr'):
   try:
    def armimm(word):
     v=word&255; r=((word>>8)&15)*2; return ((v>>r)|(v<<(32-r)))&0xffffffff if r else v
    w0,w1,w2=struct.unpack('<III',at(a,12))
    got=a+8+armimm(w0)+armimm(w1)+ins[2].operands[1].mem.disp
    if got in rels: plt[a]=(got,rels[got][0])
   except (AttributeError,IndexError): pass
ex=[]
s=elf.get_section_by_name('.ARM.exidx')
if s:
 for i in range(0,s['sh_size'],8):
  a=s['sh_addr']+i; w=u32(a); off=w&0x7fffffff;off=off-(1<<31) if off&(1<<30) else off
  ex.append(((a+off)&0xffffffff,a,u32(a+4)))
ex.sort(); starts=[x[0] for x in ex]
def desc(a):
 if a in plt:return 'PLT '+plt[a][1]
 if a in symbols:return '|'.join(sorted(set(symbols[a])))
 k=bisect.bisect_right(starts,a)-1
 if k>=0:return 'EXIDX '+hex(starts[k])+'+'+hex(a-starts[k])
 return '?'
print('FILE',p,'SIZE',len(data),'SHA256',hashlib.sha256(data).hexdigest())
print('ELF',elf.header['e_machine'],'ENTRY',hex(elf.header['e_entry']),'EXIDX_COUNT',len(ex),'FUNCTION_SYMBOLS',len(funcs))
keys=('drawFramebuffer','updateFrame','processEvent','processSystemMessage','CheckUpdateFinished','UXEngine6wgtsys','notifyDraw','isFrameDelay','updateCurrentTime','Timer','timer','Vsync','vsync','Frame')
for a,(g,n) in sorted(plt.items()):
 if any(k in n for k in keys):print('PLT',hex(a),'GOT',hex(g),n)
args=sys.argv[2:]
if '--facts' in args:
 for a in (0x377b46c,0x377b480,0x377b558,0x37d3a08): print('WORD',hex(a),hex(u32(a) or 0),'RELOC',rels.get(a))
 for s in elf.get_section_by_name('.dynsym').iter_symbols():
  if any(k in s.name for k in ('Application_Start','WidgetSystem11updateFrame','wgtsysEv','updateCurrentTime')):print('DYNSYM',hex(s['st_value']),s['st_shndx'],s.name)
 for sec in secs:
  if sec['sh_type']=='SHT_DYNAMIC':
   for tag in sec.iter_tags():
    if tag.entry.d_tag=='DT_NEEDED': print('NEEDED',tag.needed)
 targets0=(0x52a490,0x52a4d0,0x52a774)
 for t in targets0:print('SLOT',hex(t),plt.get(t),'VALUE',hex(u32(plt[t][0]) or 0) if t in plt else '?')
targets={int(x.split('=',1)[1],16) for x in args if x.startswith('--xref=')}
if targets:
 for s in secs:
  if not s['sh_flags']&4:continue
  raw=s.data();base=s['sh_addr']
  for o in range(0,len(raw)-3,2):
   h1,h2=struct.unpack_from('<HH',raw,o)
   if h1&0xf800!=0xf000 or h2&0xd000 not in (0xd000,0xc000,0x9000):continue
   sg=(h1>>10)&1;i1=(~((h2>>13)^sg))&1;i2=(~((h2>>11)^sg))&1
   imm=(sg<<24)|(i1<<23)|(i2<<22)|((h1&1023)<<12)|((h2&2047)<<1)
   if sg:imm-=1<<25
   a=base+o;t=a+4+imm
   if h2&0xd000==0xc000:t=((a+4)&~3)+imm;t&=~3
   if t in targets:
    ins=list(md.disasm(raw[o:o+4],a))
    if ins:print('XREF',hex(a),'->',hex(t),desc(t),'IN',desc(a),'DECODE',ins[0].mnemonic,ins[0].op_str)
 # literal address / pointer hits retain executable/data section identity
 for t in targets:
  for val in (t,t|1):
   needle=struct.pack('<I',val)
   for s in secs:
    if s['sh_type']=='SHT_NOBITS':continue
    raw=s.data();pos=0
    while True:
     j=raw.find(needle,pos)
     if j<0:break
     print('POINTER_BYTES',hex(s['sh_addr']+j),s.name,'VALUE',hex(val));pos=j+1
for x in args:
 if ':' not in x or x.startswith('--'):continue
 a,z=(int(v,16) for v in x.split(':'));k=bisect.bisect_right(starts,a)-1
 print('\nDUMP',hex(a),hex(z),'CONTAINING',desc(a))
 for q,loc,w in ex[max(k,0):]:
  if q>=z:break
  print('EXIDX_ENTRY',hex(q),'TABLE',hex(loc),'WORD',hex(w))
 dis=ma if '--arm' in args else md
 for ins in dis.disasm(at(a,z-a),a):
  note=''
  if ins.operands and ins.operands[0].type==ARM_OP_IMM and (ins.mnemonic.startswith('b') or ins.mnemonic in ('cbz','cbnz')):
   t=ins.operands[0].imm;note=' ; '+desc(t)
  if ins.mnemonic.startswith('ldr') and len(ins.operands)>1 and ins.operands[1].type==3 and ins.reg_name(ins.operands[1].mem.base)=='pc':
   lit=((ins.address+4)&~3)+ins.operands[1].mem.disp;v=u32(lit);note=f' ; LITERAL {lit:#x} = {v:#x}' if v is not None else ''
  print(f'{ins.address:08x} {ins.bytes.hex():10} {ins.mnemonic:9} {ins.op_str}{note}')
