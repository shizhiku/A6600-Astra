"""Read-only ELF audit: symbol-bounded dumps and raw direct-call candidates.
No firmware execution or modification. Candidate branches require instruction validation.
"""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
import io, struct, hashlib, json, sys, bisect
P=Path(sys.argv[1]) if len(sys.argv)>1 else Path('03-证据/静态分析/grm/lib/libObj.so')
b=P.read_bytes(); e=ELFFile(io.BytesIO(b)); sy=e.get_section_by_name('.dynsym')
funcs=sorted([(s['st_value']&~1,s['st_size'],s.name,s['st_value']&1) for s in sy.iter_symbols() if s['st_info']['type']=='STT_FUNC' and s['st_shndx']!='SHN_UNDEF'])
starts=[x[0] for x in funcs]
def owner(a):
    k=bisect.bisect_right(starts,a)-1
    while k>=0 and funcs[k][0]+max(funcs[k][1],1)>a:
        x=funcs[k]
        if x[0]<=a<x[0]+x[1]:return x
        k-=1
    return None
def at(a,n):
    for s in e.iter_sections():
        if s['sh_type']!='SHT_NOBITS' and s['sh_addr']<=a and a+n<=s['sh_addr']+s['sh_size']:
            o=s['sh_offset']+a-s['sh_addr'];return b[o:o+n]
    return b''
rels={}
for sec in e.iter_sections():
    if sec['sh_type'] not in ('SHT_REL','SHT_RELA'):continue
    tab=e.get_section(sec['sh_link'])
    for r in sec.iter_relocations():
        sym=tab.get_symbol(r['r_info_sym']);rels[r['r_offset']]=(sym.name,r['r_info_type'])
plt={}
sec=e.get_section_by_name('.plt')
if sec:
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM);md.detail=True
    raw=sec.data();base=sec['sh_addr']
    for o in range(0,len(raw)-11,4):
        ins=list(md.disasm(raw[o:o+12],base+o))
        if len(ins)==3 and ins[0].mnemonic=='add' and ins[1].mnemonic=='add' and ins[2].mnemonic.startswith('ldr'):
            try:
                def armimm(word):
                    v=word&255;r=((word>>8)&15)*2
                    return ((v>>r)|(v<<(32-r)))&0xffffffff if r else v
                w0,w1=struct.unpack_from('<II',raw,o)
                got=base+o+8+armimm(w0)+armimm(w1)+ins[2].operands[1].mem.disp
                if got in rels:plt[base+o]=rels[got][0]
            except (IndexError,AttributeError):pass
veneers={}
for sec in e.iter_sections():
    if not (sec['sh_flags']&4) or sec['sh_type']=='SHT_NOBITS':continue
    rawv=sec.data();bv=sec['sh_addr']
    for o in range(0,len(rawv)-15,4):
        if rawv[o:o+12]==bytes.fromhex('04c09fe50cc08fe01cff2fe1'):
            veneers[bv+o]=(bv+o+12+struct.unpack_from('<i',rawv,o+12)[0])&0xffffffff
print('FILE',str(P),'SHA256',hashlib.sha256(b).hexdigest())
keys=['drawFramebuffer','WidgetSystem','GraphicsSystem','GraphicsContext','egl','grm_init','uxengine','RenderState','swapBuffer','SwapBuffer','updateFramebuffer']
for s in sy.iter_symbols():
    if any(k in s.name for k in keys):print('SYM',hex(s['st_value']),s['st_size'],s['st_shndx'],s.name)
targets={x[0]:x[2] for x in funcs if any(k in x[2] for k in ['drawFramebuffer','WidgetSystem','GraphicsSystem','grm_init'])}
for a,n in plt.items():
    if any(k in n for k in ['drawFramebuffer','WidgetSystem','GraphicsSystem','grm_init']):targets[a]='PLT '+n
for a,t in veneers.items():
    if (t&~1) in targets:targets[a]='VENEER '+targets[t&~1]
text=e.get_section_by_name('.text');raw=text.data();base=text['sh_addr'];hits=[]
for o in range(0,len(raw)-3,2):
    h1,h2=struct.unpack_from('<HH',raw,o)
    if h1&0xf800!=0xf000:continue
    top=h2&0xd000
    if top not in (0xd000,0xc000,0x9000):continue
    s=(h1>>10)&1;i1=(~((h2>>13)^s))&1;i2=(~((h2>>11)^s))&1
    imm=(s<<24)|(i1<<23)|(i2<<22)|((h1&1023)<<12)|((h2&2047)<<1)
    if s:imm-=1<<25
    a=base+o;t=a+4+imm
    if top==0xc000:t=(a+4&~3)+imm;t&=~3
    if t in targets:
        fn=owner(a);hits.append((a,t,fn));print('XREF_CANDIDATE',hex(a),hex(t),targets[t],fn)
selected={x[0]:x for x in funcs if 'drawFramebuffer' in x[2]}
for a,t,fn in hits:
    if fn and ('drawFramebuffer' in targets[t] or '--all-dumps' in sys.argv):selected[fn[0]]=fn
if len(sys.argv)>2:
    for v in sys.argv[2:]:
        if v.startswith('0x'):
            parts=v.split(':');a=int(parts[0],16);fn=owner(a)
            if len(parts)>1:selected[a]=(a,int(parts[1],0),'explicit_range',1)
            elif fn:selected[fn[0]]=fn
for a,size,name,thumb in selected.values():
    print('\nDUMP',hex(a),size,name,'Thumb' if thumb else 'ARM')
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB if thumb else CS_MODE_ARM)
    for ins in md.disasm(at(a,min(size,12000)),a):
        note=''
        if ins.mnemonic in ('bl','blx','b','b.w') and ins.op_str.startswith('#'):
            t=int(ins.op_str[1:],16);vt=veneers.get(t,t);f=owner(vt&~1);note=' ; '+str(plt.get(vt&~1) or f or hex(vt))
        print(f'{ins.address:08x} {ins.mnemonic:9} {ins.op_str}{note}')
