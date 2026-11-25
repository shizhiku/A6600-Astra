from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import Path
import io, struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()

syms = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            v = s['st_value']
            if v and s.name and s['st_info']['type'] == 'STT_FUNC':
                syms.setdefault(v & ~1, s.name)

# GOT slot VA -> imported symbol name from .rel.plt / .rel.dyn
got_names = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA') and 'plt' in sec.name:
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            got_names[r['r_offset']] = st.get_symbol(r['r_info_sym']).name

stubs = [0x925FB0, 0x9246B8, 0x923900, 0x9256A8, 0x9240D4,
         0x925B48, 0x924B48, 0x924B04, 0x923B34, 0x9243E4,
         0x925468, 0x9249C4]

for va in stubs:
    off = struct.unpack_from('<i', d, va + 8)[0]
    target = (va + 8) + off
    if tb <= target < tb + len(td):
        info = "internal %#x %s" % (target, syms.get(target & ~1, ""))
    else:
        # target is a GOT slot address (VA). Map VA->file offset via sections.
        foff = None
        for s in e.iter_sections():
            if s['sh_type'] == 'SHT_NOBITS':
                continue
            if s['sh_addr'] <= target < s['sh_addr'] + s['sh_size']:
                foff = s['sh_offset'] + target - s['sh_addr']
                break
        if foff is None:
            info = "unmapped %#x" % target
        else:
            slot = struct.unpack_from('<I', d, foff)[0]
            info = "GOT[%#x] slot=%#x name=%s" % (
                target, slot, got_names.get(target, "(no reloc)"))
    print("%#08x -> %s" % (va, info))
