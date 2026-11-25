"""Find the instruction loading the segment-log literal by decoding ARM ldr encodings directly."""
from pathlib import Path
import json
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

KO = Path(r'<WORKSPACE>\03-证据\静态分析\liro-fault-static\liro.ko')
POOL_TARGETS = [0x488, 0x48C, 0x490]   # literal pool entries near the segment-log string

def ldr_pc_imm(word):
    """Return (rd, disp) for ARM 'ldr rd,[pc,#imm]' else None."""
    if (word & 0x0F7F0000) != 0x051F0000:
        return None
    rd = (word >> 12) & 0xF
    imm = word & 0xFFF
    up = (word >> 23) & 1
    return rd, (imm if up else -imm)

with open(KO, 'rb') as f:
    e = ELFFile(f)
    for secname in ('.init.text', '.text'):
        s = e.get_section_by_name(secname)
        if s is None:
            continue
        code = s.data()
        hits = []
        for off in range(0, len(code) - 3, 4):
            word = int.from_bytes(code[off:off + 4], 'little')
            dec = ldr_pc_imm(word)
            if not dec:
                continue
            rd, disp = dec
            tgt = off + 8 + disp
            if tgt in POOL_TARGETS:
                hits.append({'insn_offset': hex(off), 'rd': rd,
                             'literal_at': hex(tgt),
                             'literal_value': hex(int.from_bytes(code[tgt:tgt + 4], 'little'))})
        print(secname, 'literal-load hits:', len(hits))
        for h in hits:
            print('  ', h)
        if hits:
            (KO.parent / 'liro-segment-log-loader.json').write_text(
                json.dumps(hits, indent=2), encoding='utf-8')
            # disassemble the containing function window
            start = max(0, (int(hits[0]['insn_offset'], 16) - 0x80) & ~3)
            end = min(len(code), start + 0x140)
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            md.skipdata = True
            print(f'--- {secname} window {start:#x}..{end:#x} ---')
            for x in md.disasm(code[start:end], start):
                mark = '  <== loads log string' if x.address == int(hits[0]['insn_offset'], 16) else ''
                print(f'  {x.address:06x} {x.bytes.hex():8} {x.mnemonic:8} {x.op_str}{mark}')
