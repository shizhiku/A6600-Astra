"""Resolve libsencore PLT entries (ARM) to imported symbol names."""
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libsencore.so'

def decode_arm_add_imm(word):
    """Decode ARM data-processing immediate add: add rd, rn, #imm."""
    if (word >> 28) != 0xE:      # cond AL
        return None
    if ((word >> 25) & 7) != 1:  # I bit: immediate
        return None
    opcode = (word >> 21) & 0xF
    if opcode != 4:              # ADD
        return None
    rn = (word >> 16) & 0xF
    rd = (word >> 12) & 0xF
    rot = ((word >> 8) & 0xF) * 2
    imm8 = word & 0xFF
    imm = ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xFFFFFFFF if rot else imm8
    return rd, rn, imm

def decode_arm_ldr_post(word):
    """Decode ldr pc, [ip, #imm]! (pre-indexed, writeback)."""
    if (word >> 28) != 0xE:
        return None
    if ((word >> 26) & 0x3) != 1 or ((word >> 25) & 1) != 0:
        return None
    p = (word >> 24) & 1
    u = (word >> 23) & 1
    w = (word >> 21) & 1
    rn = (word >> 16) & 0xF
    rd = (word >> 12) & 0xF
    off = word & 0xFFF
    if rd != 15 or p != 1 or w != 1:
        return None
    return rn, (off if u else -off)

with open(LIB, 'rb') as f:
    e = ELFFile(f)
    import struct
    data = LIB.read_bytes()
    rel = e.get_section_by_name('.rel.plt') or e.get_section_by_name('.rel.dyn')
    rels = {}
    for sect in e.iter_sections():
        if sect['sh_type'] in ('SHT_REL', 'SHT_RELA') and sect.name in ('.rel.plt', '.rel.dyn'):
            for r in sect.iter_relocations():
                rels.setdefault(r['r_offset'], []).append(r)

    dynsym = e.get_section_by_name('.dynsym')

    def resolve(entry):
        words = [struct.unpack_from('<I', data, entry + i)[0] for i in (0, 4, 8)]
        d1 = decode_arm_add_imm(words[0])
        d2 = decode_arm_add_imm(words[1])
        d3 = decode_arm_ldr_post(words[2])
        if not (d1 and d2 and d3):
            return None, words, (d1, d2, d3)
        pc = entry + 8
        ip = (pc + d1[2]) & 0xFFFFFFFF
        ip = (ip + d2[2]) & 0xFFFFFFFF
        got = (ip + d3[1]) & 0xFFFFFFFF
        names = []
        for r in rels.get(got, []):
            sym = dynsym.get_symbol(r['r_info_sym'])
            names.append(sym.name)
        return (got, names), words, (d1, d2, d3)

    for entry in (0xE6CC, 0xEE50, 0xF080, 0xE28C):
        res, words, dec = resolve(entry)
        print(f'{entry:#06x}: words={[hex(w) for w in words]} -> {res}')
        if res is None:
            print('    decode:', dec)
