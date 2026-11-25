from elftools.elf.elffile import ELFFile
import io

d = open('03-证据/静态分析/97_abi/a5pFw_actual.so', 'rb').read()
e = ELFFile(io.BytesIO(d))
t = e.get_section_by_name('.text')
print('text addr', hex(t['sh_addr']), 'size', hex(t['sh_size']),
      'end', hex(t['sh_addr'] + t['sh_size']))
for p in e.iter_segments():
    if p['p_type'] == 'PT_LOAD':
        print('LOAD vaddr', hex(p['p_vaddr']), 'filesz', hex(p['p_filesz']),
              'memsz', hex(p['p_memsz']),
              'end', hex(p['p_vaddr'] + p['p_memsz']))

targets = [0x1c7e699, 0x1c7e6a9, 0x1d5a3d5, 0x1c7eb75, 0x1c1b875,
           0x1c1b721, 0x1c1b741, 0x165d63d, 0x2c2ea89, 0x2ce6881,
           0x2bdf571, 0x2bc326d]
print('--- target locations ---')
for tg in targets:
    where = 'unmapped'
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= tg < s['sh_addr'] + s['sh_size']:
            where = s.name
            break
    print(hex(tg), where)
