"""Generate a NEW minimal old-IMDB Application record variant; never write images.
The caller must copy the original gen5 appFwBoot.so as /usr/lib/astra.so.
This is a load-routing experiment, NOT proof of same-SONAME ABI compatibility.
"""
from pathlib import Path
import hashlib,struct,json
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_abi'
p=O/'a6usr_libIMDB.so'; original=p.read_bytes(); d=bytearray(original)
expected='05793f4e8b5b81fbb534953c1164788151d57b13d520158b89a3d1329d59518e'
assert hashlib.sha256(original).hexdigest()==expected
record=0x70f8; name=0x496f
assert struct.unpack_from('<4I',d,record)==(0x20000004,1,0xffffff9f,0x07fb0083)
assert struct.unpack_from('<I',d,record+16)[0]==name
assert d[name:name+9]==b'appFw.so\0'
struct.pack_into('<H',d,record+14,0)
d[name:name+9]=b'astra.so\0'
assert len(d)==len(original)
# All other IMDB bytes and ELF sections, symbols, REL entries remain byte-for-byte unchanged.
allowed=set(range(record+14,record+16))|set(range(name,name+9))
diffs=[i for i,(a,b) in enumerate(zip(original,d)) if a!=b]
assert set(diffs)<=allowed
out=O/'97_abi_libIMDB_appboot.so';out.write_bytes(d)
manifest={'input':str(p),'input_sha256':expected,'output':str(out),'output_sha256':hashlib.sha256(d).hexdigest(),'record_va':'0xf0f8','record_file_offset':hex(record),'record_index':123,'patches':[{'file_offset':hex(record+14),'old':'fb07','new':'0000','meaning':'Application type4 selects dlopen(record.library), instead of dlopen(NULL)'},{'file_offset':hex(name),'old':'appFw.so\\0','new':'astra.so\\0','meaning':'equal-length alias for unchanged original gen5 appFwBoot.so'}],'required_extra_file':{'guest_path':'/usr/lib/astra.so','source':'05-原始固件/zv1m2_fw/gen5/appFwBoot.so','source_sha256':'187b335c5d59ebb581ef24eee2b8a92bdfce1af61ce7298e8466e645a6cdbe5e'},'changed_byte_offsets':[hex(i) for i in diffs],'warning':'Old IMDB earlier bundled records still request /usr/lib/libObj.so or global symbols. Replacing that with gen5 is a separate ABI-breaking experiment, not isolated by this patch.'}
(O/'97_abi_imdb_patch.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps(manifest,ensure_ascii=False,indent=2))
