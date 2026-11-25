from pathlib import Path

ROOT = Path('<WORKSPACE>')
src = ROOT / '03-证据/静态分析/97_abi/a5pFw_actual.so'
out = ROOT / '03-证据/静态分析/97_abi/a5pFw_upmfix_nonotify.so'
d = bytearray(src.read_bytes())

# 1) UPM boot-factor ABI: zero the two 5th-gen-only fields.
off = 0x2BBA520
assert d[off:off + 4] == bytes.fromhex('0a6a4b6a'), 'UPM patch site mismatch'
d[off:off + 4] = bytes.fromhex('00220023')

# 2) Make notify_model_system_error a no-op return.
off = 0x2BC3174
print('notify before', d[off:off + 4].hex())
d[off:off + 2] = bytes.fromhex('7047')

out.write_bytes(bytes(d))
print('wrote', out, len(d))
