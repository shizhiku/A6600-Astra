from pathlib import Path

src = Path('<WORKSPACE>/03-证据/静态分析/97_abi/a5pFw_actual.so')
out = Path('<WORKSPACE>/03-证据/静态分析/97_abi/a5pFw_upmfix.so')
d = bytearray(src.read_bytes())
off = 0x2BBA520
print('before', d[off:off + 4].hex())
assert d[off:off + 4] == bytes.fromhex('0a6a4b6a'), 'unexpected original bytes'
d[off:off + 4] = bytes.fromhex('00220023')
print('after', d[off:off + 4].hex())
out.write_bytes(bytes(d))
print('wrote', out, len(d))
