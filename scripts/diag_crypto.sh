#!/bin/sh
python3 - <<'PY'
try:
    from Cryptodome.Hash import SHA256
    import Cryptodome
    print('Cryptodome OK', Cryptodome.__version__)
except Exception as e:
    print('Cryptodome FAIL', e)
try:
    from Crypto.Hash import SHA256
    import Crypto
    print('Crypto OK', Crypto.__version__)
except Exception as e:
    print('Crypto FAIL', e)
PY
