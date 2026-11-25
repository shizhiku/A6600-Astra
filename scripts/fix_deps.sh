#!/bin/sh
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq python3-pycryptodome
python3 - <<'PY'
import Crypto
print('pycryptodome', Crypto.__version__)
PY
