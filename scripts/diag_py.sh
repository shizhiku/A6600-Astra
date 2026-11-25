#!/bin/sh
set -x
which -a python3 || true
python3 -V || true
python3 -c 'import sys; print(sys.executable); print(sys.path)' || true
ls /usr/lib/python3/dist-packages 2>/dev/null | grep -i -E 'crypto|usb' || true
ls /usr/lib/python3*/dist-packages 2>/dev/null | grep -i -E '^Crypto' || true
