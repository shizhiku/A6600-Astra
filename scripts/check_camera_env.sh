#!/bin/bash
set -eu
for p in /root/a6600/pmca-vendor /root/bionz/.venv/bin/python /root/bionz/venv/bin/python; do [ -e "$p" ] && echo "$p"; done
