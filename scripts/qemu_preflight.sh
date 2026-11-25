#!/bin/bash
set -eu
/root/qemu-11.1.3/build/qemu-system-arm -version
/root/qemu-11.1.3/build/qemu-system-arm -machine help | grep sony
ls -l /root/qemu_in <LEGACY_WORKSPACE>/qemu_in
git -C /root/bionz rev-parse HEAD
