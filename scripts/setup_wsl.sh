#!/bin/sh
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-usb libusb-1.0-0 usbutils
echo APT_OK
python3 -c 'import usb; print("pyusb", usb.__version__)'
command -v lsusb
