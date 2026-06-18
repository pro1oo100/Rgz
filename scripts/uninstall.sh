#!/usr/bin/env bash
# uninstall.sh вЂ” removes cryptum from /usr/local (requires root)
set -e

rm -f /usr/local/bin/cryptum
rm -f /usr/local/lib/libatbash.so
rm -f /usr/local/lib/librc4.so
ldconfig
echo "cryptum uninstalled."
