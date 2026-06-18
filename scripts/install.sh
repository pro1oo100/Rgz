#!/usr/bin/env bash
# install.sh вЂ” installs cryptum to /usr/local (requires root)
set -e

INSTALL_BIN=/usr/local/bin
INSTALL_LIB=/usr/local/lib
BUILD=build

if [ ! -f "$BUILD/cryptum" ]; then
    echo "Build directory not found. Run 'make' first."
    exit 1
fi

echo "Installing cryptum binary -> $INSTALL_BIN/cryptum"
install -m 755 "$BUILD/cryptum" "$INSTALL_BIN/cryptum"

echo "Installing shared libraries -> $INSTALL_LIB/"
install -m 755 "$BUILD/libatbash.so" "$INSTALL_LIB/libatbash.so"
install -m 755 "$BUILD/librc4.so"    "$INSTALL_LIB/librc4.so"

ldconfig
echo "Done. Run 'cryptum --help' to verify."
