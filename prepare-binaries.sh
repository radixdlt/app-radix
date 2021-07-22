#!/bin/sh
set -e

APPVERSION=`make appversion 2>/dev/null | grep ^VERSION | cut -d '=' -f 2`

echo "Preparing binaries for version $APPVERSION"

rm -rf ./out >/dev/null 2>&1
mkdir out

echo "Building release binaries..."

make clean >/dev/null 2>&1
make DEBUG=0 >/dev/null 2>&1
cp -a bin out/
cp -a debug out/

echo "Creating archive..."
cd out 
zip -9rm ../LedgerNano_S-$APPVERSION-RELEASE.zip . >/dev/null 2>&1
cd ..

echo "Building debug binaries..."
make clean >/dev/null 2>&1
make DEBUG=1 > /dev/null 2>&1
cp -a bin out/
cp -a debug out/

echo "Creating archive..."
cd out 
zip -9rm ../LedgerNano_S-$APPVERSION-DEBUG.zip . >/dev/null 2>&1
cd ..

echo "Done."
