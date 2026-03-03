#!/bin/bash
set -e

echo ""
echo " ============================================"
echo "  Renef - Build (WSL/Linux)"
echo " ============================================"
echo ""

if [ ! -f CMakeLists.txt ]; then
    echo " [ERROR] CMakeLists.txt not found in $(pwd)"
    echo "         Run this script from the renef project root."
    exit 1
fi

if [ ! -d src/librenef ]; then
    echo " [ERROR] src/ folder not found in $(pwd)"
    echo "         You need the full project, not just individual files."
    echo "         Clone: git clone https://github.com/ahmeth4n/renef.git"
    exit 1
fi

echo " [1/3] Installing build dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential cmake libreadline-dev git >/dev/null 2>&1
echo "        Done."

echo " [2/3] Configuring with CMake..."
rm -rf build
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

echo " [3/3] Building..."
make -j"$(nproc)"

echo ""
echo " ============================================"
echo "  Build successful!"
echo "  Binary: build/renef"
echo ""
echo "  Usage: ./build/renef"
echo " ============================================"
