#!/bin/bash
set -e

# Get number of CPU cores for parallel builds
CORES=$(nproc)

echo "=== VulneraTestX Debug Rebuild ==="
echo "Using ${CORES} CPU cores for parallel build"
echo "Debug build includes AddressSanitizer and UndefinedBehaviorSanitizer"

echo "Cleaning debug build directory..."
rm -rf build/debug
mkdir -p build/debug

echo "Configuring with CMake (Debug)..."
cd build/debug

# Use Ninja generator for faster builds (if available)
if command -v ninja >/dev/null 2>&1; then
    echo "Using Ninja generator for faster builds..."
    cmake -G Ninja \
          -DCMAKE_BUILD_TYPE=Debug \
          -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
          ../..
    echo "Building project with Ninja using ${CORES} cores..."
    ninja -j${CORES}
else
    echo "Using Unix Makefiles with ${CORES} parallel jobs..."
    cmake -DCMAKE_BUILD_TYPE=Debug \
          -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
          ../..
    echo "Building project with ${CORES} parallel jobs..."
    cmake --build . --parallel ${CORES}
fi

echo "Running tests with sanitizers..."
echo "Note: Tests will run slower due to AddressSanitizer"
ctest --output-on-failure --parallel ${CORES}

echo "=== Debug Build Complete in $(pwd) ==="
echo "Executables (with sanitizers):"
echo "  - Main: bin/VulneraTestX"
echo "  - Tests: bin/VulneraTestXTests"
echo "  - Targets: targets/*"