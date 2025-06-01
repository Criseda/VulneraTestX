#!/bin/bash
set -e

# Get number of CPU cores for parallel builds
CORES=$(nproc)

echo "=== VulneraTestX Incremental Build ==="
echo "Using ${CORES} CPU cores for parallel build"

# Check if build directory exists and is configured
if [ ! -d "build" ]; then
    echo "No build directory found, creating and configuring..."
    mkdir -p build
    cd build
    
    if command -v ninja >/dev/null 2>&1; then
        cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
    else
        cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
    fi
else
    cd build
    
    # Check if build system is configured
    if [ ! -f "build.ninja" ] && [ ! -f "Makefile" ]; then
        echo "Build system not configured, configuring..."
        if command -v ninja >/dev/null 2>&1; then
            cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
        else
            cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
        fi
    fi
fi

echo "Running incremental build..."
if [ -f "build.ninja" ]; then
    echo "Building with Ninja (${CORES} cores)..."
    ninja -j${CORES}
elif [ -f "Makefile" ]; then
    echo "Building with Make (${CORES} jobs)..."
    make -j${CORES}
else
    echo "Fallback: Using cmake --build..."
    cmake --build . --parallel ${CORES}
fi

echo "Running tests..."
ctest --output-on-failure --parallel ${CORES}

echo "=== Incremental Build Complete ==="
echo "Tip: Use './rebuild.sh' for clean Release build or './rebuild-debug.sh' for Debug build"