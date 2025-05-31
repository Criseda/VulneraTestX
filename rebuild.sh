#!/bin/bash
set -e

echo "Cleaning build directory..."
rm -rf build/*

echo "Creating build directory if it doesn't exist..."
mkdir -p build

echo "Configuring with CMake..."
cd build
cmake ..

echo "Building project..."
cmake --build .

echo "Running tests..."
ctest --output-on-failure

echo "Build complete!"