#!/bin/bash
set -e

echo "Cleaning build directory..."
rm -rf Build/*

echo "Creating build directory if it doesn't exist..."
mkdir -p Build

echo "Configuring with CMake..."
cd Build
cmake ..

echo "Building project..."
cmake --build .

echo "Running tests..."
ctest --output-on-failure

echo "Build complete!"