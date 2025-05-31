# VulneraTestX

Modern C++ Binary Fuzzing and Analysis Tool for Linux binaries.

## Features (TODO)

- Lightweight static analysis
- Dynamic fuzzing with crash detection
- ASAN/UBSAN integration
- CVE analysis capabilities

## Requirements

- CMake 3.16+
- GCC with C++20 support
- vcpkg package manager

## Building

```bash
# Install dependencies
vcpkg install

# Build manually
mkdir Build && cd Build
cmake ..
cmake --build .

# Build automatically
./rebuild.sh

# Run tests
ctest --output-on-failure
```

## Usage

```bash
./bin/VulneraTestX [binary-file]
```

## Project Structure

```bash
├── src/           # Core implementation
├── inc/           # Public headers
├── tests/         # Unit tests
└── targets/       # Test vulnerable binaries
```

## License

Apache 2.0 License - See [LICENSE](LICENSE) file for details.
