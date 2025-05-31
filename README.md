# VulneraTestX

Modern C++ Binary Fuzzing and Analysis Tool for Linux binaries.
**Version: 0.2.0 (alpha)**

## Features

**Current (v0.2.0 - Basic Implementation):**

-   **Basic Dynamic Fuzzing Loop:**
    -   Mutates input using a simple bit-flip strategy.
    -   Executes target Linux binaries with the mutated input.
    -   Input is currently passed via **stdin**.
    -   Captures and displays stdout, stderr, and exit codes from the target.
    -   Provides a rudimentary indication of potential errors based on target exit codes.
-   **Core Input Representation:** Manages fuzz data (`Fuzzing::Input` class).
-   **Process Execution Utility:** Allows for controlled launching and monitoring of target processes (`Util::Process` class), including setting custom environment variables.
-   **Sanitizer Build Support:** Debug builds are configured with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (USan) flags. (Manual inspection of sanitizer output from the fuzzing loop is currently needed).

**Planned / Key TODOs:**

-   **Advanced Crash Detection:**
    -   Reliable parsing of ASan, USan, and other sanitizer output from `stderr`.
    -   Proper signal handling for crash detection (SIGSEGV, SIGABRT, etc.).
-   **Crashing Input Management:**
    -   Automatically saving inputs that trigger crashes.
    -   Mechanisms for crash uniqueness and triaging.
-   **Input Corpus Management:**
    -   Storing and evolving a corpus of interesting inputs.
    -   Coverage guidance (more advanced).
-   **Sophisticated Mutation Strategies:**
    -   Implementing a wider range of mutation techniques (e.g., byte-level, block-based, dictionary).
-   **Target Interaction:**
    -   Support for providing input via command-line arguments and files, in addition to stdin.
-   **Lightweight Static Analysis Modules.**
-   **Integrated CVE Analysis Capabilities.**
-   **Configuration Options:** More flexible control over fuzzing parameters.

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
