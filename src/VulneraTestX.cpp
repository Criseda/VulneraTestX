#include <iostream>
#include <string>
#include <vector>

#include <Fuzzing/Input.hpp>
#include <Util/Process.hpp>
#include <VulneraTestX.hpp>

namespace VulneraTestX {
    void Core::Initialize() {
        std::cout << "VulneraTestX Core Initialized\n";
        // Can seed rng here if we need it globally later
    }

    void Core::StartFuzzing(const std::string& targetExecutablePath, int numIterations) {
        std::cout << "Starting fuzzing on target: " << targetExecutablePath << " for " << numIterations
                  << " iterations.\n";

        // Create an initial seed input. This could be more sophisticated later (e.g., from a file or corpus).
        // For now, let's start with a simple, non-empty string.
        Fuzzing::Input currentInput("initial_seed_data_123");

        for (int i = 0; i < numIterations; ++i) {
            // 1. Mutate the current input
            currentInput.mutate();

            // 2. Prepare data for the process execution
            // The Process::execute expects std::string for stdin.
            // Input::getVector() returns std::vector<uint8_t>.
            const std::vector<uint8_t>& inputDataVec = currentInput.getVector();
            std::string stdInDataString(inputDataVec.begin(), inputDataVec.end());

            // 3. Prepare arguments for the target.
            // For many programs, the input can be passed via stdin.
            // If the target expects input via command-line arguments, this would be different.
            // The first argument (argv[0]) is typically the program name itself.
            std::vector<std::string> arguments = {targetExecutablePath};

            // Example: If target took fuzzed input as its first real argument:
            // std::vector<std::string> arguments = {targetExecutablePath, stdInDataString};
            // And then stdInDataString for Process::execute would be empty if input is via args.
            // For now, assuming stdin.

            std::cout << "\n[Iteration " << i + 1 << "/" << numIterations << "]" << std::endl;
            std::cout << "Feeding input (size " << currentInput.size() << "): ";
            for (size_t k = 0; k < currentInput.size() && k < 16; ++k) { // Print first few bytes
                printf("%02x ", inputDataVec[k]);
            }
            if (currentInput.size() > 16) {
                std::cout << "...";
            }
            std::cout << std::endl;


            // 4. Execute the target
            Util::ProcessResult result = Util::Process::execute(targetExecutablePath, arguments, stdInDataString);

            // 5. Report results (basic for now)
            std::cout << "Target Executed." << std::endl;
            std::cout << "  Exit Code: " << result.exitCode << (result.success ? " (Success)" : " (Failed/Crashed?)")
                      << std::endl;
            if (!result.stdOut.empty()) {
                std::cout << "  Stdout:\n" << result.stdOut << std::endl;
            }
            if (!result.stdErr.empty()) {
                std::cout << "  Stderr:\n" << result.stdErr << std::endl;
            }

            // Basic crash detection
            // On Linux, crashes due to signals often result in exit codes > 128.
            // SIGSEGV is 11, so exit code 128+11 = 139.
            // SIGABRT is 6, so exit code 128+6 = 134.
            // ASan/USan might use specific exit codes or print to stderr.
            if (!result.success && result.exitCode != 0) {
                // This is a very naive check. Real crash detection is more complex.
                // e.g. checking for specific signals if WIFSIGNALED(status) was true in Process.cpp
                // or parsing ASan output from stderr.
                std::cout << "  !!! POTENTIAL CRASH OR ERROR DETECTED !!!" << std::endl;
                // TODO: for later, you'd save the 'currentInput' that caused this.
            }
        }
        std::cout << "\nFuzzing completed.\n";
    }
} // namespace VulneraTestX
