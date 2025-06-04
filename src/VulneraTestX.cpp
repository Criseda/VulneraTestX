#include <cstdio>
#include <iostream>
#include <string>
#include <vector>
#include <cctype> // For isprint

#include <Fuzzing/Input.hpp>
#include <Util/Process.hpp>
#include <Util/SanitizerDetector.hpp>
#include <VulneraTestX.hpp>

namespace VulneraTestX {
    void Core::Initialize() {
        std::cout << "VulneraTestX Core Initialized\n";
        // Can seed rng here if we need it globally later
    }

    void Core::StartFuzzing(const std::string& targetExecutablePath, int numIterations) {
        std::cout << "Starting fuzzing on target: " << targetExecutablePath << " for " << numIterations
                  << " iterations.\n";

        // 1. Use a longer initial seed input, capable of overflowing a 64-byte buffer
        std::string longSeed(100, 'A'); // 100 'A' characters
        Fuzzing::Input currentInput(longSeed);

        for (int i = 0; i < numIterations; ++i) {
            currentInput.mutate(); // Mutate input

            const std::vector<uint8_t>& inputDataVec = currentInput.getVector();
            // Convert the mutated data to a string to be used as a command-line argument
            std::string mutatedArgString(inputDataVec.begin(), inputDataVec.end());

            // 2. Prepare arguments to pass the mutated input as argv[1]
            std::vector<std::string> arguments = {
                targetExecutablePath, // argv[0] is the program name/path
                mutatedArgString // argv[1] is our fuzzed input
            };

            std::cout << "\n[Iteration " << i + 1 << "/" << numIterations << "]" << std::endl;
            // For command-line args, printing the full arg might be too verbose if very long.
            // Let's print its size and a snippet.
            std::cout << "Feeding input as argv[1] (size " << mutatedArgString.length() << "): ";
            for (size_t k = 0; k < mutatedArgString.length() && k < 16; ++k) {
                // Crude print for potentially non-printable chars in arg string
                if (isprint(static_cast<unsigned char>(mutatedArgString[k]))) {
                    std::cout << mutatedArgString[k];
                } else {
                    printf("\\x%02x", static_cast<unsigned char>(mutatedArgString[k]));
                }
            }
            if (mutatedArgString.length() > 16) {
                std::cout << "...";
            }
            std::cout << std::endl;

            // 3. Execute the target, passing an empty string for stdin since input is now via argv
            Util::ProcessResult result = Util::Process::execute(targetExecutablePath, arguments, "" /* Empty stdin */);

            std::cout << "Target Executed." << std::endl;
            std::cout << "  Exit Code: " << result.exitCode << (result.success ? " (Success)" : " (Failure/Error)")
                      << std::endl;

            if (!result.stdOut.empty()) {
                std::cout << "  Stdout:\n<<<\n" << result.stdOut << "\n>>>" << std::endl;
            }
            if (!result.stdErr.empty()) {
                std::cout << "  Stderr:\n<<<\n" << result.stdErr << "\n>>>" << std::endl;
            }

            Util::SanitizerIssue issue = Util::SanitizerDetector::detectIssue(result.stdErr);

            if (issue.detected) {
                std::cout << "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
                std::cout << "  !!! SANITIZER ISSUE DETECTED !!!" << std::endl;
                std::cout << "  Sanitizer: " << issue.sanitizerName << std::endl;
                std::cout << "  Error Type: " << issue.errorType << std::endl;
                if (!issue.summaryLine.empty()) {
                    std::cout << "  Key Line: " << issue.summaryLine << std::endl;
                }
                std::cout << "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
                // In the NEXT step, we'll save 'currentInput' here.
            } else if (!result.success && result.exitCode != 0) {
                std::cout << "  !!! POTENTIAL ERROR DETECTED (Non-zero exit code) !!!" << std::endl;
            }
        }
        std::cout << "\nFuzzing completed.\n";
    }
} // namespace VulneraTestX
