#include <iostream>
#include <stdexcept>
#include <string>

#include <VulneraTestX.hpp>

int main(int argc, char* argv[]) {
    std::cout << "VulneraTestX - Modern C++ Binary Fuzzing and Analysis Tool\n";
    std::cout << "Version: 0.1.0\n";

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target_executable_path> [num_iterations]\n";
        return 1;
    }

    std::string targetPath = argv[1];
    int numIterations      = 100; // Default number of iterations

    if (argc > 2) {
        try {
            numIterations = std::stoi(argv[2]);
            if (numIterations <= 0) {
                std::cerr << "Number of iterations must be positive.\n";
                return 1;
            }
        } catch (const std::invalid_argument& ia) {
            std::cerr << "Invalid number for iterations: " << argv[2] << std::endl;
            return 1;
        } catch (const std::out_of_range& oor) {
            std::cerr << "Number of iterations out of range: " << argv[2] << std::endl;
            return 1;
        }
    }

    VulneraTestX::Core core;
    core.Initialize(); // Initialize the core components

    try {
        core.StartFuzzing(targetPath, numIterations);
    } catch (const std::exception& e) {
        std::cerr << "An error occurred during fuzzing: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "An unknown error occurred during fuzzing." << std::endl;
        return 1;
    }

    return 0;
}
