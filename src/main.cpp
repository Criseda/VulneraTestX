#include <iostream>

#include <VulneraTestX.hpp>

int main() {
    std::cout << "VulneraTestX - Modern C++ Binary Fuzzing and Analysis Tool\n";
    std::cout << "Version: 0.1.0\n";

    VulneraTestX::Core core;

    core.Initialize();

    return 0;
}
