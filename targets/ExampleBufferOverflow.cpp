#include <cstring>
#include <iostream>

int main(int argc, char* argv[]) {
    char buffer[64];
    if (argc > 1) {
        strcpy(buffer, argv[1]); // Vulnerable to buffer overflow
        std::cout << "Input: " << buffer << std::endl;
    }
    return 0;
}
