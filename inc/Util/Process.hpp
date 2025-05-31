#pragma once

#include <map>
#include <string>
#include <vector>

namespace VulneraTestX::Util {
    struct ProcessResult {
        std::string stdOut;
        std::string stdErr;
        int exitCode{0};
        bool success{false};
        // Add timeout status later if need be
    };

    class Process {
    public:
        /**
         * @brief Executes external command
         * @param executablePath Full path to executable
         * @param arguments Vector of arguments to pass to the executable. argv[0] is the executable name itself.
         * @param stdInData String of data to be fed to stdIn of executable
         * @param environment Optional environment variables to set for child process
         * @return ProcessResult containing stdout, stderr and exit code
         */
        static ProcessResult execute(const std::string& executablePath, const std::vector<std::string>& arguments,
            const std::string& stdInData, const std::map<std::string, std::string>& environment = {});

    protected:
    private:
    };
} // namespace VulneraTestX::Util
