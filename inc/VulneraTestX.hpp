#pragma once

namespace VulneraTestX {
    class Core {
    public:
        void Initialize();

        /**
         * @brief Starts a basic fuzzing loop against the specified target executable.
         * @param targetExecutablePath Path to the executable to fuzz.
         * @param numIterations Number of fuzzing iterations to perform.
         */
        void StartFuzzing(const std::string& targetExecutablePath, int numIterations);

    protected:
    private:
    };
} // namespace VulneraTestX
