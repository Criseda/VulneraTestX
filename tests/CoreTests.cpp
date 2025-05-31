#include <fstream>
#include <gtest/gtest.h>

#include <VulneraTestX.hpp>

namespace VulneraTestX::Tests {
    TEST(CoreTests, InitializeTest) {
        Core core;
        EXPECT_NO_THROW(core.Initialize());
    }

    TEST(CoreTests, CanCreateMultipleInstances) {
        Core core1;
        Core core2;
        EXPECT_NO_THROW(core1.Initialize());
        EXPECT_NO_THROW(core2.Initialize());
    }

    // Basic integration tests for fuzzing loop
    TEST(CoreTests, BasicFuzzingLoopDoesNotCrashSelf) {
        Core core;
        core.Initialize();

        // Path to ExampleBufferOverflow relative to the build directory
        // This might need adjustment based on your CMake output directories
        // In your CMakeLists.txt, targets are in ${CMAKE_BINARY_DIR}/Targets
        std::string targetPath = "./targets/ExampleBufferOverflow";

        // Check if the target actually exists to avoid test failure due to missing file
        std::ifstream targetFile(targetPath);
        if (!targetFile.is_open()) {
            // If not found, try one directory up (e.g. if tests run in Build/bin)
            targetPath = "../targets/ExampleBufferOverflow";
            std::ifstream targetFileRetry(targetPath);
            ASSERT_TRUE(targetFileRetry.is_open()) << "Test target ExampleBufferOverflow not found at " << targetPath
                                                   << " or ./targets/ExampleBufferOverflow. "
                                                   << "Ensure it's built and path is correct for test environment.";
            targetFileRetry.close();
        } else {
            targetFile.close();
        }

        // Run for a very small number of iterations
        ASSERT_NO_THROW(core.StartFuzzing(targetPath, 5)) << "VulneraTestX itself crashed during basic fuzzing loop.";
    }
} // namespace VulneraTestX::Tests
