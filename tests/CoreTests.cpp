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
} // namespace VulneraTestX::Tests
