#include <VulneraTestX.hpp>
#include <gtest/gtest.h>

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
