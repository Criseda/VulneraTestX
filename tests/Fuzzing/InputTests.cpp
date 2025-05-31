#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include <Fuzzing/Input.hpp>

namespace VulneraTextX::Tests {

    class InputTests : public ::testing::Test {
    protected:
        static void SetUpTestSuite() {}

        static void TearDownTestSuite() {}
    };

    // Base tests for Input class

    TEST_F(InputTests, CanCreateEmptyInput) {
        Fuzzing::Input input;
        EXPECT_EQ(input.size(), 0);
        EXPECT_TRUE(input.empty());
        EXPECT_NE(input.data(), nullptr); // Should point to valid (though empty) memory
    }

    TEST_F(InputTests, CanCreateFromVector) {
        std::vector<uint8_t> vecData = {0x01, 0x02, 0x03, 0x04};
        Fuzzing::Input input(vecData);
        EXPECT_EQ(input.size(), 4);
        ASSERT_NE(input.data(), nullptr);
        for (size_t i = 0; i < vecData.size(); ++i) {
            EXPECT_EQ(input.data()[i], vecData[i]);
        }
        EXPECT_FALSE(input.empty());
    }

    TEST_F(InputTests, CanCreateFromString) {
        std::string strData = "test";
        Fuzzing::Input input(strData);
        EXPECT_EQ(input.size(), 4);
        ASSERT_NE(input.data(), nullptr);
        for (size_t i = 0; i < strData.size(); ++i) {
            EXPECT_EQ(static_cast<char>(input.data()[i]), strData[i]);
        }
        EXPECT_FALSE(input.empty());
    }

    TEST_F(InputTests, CanCreateFromRawPointerAndSize) {
        uint8_t rawData[] = {0xDE, 0xAD, 0xBE, 0xEF};
        size_t rawSize    = sizeof(rawData);
        Fuzzing::Input input(rawData, rawSize);

        EXPECT_EQ(input.size(), rawSize);
        ASSERT_NE(input.data(), nullptr);
        for (size_t i = 0; i < rawSize; ++i) {
            EXPECT_EQ(input.data()[i], rawData[i]);
        }
        // Ensure it's a copy, not pointing to the original rawData
        if (rawSize > 0) {
            // Modify original data to check if input's data changes
            uint8_t originalFirstByte = rawData[0];
            rawData[0]                = 0xFF; // Modify original
            EXPECT_EQ(input.data()[0], originalFirstByte); // Input's data should remain unchanged
            rawData[0] = originalFirstByte; // Restore original for other tests if any
        }
        EXPECT_FALSE(input.empty());
    }

    TEST_F(InputTests, GetDataReturnsValidPointer) {
        std::vector<uint8_t> vecData = {0xAA, 0xBB, 0xCC};
        Fuzzing::Input input(vecData);
        const uint8_t* dataPtr = input.data();
        ASSERT_NE(dataPtr, nullptr);
        EXPECT_EQ(dataPtr[0], 0xAA);
        EXPECT_EQ(dataPtr[1], 0xBB);
        EXPECT_EQ(dataPtr[2], 0xCC);
    }

    TEST_F(InputTests, GetVectorReturnsCorrectData) {
        std::vector<uint8_t> vecData = {0x11, 0x22, 0x33, 0x44, 0x55};
        Fuzzing::Input input(vecData);
        const std::vector<uint8_t>& internalVec = input.getVector();
        EXPECT_EQ(internalVec.size(), vecData.size());
        EXPECT_EQ(internalVec, vecData);
    }

    TEST_F(InputTests, InputIsCopyConstructible) {
        std::vector<uint8_t> vecData = {0x01, 0x02, 0x03};
        Fuzzing::Input originalInput(vecData);
        Fuzzing::Input copiedInput(originalInput);

        EXPECT_EQ(copiedInput.size(), originalInput.size());
        ASSERT_NE(copiedInput.data(), nullptr);
        ASSERT_NE(originalInput.data(), nullptr);
        // Ensure data is the same
        for (size_t i = 0; i < originalInput.size(); ++i) {
            EXPECT_EQ(copiedInput.data()[i], originalInput.data()[i]);
        }
        // Ensure they are different objects (deep copy)
        // Modifying one should not affect the other.
        // This is harder to test without mutation, but at least check pointers if not empty.
        if (originalInput.size() > 0) {
            EXPECT_NE(copiedInput.data(), originalInput.data());
        }
    }

    TEST_F(InputTests, InputIsCopyAssignable) {
        std::vector<uint8_t> vecData1 = {0x0A, 0x0B, 0x0C};
        std::vector<uint8_t> vecData2 = {0x0D, 0x0E};
        Fuzzing::Input input1(vecData1);
        Fuzzing::Input input2(vecData2);

        input2 = input1; // Assign

        EXPECT_EQ(input2.size(), input1.size());
        ASSERT_NE(input1.data(), nullptr);
        ASSERT_NE(input2.data(), nullptr);
        for (size_t i = 0; i < input1.size(); ++i) {
            EXPECT_EQ(input2.data()[i], input1.data()[i]);
        }
        if (input1.size() > 0) {
            EXPECT_NE(input2.data(), input1.data()); // Should be a deep copy
        }

        // Self-assignment
        input1 = input1;
        EXPECT_EQ(input1.size(), vecData1.size());
        for (size_t i = 0; i < vecData1.size(); ++i) {
            EXPECT_EQ(input1.data()[i], vecData1[i]);
        }
    }

    // Mutate tests

    TEST_F(InputTests, MutateEmptyInput) {
        Fuzzing::Input input;
        EXPECT_NO_THROW(input.mutate()); // Should not throw or crash
        EXPECT_EQ(input.size(), 0);
        EXPECT_TRUE(input.empty());
    }

    TEST_F(InputTests, MutatePreservesSize) {
        std::vector<uint8_t> vecData = {0x01, 0x02, 0x03, 0x04, 0x05};
        Fuzzing::Input input(vecData);
        size_t originalSize = input.size();

        input.mutate();

        EXPECT_EQ(input.size(), originalSize);
    }

    TEST_F(InputTests, MutateChangesData) {
        // Use a sufficiently large input to increase chance of observable change
        std::vector<uint8_t> vecData(10, 0xAA); // 10 bytes, all 0xAA
        Fuzzing::Input input(vecData);
        std::vector<uint8_t> originalDataCopy = input.getVector(); // Make a copy for comparison

        // Mutate a few times to ensure a high probability of change
        bool changed = false;
        for (int i = 0; i < 10; ++i) { // Try mutating up to 10 times
            input.mutate();
            if (input.getVector() != originalDataCopy) {
                changed = true;
                break;
            }
            // If it didn't change, restore to original for next attempt,
            // as a bit flip can flip back.
            input = Fuzzing::Input(originalDataCopy);
        }

        if (vecData.empty()) { // If original data was empty, it can't change.
            EXPECT_EQ(input.getVector(), originalDataCopy);
        } else {
            EXPECT_TRUE(changed) << "Input data did not change after 10 mutation attempts.";
        }
    }

    TEST_F(InputTests, MutateCanProduceDifferentResults) {
        std::vector<uint8_t> vecData = {0x00, 0x00, 0x00, 0x00}; // Start with all zeros
        Fuzzing::Input input(vecData);

        // Store results of several mutations.
        // Using std::set to see if we get unique mutated inputs.
        // A std::vector<std::vector<uint8_t>> would also work.
        std::set<std::vector<uint8_t>> mutationResults;
        const int mutationAttempts       = 20; // Number of times to mutate and record
        const int expectedUniqueOutcomes = 3; // Expect at least a few different outcomes

        if (input.empty()) {
            SUCCEED() << "Skipping test for empty input as it cannot be meaningfully mutated to different results.";
            return;
        }

        for (int i = 0; i < mutationAttempts; ++i) {
            Fuzzing::Input currentInput(vecData); // Start from the same original state
            currentInput.mutate();
            mutationResults.insert(currentInput.getVector());
        }

        // This test is probabilistic. It's possible, though unlikely with enough attempts
        // on non-trivial input, to get fewer unique results than expected.
        EXPECT_GE(mutationResults.size(), std::min((size_t) expectedUniqueOutcomes, vecData.size() * 8))
            << "Mutation did not produce a variety of outcomes. Got " << mutationResults.size() << " unique results.";
    }
} // namespace VulneraTextX::Tests
