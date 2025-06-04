#include <gtest/gtest.h>

#include <Util/SanitizerDetector.hpp>

namespace VulneraTestX::Tests {

    TEST(SanitizerDetectorTests, NoIssueDetected) {
        std::string stderrOutput   = "This is some normal error output.\nNo sanitizer messages here.";
        Util::SanitizerIssue issue = Util::SanitizerDetector::detectIssue(stderrOutput);
        EXPECT_FALSE(issue.detected);
        EXPECT_TRUE(issue.errorType.empty());
        EXPECT_TRUE(issue.sanitizerName.empty());
    }

    TEST(SanitizerDetectorTests, EmptyStdErr) {
        std::string stderrOutput   = "";
        Util::SanitizerIssue issue = Util::SanitizerDetector::detectIssue(stderrOutput);
        EXPECT_FALSE(issue.detected);
    }

    TEST(SanitizerDetectorTests, DetectsASanHeapBufferOverflow) {
        std::string stderrOutput =
            "=================================================================\n"
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef at pc 0x000000400080 bp "
            "0x7ffd9778e6a0 sp 0x7ffd9778e698\n"
            "READ of size 4 at 0xdeadbeef thread T0\n"
            "    #0 0x40007f in main /path/to/source.c:10\n"
            "0xdeadbeef is located 0 bytes to the right of 64-byte region [0xdeadbeef-0xdeadbeef]\n"
            "allocated by thread T0 here:\n"
            "    #0 0x7f50c0a00000  (/lib/x86_64-linux-gnu/libasan.so.5+0x10a000)\n"
            "    #1 0x40003e in main /path/to/source.c:5\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /path/to/source.c:10 in main\n";

        Util::SanitizerIssue issue = Util::SanitizerDetector::detectIssue(stderrOutput);
        EXPECT_TRUE(issue.detected);
        EXPECT_EQ(issue.sanitizerName, "AddressSanitizer");
        // Basic detection might just grab "heap-buffer-overflow" from the summary line or error line
        EXPECT_NE(issue.errorType.find("heap-buffer-overflow"), std::string::npos);
        EXPECT_FALSE(issue.summaryLine.empty()); // Check if summary line was captured
    }

    TEST(SanitizerDetectorTests, DetectsUSanIntegerOverflow) {
        std::string stderrOutput =
            "/app/example.cpp:20:10: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in "
            "type 'int'\n"
            "SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow /app/example.cpp:20:10 in main\n";

        Util::SanitizerIssue issue = Util::SanitizerDetector::detectIssue(stderrOutput);
        EXPECT_TRUE(issue.detected);
        EXPECT_EQ(issue.sanitizerName, "UndefinedBehaviorSanitizer");
        EXPECT_NE(issue.errorType.find("signed-integer-overflow"), std::string::npos);
        EXPECT_FALSE(issue.summaryLine.empty());
    }

    TEST(SanitizerDetectorTests, DetectsASanStackBufferOverflow) {
        std::string stderrOutput = "SUMMARY: AddressSanitizer: stack-buffer-overflow /path/to/another.c:30 in foo\n"
                                   "==ERROR: AddressSanitizer: stack-buffer-overflow on address ..."; // Other details

        Util::SanitizerIssue issue = Util::SanitizerDetector::detectIssue(stderrOutput);
        EXPECT_TRUE(issue.detected);
        EXPECT_EQ(issue.sanitizerName, "AddressSanitizer");
        EXPECT_NE(issue.errorType.find("stack-buffer-overflow"), std::string::npos);
        EXPECT_FALSE(issue.summaryLine.empty());
    }

    TEST(SanitizerDetectorTests, DetectsASanUseAfterFree) {
        std::string stderrOutput =
            "==13579==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc ...\n"
            "READ of size 1 at 0x602000000010 thread T0\n"
            "SUMMARY: AddressSanitizer: heap-use-after-free /app/src/main.cpp:42\n";

        Util::SanitizerIssue issue = Util::SanitizerDetector::detectIssue(stderrOutput);
        EXPECT_TRUE(issue.detected);
        EXPECT_EQ(issue.sanitizerName, "AddressSanitizer");
        EXPECT_NE(issue.errorType.find("heap-use-after-free"), std::string::npos);
        EXPECT_FALSE(issue.summaryLine.empty());
    }

    TEST(SanitizerDetectorTests, IgnoresNonSanitizerErrors) {
        std::string stderrOutput   = "Error: File not found.\n"
                                     "Permission denied.\n";
        Util::SanitizerIssue issue = Util::SanitizerDetector::detectIssue(stderrOutput);
        EXPECT_FALSE(issue.detected);
    }

    TEST(SanitizerDetectorTests, MixedContentWithSanitizerError) {
        std::string stderrOutput   = "Some initial debug output from the program.\n"
                                     "Followed by a critical issue:\n"
                                     "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef\n"
                                     "And then some more logging.\n"
                                     "SUMMARY: AddressSanitizer: heap-buffer-overflow /path/to/source.c:10 in main\n";
        Util::SanitizerIssue issue = Util::SanitizerDetector::detectIssue(stderrOutput);
        EXPECT_TRUE(issue.detected);
        EXPECT_EQ(issue.sanitizerName, "AddressSanitizer");
        EXPECT_NE(issue.errorType.find("heap-buffer-overflow"), std::string::npos);
    }

    // Add more tests for other sanitizer types (LeakSanitizer, ThreadSanitizer if relevant)
    // and different error messages as you encounter them.

} // namespace VulneraTestX::Tests
