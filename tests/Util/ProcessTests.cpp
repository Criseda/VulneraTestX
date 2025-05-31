#include <fstream>
#include <gtest/gtest.h>
#include <unistd.h>

#include <Util/Process.hpp>

namespace VulneraTestX::Tests {

    TEST(ProcessTests, ExecuteEcho) {
        Util::ProcessResult result = Util::Process::execute("/bin/echo", {"echo", "hello", "world"}, "");
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.exitCode, 0);
        EXPECT_EQ(result.stdOut, "hello world\n");
        EXPECT_EQ(result.stdErr, "");
    }
    TEST(ProcessTests, ExecuteCatWithStdin) {
        std::string inputData      = "This is a test\nLine 2";
        Util::ProcessResult result = Util::Process::execute("/bin/cat", {"cat"}, inputData);
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.exitCode, 0);
        EXPECT_EQ(result.stdOut, inputData);
        EXPECT_EQ(result.stdErr, "");
    }

    TEST(ProcessTests, CommandWritesToStdErr) {
        // Using sh to redirect echo to stderr
        Util::ProcessResult result = Util::Process::execute("/bin/sh", {"sh", "-c", "echo 'error message' >&2"}, "");
        EXPECT_TRUE(result.success); // sh itself succeeds
        EXPECT_EQ(result.exitCode, 0);
        EXPECT_EQ(result.stdOut, "");
        EXPECT_EQ(result.stdErr, "error message\n");
    }

    TEST(ProcessTests, CommandFailsWithExitCode) {
        // Using sh to exit with a specific code
        Util::ProcessResult result = Util::Process::execute("/bin/sh", {"sh", "-c", "exit 42"}, "");
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.exitCode, 42);
        EXPECT_EQ(result.stdOut, "");
        EXPECT_EQ(result.stdErr, ""); // sh doesn't output to stderr on exit
    }

    TEST(ProcessTests, NonExistentCommand) {
        // This behavior can vary. execvp will fail. The exit code reported by our wrapper
        // should indicate failure.
        Util::ProcessResult result = Util::Process::execute("/path/to/nonexistent/command", {"nonexistent"}, "");
        EXPECT_FALSE(result.success);
        // The exact exit code from our wrapper when execvp fails might be specific.
        // Typically, the child process itself exits with 127 if shell can't find command,
        // or our execvp wrapper might return a custom error. Let's check for non-zero.
        EXPECT_NE(result.exitCode, 0);
        // We might also populate stderr with a message from our wrapper.
        // For now, just checking it's not successful.
        // EXPECT_FALSE(result.stdErr.empty()); // This depends on implementation
    }

    TEST(ProcessTests, ExecuteWithArguments) {
        // Test with a command that uses arguments, e.g., head
        // Create a temporary string with multiple lines
        std::string multiLineInput = "line1\nline2\nline3\n";
        Util::ProcessResult result = Util::Process::execute("/usr/bin/head", {"head", "-n", "2"}, multiLineInput);
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.exitCode, 0);
        EXPECT_EQ(result.stdOut, "line1\nline2\n");
        EXPECT_EQ(result.stdErr, "");
    }

    // Test for environment variables (optional, if implemented)
    TEST(ProcessTests, ExecuteWithEnvironmentVariable) {
        std::map<std::string, std::string> env;
        env["MY_TEST_VAR"] = "hello_env";
        // /usr/bin/env will print environment, then grep for our var
        // A bit complex, simpler might be `sh -c 'echo $MY_TEST_VAR'`
        Util::ProcessResult result =
            Util::Process::execute("/bin/sh", {"sh", "-c", "echo \"Var is: $MY_TEST_VAR\""}, "", env);
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.exitCode, 0);
        EXPECT_EQ(result.stdOut, "Var is: hello_env\n");
    }

    TEST(ProcessTests, ExecuteTargetExampleBufferOverflowClean) {
        // Assuming ExampleBufferOverflow is built into build/targets/
        // Adjust path as necessary, e.g., by finding the project root or using a known relative path.
        // This path needs to be correct relative to where ctest is run (usually the build dir).
        // For now, this might be tricky without a proper way to locate targets.
        // Let's assume it's accessible via a relative path from the build directory where tests run.
        // This test is more of an integration test.
        // If ExampleBufferOverflow is in ${CMAKE_BINARY_DIR}/targets/ExampleBufferOverflow
        // And tests run from ${CMAKE_BINARY_DIR}, then path is "targets/ExampleBufferOverflow"
        // For now, let's use a known system command that expects specific args.
        Util::ProcessResult result = Util::Process::execute("./targets/ExampleBufferOverflow",
            {"./targets/ExampleBufferOverflow", "safe_input"}, ""); // Path relative to build dir
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.exitCode, 0);
        EXPECT_NE(result.stdOut.find("Input: safe_input"), std::string::npos);
    }
} // namespace VulneraTestX::Tests
