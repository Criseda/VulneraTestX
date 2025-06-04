#include <regex> // For more flexible pattern matching
#include <sstream> // For std::istringstream
#include <string>
#include <vector>

#include <Util/SanitizerDetector.hpp>

namespace VulneraTestX::Util {

    SanitizerIssue SanitizerDetector::detectIssue(const std::string& stderrOutput) {
        SanitizerIssue issue;

        // Common sanitizer names and keywords
        const std::string asanName = "AddressSanitizer";
        const std::string usanName = "UndefinedBehaviorSanitizer";
        // Add LSan, TSan etc. if needed later

        // Regex patterns to find summary lines
        // Example: "SUMMARY: AddressSanitizer: heap-buffer-overflow /path/to/file.cpp:123 in func"
        // Example: "SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow /app/example.cpp:20:10 in main"
        // This regex tries to capture Sanitizer Name and Error Type from SUMMARY lines.
        // It's a simplified example; real sanitizer output can be complex.
        std::regex summaryPattern(R"(SUMMARY:\s*([a-zA-Z_]+Sanitizer):\s*([a-zA-Z0-9_-]+(?:-after-[a-zA-Z0-9_-]+)?))");
        // The error type part (([a-zA-Z0-9_-]+(?:-after-[a-zA-Z0-9_-]+)?)) tries to match simple words
        // or patterns like 'type-after-type'.

        std::smatch match;
        std::string line;
        std::istringstream stream(stderrOutput); // To iterate line by line

        while (std::getline(stream, line)) {
            if (std::regex_search(line, match, summaryPattern)) {
                if (match.size() >= 3) { // Ensure we have sanitizer name and error type
                    issue.detected      = true;
                    issue.sanitizerName = match[1].str();
                    issue.errorType     = match[2].str();
                    issue.summaryLine   = line; // Capture the full summary line
                    // Once a summary is found, we can often stop, as it's the most reliable indicator.
                    return issue;
                }
            }
            // Fallback: If no SUMMARY line, look for "ERROR: AddressSanitizer:" lines directly,
            // though these are less structured for extracting the precise "errorType".
            // This part makes it more robust if SUMMARY is missing or different.
            if (!issue.detected) { // Only if not already detected via SUMMARY
                size_t asanErrorPos = line.find("ERROR: " + asanName + ":");
                if (asanErrorPos != std::string::npos) {
                    issue.detected      = true;
                    issue.sanitizerName = asanName;
                    issue.summaryLine   = line; // Capture the ERROR line as a key line
                    // Try to extract error type from the line, e.g., after "ERROR: AddressSanitizer: "
                    std::string errorDetails = line.substr(asanErrorPos + ("ERROR: " + asanName + ":").length());
                    // Simplistic extraction: take the first word (e.g. heap-buffer-overflow)
                    std::istringstream errorStream(errorDetails);
                    errorStream >> issue.errorType;
                    // Remove trailing chars like " on" if any, e.g. "heap-buffer-overflow on"
                    size_t onPos = issue.errorType.rfind(" on");
                    if (onPos != std::string::npos && onPos + 3 == issue.errorType.length()) { // check " on" at the end
                        issue.errorType = issue.errorType.substr(0, onPos);
                    }

                    return issue; // Found an ASan error line
                }
                // Add similar direct "ERROR: UndefinedBehaviorSanitizer:" checks if needed,
                // though USan often just prints the runtime error line and then a SUMMARY.
            }
        }

        // If no specific "SUMMARY" or "ERROR:" line was found, but keywords exist,
        // it might be a less structured report or a different sanitizer.
        // This is a simpler, broader check if the regex fails or for other patterns.
        if (!issue.detected) {
            if (stderrOutput.find(asanName) != std::string::npos) {
                issue.detected      = true;
                issue.sanitizerName = asanName;
                // errorType would be unknown here unless more parsing is done
            } else if (stderrOutput.find(usanName) != std::string::npos) {
                issue.detected      = true;
                issue.sanitizerName = usanName;
            }
        }
        // If issue.summaryLine is still empty but detected is true, try to find any line with the sanitizer name.
        if (issue.detected && issue.summaryLine.empty()) {
            std::istringstream fullStream(stderrOutput);
            while (std::getline(fullStream, line)) {
                if (line.find(issue.sanitizerName) != std::string::npos) {
                    issue.summaryLine = line;
                    break;
                }
            }
        }


        return issue;
    }

} // namespace VulneraTestX::Util
