#pragma once

#include <string>
#include <vector>

namespace VulneraTestX::Util {
/**
 * @brief Stores information about a detected sanitizer issue.
 */
struct SanitizerIssue {
  bool detected = false;
  std::string errorType;  // e.g., "heap-buffer-overflow", "use-after-free"
  std::string
      sanitizerName;  // e.g., "AddressSanitizer", "UndefinedBehaviorSanitizer"
  std::string summaryLine;  // The primary line indicating the error
};

class SanitizerDetector {
 public:
  /**
   * @brief Detects sanitizer issues in the provided log.
   * @param log The log content to analyze.
   * @return A vector of SanitizerIssue objects representing detected issues.
   */
  static SanitizerIssue detectIssue(
      const std::string &stdErrorOutput);

 protected:
 private:
  SanitizerDetector() = default;  // Prevent instantiation
};
}  // namespace VulneraTestX::Util