#include <algorithm>
#include <cerrno>
#include <cstdio> // For setvbuf, NULL, _IOLBF, _IONBF
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include <Util/Process.hpp>

extern char** environ; // For default environment if not using custom

namespace VulneraTestX::Util {
    namespace {
        // Helper functions
        std::vector<char*> prepare_argv(const std::vector<std::string>& arguments) {
            std::vector<char*> argv;
            for (const auto& arg : arguments) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);
            return argv;
        }

        // Helper to prepare environment variables for execvpe
        // It populates env_storage (which owns the "KEY=VALUE" strings)
        // and envp_c (which contains char* pointers to strings in env_storage).
        void build_envp(const std::map<std::string, std::string>& environment_map,
            std::vector<std::string>& env_storage, std::vector<char*>& envp_c) {
            env_storage.clear();
            envp_c.clear();

            for (const auto& pair : environment_map) {
                env_storage.push_back(pair.first + "=" + pair.second);
            }

            for (const auto& env_str : env_storage) {
                envp_c.push_back(const_cast<char*>(env_str.c_str()));
            }
            envp_c.push_back(nullptr); // Null-terminate the envp array
        }

        // Helper function to read from a file descriptor until EOF
        std::string read_fd_to_string(int fd) {
            std::string result_str;
            char buffer[4096];
            ssize_t bytes_read;

            // Set fd to non-blocking to avoid hanging if no data
            // int flags = fcntl(fd, F_GETFL, 0);
            // fcntl(fd, F_SETFL, flags | O_NONBLOCK);

            while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
                buffer[bytes_read] = '\0'; // Null-terminate
                result_str += buffer;
            }
            // Handle read errors if necessary (bytes_read == -1 && errno != EAGAIN)
            return result_str;
        }
    } // namespace

    ProcessResult Process::execute(const std::string& executablePath, const std::vector<std::string>& arguments,
        const std::string& stdInData, const std::map<std::string, std::string>& environment_map) {
        ProcessResult result;

        // Pipes for stdin, stdout, stderr redirection
        // pipe_stdin[0] is read end for child, pipe_stdin[1] is write end for parent
        // pipe_stdout[0] is read end for parent, pipe_stdout[1] is write end for child
        // pipe_stderr[0] is read end for parent, pipe_stderr[1] is write end for child
        int pipe_stdin[2], pipe_stdout[2], pipe_stderr[2];

        if (pipe(pipe_stdin) == -1 || pipe(pipe_stdout) == -1 || pipe(pipe_stderr) == -1) {
            result.stdErr   = "Failed to create pipes: " + std::string(strerror(errno));
            result.exitCode = -1; // Indicate internal error
            result.success  = false;
            return result;
        }

        pid_t pid = fork();

        if (pid == -1) { // fork failed
            result.stdErr   = "Failed to fork: " + std::string(strerror(errno));
            result.exitCode = -1;
            result.success  = false;
            close(pipe_stdin[0]);
            close(pipe_stdin[1]);
            close(pipe_stdout[0]);
            close(pipe_stdout[1]);
            close(pipe_stderr[0]);
            close(pipe_stderr[1]);
            return result;
        }

        if (pid == 0) { // We are the child >:)
            // Redirect stdin
            close(pipe_stdin[1]); // Close write end of child's stdin pipe
            dup2(pipe_stdin[0], STDIN_FILENO);
            close(pipe_stdin[0]); // Close original read end

            // Redirect stdout
            close(pipe_stdout[0]); // Close read end of child's stdout pipe
            dup2(pipe_stdout[1], STDOUT_FILENO);
            close(pipe_stdout[1]); // Close original write end

            // Redirect stderr
            close(pipe_stderr[0]); // Close read end of child's stderr pipe
            dup2(pipe_stderr[1], STDERR_FILENO);
            close(pipe_stderr[1]); // Close original write end

            if (setvbuf(stderr, NULL, _IOLBF, 0) != 0) {
                // Optional: Log an error if setvbuf fails, though it's unlikely to be critical.
                // perror("child: setvbuf for stderr failed");
            }

            std::vector<char*> argv_c = prepare_argv(arguments);

            std::vector<std::string> env_storage;
            std::vector<char*> envp_c;

            if (!environment_map.empty()) {
                build_envp(environment_map, env_storage, envp_c);
#ifdef __APPLE__
                // macOS doesn't have execvpe, so we need to resolve path manually
                std::string resolved_path = executablePath;
                if (executablePath.find('/') == std::string::npos) {
                    // Search in PATH
                    const char* path_env = getenv("PATH");
                    if (path_env) {
                        std::string path_str(path_env);
                        size_t start = 0;
                        size_t end   = 0;

                        while ((end = path_str.find(':', start)) != std::string::npos) {
                            std::string dir       = path_str.substr(start, end - start);
                            std::string full_path = dir + "/" + executablePath;

                            if (access(full_path.c_str(), X_OK) == 0) {
                                resolved_path = full_path;
                                break;
                            }
                            start = end + 1;
                        }

                        // Check last directory
                        if (resolved_path == executablePath && start < path_str.length()) {
                            std::string dir       = path_str.substr(start);
                            std::string full_path = dir + "/" + executablePath;

                            if (access(full_path.c_str(), X_OK) == 0) {
                                resolved_path = full_path;
                            }
                        }
                    }
                }
                execve(resolved_path.c_str(), argv_c.data(), envp_c.data());
#else
                // Linux and other systems have execvpe
                execvpe(executablePath.c_str(), argv_c.data(), envp_c.data());
#endif
            } else {
                // If environment_map is empty, use execvp to inherit parent's environment
                execvp(executablePath.c_str(), argv_c.data());
            }

            // If execvp returns, an error occurred
            std::cerr << "Execvp failed for " << executablePath << ": " << strerror(errno) << std::endl;
            _exit(127); // Standard exit code for command not found or exec error
        } else { // We are parent >:(
            close(pipe_stdin[0]); // Close read end of child's stdin pipe
            close(pipe_stdout[1]); // Close write end of child's stdout pipe
            close(pipe_stderr[1]); // Close write end of child's stderr pipe

            // Write to child's stdin
            if (!stdInData.empty()) {
                ssize_t bytes_written = write(pipe_stdin[1], stdInData.c_str(), stdInData.length());
                if (bytes_written == -1) {
                    // Handle error writing to stdin if necessary
                    result.stdErr += "Error writing to child stdin: " + std::string(strerror(errno)) + "\n";
                }
            }
            close(pipe_stdin[1]); // Close write end - signals EOF to child's stdin

            // Read from child's stdout and stderr
            result.stdOut = read_fd_to_string(pipe_stdout[0]);
            result.stdErr += read_fd_to_string(pipe_stderr[0]); // Append as we might have write errors

            close(pipe_stdout[0]);
            close(pipe_stderr[0]);

            // Wait for child to terminate and get exit status
            int status;
            waitpid(pid, &status, 0);

            if (WIFEXITED(status)) {
                result.exitCode = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                // Process killed by signal
                result.exitCode = 128 + WTERMSIG(status); // Common convention
                result.stdErr += "Process terminated by signal: " + std::to_string(WTERMSIG(status)) + "\n";
            } else {
                result.exitCode = -1; // Unknown termination
                result.stdErr += "Process terminated abnormally.\n";
            }
            result.success = (result.exitCode == 0);
        }
        return result;
    } // namespace VulneraTestX::Util
} // namespace VulneraTestX::Util
