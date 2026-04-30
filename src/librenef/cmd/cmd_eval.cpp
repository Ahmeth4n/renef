#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <signal.h>

extern bool ptrace_resume(int pid);

class Eval : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "exec";
    }

    std::string get_description() const override {
        return "Execute Lua code in the target process.";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        int pid = CommandRegistry::instance().get_current_pid();

        if (pid <= 0) {
            const char* error_msg = "ERROR: No target PID set. Please attach/spawn first.\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "No target PID set");
        }

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        int sock = socket_helper.ensure_connection(pid);

        if (sock < 0) {
            const char* error_msg = "ERROR: Failed to connect to agent\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Socket connection failed");
        }

        if (cmd_size <= 5) {
            const char* error = "ERROR: Usage: exec <lua_code>\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "No Lua code provided");
        }

        const char* lua_code = cmd_buffer + 5;

        std::string command = std::string("exec ") + lua_code + "\n";
        fprintf(stderr, "[DEBUG exec] Sending %zu bytes to agent\n", command.length());
        ssize_t sent = socket_helper.send_data(command.c_str(), command.length());
        fprintf(stderr, "[DEBUG exec] Actually sent %zd bytes\n", sent);

        int gated = CommandRegistry::instance().gated_pid;
        bool need_resume = (gated > 0 && gated == pid);

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        char buffer[4096];
        bool script_done = false;
        int timeout_count = 0;
        const int max_timeout = need_resume ? 5 : 50;
        int iterations = 0;
        int total_bytes = 0;

        while (!script_done && timeout_count < max_timeout) {
            struct pollfd pfd = {sock, POLLIN, 0};
            int ret = poll(&pfd, 1, 100);
            iterations++;

            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (n > 0) {
                    buffer[n] = '\0';
                    total_bytes += n;
                    fprintf(stderr, "[eval-debug] recv %zd bytes (total %d)\n", n, total_bytes);
                    write(client_fd, buffer, n);

                    if (strstr(buffer, "\342\234\223 Lua executed") || strstr(buffer, "\342\234\227 Lua")) {
                        script_done = true;
                    }
                    timeout_count = 0;
                } else if (n == 0) {
                    fprintf(stderr, "[eval-debug] recv returned 0 (connection closed)\n");
                    break;
                }
            } else if (ret == 0) {
                timeout_count++;
            } else {
                fprintf(stderr, "[eval-debug] poll error: %s\n", strerror(errno));
                break;
            }
        }

        fprintf(stderr, "[eval-debug] loop done: iterations=%d, total_bytes=%d, script_done=%d, timeout_count=%d\n",
                iterations, total_bytes, script_done, timeout_count);

        if (need_resume) {
            fprintf(stderr, "[spawn-gate] Script delivered (%d bytes), resuming (pid=%d)\n",
                    total_bytes, gated);
            ptrace_resume(gated);
            CommandRegistry::instance().gated_pid = -1;
        }

        fcntl(sock, F_SETFL, flags);

        return CommandResult(true, "Eval executed");
    }
};

std::unique_ptr<CommandDispatcher> create_eval_command() {
    return std::make_unique<Eval>();
}
