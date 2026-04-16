#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/string_utils.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <string>
#include <iostream>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <signal.h>

extern bool ptrace_resume(int pid);

static std::string read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return "";
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) { fclose(f); return ""; }
    std::string content(size, '\0');
    fread(&content[0], 1, size, f);
    fclose(f);
    return content;
}

class LoadScriptCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "l";
    }

    std::string get_description() const override {
        return "Load and execute a Lua script in the target process.";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        std::vector<std::string> cmd_parts = split(cmd_buffer, ' ');
        if (cmd_parts.size() < 2) {
            const char* error = "ERROR: Usage: l <filename>\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Invalid arguments");
        }

        std::string file_path = cmd_parts[1];

        std::string lua_script = read_file(file_path.c_str());
        if (lua_script.empty()) {
            std::string error = "ERROR: Cannot read file: " + file_path + "\n";
            write(client_fd, error.c_str(), error.length());
            return CommandResult(false, "File read failed");
        }

        int pid = CommandRegistry::instance().get_current_pid();
        if (pid <= 0) {
            const char* error_msg = "ERROR: No target PID set. Please attach first.\n";
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

        std::string hex = hex_encode(lua_script);
        std::string command = "hexexec " + hex + "\n";
        socket_helper.send_data(command.c_str(), command.length());

        int gated = CommandRegistry::instance().gated_pid;
        bool need_resume = (gated > 0 && gated == pid);

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        char buffer[4096];
        bool script_done = false;
        int timeout_count = 0;
        const int max_timeout = 50;

        while (!script_done && timeout_count < max_timeout) {
            struct pollfd pfd = {sock, POLLIN, 0};
            int ret = poll(&pfd, 1, 100);

            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (n > 0) {
                    buffer[n] = '\0';
                    write(client_fd, buffer, n);
                    if (strstr(buffer, "\342\234\223 Lua executed") || strstr(buffer, "\342\234\227 Lua")) {
                        script_done = true;
                    }
                    timeout_count = 0;
                } else if (n == 0) {
                    break;
                }
            } else if (ret == 0) {
                timeout_count++;
            } else {
                break;
            }
        }

        if (need_resume) {
            fprintf(stderr, "[spawn-gate] Script delivered, resuming (pid=%d)\n", gated);
            ptrace_resume(gated);
            CommandRegistry::instance().gated_pid = -1;
        }

        fcntl(sock, F_SETFL, flags);
        return CommandResult(true, "Script loaded and executed");
    }
};

std::unique_ptr<CommandDispatcher> create_load_command() {
    return std::make_unique<LoadScriptCommand>();
}
