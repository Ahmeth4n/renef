#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <poll.h>

class HooksCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "hooks";
    }

    std::string get_description() const override {
        return "List active hooks";
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

        const char* cmd = "hooks\n";
        socket_helper.send_data(cmd, strlen(cmd));

        char buffer[1024];
        struct pollfd pfd = {sock, POLLIN, 0};
        int ret = poll(&pfd, 1, 2000);

        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = ::recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (n > 0) {
                buffer[n] = '\0';
                write(client_fd, buffer, n);
            }
        } else {
            const char* error = "ERROR: No response from agent\n";
            write(client_fd, error, strlen(error));
        }

        return CommandResult(true, "Hooks listed");
    }
};

class UnhookCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "unhook";
    }

    std::string get_description() const override {
        return "Remove hook(s): unhook [id] or unhook all";
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

        std::string cmd(cmd_buffer, cmd_size);
        if (cmd.empty() || cmd.back() != '\n') {
            cmd += "\n";
        }
        socket_helper.send_data(cmd.c_str(), cmd.size());

        char buffer[256];
        struct pollfd pfd = {sock, POLLIN, 0};
        int ret = poll(&pfd, 1, 2000);

        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = ::recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (n > 0) {
                buffer[n] = '\0';
                write(client_fd, buffer, n);
            }
        } else {
            const char* error = "ERROR: No response from agent\n";
            write(client_fd, error, strlen(error));
        }

        return CommandResult(true, "Unhook completed");
    }
};

std::unique_ptr<CommandDispatcher> create_hooks_command() {
    return std::make_unique<HooksCommand>();
}

std::unique_ptr<CommandDispatcher> create_unhook_command() {
    return std::make_unique<UnhookCommand>();
}
