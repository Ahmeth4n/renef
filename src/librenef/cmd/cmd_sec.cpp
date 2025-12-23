#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <unistd.h>
#include <cstring>
#include <sys/socket.h>
#include <poll.h>

class SecCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "sec";
    }

    std::string get_description() const override {
        return "List ELF sections of a library: sec libname.so";
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

        char buffer[4096];
        struct pollfd pfd = {sock, POLLIN, 0};

        int timeout_count = 0;
        while (timeout_count < 20) {
            int ret = poll(&pfd, 1, 100);

            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = ::recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (n > 0) {
                    buffer[n] = '\0';
                    write(client_fd, buffer, n);
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

        return CommandResult(true, "Sections listed");
    }
};

std::unique_ptr<CommandDispatcher> create_sec_command() {
    return std::make_unique<SecCommand>();
}
