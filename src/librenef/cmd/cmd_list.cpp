#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/string_utils.h>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <cerrno>
#include <cstring>

class ListAppsCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "la";
    }

    std::string get_description() const override {
        return "List installed applications on your device";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        int pid = CommandRegistry::instance().get_current_pid();

        if (pid <= 0) {
            const char* error_msg = "ERROR: No target PID set. Please attach first.\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "No target PID set");
        }

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        int sock = socket_helper.ensure_connection(pid);

        if (sock < 0) {
            const char* error_msg = "ERROR: Failed to create socket\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Socket creation failed");
        }

        std::string clean_cmd(cmd_buffer, cmd_size);
        while (!clean_cmd.empty() && (clean_cmd.back() == '\n' || clean_cmd.back() == '\r' || clean_cmd.back() == ' ' || clean_cmd.back() == '\0')) {
            clean_cmd.pop_back();
        }

        std::string filter = extract_filter(clean_cmd.c_str(), clean_cmd.length());
        std::string command = build_agent_command("la", filter);
        socket_helper.send_data(command.c_str(), command.length());

        char buffer[4096];
        ssize_t n;
        int agent_fd = socket_helper.get_socket_fd();

        while (true) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(agent_fd, &read_fds);

            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 200000;

            int select_result = select(agent_fd + 1, &read_fds, NULL, NULL, &timeout);

            if (select_result < 0) {
                break;
            } else if (select_result == 0) {
                break;
            }

            n = socket_helper.receive_data(buffer, sizeof(buffer));
            if (n <= 0) {
                break;
            }

            write(client_fd, buffer, n);
        }

        return CommandResult(true, "List apps successful");
    }
};

std::unique_ptr<CommandDispatcher> create_list_command() {
    return std::make_unique<ListAppsCommand>();
}
