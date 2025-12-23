#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/string_utils.h>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstring>

class InspectBinary : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "hookn";
    }

    std::string get_description() const override {
        return "Install native hook at offset in library. Usage: hookn <lib_name> <offset>";
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

        std::vector<std::string> cmd_parts = split(cmd_buffer, ' ');

        if (cmd_parts.size() < 3) {
            const char* error = "ERROR: Usage: ib <lib_name> <offset>\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Invalid arguments");
        }

        std::string lib_name = cmd_parts[1];
        std::string offset = cmd_parts[2];

        std::string filter = extract_filter(cmd_buffer, cmd_size);
        std::string command = build_agent_command("hook " + lib_name + " " + offset, filter);
        socket_helper.send_data(command.c_str(), command.length());

        char buffer[4096];
        ssize_t n = socket_helper.receive_data(buffer, sizeof(buffer));

        if (n > 0) {
            write(client_fd, buffer, n);
        } else if (n == 0) {
            const char* msg = "ERROR: Agent disconnected\n";
            write(client_fd, msg, strlen(msg));
            return CommandResult(false, "Agent disconnected");
        } else {
            const char* msg = "ERROR: Failed to read from agent\n";
            write(client_fd, msg, strlen(msg));
            return CommandResult(false, "Failed to read from agent");
        }

        return CommandResult(true, "Inspect binary finished");
    }
};

std::unique_ptr<CommandDispatcher> create_inspect_command() {
    return std::make_unique<InspectBinary>();
}
