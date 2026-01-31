#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/string_utils.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <string>
#include <iostream>

static std::string get_lua_code(char* file_path) {
    std::string lua_code;
    FILE* file = fopen(file_path, "r");
    if (!file) {
        return "";
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        lua_code += line;
    }

    fclose(file);
    return lua_code;
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

        std::string lua_script = get_lua_code((char*)file_path.c_str());
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

        std::string command = "exec " + lua_script + "\n";
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

        return CommandResult(true, "Script loaded and executed");
    }
};

std::unique_ptr<CommandDispatcher> create_load_command() {
    return std::make_unique<LoadScriptCommand>();
}
