#pragma once

#include <string>
#include <memory>
#include <map>
#include <vector>
#include "socket_helper.h"

struct CommandResult {
    bool success;
    std::string output;

    CommandResult(bool ok = true, const std::string& msg = "")
        : success(ok), output(msg) {}
};

inline std::string extract_filter(const char* cmd_buffer, size_t cmd_size) {
    std::string cmd(cmd_buffer, cmd_size);
    size_t tilde_pos = cmd.find('~');
    if (tilde_pos != std::string::npos) {
        return cmd.substr(tilde_pos);  // Returns "~pattern"
    }
    return "";
}

inline std::string build_agent_command(const std::string& agent_cmd, const std::string& filter) {
    return agent_cmd + filter + "\n";
}

class CommandDispatcher {
public:
    virtual ~CommandDispatcher() = default;

    virtual CommandResult dispatch(
        int client_fd,
        const char* cmd_buffer,
        size_t cmd_size) = 0;

    virtual std::string get_name() const = 0;

    virtual std::string get_description() const = 0;
};

class CommandRegistry {
public:

    static CommandRegistry& instance() {
        static CommandRegistry registry;
        return registry;
    }


    int current_pid = -1;
    SocketHelper sock;

    int get_current_pid() const;
    void set_current_pid(int pid);

    void register_command(std::unique_ptr<CommandDispatcher> cmd);

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size);

    void setup_all_commands();
    bool is_command_exist(const std::string& name);

    std::vector<std::pair<std::string, std::string>> get_all_commands_with_descriptions() const;


    SocketHelper& get_socket_helper();

private:
    CommandRegistry() = default;

    CommandRegistry(const CommandRegistry&) = delete;
    CommandRegistry& operator=(const CommandRegistry&) = delete;

    std::map<std::string, std::unique_ptr<CommandDispatcher>> commands;
};
