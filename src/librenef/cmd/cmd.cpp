#include <renef/cmd.h>
#include <iostream>
#include <cstring>
#include <unistd.h>

// Forward declarations for command classes
class PingCommand;
class AttachCommand;
class SpawnCommand;
class ListAppsCommand;
class InspectBinary;
class Eval;
class LoadScriptCommand;
class WatchCommand;
class MemScan;
class MemScanJson;
class HooksCommand;
class UnhookCommand;
class SecCommand;
class MemDumpCommand;
class HookGen;

// These are implemented in separate cmd_*.cpp files
std::unique_ptr<CommandDispatcher> create_ping_command();
std::unique_ptr<CommandDispatcher> create_attach_command();
std::unique_ptr<CommandDispatcher> create_spawn_command();
std::unique_ptr<CommandDispatcher> create_list_command();
std::unique_ptr<CommandDispatcher> create_inspect_command();
std::unique_ptr<CommandDispatcher> create_eval_command();
std::unique_ptr<CommandDispatcher> create_load_command();
std::unique_ptr<CommandDispatcher> create_watch_command();
std::unique_ptr<CommandDispatcher> create_memscan_command();
std::unique_ptr<CommandDispatcher> create_memscanjson_command();
std::unique_ptr<CommandDispatcher> create_hooks_command();
std::unique_ptr<CommandDispatcher> create_unhook_command();
std::unique_ptr<CommandDispatcher> create_sec_command();
std::unique_ptr<CommandDispatcher> create_memdump_command();
std::unique_ptr<CommandDispatcher> create_hookgen_command();

void CommandRegistry::register_command(std::unique_ptr<CommandDispatcher> cmd) {
    if (!cmd) {
        std::cerr << "ERROR: Trying to register null command\n";
        return;
    }

    std::string name = cmd->get_name();
    commands[name] = std::move(cmd);
}

std::vector<std::pair<std::string, std::string>>
CommandRegistry::get_all_commands_with_descriptions() const {
    std::vector<std::pair<std::string, std::string>> result;

    for (const auto& [name, cmd] : commands) {
        result.push_back({
            cmd->get_name(),
            cmd->get_description()
        });
    }

    return result;
}

CommandResult CommandRegistry::dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) {
    if (!cmd_buffer || cmd_size == 0) {
        return CommandResult(false, "Empty command");
    }

    std::string full_cmd(cmd_buffer, cmd_size);

    while (!full_cmd.empty() && (full_cmd.back() == '\n' || full_cmd.back() == '\r' || full_cmd.back() == ' ' || full_cmd.back() == '\0')) {
        full_cmd.pop_back();
    }

    const std::string prefix = "renef://";

    if (full_cmd.find(prefix) == 0) {
        full_cmd = full_cmd.substr(prefix.length());
    }

    std::string cmd_name;
    size_t delim_pos = full_cmd.find("//");
    if (delim_pos != std::string::npos) {
        cmd_name = full_cmd.substr(0, delim_pos);
    } else {
        size_t space_pos = full_cmd.find(' ');
        size_t tilde_pos = full_cmd.find('~');
        size_t split_pos = std::string::npos;

        if (space_pos != std::string::npos && tilde_pos != std::string::npos) {
            split_pos = std::min(space_pos, tilde_pos);
        } else if (space_pos != std::string::npos) {
            split_pos = space_pos;
        } else if (tilde_pos != std::string::npos) {
            split_pos = tilde_pos;
        }

        if (split_pos != std::string::npos) {
            cmd_name = full_cmd.substr(0, split_pos);
        } else {
            cmd_name = full_cmd;
        }
    }

    for (char c : cmd_name) {
        printf("%02x ", (unsigned char)c);
    }
    std::cout << "\n";
    for (const auto& pair : commands) {
        std::cout << "'" << pair.first << "' (len=" << pair.first.length() << ") ";
    }
    std::cout << "\n";

    auto it = commands.find(cmd_name);
    if (it == commands.end()) {
        const char* error_msg = "ERROR: Unknown command. Type 'help' for available commands.\n";
        write(client_fd, error_msg, strlen(error_msg));
        return CommandResult(false, "Unknown command: " + cmd_name);
    }

    return it->second->dispatch(client_fd, cmd_buffer, cmd_size);
}

void CommandRegistry::setup_all_commands() {
    register_command(create_ping_command());
    register_command(create_attach_command());
    register_command(create_spawn_command());
    register_command(create_list_command());
    register_command(create_inspect_command());
    register_command(create_eval_command());
    register_command(create_load_command());
    register_command(create_watch_command());
    register_command(create_memscan_command());
    register_command(create_memscanjson_command());
    register_command(create_hooks_command());
    register_command(create_unhook_command());
    register_command(create_sec_command());
    register_command(create_memdump_command());
    register_command(create_hookgen_command());
}

bool CommandRegistry::is_command_exist(const std::string& name) {
    if (commands.find(name) != commands.end()) {
        return true;
    }
    return false;
}

int CommandRegistry::get_current_pid() const {
    return current_pid;
}

void CommandRegistry::set_current_pid(int pid) {
    if (current_pid > 0 && pid != current_pid) {
        sock.close_connection();
    }
    current_pid = pid;
}

SocketHelper& CommandRegistry::get_socket_helper() {
    return sock;
}
