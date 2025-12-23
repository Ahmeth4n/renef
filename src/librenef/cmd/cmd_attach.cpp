#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/string_utils.h>
#include <renef/crypto.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdlib>

#define DEFAULT_PAYLOAD_PATH "/data/local/tmp/.r"

static inline std::string get_payload_path() {
    const char* custom_path = getenv("RENEF_PAYLOAD_PATH");
    return custom_path ? std::string(custom_path) : DEFAULT_PAYLOAD_PATH;
}

static std::string get_device_id_attach() {
    const char* device = getenv("RENEF_DEVICE_ID");
    return device ? std::string(device) : "";
}

static std::string build_adb_cmd_attach(const std::string& cmd) {
    std::string device_id = get_device_id_attach();
    std::string adb_prefix = "adb";
    if (!device_id.empty()) {
        adb_prefix += " -s " + device_id;
    }
    return adb_prefix + " shell " + cmd;
}

struct AttachParams {
    int pid;
    std::string hook_type;
};

static AttachParams parse_attach_params(const char* cmd_buffer, size_t cmd_size) {
    AttachParams params;
    params.pid = -1;

    std::string full_cmd(cmd_buffer, cmd_size);

    while (!full_cmd.empty() && (full_cmd.back() == '\n' || full_cmd.back() == '\r' || full_cmd.back() == ' ' || full_cmd.back() == '\0')) {
        full_cmd.pop_back();
    }

    size_t space_pos = full_cmd.find(' ');
    if (space_pos == std::string::npos) {
        return params;
    }

    std::string args = full_cmd.substr(space_pos + 1);

    size_t hook_pos = args.find("--hook=");
    if (hook_pos != std::string::npos) {
        size_t hook_start = hook_pos + 7;
        size_t hook_end = args.find(' ', hook_start);
        if (hook_end == std::string::npos) {
            hook_end = args.length();
        }
        params.hook_type = args.substr(hook_start, hook_end - hook_start);

        std::string before_hook = args.substr(0, hook_pos);
        std::string after_hook = (hook_end < args.length()) ? args.substr(hook_end) : "";
        args = before_hook + after_hook;
    }

    size_t start = args.find_first_not_of(" \t");
    size_t end = args.find_last_not_of(" \t");
    if (start != std::string::npos && end != std::string::npos) {
        std::string pid_str = args.substr(start, end - start + 1);
        try {
            params.pid = std::stoi(pid_str);
        } catch (...) {
            params.pid = -1;
        }
    }

    return params;
}

extern bool inject(int pid, const char* so_path);

class AttachCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "attach";
    }

    std::string get_description() const override {
        return "Attach to a process by PID and inject the payload";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        AttachParams params = parse_attach_params(cmd_buffer, cmd_size);
        std::string session_key = generate_auth_key();
        SocketHelper& sock = CommandRegistry::instance().get_socket_helper();

        if (params.pid <= 0) {
            const char* error_msg = "ERROR: Invalid PID\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Invalid PID");
        }

        std::string payload_path = get_payload_path();
        bool is_injected = inject(params.pid, payload_path.c_str());
        if (is_injected) {
            int con_pid = sock.ensure_connection(params.pid);
            std::string con_cmd = "con " + session_key + "\n";
            ssize_t con_payload = sock.send_data(con_cmd.c_str(), con_cmd.length(), false);

            sock.set_session_key(session_key);

            if (!params.hook_type.empty()) {
                std::string hook_cmd = "exec _G.__hook_type__ = \"" + params.hook_type + "\"\n";
                sock.send_data(hook_cmd.c_str(), hook_cmd.length(), false);
            }
        }

        const char* response = is_injected ? "OK\n" : "FAIL\n";
        write(client_fd, response, strlen(response));

        CommandRegistry::instance().set_current_pid(params.pid);

        return CommandResult(is_injected, is_injected ? "Injection successful" : "Injection failed");
    }
};

std::unique_ptr<CommandDispatcher> create_attach_command() {
    return std::make_unique<AttachCommand>();
}
