#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sstream>
#include <cstring>
#include <sys/socket.h>

static std::string generate_hook_template(const std::string& lib_name, const std::string& offset_str) {
    std::stringstream ss;
    ss << "hook(\"" << lib_name << "\", " << offset_str << ", {\n";
    ss << "    onEnter = function(args)\n";
    ss << "        print(\"[+] " << lib_name << "+" << offset_str << " called\")\n";
    ss << "        print(\"    arg0: \" .. string.format(\"0x%x\", args[0]))\n";
    ss << "        print(\"    arg1: \" .. string.format(\"0x%x\", args[1]))\n";
    ss << "    end,\n";
    ss << "    onLeave = function(retval)\n";
    ss << "        print(\"[-] Returning: \" .. string.format(\"0x%x\", retval))\n";
    ss << "        return retval\n";
    ss << "    end\n";
    ss << "})\n";
    return ss.str();
}

class HookGen : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "hookgen";
    }

    std::string get_description() const override {
        return "Generate Lua hook template.";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        if (cmd_size <= 8) {
            const char* usage = "Usage:\n"
                              "  hookgen <lib_name> <offset_hex>  - Generate hook for specific offset\n"
                              "  hookgen <lib_name> <symbol>      - Generate hook for symbol\n"
                              "  hookgen <symbol>                 - Search symbol in all libraries\n";
            write(client_fd, usage, strlen(usage));
            return CommandResult(false, "Invalid arguments");
        }

        const char* args = cmd_buffer + 8;

        char lib_name[256];
        uint64_t offset;

        if (sscanf(args, "%255s %lx", lib_name, &offset) == 2) {
            char offset_str[32];
            snprintf(offset_str, sizeof(offset_str), "0x%lx", offset);
            std::string template_code = generate_hook_template(lib_name, offset_str);
            write(client_fd, template_code.c_str(), template_code.length());
            return CommandResult(true, "Template generated");
        }

        char arg1[256] = {0};
        char arg2[256] = {0};
        int parsed = sscanf(args, "%255s %255s", arg1, arg2);

        if (parsed == 0) {
            const char* error = "ERROR: Invalid arguments\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Invalid arguments");
        }

        int pid = CommandRegistry::instance().get_current_pid();
        if (pid <= 0) {
            const char* error = "ERROR: No target process attached. Use 'attach' or 'spawn' first.\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "No target PID");
        }

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        int sock = socket_helper.ensure_connection(pid);

        if (sock < 0) {
            const char* error = "ERROR: Failed to connect to agent\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Connection failed");
        }

        std::string lua_code;
        std::string symbol_name;
        std::string target_lib;

        if (parsed == 1) {
            symbol_name = arg1;
            target_lib = "";
        } else {
            target_lib = arg1;
            symbol_name = arg2;
        }

        lua_code = "local function find_symbol(lib, sym)\n"
                   "  local exports = Module.exports(lib)\n"
                   "  if not exports then return nil end\n"
                   "  for i, exp in ipairs(exports) do\n"
                   "    if exp.name == sym then\n"
                   "      return exp.offset\n"
                   "    end\n"
                   "  end\n"
                   "  return nil\n"
                   "end\n";

        if (target_lib.empty()) {
            lua_code += "local libs = {'libc.so', 'libm.so', 'libdl.so', 'liblog.so', 'libart.so'}\n"
                       "for _, lib in ipairs(libs) do\n"
                       "  local offset = find_symbol(lib, '" + symbol_name + "')\n"
                       "  if offset then\n"
                       "    print('FOUND:' .. lib .. ':' .. string.format('0x%x', offset))\n"
                       "    return\n"
                       "  end\n"
                       "end\n"
                       "print('ERROR:Symbol not found')\n";
        } else {
            lua_code += "local offset = find_symbol('" + target_lib + "', '" + symbol_name + "')\n"
                       "if offset then\n"
                       "  print('FOUND:" + target_lib + ":' .. string.format('0x%x', offset))\n"
                       "else\n"
                       "  print('ERROR:Symbol not found in " + target_lib + "')\n"
                       "end\n";
        }

        std::string command = "exec " + lua_code + "\n";
        ssize_t sent = socket_helper.send_data(command.c_str(), command.length());

        if (sent <= 0) {
            const char* error = "ERROR: Failed to send command to agent\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Send failed");
        }

        char buffer[8192];
        ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);

        if (n <= 0) {
            const char* error = "ERROR: Failed to receive response\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Receive failed");
        }

        buffer[n] = '\0';
        std::string response(buffer);

        if (response.find("FOUND:") == 0) {
            size_t colon1 = response.find(':', 6);
            if (colon1 != std::string::npos) {
                std::string found_lib = response.substr(6, colon1 - 6);
                std::string offset_str = response.substr(colon1 + 1);

                if (!offset_str.empty() && offset_str.back() == '\n') {
                    offset_str.pop_back();
                }

                std::string template_code = generate_hook_template(found_lib, offset_str);
                write(client_fd, template_code.c_str(), template_code.length());
                return CommandResult(true, "Template generated");
            }
        }

        write(client_fd, response.c_str(), response.length());
        return CommandResult(false, "Symbol not found");
    }
};

std::unique_ptr<CommandDispatcher> create_hookgen_command() {
    return std::make_unique<HookGen>();
}
