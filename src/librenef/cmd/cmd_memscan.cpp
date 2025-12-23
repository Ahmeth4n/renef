#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <cstdio>
#include <string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sstream>
#include <iomanip>
#include "json.hpp"

using json = nlohmann::json;

static std::string format_memscan_response(const std::string& json_response) {
    std::ostringstream out;

    try {
        json j = json::parse(json_response);

        if (!j.value("success", false)) {
            out << "Error: " << j.value("error", "Unknown error") << "\n";
            return out.str();
        }

        int count = j.value("count", 0);

        if (count == 0) {
            out << "No matches found.\n";
            return out.str();
        }

        out << "Found " << count << " match(es):\n";
        out << std::string(60, '-') << "\n";

        int result_num = 1;
        for (const auto& item : j["results"]) {
            std::string library = item.value("library", "");
            long offset = item.value("offset", 0L);
            unsigned long address = item.value("address", 0UL);
            std::string hex = item.value("hex", "");
            std::string ascii = item.value("ascii", "");

            out << "[" << result_num++ << "] ";
            if (!library.empty()) {
                out << library << " + 0x" << std::hex << offset << std::dec;
                out << " (addr: 0x" << std::hex << address << std::dec << ")\n";
            } else {
                out << "0x" << std::hex << offset << std::dec << "\n";
            }
            out << "    Hex:   " << hex << "\n";
            out << "    ASCII: " << ascii << "\n";
        }

        out << std::string(60, '-') << "\n";

    } catch (const json::exception& e) {
        out << "Error parsing response: " << e.what() << "\n";
    }

    return out.str();
}

class MemScan : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "ms";
    }

    std::string get_description() const override {
        return "Scan memory for a hex pattern. Usage: ms <hex_pattern>";
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

        if (cmd_size <= 3) {
            const char* error = "ERROR: Usage: ms <hex_pattern>\nExample: ms FFFF or ms 4A617661\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "No pattern provided");
        }

        std::string hex_pattern(cmd_buffer + 3, cmd_size - 3);

        while (!hex_pattern.empty() && isspace(hex_pattern.back())) {
            hex_pattern.pop_back();
        }

        std::string command = "ms " + hex_pattern + "\n";
        socket_helper.send_data(command.c_str(), command.length());

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        char buffer[8192];
        std::string response;
        int timeout_count = 0;
        const int max_timeout = 100;

        while (timeout_count < max_timeout) {
            struct pollfd pfd = {sock, POLLIN, 0};
            int ret = poll(&pfd, 1, 100);

            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (n > 0) {
                    buffer[n] = '\0';
                    response += buffer;

                    size_t json_end = response.find("}\n");
                    if (json_end != std::string::npos) {
                        response = response.substr(0, json_end + 2);
                        break;
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

        char drain_buffer[1024];
        while (true) {
            struct pollfd pfd = {sock, POLLIN, 0};
            int ret = poll(&pfd, 1, 10);
            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(sock, drain_buffer, sizeof(drain_buffer), 0);
                if (n <= 0) break;
            } else {
                break;
            }
        }

        fcntl(sock, F_SETFL, flags);

        if (!response.empty()) {
            std::string formatted = format_memscan_response(response);
            write(client_fd, formatted.c_str(), formatted.length());
        } else {
            const char* error = "ERROR: No response from agent\n";
            write(client_fd, error, strlen(error));
        }

        return CommandResult(true, "Memory scan completed");
    }
};

class MemScanJson : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "msj";
    }

    std::string get_description() const override {
        return "Memory scan with JSON output (for TUI). Usage: msj <hex_pattern>";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        int pid = CommandRegistry::instance().get_current_pid();

        if (pid <= 0) {
            const char* error_msg = "{\"success\":false,\"error\":\"No target PID set\"}\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "No target PID set");
        }

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        int sock = socket_helper.ensure_connection(pid);

        if (sock < 0) {
            const char* error_msg = "{\"success\":false,\"error\":\"Failed to connect to agent\"}\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Socket connection failed");
        }

        if (cmd_size <= 4) {
            const char* error = "{\"success\":false,\"error\":\"No pattern provided\"}\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "No pattern provided");
        }

        std::string hex_pattern(cmd_buffer + 4, cmd_size - 4);

        while (!hex_pattern.empty() && isspace(hex_pattern.back())) {
            hex_pattern.pop_back();
        }

        std::string command = "ms " + hex_pattern + "\n";
        socket_helper.send_data(command.c_str(), command.length());

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        char buffer[8192];
        std::string response;
        int timeout_count = 0;
        const int max_timeout = 100;

        while (timeout_count < max_timeout) {
            struct pollfd pfd = {sock, POLLIN, 0};
            int ret = poll(&pfd, 1, 100);

            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (n > 0) {
                    buffer[n] = '\0';
                    response += buffer;

                    size_t json_end = response.find("}\n");
                    if (json_end != std::string::npos) {
                        response = response.substr(0, json_end + 2);
                        break;
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

        char drain_buffer[1024];
        while (true) {
            struct pollfd pfd = {sock, POLLIN, 0};
            int ret = poll(&pfd, 1, 10);
            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(sock, drain_buffer, sizeof(drain_buffer), 0);
                if (n <= 0) break;
            } else {
                break;
            }
        }

        fcntl(sock, F_SETFL, flags);

        if (!response.empty()) {
            write(client_fd, response.c_str(), response.length());
        } else {
            const char* error = "{\"success\":false,\"error\":\"No response from agent\"}\n";
            write(client_fd, error, strlen(error));
        }

        return CommandResult(true, "Memory scan JSON completed");
    }
};

std::unique_ptr<CommandDispatcher> create_memscan_command() {
    return std::make_unique<MemScan>();
}

std::unique_ptr<CommandDispatcher> create_memscanjson_command() {
    return std::make_unique<MemScanJson>();
}
