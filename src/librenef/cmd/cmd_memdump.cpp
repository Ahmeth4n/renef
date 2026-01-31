#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/string_utils.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <capstone/capstone.h>

class MemDumpCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "md";
    }

    std::string get_description() const override {
        return "Memory dump/disassemble at address (md <addr> <size> [-d])";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        std::vector<std::string> parts = split(cmd_buffer, ' ');

        if (parts.size() < 3) {
            const char* error = "Usage: md <address> <size> [-d for disassemble]\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Invalid arguments");
        }

        uintptr_t address = 0;
        std::string addr_str = parts[1];
        try {
            if (addr_str.rfind("0x", 0) == 0 || addr_str.rfind("0X", 0) == 0) {
                address = std::stoull(addr_str, nullptr, 16);
            } else {
                address = std::stoull(addr_str, nullptr, 10);
            }
        } catch (const std::exception& e) {
            const char* error = "ERROR: Invalid address format. Use hex (0x...) or decimal.\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Invalid address");
        }

        size_t size = 0;
        try {
            size = std::stoull(parts[2]);
        } catch (const std::exception& e) {
            const char* error = "ERROR: Invalid size format.\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Invalid size");
        }
        if (size == 0 || size > 4096) {
            const char* error = "Size must be between 1 and 4096 bytes\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Invalid size");
        }

        bool disassemble = false;
        if (parts.size() > 3 && parts[3] == "-d") {
            disassemble = true;
        }

        int pid = CommandRegistry::instance().get_current_pid();
        if (pid <= 0) {
            const char* error = "ERROR: No target PID set. Please attach/spawn first.\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "No PID");
        }

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        int sock = socket_helper.ensure_connection(pid);

        if (sock < 0) {
            const char* error = "ERROR: Failed to connect to agent\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Connection failed");
        }

        std::stringstream cmd;
        cmd << "md " << std::hex << address << " " << std::dec << size << "\n";
        socket_helper.send_data(cmd.str().c_str(), cmd.str().length());

        char* buffer = new char[size + 256];
        size_t total_received = 0;

        ssize_t first_read = socket_helper.receive_data(buffer, std::min(size_t(64), size));
        if (first_read <= 0) {
            delete[] buffer;
            const char* error = "ERROR: Failed to read memory from agent\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Read failed");
        }

        total_received = first_read;

        if (total_received >= 6 && memcmp(buffer, "ERROR:", 6) == 0) {
            while (buffer[total_received - 1] != '\n') {
                ssize_t extra = socket_helper.receive_data(buffer + total_received, 1);
                if (extra <= 0) break;
                total_received += extra;
                if (total_received >= size + 255) break;
            }
            buffer[total_received] = '\0';
            write(client_fd, buffer, total_received);
            delete[] buffer;
            return CommandResult(false, "Memory access error");
        }

        while (total_received < size) {
            ssize_t received = socket_helper.receive_data(buffer + total_received, size - total_received);

            if (received <= 0) {
                delete[] buffer;
                const char* error = "ERROR: Failed to read complete memory dump\n";
                write(client_fd, error, strlen(error));
                return CommandResult(false, "Incomplete read");
            }

            total_received += received;
        }

        size_t received_size = total_received;

        std::stringstream output;
        output << "Memory at 0x" << std::hex << address << " (" << std::dec << received_size << " bytes):\n";

        if (disassemble) {
            csh handle;
            cs_insn *insn;

            cs_arch arch = CS_ARCH_ARM64;
            cs_mode mode = CS_MODE_ARM;

            if (cs_open(arch, mode, &handle) == CS_ERR_OK) {
                cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

                size_t count = cs_disasm(handle, (const uint8_t*)buffer, received_size, address, 0, &insn);

                if (count > 0) {
                    for (size_t i = 0; i < count; i++) {
                        output << "0x" << std::hex << insn[i].address << ":  "
                               << insn[i].mnemonic << " " << insn[i].op_str << "\n";
                    }
                    cs_free(insn, count);
                } else {
                    output << "ERROR: Failed to disassemble (not valid ARM64 code or data section)\n";
                }
                cs_close(&handle);
            } else {
                output << "ERROR: Capstone initialization failed\n";
            }
        } else {
            for (size_t i = 0; i < received_size; i += 16) {
                output << "0x" << std::hex << std::setfill('0') << std::setw(8) << (address + i) << ":  ";

                for (size_t j = 0; j < 16 && (i + j) < received_size; j++) {
                    output << std::hex << std::setfill('0') << std::setw(2)
                           << (int)(unsigned char)buffer[i + j] << " ";
                }

                for (size_t j = received_size - i; j < 16; j++) {
                    output << "   ";
                }

                output << " |";

                for (size_t j = 0; j < 16 && (i + j) < received_size; j++) {
                    unsigned char c = buffer[i + j];
                    output << (char)((c >= 32 && c <= 126) ? c : '.');
                }

                output << "|\n";
            }
        }

        delete[] buffer;

        std::string result = output.str();
        write(client_fd, result.c_str(), result.length());

        return CommandResult(true, "Memory dumped");
    }
};

std::unique_ptr<CommandDispatcher> create_memdump_command() {
    return std::make_unique<MemDumpCommand>();
}
