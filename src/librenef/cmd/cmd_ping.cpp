#include <renef/cmd.h>
#include <unistd.h>
#include <cstring>

class PingCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "ping";
    }

    std::string get_description() const override {
        return "Test connection with pong response";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        const char* response = "pong\n";
        write(client_fd, response, strlen(response));
        return CommandResult(true, "Pong sent");
    }
};

std::unique_ptr<CommandDispatcher> create_ping_command() {
    return std::make_unique<PingCommand>();
}
