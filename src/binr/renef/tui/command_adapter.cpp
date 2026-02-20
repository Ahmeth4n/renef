#include "command_adapter.h"
#include <renef/cmd.h>
#include <renef/server_connection.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <poll.h>

std::string CommandAdapter::execute(const std::string& command) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return "ERROR: pipe() failed\n";
    }

    int read_end = pipefd[0];
    int write_end = pipefd[1];

    // Set read end non-blocking for safe reads
    int flags = fcntl(read_end, F_GETFL, 0);
    fcntl(read_end, F_SETFL, flags | O_NONBLOCK);

    auto& registry = CommandRegistry::instance();
    registry.dispatch(write_end, command.c_str(), command.size());

    ::close(write_end);

    // Read all captured output
    std::string result;
    char buffer[4096];

    // Poll with timeout to avoid hanging
    struct pollfd pfd = {read_end, POLLIN, 0};
    while (true) {
        int ret = poll(&pfd, 1, 100); // 100ms timeout
        if (ret <= 0) break;
        if (pfd.revents & POLLIN) {
            ssize_t n = ::read(read_end, buffer, sizeof(buffer) - 1);
            if (n <= 0) break;
            buffer[n] = '\0';
            result.append(buffer, n);
        } else {
            break;
        }
    }

    ::close(read_end);
    return result;
}

void CommandAdapter::execute_async(const std::string& command,
                                   std::shared_ptr<TuiState> state,
                                   std::function<void(const std::string&)> callback) {
    std::thread([command, state, callback]() {
        state->set_busy(true);
        state->request_refresh();

        std::string result = CommandAdapter::execute_server(command);

        state->set_busy(false);
        if (callback) {
            callback(result);
        }
        state->request_refresh();
    }).detach();
}

std::string CommandAdapter::execute_server(const std::string& command) {
    auto& conn = ServerConnection::instance();
    if (!conn.is_connected()) {
        if (!conn.connect()) {
            return "ERROR: Not connected to server\n";
        }
    }
    if (!conn.send(command + "\n")) {
        return "ERROR: Failed to send command\n";
    }
    return conn.receive(10000);
}
