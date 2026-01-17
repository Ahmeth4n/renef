#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <iostream>
#include <cstring>
#include <cerrno>

class WatchCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "watch";
    }

    std::string get_description() const override {
        return "Watch hook output in real-time (Ctrl+C to stop).";
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

        std::cout << "[WATCH] Starting watch on agent socket fd=" << sock << ", client_fd=" << client_fd << "\n";

        const char* start_msg = "Watching hook output... (waiting for hooks to trigger)\n";
        write(client_fd, start_msg, strlen(start_msg));

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int client_flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, client_flags | O_NONBLOCK);

        char buffer[4096];
        bool running = true;

        while (running) {
            struct pollfd pfds[2];
            pfds[0] = {sock, POLLIN, 0};
            pfds[1] = {client_fd, POLLIN, 0};

            int ret = poll(pfds, 2, 1000);

            if (ret > 0) {
                if (pfds[0].revents & POLLIN) {
                    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    std::cout << "[WATCH] recv from agent: n=" << n << "\n";
                    if (n > 0) {
                        buffer[n] = '\0';
                        std::cout << "[WATCH] Got data: " << buffer << "\n";
                        write(client_fd, buffer, n);
                    } else if (n == 0) {
                        const char* msg = "Agent disconnected\n";
                        write(client_fd, msg, strlen(msg));
                        running = false;
                    }
                }

                if (pfds[1].revents & (POLLHUP | POLLERR)) {
                    std::cout << "[WATCH] Client disconnected\n";
                    running = false;
                }

                if (pfds[1].revents & POLLIN) {
                    char cmd[32];
                    ssize_t n = recv(client_fd, cmd, sizeof(cmd) - 1, MSG_PEEK);
                    if (n <= 0) {
                        running = false;
                    } else {
                        std::cout << "[WATCH] Client sent data, exiting watch mode\n";
                        running = false;
                    }
                }
            } else if (ret < 0) {
                std::cout << "[WATCH] poll error: " << strerror(errno) << "\n";
                running = false;
            }
        }

        fcntl(sock, F_SETFL, flags);
        fcntl(client_fd, F_SETFL, client_flags);

        const char* end_msg = "Watch stopped\n";
        write(client_fd, end_msg, strlen(end_msg));

        return CommandResult(true, "Watch completed");
    }
};

std::unique_ptr<CommandDispatcher> create_watch_command() {
    return std::make_unique<WatchCommand>();
}
