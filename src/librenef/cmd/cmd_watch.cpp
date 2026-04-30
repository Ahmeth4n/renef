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

        fprintf(stderr, "[WATCH] Starting watch on agent socket fd=%d, client_fd=%d\n", sock, client_fd);

        // Drain any data already in socket buffer (e.g. hook output that
        // fired between script execution and watch startup) and forward to client
        {
            int old_flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, old_flags | O_NONBLOCK);
            char buf[4096];
            ssize_t drained_total = 0;
            while (true) {
                ssize_t n = recv(sock, buf, sizeof(buf), 0);
                if (n > 0) {
                    write(client_fd, buf, n);
                    drained_total += n;
                } else {
                    break;
                }
            }
            fcntl(sock, F_SETFL, old_flags);
            if (drained_total > 0) {
                fprintf(stderr, "[WATCH] forwarded %zd bytes of buffered hook output\n", drained_total);
            }
        }

        const char* start_msg = "Watching hook output... (waiting for hooks to trigger)\n";
        write(client_fd, start_msg, strlen(start_msg));

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int client_flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, client_flags | O_NONBLOCK);

        char buffer[4096];
        bool running = true;

        int poll_count = 0;
        while (running) {
            struct pollfd pfds[2];
            pfds[0] = {sock, POLLIN, 0};
            pfds[1] = {client_fd, POLLIN, 0};

            int ret = poll(pfds, 2, 1000);
            poll_count++;
            if (poll_count % 5 == 0) {
                // Also try a non-blocking recv to see if there's data poll missed
                char peek_buf[64];
                ssize_t peek = recv(sock, peek_buf, sizeof(peek_buf), MSG_PEEK | MSG_DONTWAIT);
                fprintf(stderr, "[WATCH] poll iter=%d, ret=%d, sock_rev=0x%x, client_rev=0x%x, peek=%zd\n",
                        poll_count, ret, pfds[0].revents, pfds[1].revents, peek);
                if (peek > 0) {
                    fprintf(stderr, "[WATCH] peek data: %.*s\n", (int)peek, peek_buf);
                }
            }

            if (ret > 0) {
                if (pfds[0].revents & POLLIN) {
                    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    fprintf(stderr, "[WATCH] recv from agent: n=%zd\n", n);
                    if (n > 0) {
                        buffer[n] = '\0';
                        fprintf(stderr, "[WATCH] Forwarding to client: %.*s\n", (int)n, buffer);
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
                    ssize_t n = recv(client_fd, cmd, sizeof(cmd) - 1, 0);
                    if (n <= 0) {
                        running = false;
                    } else {
                        cmd[n] = '\0';
                        std::cout << "[WATCH] Client sent data: '" << cmd << "', exiting watch mode\n";
                        running = false;
                    }
                }
            } else if (ret < 0) {
                std::cout << "[WATCH] poll error: " << strerror(errno) << "\n";
                running = false;
            }
        }

        {
            char drain_buf[4096];
            struct pollfd drain_pfd = {sock, POLLIN, 0};
            while (poll(&drain_pfd, 1, 50) > 0 && (drain_pfd.revents & POLLIN)) {
                ssize_t n = recv(sock, drain_buf, sizeof(drain_buf), 0);
                if (n <= 0) break;
            }
        }

        fcntl(sock, F_SETFL, flags);
        fcntl(client_fd, F_SETFL, client_flags);

        return CommandResult(true, "Watch completed");
    }
};

std::unique_ptr<CommandDispatcher> create_watch_command() {
    return std::make_unique<WatchCommand>();
}
