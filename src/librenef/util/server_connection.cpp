#include <renef/server_connection.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <iostream>

ServerConnection& ServerConnection::instance() {
    static ServerConnection inst;
    return inst;
}

ServerConnection::ServerConnection() : sock_fd(-1) {}

ServerConnection::~ServerConnection() {
    disconnect();
}

bool ServerConnection::connect(const std::string& host, int port) {
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd >= 0) {
        return true;
    }

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        std::cerr << "[ServerConnection] socket() failed\n";
        return false;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host.c_str());

    if (::connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[ServerConnection] connect() failed\n";
        close(sock_fd);
        sock_fd = -1;
        return false;
    }

    return true;
}

void ServerConnection::disconnect() {
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }
}

bool ServerConnection::is_connected() const {
    return sock_fd >= 0;
}

bool ServerConnection::send(const std::string& data) {
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd < 0) return false;

    ssize_t total = 0;
    ssize_t len = data.length();
    const char* ptr = data.c_str();

    while (total < len) {
        ssize_t n = ::send(sock_fd, ptr + total, len - total, MSG_NOSIGNAL);
        if (n <= 0) return false;
        total += n;
    }

    return true;
}

std::string ServerConnection::receive(int timeout_ms) {
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd < 0) return "";

    std::string result;
    char buffer[4096];

    struct pollfd pfd;
    pfd.fd = sock_fd;
    pfd.events = POLLIN;

    while (true) {
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) break; 

        if (pfd.revents & POLLIN) {
            ssize_t n = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);
            if (n <= 0) break;

            buffer[n] = '\0';
            result += buffer;

            if (buffer[n - 1] == '\n') break;

            timeout_ms = 100;
        } else {
            break;
        }
    }

    return result;
}
