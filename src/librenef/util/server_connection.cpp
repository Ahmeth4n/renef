#include <renef/server_connection.h>
#include <sys/socket.h>
#include <sys/un.h>
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

    // Check if host starts with @ -> abstract UDS
    if (!host.empty() && host[0] == '@') {
        sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            std::cerr << "[ServerConnection] socket(AF_UNIX) failed\n";
            return false;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        addr.sun_path[0] = '\0';  // Abstract namespace
        strncpy(addr.sun_path + 1, host.c_str() + 1, sizeof(addr.sun_path) - 2);
        socklen_t addr_len = sizeof(addr.sun_family) + 1 + strlen(host.c_str() + 1);

        if (::connect(sock_fd, (struct sockaddr*)&addr, addr_len) < 0) {
            std::cerr << "[ServerConnection] connect(UDS) failed: " << strerror(errno) << "\n";
            close(sock_fd);
            sock_fd = -1;
            return false;
        }

        std::cout << "[*] Connected to UDS: " << host << "\n";
        connected_host_ = host;
        connected_port_ = port;
        return true;
    }

    // TCP connection
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

    connected_host_ = host;
    connected_port_ = port;
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

    if (poll(&pfd, 1, timeout_ms) <= 0) return "";

    while (true) {
        ssize_t n = recv(sock_fd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);

        if (n > 0) {
            buffer[n] = '\0';
            result += buffer;
            continue;
        }

        if (n == 0) break;

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (poll(&pfd, 1, 50) <= 0) break;
            continue;
        }

        break;
    }

    return result;
}

std::string ServerConnection::get_host() const {
    return connected_host_;
}

int ServerConnection::get_port() const {
    return connected_port_;
}

int ServerConnection::get_socket_fd() const {
    return sock_fd;
}
