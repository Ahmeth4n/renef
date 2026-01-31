#include "tcp.h"
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>

TCPTransport::TCPTransport(int port, const std::string& host)
    : server_fd(-1), client_fd(-1), port(port), host(host) {
    memset(&addr, 0, sizeof(addr));
}

TCPTransport::~TCPTransport() {
    close();
}

int TCPTransport::create_server() {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        std::cerr << "socket() failed: " << strerror(errno) << "\n";
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt(SO_REUSEADDR) failed: " << strerror(errno) << "\n";
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host.c_str());
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "bind() failed: " << strerror(errno) << "\n";
        ::close(server_fd);
        server_fd = -1;
        return -1;
    }

    if (listen(server_fd, 5) < 0) {
        std::cerr << "listen() failed: " << strerror(errno) << "\n";
        ::close(server_fd);
        server_fd = -1;
        return -1;
    }

    std::cout << "TCP Server listening on " << host << ":" << port << "\n";
    return server_fd;
}

int TCPTransport::accept_client() {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        std::cerr << "accept() failed: " << strerror(errno) << "\n";
        return -1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    std::cout << "TCP Client connected from " << client_ip << ":" << ntohs(client_addr.sin_port)
              << " (fd=" << client_fd << ")\n";

    return client_fd;
}

int TCPTransport::connect_to_server(const std::string& target) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    std::string connect_host = host;
    int connect_port = port;

    size_t colon_pos = target.find(':');
    if (colon_pos != std::string::npos) {
        connect_host = target.substr(0, colon_pos);
        connect_port = std::stoi(target.substr(colon_pos + 1));
    }

    server_addr.sin_addr.s_addr = inet_addr(connect_host.c_str());
    server_addr.sin_port = htons(connect_port);

    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        ::close(sock_fd);
        return -1;
    }

    client_fd = sock_fd;
    return client_fd;
}

ssize_t TCPTransport::send_data(const void* data, size_t size) {
    if (client_fd < 0) {
        std::cerr << "No client connected\n";
        return -1;
    }

    const char* send_ptr = (const char*)data;
    size_t remaining = size;
    size_t total_sent = 0;

    while (remaining > 0) {
        ssize_t sent = send(client_fd, send_ptr, remaining, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            std::cerr << "send() failed: " << strerror(errno) << "\n";
            return -1;
        }
        if (sent == 0) break;

        send_ptr += sent;
        remaining -= sent;
        total_sent += sent;
    }

    return total_sent;
}

ssize_t TCPTransport::receive_data(void* buffer, size_t size) {
    if (client_fd < 0) {
        std::cerr << "No client connected\n";
        return -1;
    }

    ssize_t received = recv(client_fd, buffer, size, 0);
    if (received < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; 
        }
        std::cerr << "recv() failed: " << strerror(errno) << "\n";
        return -1;
    }
    if (received == 0) {
        std::cout << "Client closed connection\n";
    }
    return received;
}

void TCPTransport::close() {
    if (client_fd >= 0) {
        ::close(client_fd);
        client_fd = -1;
    }

    if (server_fd >= 0) {
        ::close(server_fd);
        server_fd = -1;
    }
}
