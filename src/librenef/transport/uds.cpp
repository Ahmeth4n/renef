#include "uds.h"
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <iostream>

UDSTransport::UDSTransport(const std::string& path, bool abstract)
    : server_fd(-1), client_fd(-1), socket_path(path), is_abstract(abstract) {
    memset(&addr, 0, sizeof(addr));
}

UDSTransport::~UDSTransport() {
    close();
}

int UDSTransport::create_server() {
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1) {
        std::cerr << "socket() failed: " << strerror(errno) << "\n";
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt(SO_REUSEADDR) failed: " << strerror(errno) << "\n";
    }

    addr.sun_family = AF_UNIX;
    memset(addr.sun_path, 0, sizeof(addr.sun_path));

    socklen_t addr_len;

    if (is_abstract) {
        addr.sun_path[0] = '\0';
        strncpy(addr.sun_path + 1, socket_path.c_str(), sizeof(addr.sun_path) - 2);
        addr_len = sizeof(addr.sun_family) + 1 + socket_path.length();
    } else {
        strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
        addr_len = sizeof(addr);
        unlink(socket_path.c_str());
    }

    if (bind(server_fd, (struct sockaddr*)&addr, addr_len) < 0) {
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

    if (is_abstract) {
        std::cout << "UDS Server listening on abstract socket: @" << socket_path << "\n";
    } else {
        std::cout << "UDS Server listening on: " << socket_path << "\n";
    }

    return server_fd;
}

int UDSTransport::accept_client() {
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        std::cerr << "accept() failed: " << strerror(errno) << "\n";
        return -1;
    }

    std::cout << "UDS Client connected (fd=" << client_fd << ")\n";
    return client_fd;
}

int UDSTransport::connect_to_server(const std::string& target) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        return -1;
    }

    struct sockaddr_un connect_addr;
    memset(&connect_addr, 0, sizeof(connect_addr));
    connect_addr.sun_family = AF_UNIX;
    connect_addr.sun_path[0] = '\0';

    std::string agent_socket = "renef_pl_" + target;
    strncpy(connect_addr.sun_path + 1, agent_socket.c_str(), sizeof(connect_addr.sun_path) - 2);
    socklen_t addr_len = sizeof(connect_addr.sun_family) + agent_socket.length() + 1;

    if (connect(sock_fd, (struct sockaddr*)&connect_addr, addr_len) < 0) {
        ::close(sock_fd);
        return -1;
    }

    client_fd = sock_fd;
    return client_fd;
}

ssize_t UDSTransport::send_data(const void* data, size_t size) {
    if (client_fd < 0) {
        std::cerr << "No client connected\n";
        return -1;
    }

    const char* send_ptr = (const char*)data;
    size_t remaining = size;
    size_t total_sent = 0;

    while (remaining > 0) {
        ssize_t sent = send(client_fd, send_ptr, remaining, MSG_NOSIGNAL);
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

ssize_t UDSTransport::receive_data(void* buffer, size_t size) {
    if (client_fd < 0) {
        std::cerr << "No client connected\n";
        return -1;
    }

    ssize_t received = recv(client_fd, buffer, size, 0);
    if (received < 0) {
        if (errno == EINTR) {
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

void UDSTransport::close() {
    if (client_fd >= 0) {
        ::close(client_fd);
        client_fd = -1;
    }

    if (server_fd >= 0) {
        ::close(server_fd);
        server_fd = -1;
    }

    if (!is_abstract && !socket_path.empty()) {
        unlink(socket_path.c_str());
    }
}
