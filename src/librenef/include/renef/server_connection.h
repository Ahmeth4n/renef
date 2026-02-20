#pragma once

#include <string>
#include <mutex>

class ServerConnection {
public:
    static ServerConnection& instance();

    bool connect(const std::string& host = "127.0.0.1", int port = 1907);
    void disconnect();
    bool is_connected() const;

    bool send(const std::string& data);
    std::string receive(int timeout_ms = 2000);

    // Connection parameters (for creating additional connections)
    std::string get_host() const;
    int get_port() const;

    // Raw socket fd for direct poll/recv (watch streaming)
    int get_socket_fd() const;

private:
    ServerConnection();
    ~ServerConnection();
    ServerConnection(const ServerConnection&) = delete;
    ServerConnection& operator=(const ServerConnection&) = delete;

    int sock_fd;
    std::mutex mtx;
    std::string connected_host_;
    int connected_port_ = 0;
};
