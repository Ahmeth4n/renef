#pragma once

#include <renef/transport.h>
#include <netinet/in.h>
#include <string>

/**
 * TCP Socket transport implementation
 * Cross-platform (works on Android, iOS, Linux, macOS)
 */
class TCPTransport : public ITransport {
private:
    int server_fd;
    int client_fd;
    int port;
    std::string host;
    struct sockaddr_in addr;

public:
    /**
     * Constructor for TCP transport
     * @param port Port number (default 1907)
     * @param host Host address (default "127.0.0.1" for localhost)
     */
    TCPTransport(int port = 1907, const std::string& host = "127.0.0.1");
    ~TCPTransport() override;

    int create_server() override;
    int accept_client() override;
    int connect_to_server(const std::string& target) override;
    ssize_t send_data(const void* data, size_t size) override;
    ssize_t receive_data(void* buffer, size_t size) override;
    void close() override;

    std::string get_type() const override { return "TCP"; }
    int get_fd() const override { return client_fd >= 0 ? client_fd : server_fd; }
    bool is_connected() const override { return client_fd >= 0; }

    void set_client_fd(int fd) { client_fd = fd; }
    int get_server_fd() const { return server_fd; }
    int get_client_fd() const { return client_fd; }
    int get_port() const { return port; }
};
