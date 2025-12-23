#pragma once

#include <renef/transport.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string>

/**
 * Unix Domain Socket transport implementation
 * Used for local IPC on Android/Linux
 */
class UDSTransport : public ITransport {
private:
    int server_fd;
    int client_fd;
    std::string socket_path;
    struct sockaddr_un addr;
    bool is_abstract;  // Abstract socket (Linux-specific)

public:
    /**
     * Constructor for UDS transport
     * @param path Socket path (for abstract sockets, use without leading /)
     * @param abstract Use Linux abstract socket namespace
     */
    UDSTransport(const std::string& path, bool abstract = true);
    ~UDSTransport() override;

    int create_server() override;
    int accept_client() override;
    int connect_to_server(const std::string& target) override;
    ssize_t send_data(const void* data, size_t size) override;
    ssize_t receive_data(void* buffer, size_t size) override;
    void close() override;

    std::string get_type() const override { return "UDS"; }
    int get_fd() const override { return client_fd >= 0 ? client_fd : server_fd; }
    bool is_connected() const override { return client_fd >= 0; }

    void set_client_fd(int fd) { client_fd = fd; }
    int get_server_fd() const { return server_fd; }
    int get_client_fd() const { return client_fd; }
};
