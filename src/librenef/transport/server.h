#pragma once

#include <renef/transport.h>
#include <memory>
#include <vector>

#define BUFFER_SIZE 4096

/**
 * Generic server wrapper that uses ITransport for communication
 * Replaces the old UdsServer class
 */
class TransportServer {
private:
    std::unique_ptr<ITransport> transport;

    void handle_command(const char* cmd_buffer, size_t cmd_size);

public:
    /**
     * Constructor
     * @param transport Ownership of transport implementation
     */
    explicit TransportServer(ITransport* transport);
    ~TransportServer();

    /**
     * Create and start server
     * @return server fd or -1 on error
     */
    int create_server();

    /**
     * Accept incoming client
     * @return client fd or -1 on error
     */
    int accept_client();

    /**
     * Handle client communication loop
     */
    void handle_client();

    /**
     * Send data to client
     * @param data Data to send
     * @param size Size of data
     * @return bytes sent or -1 on error
     */
    ssize_t send_data(const void* data, size_t size);

    /**
     * Receive data from client
     * @param buffer Buffer to receive into
     * @param size Buffer size
     * @return bytes received or -1 on error
     */
    ssize_t receive_data(void* buffer, size_t size);

    /**
     * Close server and connections
     */
    void close_server();

    /**
     * Get underlying transport
     * @return Transport pointer
     */
    ITransport* get_transport() { return transport.get(); }
};
