#pragma once

#include <string>
#include <sys/types.h>

/**
 * Abstract base class for transport layer implementations.
 * Provides interface for different IPC mechanisms (UDS, TCP, Mach Ports, etc.)
 */
class ITransport {
public:
    virtual ~ITransport() = default;

    /**
     * Create and bind server socket/port
     * @return file descriptor or -1 on error
     */
    virtual int create_server() = 0;

    /**
     * Accept incoming client connection
     * @return client fd or -1 on error
     */
    virtual int accept_client() = 0;

    /**
     * Connect to server (client-side)
     * @param target Target identifier (PID, host:port, etc.)
     * @return socket fd or -1 on error
     */
    virtual int connect_to_server(const std::string& target) = 0;

    /**
     * Send data through transport
     * @param data Data buffer to send
     * @param size Size of data
     * @return bytes sent or -1 on error
     */
    virtual ssize_t send_data(const void* data, size_t size) = 0;

    /**
     * Receive data from transport
     * @param buffer Buffer to receive into
     * @param size Buffer size
     * @return bytes received or -1 on error
     */
    virtual ssize_t receive_data(void* buffer, size_t size) = 0;

    /**
     * Close transport connection
     */
    virtual void close() = 0;

    /**
     * Get transport type name
     * @return Transport type (e.g., "UDS", "TCP", "MACH")
     */
    virtual std::string get_type() const = 0;

    /**
     * Get current file descriptor
     * @return Current socket/connection fd
     */
    virtual int get_fd() const = 0;

    /**
     * Check if connected
     * @return true if connected
     */
    virtual bool is_connected() const = 0;
};
