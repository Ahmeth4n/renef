#pragma once
#include <sys/types.h>
#include <string>
#include <memory>

class ITransport;

/**
 * Socket helper class for managing agent connections
 * Now uses ITransport for platform-agnostic communication
 */
class SocketHelper {
private:
    std::unique_ptr<ITransport> transport;
    int current_pid;
    std::string session_key;

public:
    SocketHelper();
    ~SocketHelper();

    /**
     * Ensure connection to agent in target process
     * @param pid Target process PID
     * @return socket fd or -1 on error
     */
    int ensure_connection(int pid);

    /**
     * Send data to agent
     * @param data Data to send
     * @param size Size of data
     * @param prefix_key Prepend session key (default: true)
     * @return bytes sent or -1 on error
     */
    ssize_t send_data(const void* data, size_t size, bool prefix_key = true);

    /**
     * Receive data from agent
     * @param buffer Buffer to receive into
     * @param size Buffer size
     * @return bytes received or -1 on error
     */
    ssize_t receive_data(void* buffer, size_t size);

    /**
     * Close connection to agent
     */
    void close_connection();

    /**
     * Check if connected to agent
     * @return true if connected
     */
    bool is_connected() const;

    /**
     * Get socket file descriptor
     * @return Current socket fd
     */
    int get_socket_fd() const;

    /**
     * Set session authentication key
     * @param key Session key
     */
    void set_session_key(std::string key);

    /**
     * Get current session key
     * @return Session key
     */
    std::string get_session_key();
};
