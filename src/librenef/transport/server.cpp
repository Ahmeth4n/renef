#include "server.h"
#include <renef/cmd.h>
#include <iostream>
#include <cstring>
#include <unistd.h>

TransportServer::TransportServer(ITransport* transport)
    : transport(transport) {
}

TransportServer::~TransportServer() {
    close_server();
}

int TransportServer::create_server() {
    return transport->create_server();
}

int TransportServer::accept_client() {
    return transport->accept_client();
}

ssize_t TransportServer::send_data(const void* data, size_t size) {
    return transport->send_data(data, size);
}

ssize_t TransportServer::receive_data(void* buffer, size_t size) {
    return transport->receive_data(buffer, size);
}

void TransportServer::handle_client() {
    std::cout << "Entering handle_client loop (" << transport->get_type() << ")\n";

    while (true) {
        std::vector<char> buffer;
        buffer.reserve(BUFFER_SIZE);

        char chunk[BUFFER_SIZE];
        ssize_t total = 0;

        while (true) {
            ssize_t n = receive_data(chunk, sizeof(chunk));

            if (n <= 0) {
                if (total == 0) {
                    std::cout << "Client disconnected (recv returned " << n << ")\n";
                    return;
                }
                break;
            }

            buffer.insert(buffer.end(), chunk, chunk + n);
            total += n;

            if (chunk[n-1] == '\n') {
                break;
            }

            if (total > 1024 * 1024) {
                std::cerr << "Command too large (>1MB), rejecting\n";
                const char* error = "ERROR: Command too large\n";
                send_data(error, strlen(error));
                return;
            }
        }

        if (total <= 0) {
            return;
        }

        buffer.push_back('\0');

        if (total > 0 && buffer[total-1] == '\n') {
            buffer[total-1] = '\0';
            total--;
        }

        std::cout << "Received command (" << total << " bytes)\n";
        handle_command(buffer.data(), total);
    }

    std::cout << "Exiting handle_client loop\n";
}

void TransportServer::handle_command(const char* cmd_buffer, size_t cmd_size) {
    CommandRegistry& registry = CommandRegistry::instance();
    int client_fd = transport->get_fd();
    registry.dispatch(client_fd, cmd_buffer, cmd_size);
}

void TransportServer::close_server() {
    if (transport) {
        transport->close();
    }
}
