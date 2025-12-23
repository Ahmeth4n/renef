#include <renef/socket_helper.h>
#include "../transport/uds.h"
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <string>

SocketHelper::SocketHelper()
    : transport(nullptr), current_pid(-1) {
}

SocketHelper::~SocketHelper() {
    close_connection();
}

int SocketHelper::ensure_connection(int pid) {
    if (current_pid == pid && transport && transport->is_connected()) {
        return transport->get_fd();
    }

    if (transport) {
        close_connection();
    }

    transport.reset(new UDSTransport("", true));

    char target[64];
    snprintf(target, sizeof(target), "%d", pid);

    int max_retries = 10;
    int retry_delay_ms = 100;

    for (int i = 0; i < max_retries; i++) {
        int fd = transport->connect_to_server(std::string(target));
        if (fd >= 0) {
            current_pid = pid;
            return fd;
        }

        usleep(retry_delay_ms * 1000);
        retry_delay_ms *= 2;
    }

    transport.reset();
    return -1;
}

ssize_t SocketHelper::send_data(const void* data, size_t size, bool prefix_key) {
    if (!transport || !transport->is_connected()) {
        return -1;
    }

    if (prefix_key && !session_key.empty()) {
        std::string full_data = session_key + " " + std::string((const char*)data, size);
        return transport->send_data(full_data.c_str(), full_data.length());
    }

    return transport->send_data(data, size);
}

ssize_t SocketHelper::receive_data(void* buffer, size_t size) {
    if (!transport || !transport->is_connected()) {
        return -1;
    }
    return transport->receive_data(buffer, size);
}

bool SocketHelper::is_connected() const {
    return transport && transport->is_connected();
}

int SocketHelper::get_socket_fd() const {
    return transport ? transport->get_fd() : -1;
}

void SocketHelper::close_connection() {
    if (transport) {
        transport->close();
        transport.reset();
        current_pid = -1;
    }
}

void SocketHelper::set_session_key(std::string key) {
    session_key = key;
}

std::string SocketHelper::get_session_key() {
    return session_key;
}
