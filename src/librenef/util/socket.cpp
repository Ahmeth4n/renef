#include <renef/socket_helper.h>
#include "../transport/uds.h"
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <string>
#include <fcntl.h>
#include <sys/socket.h>
#include <poll.h>

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
    int retry_delay_ms = 20;

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

    ssize_t result;
    if (prefix_key && !session_key.empty()) {
        std::string full_data = session_key + " " + std::string((const char*)data, size);
        result = transport->send_data(full_data.c_str(), full_data.length());
    } else {
        result = transport->send_data(data, size);
    }

    if (result < 0 && current_pid > 0) {
        fprintf(stderr, "[SocketHelper] send failed, reconnecting to pid %d...\n", current_pid);
        int pid = current_pid;
        close_connection();

        if (ensure_connection(pid) < 0) {
            fprintf(stderr, "[SocketHelper] reconnect failed\n");
            return -1;
        }

        if (!session_key.empty()) {
            std::string con_cmd = "con " + session_key + "\n";
            transport->send_data(con_cmd.c_str(), con_cmd.length());

            char drain[256];
            usleep(50000);
            int old_flags = fcntl(transport->get_fd(), F_GETFL, 0);
            fcntl(transport->get_fd(), F_SETFL, old_flags | O_NONBLOCK);
            while (recv(transport->get_fd(), drain, sizeof(drain), 0) > 0) {}
            fcntl(transport->get_fd(), F_SETFL, old_flags);
        }

        if (prefix_key && !session_key.empty()) {
            std::string full_data = session_key + " " + std::string((const char*)data, size);
            result = transport->send_data(full_data.c_str(), full_data.length());
        } else {
            result = transport->send_data(data, size);
        }
    }

    return result;
}

ssize_t SocketHelper::receive_data(void* buffer, size_t size) {
    if (!transport || !transport->is_connected()) {
        return -1;
    }
    return transport->receive_data(buffer, size);
}

void SocketHelper::drain_buffer() {
    if (!transport || !transport->is_connected()) return;

    int fd = transport->get_fd();
    if (fd < 0) return;

    int old_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);

    char drain[4096];
    for (int i = 0; i < 50; i++) {
        struct pollfd pfd = {fd, POLLIN, 0};
        int ret = poll(&pfd, 1, 10);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(fd, drain, sizeof(drain), 0);
            if (n <= 0) break;
        } else {
            break;
        }
    }

    fcntl(fd, F_SETFL, old_flags);
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
