#include <renef/transport.h>
#include "transport/server.h"
#include "transport/uds.h"
#include "transport/tcp.h"
#include <renef/cmd.h>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <csignal>
#include <cstdlib>

#define DEFAULT_TRANSPORT "UDS"
#define DEFAULT_UDS_PATH "com.android.internal.os.RuntimeInit"
#define DEFAULT_TCP_PORT 1907

static void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -t, --transport TYPE   Transport type: UDS (default) or TCP\n";
    std::cout << "  -p, --port PORT        TCP port (default: 1907)\n";
    std::cout << "  -s, --socket PATH      UDS socket path (default: com.android.internal.os.RuntimeInit)\n";
    std::cout << "  -h, --help             Show this help message\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << prog_name << "                    # Use default UDS\n";
    std::cout << "  " << prog_name << " -t TCP             # Use TCP on port 1907\n";
    std::cout << "  " << prog_name << " -t TCP -p 8080     # Use TCP on port 8080\n";
    std::cout << "\n";
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);

    std::string transport_type = DEFAULT_TRANSPORT;
    std::string uds_path = DEFAULT_UDS_PATH;
    int tcp_port = DEFAULT_TCP_PORT;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-t" || arg == "--transport") {
            if (i + 1 < argc) {
                transport_type = argv[++i];
                for (auto& c : transport_type) {
                    c = toupper(c);
                }
            } else {
                std::cerr << "Error: --transport requires an argument\n";
                return 1;
            }
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                tcp_port = std::atoi(argv[++i]);
            } else {
                std::cerr << "Error: --port requires an argument\n";
                return 1;
            }
        } else if (arg == "-s" || arg == "--socket") {
            if (i + 1 < argc) {
                uds_path = argv[++i];
            } else {
                std::cerr << "Error: --socket requires an argument\n";
                return 1;
            }
        } else {
            std::cerr << "Error: Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    CommandRegistry& registry = CommandRegistry::instance();
    registry.setup_all_commands();

    ITransport* transport = nullptr;

    if (transport_type == "UDS") {
        std::cout << "Using UDS transport (abstract socket)\n";
        transport = new UDSTransport(uds_path, true);
    } else if (transport_type == "TCP") {
        std::cout << "Using TCP transport\n";
        transport = new TCPTransport(tcp_port, "127.0.0.1");
    } else {
        std::cerr << "Error: Unknown transport type: " << transport_type << "\n";
        std::cerr << "Supported types: UDS, TCP\n";
        return 1;
    }

    TransportServer server(transport);

    int result = server.create_server();
    if (result < 0) {
        std::cerr << "Failed to create server\n";
        return 1;
    }

    while (true) {
        std::cout << "Waiting for client connection...\n";

        int client = server.accept_client();
        if (client < 0) {
            if (errno == EINTR) {
                std::cout << "accept() interrupted by signal, retrying...\n";
                continue;
            }
            std::cerr << "Failed to accept client: " << strerror(errno) << ", retrying...\n";
            sleep(1);
            continue;
        }

        server.handle_client();
        std::cout << "Client handler finished, looping back to accept\n";
    }

    return 0;
}
