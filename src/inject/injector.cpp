#include <iostream>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "shellcode.h"

#ifndef __NR_memfd_create
#if defined(__aarch64__) || defined(__arm64__)
#define __NR_memfd_create 279
#elif defined(__arm__)
#define __NR_memfd_create 385
#elif defined(__x86_64__)
#define __NR_memfd_create 319
#elif defined(__i386__)
#define __NR_memfd_create 356
#endif
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#if defined(__aarch64__) || defined(__arm64__)
    #define LIBC_PATH "/apex/com.android.runtime/lib64/bionic/libc.so"
    #define LIBDL_PATH "/apex/com.android.runtime/lib64/bionic/libdl.so"
#elif defined(__arm__)
    #define LIBC_PATH "/apex/com.android.runtime/lib/bionic/libc.so"
    #define LIBDL_PATH "/apex/com.android.runtime/lib/bionic/libdl.so"
#elif defined(__x86_64__) || defined(__amd64__)
    #define LIBC_PATH "/apex/com.android.runtime/lib64/bionic/libc.so"
    #define LIBDL_PATH "/apex/com.android.runtime/lib64/bionic/libdl.so"
#elif defined(__i386__) || defined(__i686__)
    #define LIBC_PATH "/apex/com.android.runtime/lib/bionic/libc.so"
    #define LIBDL_PATH "/apex/com.android.runtime/lib/bionic/libdl.so"
#else
    #error "Unsupported architecture. Please compile for ARM or x86."
#endif

#define DEFAULT_PAYLOAD_PATH "/data/local/tmp/.r"
#define TEMP_PAYLOAD_PATH "/data/local/tmp/.r"

static bool copy_file(const char* src, const char* dst) {
    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) return false;

    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (dst_fd < 0) {
        close(src_fd);
        return false;
    }

    char buf[8192];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(dst_fd, buf, n) != n) {
            close(src_fd);
            close(dst_fd);
            unlink(dst);
            return false;
        }
    }

    close(src_fd);
    close(dst_fd);
    return n == 0;
}

bool write_memory(int pid, uintptr_t addr, const std::vector<uint8_t>& data) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        std::cerr << "Failed to open " << path << "\n";
        return false;
    }

    ssize_t written = pwrite(fd, data.data(), data.size(), addr);
    close(fd);

    if (written != (ssize_t)data.size()) {
        std::cerr << "Write failed: " << written << "/" << data.size() << " bytes\n";
        return false;
    }

    return true;
}

std::vector<uint8_t> read_memory(int pid, uintptr_t addr, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return {};
    }

    std::vector<uint8_t> buf(size);
    ssize_t bytes_read = pread(fd, buf.data(), size, addr);
    close(fd);

    if (bytes_read != (ssize_t)size) {
        return {};
    }

    return buf;
}

uintptr_t find_symbol(const char* libc_path, const char* symbol_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "readelf -s %s | grep ' %s$' | head -1 | awk '{print $2}'",
             libc_path, symbol_name);

    FILE* fp = popen(cmd, "r");
    if (!fp) return 0;

    char result[64];
    if (fgets(result, sizeof(result), fp)) {
        pclose(fp);
        return strtoul(result, NULL, 16);
    }

    pclose(fp);
    return 0;
}

uintptr_t find_library_base(int pid, const char* lib_name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE* fp = fopen(path, "r");
    if (!fp) return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name)) {
            char* end;
            uintptr_t addr = strtoul(line, &end, 16);
            fclose(fp);
            return addr;
        }
    }

    fclose(fp);
    return 0;
}

uintptr_t find_libc_base(int pid) {
    return find_library_base(pid, "libc.so");
}

int create_memfd_from_file(const char* so_path) {
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) {
        std::cerr << "  ✗ Failed to open SO file: " << so_path << "\n";
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        std::cerr << "  ✗ Failed to stat SO file\n";
        close(fd);
        return -1;
    }
    size_t file_size = st.st_size;

    int memfd = syscall(__NR_memfd_create, "", MFD_CLOEXEC);
    if (memfd < 0) {
        std::cerr << "  ✗ memfd_create failed (errno: " << errno << ")\n";
        close(fd);
        return -1;
    }

    char buf[8192];
    ssize_t total_written = 0;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t written = write(memfd, buf, n);
        if (written != n) {
            std::cerr << "  ✗ Failed to write to memfd\n";
            close(fd);
            close(memfd);
            return -1;
        }
        total_written += written;
    }

    close(fd);

    if (total_written != (ssize_t)file_size) {
        std::cerr << "  ✗ Size mismatch: " << total_written << " != " << file_size << "\n";
        close(memfd);
        return -1;
    }

    std::cout << "  ✓ memfd created (fd=" << memfd << ", size=" << file_size << "B)\n";
    return memfd;
}

bool inject(int pid, const char* so_path) {
    std::cout << "=== RENEF Injection ===\n";
    std::cout << "Target PID: " << pid << "\n";
    std::cout << "Payload: " << so_path << "\n\n";

    std::cout << "[1/7] Finding libc base...\n";
    uintptr_t libc_base = find_libc_base(pid);
    if (!libc_base) {
        std::cerr << " Failed to find libc base\n";
        return false;
    }
    std::cout << "  ✓ 0x" << std::hex << libc_base << std::dec << "\n";

    std::cout << "[2/7] Finding symbols...\n";
    uintptr_t malloc_offset = find_symbol(LIBC_PATH, "malloc");
    uintptr_t timezone_offset = find_symbol(LIBC_PATH, "timezone");
    uintptr_t dlopen_offset = find_symbol(LIBDL_PATH, "dlopen");

    if (!malloc_offset || !timezone_offset || !dlopen_offset) {
        std::cerr << " Failed to find symbols\n";
        return false;
    }

    uintptr_t libdl_base = find_library_base(pid, "libdl.so");
    if (!libdl_base) {
        std::cerr << " Failed to find libdl.so\n";
        return false;
    }

    uintptr_t malloc_addr = libc_base + malloc_offset;
    uintptr_t timezone_addr = libc_base + timezone_offset;
    uintptr_t dlopen_addr = libdl_base + dlopen_offset;

    std::cout << "  ✓ malloc: 0x" << std::hex << malloc_addr << std::dec << "\n";
    std::cout << "  ✓ dlopen: 0x" << std::hex << dlopen_addr << std::dec << "\n";

    std::cout << "[3/7] Preparing payload...\n";
    char final_path[64];
    bool using_temp_file = false;

    if (strcmp(so_path, TEMP_PAYLOAD_PATH) == 0) {
        strncpy(final_path, so_path, sizeof(final_path) - 1);
        std::cout << "  ✓ Using payload directly: " << so_path << "\n";
    } else if (copy_file(so_path, TEMP_PAYLOAD_PATH)) {
        strncpy(final_path, TEMP_PAYLOAD_PATH, sizeof(final_path) - 1);
        using_temp_file = true;
        std::cout << "  ✓ Payload copied to temp path\n";
    } else {
        std::cerr << "  ⚠ Failed to copy, using original path\n";
        strncpy(final_path, so_path, sizeof(final_path) - 1);
    }
    final_path[sizeof(final_path) - 1] = '\0';

    auto stage2 = shellcode::arm64_stage2_dlopen_linjector(dlopen_addr, final_path, malloc_addr);
    auto stage1 = shellcode::arm64_stage1_linjector_exact(timezone_addr, stage2.size());
    std::cout << "  ✓ Stage1: " << stage1.size() << "B, Stage2: " << stage2.size() << "B\n";

    std::cout << "[4/7] Backing up original memory...\n";
    auto malloc_backup = read_memory(pid, malloc_addr, stage1.size());
    auto timezone_backup = read_memory(pid, timezone_addr, 8);
    if (malloc_backup.empty() || timezone_backup.empty()) {
        std::cerr << " Failed to backup memory\n";
        return false;
    }
    std::cout << "  ✓ Backup complete\n";

    std::cout << "[5/7] Injecting stage 1 shellcode...\n";
    std::vector<uint8_t> zero(8, 0);
    if (!write_memory(pid, timezone_addr, zero)) {
        std::cerr << " Failed to zero timezone\n";
        return false;
    }
    if (!write_memory(pid, malloc_addr, stage1)) {
        std::cerr << " Failed to write stage1\n";
        write_memory(pid, timezone_addr, timezone_backup);
        return false;
    }
    std::cout << "  ✓ Stage1 injected\n";

    std::cout << "[6/7] Waiting for malloc() trigger...\n";
    uintptr_t new_map = 0;
    int timeout_counter = 0;
    const int MAX_TIMEOUT = 30000;

    char kill_cmd[256];
    snprintf(kill_cmd, sizeof(kill_cmd), "kill -10 %d 2>/dev/null", pid);  // SIGUSR1 → GC
    system(kill_cmd);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::cout << "  → Trigger signals sent\n";


    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        auto data = read_memory(pid, timezone_addr, 8);
        if (data.size() != 8) {
            timeout_counter++;
            if (timeout_counter > MAX_TIMEOUT) {
                std::cerr << " Timeout waiting for malloc trigger\n";
                write_memory(pid, malloc_addr, malloc_backup);
                write_memory(pid, timezone_addr, timezone_backup);
                if (using_temp_file) unlink(TEMP_PAYLOAD_PATH);
                return false;
            }
            continue;
        }

        uint64_t val = 0;
        memcpy(&val, data.data(), 8);

        if ((val & 0x1) && (val & 0xFFFFFFFFFFFFFFF0)) {
            new_map = val & 0xFFFFFFFFFFFFFFF0;
            break;
        }

        timeout_counter++;
        if (timeout_counter > MAX_TIMEOUT) {
            std::cerr << " Timeout waiting for malloc trigger\n";
            write_memory(pid, malloc_addr, malloc_backup);
            write_memory(pid, timezone_addr, timezone_backup);
            if (using_temp_file) unlink(TEMP_PAYLOAD_PATH);
            return false;
        }
    }
    std::cout << "  ✓ Triggered! New map: 0x" << std::hex << new_map << std::dec << "\n";

    std::cout << "[7/7] Finalizing injection...\n";

    if (!write_memory(pid, new_map, stage2)) {
        std::cerr << "Failed to write stage2\n";
        if (using_temp_file) unlink(TEMP_PAYLOAD_PATH);
        return false;
    }
    std::cout << "  ✓ Stage2 written to new map\n";

    auto loop = shellcode::arm64_infinite_loop();
    if (!write_memory(pid, malloc_addr, loop)) {
        std::cerr << "Failed to write infinite loop\n";
        return false;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (!write_memory(pid, malloc_addr, malloc_backup)) {
        std::cerr << "Warning: Failed to restore malloc\n";
    }
    if (!write_memory(pid, timezone_addr, timezone_backup)) {
        std::cerr << "Warning: Failed to restore timezone\n";
    }
    std::cout << "  ✓ Original functions restored\n";

    std::cout << "\n Injection complete! Loaded: " << so_path << "\n";
    return true;
}

#ifdef BUILD_STANDALONE_AGENT
int main(int argc, char** argv) {
    int pid;
    const char* so_path;

    if (argc == 2) {
        pid = atoi(argv[1]);
        so_path = DEFAULT_PAYLOAD_PATH;
    } else if (argc == 3) {
        pid = atoi(argv[1]);
        so_path = argv[2];
    } else {
        std::cerr << "Usage: " << argv[0] << " <PID> [SO_PATH]\n";
        std::cerr << "  Default payload: " << DEFAULT_PAYLOAD_PATH << "\n";
        return 1;
    }

    if (inject(pid, so_path)) {
        return 0;
    } else {
        return 1;
    }
}
#endif
