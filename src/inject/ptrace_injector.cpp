// Ptrace-based injector for spawn gate (--pause) only.
// This is intentionally separate from the normal signal-based injector.
// Normal injection stays ptrace-free — only --pause uses this to freeze
// the target app before onCreate runs.
//
// Flow:
//   1. PTRACE_ATTACH → main thread stops
//   2. Save registers
//   3. Find dlopen + libc base + path scratch space
//   4. Write path string to a RW page
//   5. Set up x0=path, x1=RTLD_NOW, LR=0, PC=dlopen
//   6. PTRACE_CONT → dlopen runs
//   7. Wait for SIGSEGV (return to LR=0)
//   8. Restore registers
//   9. PTRACE_DETACH (or keep attached if we want to stay paused)
//
// On success the agent is loaded but the main thread is still stopped (if
// we chose to re-stop). Caller connects to the agent's socket, loads the
// script, then calls ptrace_resume() to detach.

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <linux/elf.h>

// user_regs_struct for ARM64
struct arm64_regs {
    uint64_t x[31];  // x0-x30
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

// From the existing signal-based injector (injector.cpp)
extern uintptr_t find_library_base(int pid, const char *name);
extern uintptr_t find_symbol(const char *lib_path, const char *sym);
extern bool write_memory(int pid, uintptr_t addr, const std::vector<uint8_t> &data);
extern std::vector<uint8_t> read_memory(int pid, uintptr_t addr, size_t size);

static bool ptrace_get_regs(int pid, arm64_regs *regs) {
    struct iovec iov = {regs, sizeof(*regs)};
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) {
        fprintf(stderr, "[ptrace] GETREGSET failed: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static bool ptrace_set_regs(int pid, const arm64_regs *regs) {
    struct iovec iov = {(void*)regs, sizeof(*regs)};
    if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) {
        fprintf(stderr, "[ptrace] SETREGSET failed: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static bool ptrace_attach_and_wait(int pid) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        fprintf(stderr, "[ptrace] ATTACH failed: %s\n", strerror(errno));
        return false;
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "[ptrace] waitpid after attach failed: %s\n", strerror(errno));
        return false;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[ptrace] target did not stop after attach\n");
        return false;
    }
    return true;
}

// Run code with modified regs until the target stops (expected via SIGSEGV on LR=0)
// Returns the stopped-state registers.
static bool ptrace_call_function(int pid, arm64_regs *saved_regs_out,
                                 uintptr_t func_addr, uintptr_t x0, uintptr_t x1,
                                 uintptr_t x2 = 0) {
    arm64_regs regs, orig_regs;
    if (!ptrace_get_regs(pid, &orig_regs)) return false;
    *saved_regs_out = orig_regs;

    regs = orig_regs;
    regs.x[0] = x0;
    regs.x[1] = x1;
    regs.x[2] = x2;
    regs.x[30] = 0; // LR = 0 → SIGSEGV on return
    regs.pc = func_addr;
    // 16-byte align sp
    regs.sp = (orig_regs.sp - 256) & ~0xFULL;

    if (!ptrace_set_regs(pid, &regs)) return false;

    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
        fprintf(stderr, "[ptrace] CONT failed: %s\n", strerror(errno));
        return false;
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "[ptrace] waitpid after CONT failed: %s\n", strerror(errno));
        return false;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[ptrace] target not stopped after call (status=%d)\n", status);
        return false;
    }

    int sig = WSTOPSIG(status);
    if (sig != SIGSEGV && sig != SIGBUS) {
        fprintf(stderr, "[ptrace] unexpected signal after call: %d\n", sig);
    }
    return true;
}

bool ptrace_inject(int pid, const char *so_path) {
    fprintf(stderr, "[ptrace-inject] target pid=%d path=%s\n", pid, so_path);

    if (!ptrace_attach_and_wait(pid)) return false;
    fprintf(stderr, "[ptrace-inject] attached, target stopped\n");

    // Find dlopen address
    uintptr_t libdl_base = find_library_base(pid, "libdl.so");
    if (!libdl_base) {
        fprintf(stderr, "[ptrace-inject] libdl.so not found in target\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }

    // Read /proc/<pid>/maps to find libdl's on-disk path
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        fprintf(stderr, "[ptrace-inject] cannot read /proc/%d/maps\n", pid);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }
    char line[512];
    char libdl_disk_path[256] = "";
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libdl.so") && strstr(line, "r--p")) {
            char *p = strrchr(line, '/');
            if (p) {
                // Copy from first '/' of path
                const char *path_start = strchr(line, '/');
                if (path_start) {
                    size_t len = strlen(path_start);
                    while (len > 0 && (path_start[len-1] == '\n' || path_start[len-1] == ' '))
                        len--;
                    if (len < sizeof(libdl_disk_path)) {
                        memcpy(libdl_disk_path, path_start, len);
                        libdl_disk_path[len] = 0;
                        break;
                    }
                }
            }
        }
    }
    fclose(f);

    if (libdl_disk_path[0] == 0) {
        fprintf(stderr, "[ptrace-inject] could not resolve libdl.so path\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }
    fprintf(stderr, "[ptrace-inject] libdl: %s @ 0x%lx\n", libdl_disk_path, libdl_base);

    // Use __loader_dlopen from linker64 to bypass namespace check.
    // Signature: void* __loader_dlopen(const char* filename, int flags, const void* caller_addr);
    // Find linker64 base in target process
    rewind(f);
    f = fopen(maps_path, "r");
    uintptr_t linker_base = 0;
    char linker_disk_path[256] = "";
    while (f && fgets(line, sizeof(line), f)) {
        if (strstr(line, "linker64") && strstr(line, "r--p")) {
            uintptr_t start;
            if (sscanf(line, "%lx-", &start) == 1 && linker_base == 0) {
                linker_base = start;
                const char* path_start = strchr(line, '/');
                if (path_start) {
                    size_t len = strlen(path_start);
                    while (len > 0 && (path_start[len-1] == '\n' || path_start[len-1] == ' '))
                        len--;
                    if (len < sizeof(linker_disk_path)) {
                        memcpy(linker_disk_path, path_start, len);
                        linker_disk_path[len] = 0;
                    }
                }
                break;
            }
        }
    }
    if (f) fclose(f);
    if (!linker_base || !linker_disk_path[0]) {
        fprintf(stderr, "[ptrace-inject] linker64 not found in target maps\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }
    uintptr_t loader_dlopen_offset = find_symbol(linker_disk_path, "__loader_dlopen");
    if (!loader_dlopen_offset) {
        fprintf(stderr, "[ptrace-inject] __loader_dlopen not found in linker64\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }
    uintptr_t dlopen_addr = linker_base + loader_dlopen_offset;
    fprintf(stderr, "[ptrace-inject] linker64: %s @ 0x%lx\n", linker_disk_path, linker_base);
    fprintf(stderr, "[ptrace-inject] __loader_dlopen @ 0x%lx\n", dlopen_addr);

    uintptr_t caller_addr = linker_base + 0x1000;

    // Save original regs
    arm64_regs orig_regs;
    if (!ptrace_get_regs(pid, &orig_regs)) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }

    // Write path to target's stack (below current sp)
    size_t path_len = strlen(so_path) + 1;
    uintptr_t path_addr = (orig_regs.sp - 512) & ~0xFULL;
    std::vector<uint8_t> path_bytes(so_path, so_path + path_len);
    if (!write_memory(pid, path_addr, path_bytes)) {
        fprintf(stderr, "[ptrace-inject] failed to write path to target stack\n");
        ptrace_set_regs(pid, &orig_regs);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }

    // Call __loader_dlopen(path, RTLD_NOW=2, caller_addr=libc)
    arm64_regs saved_regs;
    if (!ptrace_call_function(pid, &saved_regs, dlopen_addr, path_addr, 2, caller_addr)) {
        fprintf(stderr, "[ptrace-inject] dlopen call failed\n");
        ptrace_set_regs(pid, &orig_regs);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }

    // Read return value (dlopen handle) from x0
    arm64_regs ret_regs;
    if (!ptrace_get_regs(pid, &ret_regs)) {
        ptrace_set_regs(pid, &orig_regs);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }
    uint64_t handle = ret_regs.x[0];
    fprintf(stderr, "[ptrace-inject] dlopen returned 0x%lx\n", handle);

    // Restore original registers
    if (!ptrace_set_regs(pid, &orig_regs)) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }

    // Verify library is loaded
    uintptr_t agent_base = find_library_base(pid, "libagent.so");
    if (!agent_base) {
        fprintf(stderr, "[ptrace-inject] libagent.so NOT found in target maps\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }
    fprintf(stderr, "[ptrace-inject] libagent.so @ 0x%lx\n", agent_base);

    // Note: target is STILL STOPPED here. Caller must call ptrace_resume() later.
    fprintf(stderr, "[ptrace-inject] success, target still stopped\n");
    return true;
}

bool ptrace_resume(int pid) {
    if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
        fprintf(stderr, "[ptrace-inject] DETACH failed: %s\n", strerror(errno));
        return false;
    }
    fprintf(stderr, "[ptrace-inject] detached, target resumed\n");
    return true;
}
