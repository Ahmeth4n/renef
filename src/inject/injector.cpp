#include "shellcode.h"
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#ifdef __linux__
#include <elf.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#else
// ELF definitions for non-Linux platforms (macOS, etc.)
// These are needed for parsing Android ELF binaries from the host

#include <cstdint>

#define EI_NIDENT 16
#define ELFMAG "\177ELF"
#define SELFMAG 4

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;

typedef struct {
  unsigned char e_ident[EI_NIDENT];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
  Elf64_Word sh_name;
  Elf64_Word sh_type;
  Elf64_Xword sh_flags;
  Elf64_Addr sh_addr;
  Elf64_Off sh_offset;
  Elf64_Xword sh_size;
  Elf64_Word sh_link;
  Elf64_Word sh_info;
  Elf64_Xword sh_addralign;
  Elf64_Xword sh_entsize;
} Elf64_Shdr;

typedef struct {
  Elf64_Word st_name;
  unsigned char st_info;
  unsigned char st_other;
  Elf64_Section st_shndx;
  Elf64_Addr st_value;
  Elf64_Xword st_size;
} Elf64_Sym;

#endif // __linux__

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
static const char *LIBC_PATHS[] = {
    "/apex/com.android.runtime/lib64/bionic/libc.so", // Android 10+
    "/system/lib64/libc.so",                          // Android 8-9
    nullptr};
static const char *LIBDL_PATHS[] = {
    "/apex/com.android.runtime/lib64/bionic/libdl.so", "/system/lib64/libdl.so",
    nullptr};
#elif defined(__arm__)
static const char *LIBC_PATHS[] = {
    "/apex/com.android.runtime/lib/bionic/libc.so", "/system/lib/libc.so",
    nullptr};
static const char *LIBDL_PATHS[] = {
    "/apex/com.android.runtime/lib/bionic/libdl.so", "/system/lib/libdl.so",
    nullptr};
#elif defined(__x86_64__) || defined(__amd64__)
static const char *LIBC_PATHS[] = {
    "/apex/com.android.runtime/lib64/bionic/libc.so", "/system/lib64/libc.so",
    nullptr};
static const char *LIBDL_PATHS[] = {
    "/apex/com.android.runtime/lib64/bionic/libdl.so", "/system/lib64/libdl.so",
    nullptr};
#elif defined(__i386__) || defined(__i686__)
static const char *LIBC_PATHS[] = {
    "/apex/com.android.runtime/lib/bionic/libc.so", "/system/lib/libc.so",
    nullptr};
static const char *LIBDL_PATHS[] = {
    "/apex/com.android.runtime/lib/bionic/libdl.so", "/system/lib/libdl.so",
    nullptr};
#else
#error "Unsupported architecture. Please compile for ARM or x86."
#endif

// Find the actual path of a library by checking multiple locations
static const char *resolve_lib_path(const char **paths) {
  for (int i = 0; paths[i] != nullptr; i++) {
    if (access(paths[i], R_OK) == 0) {
      return paths[i];
    }
  }
  return nullptr;
}

#define HIDDEN_PAYLOAD_PATH "/data/local/tmp/libagent.so"
#define TEMP_PAYLOAD_PATH "/data/local/tmp/libagent.so"

static bool copy_file(const char *src, const char *dst) {
  int src_fd = open(src, O_RDONLY);
  if (src_fd < 0)
    return false;

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

bool write_memory(int pid, uintptr_t addr, const std::vector<uint8_t> &data) {
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
    std::cerr << "Write failed: " << written << "/" << data.size()
              << " bytes\n";
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

uintptr_t find_symbol(const char *lib_path, const char *symbol_name) {
  int fd = open(lib_path, O_RDONLY);
  if (fd < 0) {
    std::cerr << "  ✗ Cannot open " << lib_path << "\n";
    return 0;
  }

  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    return 0;
  }

  void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);

  if (map == MAP_FAILED) {
    return 0;
  }

  uintptr_t result = 0;
  auto *ehdr = static_cast<Elf64_Ehdr *>(map);

  // Verify ELF magic
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    munmap(map, st.st_size);
    return 0;
  }

  auto *shdr = reinterpret_cast<Elf64_Shdr *>(static_cast<uint8_t *>(map) +
                                              ehdr->e_shoff);

  Elf64_Shdr *dynsym = nullptr;
  Elf64_Shdr *dynstr = nullptr;
  Elf64_Shdr *symtab = nullptr;
  Elf64_Shdr *strtab = nullptr;

  Elf64_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];
  const char *shstrtab_data =
      static_cast<const char *>(map) + shstrtab->sh_offset;

  for (int i = 0; i < ehdr->e_shnum; i++) {
    const char *name = shstrtab_data + shdr[i].sh_name;
    if (strcmp(name, ".dynsym") == 0)
      dynsym = &shdr[i];
    else if (strcmp(name, ".dynstr") == 0)
      dynstr = &shdr[i];
    else if (strcmp(name, ".symtab") == 0)
      symtab = &shdr[i];
    else if (strcmp(name, ".strtab") == 0)
      strtab = &shdr[i];
  }

  if (dynsym && dynstr) {
    auto *sym = reinterpret_cast<Elf64_Sym *>(static_cast<uint8_t *>(map) +
                                              dynsym->sh_offset);
    const char *str = static_cast<const char *>(map) + dynstr->sh_offset;
    size_t sym_count = dynsym->sh_size / sizeof(Elf64_Sym);

    for (size_t i = 0; i < sym_count; i++) {
      if (sym[i].st_name && sym[i].st_value != 0) {
        if (strcmp(str + sym[i].st_name, symbol_name) == 0) {
          result = sym[i].st_value;
          goto done;
        }
      }
    }
  }

  if (!result && symtab && strtab) {
    auto *sym = reinterpret_cast<Elf64_Sym *>(static_cast<uint8_t *>(map) +
                                              symtab->sh_offset);
    const char *str = static_cast<const char *>(map) + strtab->sh_offset;
    size_t sym_count = symtab->sh_size / sizeof(Elf64_Sym);

    for (size_t i = 0; i < sym_count; i++) {
      if (sym[i].st_name && sym[i].st_value != 0) {
        if (strcmp(str + sym[i].st_name, symbol_name) == 0) {
          result = sym[i].st_value;
          goto done;
        }
      }
    }
  }

done:
  munmap(map, st.st_size);
  return result;
}

uintptr_t find_library_base(int pid, const char *lib_name) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);

  FILE *fp = fopen(path, "r");
  if (!fp)
    return 0;

  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, lib_name)) {
      char *end;
      uintptr_t addr = strtoul(line, &end, 16);
      fclose(fp);
      return addr;
    }
  }

  fclose(fp);
  return 0;
}

uintptr_t find_libc_base(int pid) { return find_library_base(pid, "libc.so"); }

int create_memfd_from_file(const char *so_path) {
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
    std::cerr << "  ✗ Size mismatch: " << total_written << " != " << file_size
              << "\n";
    close(memfd);
    return -1;
  }

  std::cout << "  ✓ memfd created (fd=" << memfd << ", size=" << file_size
            << "B)\n";
  return memfd;
}

bool inject(int pid, const char *so_path) {
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

  const char *libc_path = resolve_lib_path(LIBC_PATHS);
  const char *libdl_path = resolve_lib_path(LIBDL_PATHS);

  if (!libc_path) {
    std::cerr << "  ✗ Cannot find libc.so on this device\n";
    return false;
  }
  if (!libdl_path) {
    std::cerr << "  ✗ Cannot find libdl.so on this device\n";
    return false;
  }

  std::cout << "  → Using libc: " << libc_path << "\n";
  std::cout << "  → Using libdl: " << libdl_path << "\n";

  uintptr_t malloc_offset = find_symbol(libc_path, "malloc");
  uintptr_t timezone_offset = find_symbol(libc_path, "timezone");
  uintptr_t dlopen_offset = find_symbol(libdl_path, "dlopen");

  if (!malloc_offset || !timezone_offset || !dlopen_offset) {
    std::cerr << "  ✗ Failed to find symbols (malloc=" << std::hex
              << malloc_offset << ", timezone=" << timezone_offset
              << ", dlopen=" << dlopen_offset << ")\n"
              << std::dec;
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

  auto stage2 = shellcode::arm64_stage2_dlopen_linjector(
      dlopen_addr, final_path, malloc_addr);
  auto stage1 =
      shellcode::arm64_stage1_linjector_exact(timezone_addr, stage2.size());
  std::cout << "  ✓ Stage1: " << stage1.size() << "B, Stage2: " << stage2.size()
            << "B\n";

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
  snprintf(kill_cmd, sizeof(kill_cmd), "kill -10 %d 2>/dev/null",
           pid); // SIGUSR1 → GC
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
        if (using_temp_file)
          unlink(TEMP_PAYLOAD_PATH);
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
      if (using_temp_file)
        unlink(TEMP_PAYLOAD_PATH);
      return false;
    }
  }
  std::cout << "  ✓ Triggered! New map: 0x" << std::hex << new_map << std::dec
            << "\n";

  std::cout << "[7/7] Finalizing injection...\n";

  if (!write_memory(pid, new_map, stage2)) {
    std::cerr << "Failed to write stage2\n";
    if (using_temp_file)
      unlink(TEMP_PAYLOAD_PATH);
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
int main(int argc, char **argv) {
  int pid;
  const char *so_path;

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
