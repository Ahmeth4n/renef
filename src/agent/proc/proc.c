#include <agent/proc.h>
#include <agent/globals.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <dlfcn.h>
#include <link.h>

struct dl_find_data {
    const char* lib_name;
    void* base_addr;
};

static int dl_find_callback(struct dl_phdr_info *info, size_t size, void *data) {
    struct dl_find_data *find_data = (struct dl_find_data *)data;

    if (info->dlpi_name && strstr(info->dlpi_name, find_data->lib_name)) {
        find_data->base_addr = (void*)info->dlpi_addr;
        LOGI("Found %s at base: %p via dl_iterate_phdr (path: %s)",
             find_data->lib_name, find_data->base_addr, info->dlpi_name);
        return 1;
    }

    return 0;
}

void* find_library_base(const char* lib_name) {
    LOGI("Searching for library: %s", lib_name);

    struct dl_find_data find_data = {
        .lib_name = lib_name,
        .base_addr = NULL
    };

    dl_iterate_phdr(dl_find_callback, &find_data);

    if (find_data.base_addr) {
        return find_data.base_addr;
    }

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps");
        return NULL;
    }

    char line[512];
    void* base_addr = NULL;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name)) {
            if (strstr(line, "r-xp") || (strstr(line, "r--p") && strstr(line, " 00000000 "))) {
                unsigned long addr;
                if (sscanf(line, "%lx", &addr) == 1) {
                    base_addr = (void*)addr;
                    LOGI("Found %s at base: %p (via /proc/self/maps)", lib_name, base_addr);
                    break;
                }
            }
        }
    }

    fclose(fp);

    if (!base_addr) {
        LOGW("Library %s not found", lib_name);
    }

    return base_addr;
}

char* get_loaded_libraries(void) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        return NULL;
    }

    size_t buf_size = 4096;
    size_t buf_used = 0;
    char* result = (char*)malloc(buf_size);
    if (!result) {
        fclose(fp);
        return NULL;
    }
    result[0] = '\0';

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // Match .so files at offset 0 (first segment) - can be r-xp or r--p
        if (strstr(line, ".so") && strstr(line, " 00000000 ") &&
            (strstr(line, "r-xp") || strstr(line, "r--p"))) {
            size_t line_len = strlen(line);

            if (buf_used + line_len + 1 > buf_size) {
                buf_size *= 2;
                char* new_buf = (char*)realloc(result, buf_size);
                if (!new_buf) {
                    free(result);
                    fclose(fp);
                    return NULL;
                }
                result = new_buf;
            }

            strcat(result, line);
            buf_used += line_len;
        }
    }

    fclose(fp);
    return result;
}

void list_apps(int client_fd) {
    LOGI("Listing installed apps...");

    FILE *fp = popen("pm list packages", "r");
    if (!fp) {
        const char* error = "ERROR: pm command failed\n";
        write(client_fd, error, strlen(error));
        return;
    }

    char line[256];
    int count = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "package:", 8) == 0) {
            if (write(client_fd, line + 8, strlen(line + 8)) < 0) {
                LOGW("Write failed, client disconnected");
                pclose(fp);
                return;
            }
            count++;
        }
    }

    char summary[128];
    snprintf(summary, sizeof(summary), "\nTotal: %d packages\n", count);
    write(client_fd, summary, strlen(summary));

    pclose(fp);
    LOGI("Listed %d packages", count);
}


elf_sections_t* parse_elf_sections(const char* file_path) {
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        LOGE("Failed to open: %s", file_path);
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        LOGE("fstat failed");
        close(fd);
        return NULL;
    }

    void* map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) {
        LOGE("mmap failed");
        return NULL;
    }

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("Not a valid ELF file");
        munmap(map, st.st_size);
        return NULL;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        LOGE("Not a 64-bit ELF");
        munmap(map, st.st_size);
        return NULL;
    }

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        LOGE("No section headers (stripped?)");
        munmap(map, st.st_size);
        return NULL;
    }

    Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);

    if (ehdr->e_shstrndx >= ehdr->e_shnum) {
        LOGE("Invalid string table index");
        munmap(map, st.st_size);
        return NULL;
    }

    const char* strtab = (const char*)((uint8_t*)map + shdr[ehdr->e_shstrndx].sh_offset);

    elf_sections_t* result = (elf_sections_t*)malloc(sizeof(elf_sections_t));
    if (!result) {
        munmap(map, st.st_size);
        return NULL;
    }

    result->sections = (elf_section_t*)malloc(sizeof(elf_section_t) * ehdr->e_shnum);
    if (!result->sections) {
        free(result);
        munmap(map, st.st_size);
        return NULL;
    }

    result->count = 0;

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        const char* name = strtab + shdr[i].sh_name;

        if (shdr[i].sh_type == SHT_NULL || name[0] == '\0') {
            continue;
        }

        elf_section_t* sec = &result->sections[result->count];
        strncpy(sec->name, name, sizeof(sec->name) - 1);
        sec->name[sizeof(sec->name) - 1] = '\0';
        sec->addr = shdr[i].sh_addr;
        sec->offset = shdr[i].sh_offset;
        sec->size = shdr[i].sh_size;
        sec->type = shdr[i].sh_type;

        result->count++;
    }

    munmap(map, st.st_size);
    LOGI("Parsed %zu sections from %s", result->count, file_path);
    return result;
}

void free_elf_sections(elf_sections_t* secs) {
    if (secs) {
        free(secs->sections);
        free(secs);
    }
}

elf_section_t* find_section_by_name(elf_sections_t* secs, const char* name) {
    if (!secs || !name) return NULL;

    for (size_t i = 0; i < secs->count; i++) {
        if (strcmp(secs->sections[i].name, name) == 0) {
            return &secs->sections[i];
        }
    }
    return NULL;
}

void dump_elf_sections(int client_fd, const char* file_path) {
    elf_sections_t* secs = parse_elf_sections(file_path);
    if (!secs) {
        const char* err = "ERROR: Failed to parse ELF\n";
        write(client_fd, err, strlen(err));
        return;
    }

    char header[256];
    snprintf(header, sizeof(header),
        "Sections in %s (%zu total):\n"
        "%-20s %-16s %-16s %-10s\n"
        "------------------------------------------------------------\n\n",
        file_path, secs->count,
        "Name", "Addr", "Size", "Type");
    write(client_fd, header, strlen(header));

    for (size_t i = 0; i < secs->count; i++) {
        elf_section_t* s = &secs->sections[i];

        const char* type_str;
        switch (s->type) {
            case SHT_PROGBITS: type_str = "PROGBITS"; break;
            case SHT_SYMTAB:   type_str = "SYMTAB"; break;
            case SHT_STRTAB:   type_str = "STRTAB"; break;
            case SHT_RELA:     type_str = "RELA"; break;
            case SHT_HASH:     type_str = "HASH"; break;
            case SHT_DYNAMIC:  type_str = "DYNAMIC"; break;
            case SHT_NOTE:     type_str = "NOTE"; break;
            case SHT_NOBITS:   type_str = "NOBITS"; break;
            case SHT_REL:      type_str = "REL"; break;
            case SHT_DYNSYM:   type_str = "DYNSYM"; break;
            default:           type_str = "OTHER"; break;
        }

        char line[256];
        snprintf(line, sizeof(line), "%-20s 0x%014lx 0x%014lx %-10s\n",
            s->name,
            (unsigned long)s->addr,
            (unsigned long)s->size,
            type_str);
        write(client_fd, line, strlen(line));
    }

    free_elf_sections(secs);
}

struct dl_path_data {
    const char* lib_name;
    char* path;
};

static int dl_path_callback(struct dl_phdr_info *info, size_t size, void *data) {
    struct dl_path_data *path_data = (struct dl_path_data *)data;

    if (info->dlpi_name && strlen(info->dlpi_name) > 0 && strstr(info->dlpi_name, path_data->lib_name)) {
        path_data->path = strdup(info->dlpi_name);
        LOGI("Found library path: %s via dl_iterate_phdr", path_data->path);
        return 1;
    }

    return 0;
}

char* find_library_path(const char* lib_name) {
    LOGI("Searching for library path: %s", lib_name);

    struct dl_path_data path_data = {
        .lib_name = lib_name,
        .path = NULL
    };

    dl_iterate_phdr(dl_path_callback, &path_data);

    if (path_data.path) {
        return path_data.path;
    }

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps");
        return NULL;
    }

    char line[512];
    char* result = NULL;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name)) {
            char* path_start = strrchr(line, '/');
            if (path_start) {
                char* newline = strchr(path_start, '\n');
                if (newline) *newline = '\0';

                char* full_path = strchr(line, '/');
                if (full_path) {
                    result = strdup(full_path);
                    LOGI("Found library path: %s (via /proc/self/maps)", result);
                    break;
                }
            }
        }
    }

    fclose(fp);

    if (!result) {
        LOGW("Library path not found for: %s", lib_name);
    }

    return result;
}


elf_exports_t* get_exports(const char* lib_name) {
    char* file_path = find_library_path(lib_name);
    void* base_addr = find_library_base(lib_name);

    if (!base_addr) {
        LOGE("Library not loaded: %s", lib_name);
        if (file_path) free(file_path);
        return NULL;
    }

    int is_apk_embedded = (file_path && strstr(file_path, "!") != NULL);

    void* map = NULL;
    size_t map_size = 0;
    int needs_unmap = 0;

    if (is_apk_embedded) {
        LOGI("Reading exports from memory for APK-embedded library: %s", lib_name);
        map = base_addr;
        needs_unmap = 0;
    } else {
        int fd = open(file_path, O_RDONLY);
        if (fd < 0) {
            LOGE("Failed to open: %s", file_path);
            free(file_path);
            return NULL;
        }

        struct stat st;
        if (fstat(fd, &st) < 0) {
            LOGE("fstat failed");
            close(fd);
            free(file_path);
            return NULL;
        }

        map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        map_size = st.st_size;
        close(fd);

        if (map == MAP_FAILED) {
            LOGE("mmap failed");
            free(file_path);
            return NULL;
        }
        needs_unmap = 1;
    }

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("Not a valid ELF file");
        if (needs_unmap) munmap(map, map_size);
        if (file_path) free(file_path);
        return NULL;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        LOGE("Not a 64-bit ELF");
        if (needs_unmap) munmap(map, map_size);
        if (file_path) free(file_path);
        return NULL;
    }

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        LOGE("No section headers");
        if (needs_unmap) munmap(map, map_size);
        if (file_path) free(file_path);
        return NULL;
    }

    Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);

    Elf64_Shdr* dynsym_shdr = NULL;
    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_DYNSYM) {
            dynsym_shdr = &shdr[i];
            break;
        }
    }

    if (!dynsym_shdr) {
        LOGE("No .dynsym section found");
        if (needs_unmap) munmap(map, map_size);
        if (file_path) free(file_path);
        return NULL;
    }

    Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)map + dynsym_shdr->sh_offset);
    size_t sym_count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

    const char* strtab = (const char*)((uint8_t*)map + shdr[dynsym_shdr->sh_link].sh_offset);

    elf_exports_t* result = (elf_exports_t*)malloc(sizeof(elf_exports_t));
    if (!result) {
        if (needs_unmap) munmap(map, map_size);
        if (file_path) free(file_path);
        return NULL;
    }

    result->exports = (elf_export_t*)malloc(sizeof(elf_export_t) * sym_count);
    if (!result->exports) {
        free(result);
        if (needs_unmap) munmap(map, map_size);
        if (file_path) free(file_path);
        return NULL;
    }

    result->count = 0;

    for (size_t i = 0; i < sym_count; i++) {
        unsigned char type = ELF64_ST_TYPE(symtab[i].st_info);
        unsigned char bind = ELF64_ST_BIND(symtab[i].st_info);

        if (type == STT_FUNC && symtab[i].st_value != 0 &&
            (bind == STB_GLOBAL || bind == STB_WEAK)) {

            elf_export_t* exp = &result->exports[result->count];
            const char* name = strtab + symtab[i].st_name;

            strncpy(exp->name, name, sizeof(exp->name) - 1);
            exp->name[sizeof(exp->name) - 1] = '\0';
            exp->offset = symtab[i].st_value;

            result->count++;
        }
    }

    LOGI("Found %zu exports in %s", result->count, lib_name);

    if (needs_unmap) munmap(map, map_size);
    if (file_path) free(file_path);
    return result;
}

void free_elf_exports(elf_exports_t* exp) {
    if (exp) {
        free(exp->exports);
        free(exp);
    }
}

elf_exports_t* get_symbols(const char* lib_name) {
    char* file_path = find_library_path(lib_name);

    if (!file_path) {
        LOGE("Library path not found: %s", lib_name);
        return NULL;
    }

    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        LOGE("Failed to open: %s", file_path);
        free(file_path);
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        LOGE("fstat failed");
        close(fd);
        free(file_path);
        return NULL;
    }

    void* map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) {
        LOGE("mmap failed");
        free(file_path);
        return NULL;
    }

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("Not a valid ELF file");
        munmap(map, st.st_size);
        free(file_path);
        return NULL;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        LOGE("Not a 64-bit ELF");
        munmap(map, st.st_size);
        free(file_path);
        return NULL;
    }

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        LOGE("No section headers");
        munmap(map, st.st_size);
        free(file_path);
        return NULL;
    }

    Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);

    Elf64_Shdr* symtab_shdr = NULL;
    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            symtab_shdr = &shdr[i];
            break;
        }
    }

    if (!symtab_shdr) {
        LOGE("No .symtab section found (binary may be stripped)");
        munmap(map, st.st_size);
        free(file_path);
        return NULL;
    }

    Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)map + symtab_shdr->sh_offset);
    size_t sym_count = symtab_shdr->sh_size / sizeof(Elf64_Sym);

    const char* strtab = (const char*)((uint8_t*)map + shdr[symtab_shdr->sh_link].sh_offset);

    elf_exports_t* result = (elf_exports_t*)malloc(sizeof(elf_exports_t));
    if (!result) {
        munmap(map, st.st_size);
        free(file_path);
        return NULL;
    }

    result->exports = (elf_export_t*)malloc(sizeof(elf_export_t) * sym_count);
    if (!result->exports) {
        free(result);
        munmap(map, st.st_size);
        free(file_path);
        return NULL;
    }

    result->count = 0;

    for (size_t i = 0; i < sym_count; i++) {
        unsigned char type = ELF64_ST_TYPE(symtab[i].st_info);

        if (type == STT_FUNC && symtab[i].st_value != 0) {
            elf_export_t* exp = &result->exports[result->count];
            const char* name = strtab + symtab[i].st_name;

            if (name[0] == '\0') continue;

            strncpy(exp->name, name, sizeof(exp->name) - 1);
            exp->name[sizeof(exp->name) - 1] = '\0';
            exp->offset = symtab[i].st_value;

            result->count++;
        }
    }

    LOGI("Found %zu symbols in %s (.symtab)", result->count, lib_name);

    munmap(map, st.st_size);
    free(file_path);
    return result;
}
