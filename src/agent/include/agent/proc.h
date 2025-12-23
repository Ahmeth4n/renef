#ifndef AGENT_PROC_H
#define AGENT_PROC_H

#include <stdint.h>

void* find_library_base(const char* lib_name);

char* get_loaded_libraries(void);

void list_apps(int client_fd);

typedef struct {
    char name[64];
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t type;
} elf_section_t;

typedef struct {
    elf_section_t* sections;
    size_t count;
} elf_sections_t;

typedef struct {
    char name[256];
    uint64_t offset;
} elf_export_t;

typedef struct {
    elf_export_t* exports;
    size_t count;
} elf_exports_t;

elf_exports_t* get_exports(const char* lib_name);
elf_exports_t* get_symbols(const char* lib_name);  // Full .symtab (internal symbols)
void free_elf_exports(elf_exports_t* exp);


elf_sections_t* parse_elf_sections(const char* file_path);

void free_elf_sections(elf_sections_t* secs);

elf_section_t* find_section_by_name(elf_sections_t* secs, const char* name);

void dump_elf_sections(int client_fd, const char* file_path);

char* find_library_path(const char* lib_name);

#endif
