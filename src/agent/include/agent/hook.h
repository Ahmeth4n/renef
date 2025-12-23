#ifndef AGENT_HOOK_H
#define AGENT_HOOK_H

#include <stdint.h>
#include <stdbool.h>
#include <agent/lua_hook.h>

enum hook_type {
    HOOK_TRAMPOLINE,
    HOOK_PLT_GOT,
    HOOK_JAVA_METHOD
};

typedef struct {
    void* target_addr;
    void* trampoline_addr;
    void* hook_addr;
    size_t original_size;
    uint32_t original_insn[4];
    enum hook_type type;
} TrampolineHook;

typedef struct {
    void** got_entry;
    void* original_func;
    void* hook_func;
} PltGotHook;

typedef struct {
    enum hook_type type;
    union {
        TrampolineHook trampoline;
        PltGotHook plt_got;
    } data;

    struct HookTarget target;

    int lua_onEnter_ref;
    int lua_onLeave_ref;

    void* thunk_addr;
    int hook_index;
} HookInfo;

extern HookInfo g_hooks[32];
extern int g_hook_count;
extern __thread int g_current_hook_index;

int change_page_protection(void* addr, int prot);
uint32_t create_branch_insn(void* from, void* to);
void* allocate_trampoline(size_t size);
size_t disassemble_instructions(void* addr, void** insn_out, size_t min_bytes);
bool is_pc_relative(void* insn);
void** find_got_entry(void* func_addr);
int install_trampoline_hook(void* target_func, void* hook_func, HookInfo* hook_info);
int install_plt_got_hook(void* target_func, void* hook_func, HookInfo* hook_info);
bool install_lua_hook(const char* lib_name, uintptr_t offset, int onEnter_ref, int onLeave_ref);

void generic_hook_handler(void);
void hook_logger(uint64_t* saved_regs);
uint64_t log_return_value(uint64_t ret_val);
void* get_current_trampoline(void);

void* create_hook_thunk(int hook_index);
void set_current_hook_index(int index);

int uninstall_hook(int hook_id);
int uninstall_all_hooks(void);

#include "hook_java.h"

bool install_lua_java_hook(const char* class_name, const char* method_name,
                           const char* signature, int onEnter_ref, int onLeave_ref);

#endif
