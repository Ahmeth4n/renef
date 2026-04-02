#ifndef AGENT_STRACE_H
#define AGENT_STRACE_H

#include <stdint.h>
#include <stdbool.h>
#include <agent/hook.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_STRACE_HOOKS 64
#define STRACE_MAX_ARGS 6

enum SyscallArgType {
    ARG_INT,
    ARG_UINT,
    ARG_FD,
    ARG_PTR,
    ARG_STR,
    ARG_BUF,
    ARG_FLAGS_OPEN,
    ARG_MODE,
    ARG_SIZE
};

typedef struct {
    const char* name;
    const char* symbol;
    const char* alt_symbol;
    int nr_args;
    enum SyscallArgType arg_types[STRACE_MAX_ARGS];
    const char* category;
} SyscallDef;

typedef struct {
    SyscallDef* def;
    HookInfo hook;
    int lua_onCall_ref;
    int lua_onReturn_ref;
    bool active;
    void* resolved_addr;
    void* thunk_addr;
} StraceEntry;

extern StraceEntry g_strace_hooks[MAX_STRACE_HOOKS];
extern int g_strace_count;

int strace_install(const char* syscall_name, const char* caller_lib,
                   int onCall_ref, int onReturn_ref);
int strace_remove(const char* syscall_name);
void strace_remove_all(void);

void strace_hook_handler(void);
int strace_on_enter(uint64_t* saved_regs);
uint64_t strace_on_return(uint64_t ret_val);
void* strace_get_original(void);
uint64_t strace_get_skip_retval(void);

SyscallDef* strace_find_def(const char* name);
int strace_get_defs_by_category(const char* category, SyscallDef** out, int max);
int strace_get_all_defs(SyscallDef** out, int max);

void strace_set_current_index(int index);

#ifdef __cplusplus
}
#endif

#endif
