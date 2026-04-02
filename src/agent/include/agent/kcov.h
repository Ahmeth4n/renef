#ifndef AGENT_KCOV_H
#define AGENT_KCOV_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * KCOV - Kernel Coverage interface
 *
 * Linux kernel's internal code coverage mechanism.
 * On each kernel function entry, the function's PC (program counter)
 * address is written to a shared mmap'd buffer with userspace.
 *
 * Requirement: kernel must be compiled with CONFIG_KCOV=y.
 *
 * Flow:
 *   1. kcov_open()    -> open /sys/kernel/debug/kcov, mmap buffer
 *   2. kcov_enable()  -> start coverage recording for this thread
 *   3. ... make syscalls ...
 *   4. kcov_disable() -> stop recording
 *   5. kcov_collect() -> read PC addresses from buffer
 *   6. kcov_close()   -> cleanup
 */

/* ioctl commands - same as <linux/kcov.h> */
#define KCOV_INIT_TRACE   _IOR('c', 1, unsigned long)
#define KCOV_ENABLE       _IO('c', 100)
#define KCOV_DISABLE      _IO('c', 101)

/* coverage mode */
#define KCOV_TRACE_PC     0
#define KCOV_TRACE_CMP    1

/* default buffer size (entry count, each 8 bytes) */
#define KCOV_DEFAULT_SIZE (256 * 1024)

typedef struct {
    int fd;                    /* /sys/kernel/debug/kcov fd */
    uint64_t* buffer;         /* mmap'd shared buffer */
    size_t buffer_size;        /* number of entries in buffer */
    bool enabled;              /* is coverage active */
    bool initialized;          /* successfully opened */
} KCovState;

/*
 * kcov_open - Open KCOV device and prepare buffer
 *
 * @buf_size: number of entries to hold (0 = default 256K)
 *            each entry = 1 kernel PC address = 8 bytes
 *            256K entries = 2MB RAM
 *
 * Return: 0 on success, -1 on error (kernel not supported etc.)
 */
int kcov_open(KCovState* state, size_t buf_size);

/*
 * kcov_enable - Start coverage recording for this thread
 *
 * IMPORTANT: KCOV is thread-local. Only the thread that calls enable()
 * will have its syscalls recorded.
 *
 * Return: 0 on success, -1 on error
 */
int kcov_enable(KCovState* state);

/*
 * kcov_disable - Stop coverage recording
 *
 * Return: 0 on success, -1 on error
 */
int kcov_disable(KCovState* state);

/*
 * kcov_collect - Read coverage data from buffer
 *
 * @out_pcs:   array to write PC addresses into (caller allocates)
 * @max_count: capacity of out_pcs
 *
 * Return: number of PCs read (0 = no data)
 */
size_t kcov_collect(KCovState* state, uint64_t* out_pcs, size_t max_count);

/*
 * kcov_count - Get entry count (without copying buffer)
 *
 * Return: buffer[0] value = total hit count
 */
size_t kcov_count(KCovState* state);

/*
 * kcov_reset - Reset buffer (for new measurement)
 *
 * Sets buffer[0] = 0. Kernel will start writing from 0
 * on next enable.
 */
void kcov_reset(KCovState* state);

/*
 * kcov_close - Close, munmap, cleanup
 */
void kcov_close(KCovState* state);

#ifdef __cplusplus
}
#endif

#endif
