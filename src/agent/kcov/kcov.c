#include <agent/kcov.h>
#include <agent/globals.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/*
 * KCOV implementation
 *
 * /sys/kernel/debug/kcov records the PC address of every kernel
 * function entry into a shared mmap'd buffer.
 *
 * Buffer layout (mmap'd):
 *   buffer[0] = entry count (kernel increments atomically on each hit)
 *   buffer[1] = first hit PC
 *   buffer[2] = second hit PC
 *   ...
 *   buffer[N] = Nth PC
 *
 * All values are uint64_t (8 bytes).
 * buffer[0] is incremented atomically, no locks needed.
 */

int kcov_open(KCovState* state, size_t buf_size) {
    memset(state, 0, sizeof(KCovState));
    state->fd = -1;

    if (buf_size == 0) {
        buf_size = KCOV_DEFAULT_SIZE;
    }

    /* open /sys/kernel/debug/kcov */
    state->fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (state->fd < 0) {
        LOGE("kcov: open failed: %s (kernel CONFIG_KCOV=y required)", strerror(errno));
        return -1;
    }

    /* tell kernel the buffer size */
    if (ioctl(state->fd, KCOV_INIT_TRACE, buf_size) < 0) {
        LOGE("kcov: KCOV_INIT_TRACE(%zu) failed: %s", buf_size, strerror(errno));
        close(state->fd);
        state->fd = -1;
        return -1;
    }

    /* mmap shared buffer with kernel
     * size = entry count * 8 bytes (uint64_t)
     * kernel writes directly, we read directly
     * zero-copy - no overhead */
    size_t mmap_size = buf_size * sizeof(uint64_t);
    state->buffer = (uint64_t*)mmap(NULL, mmap_size,
                                     PROT_READ | PROT_WRITE,
                                     MAP_SHARED, state->fd, 0);
    if (state->buffer == MAP_FAILED) {
        LOGE("kcov: mmap(%zu bytes) failed: %s", mmap_size, strerror(errno));
        close(state->fd);
        state->fd = -1;
        state->buffer = NULL;
        return -1;
    }

    state->buffer_size = buf_size;
    state->enabled = false;
    state->initialized = true;

    LOGI("kcov: opened, buffer=%p, entries=%zu (%zu KB)",
         state->buffer, buf_size, mmap_size / 1024);
    return 0;
}

int kcov_enable(KCovState* state) {
    if (!state->initialized) {
        LOGE("kcov: not initialized");
        return -1;
    }
    if (state->enabled) {
        return 0; /* already active */
    }

    /* reset buffer - start fresh for new measurement */
    __atomic_store_n(&state->buffer[0], 0, __ATOMIC_RELAXED);

    /* start coverage in PC trace mode for this thread
     * KCOV_TRACE_PC = record PC at each function entry
     * only the thread that calls this ioctl is traced */
    if (ioctl(state->fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0) {
        LOGE("kcov: KCOV_ENABLE failed: %s", strerror(errno));
        return -1;
    }

    state->enabled = true;
    return 0;
}

int kcov_disable(KCovState* state) {
    if (!state->initialized || !state->enabled) {
        return 0;
    }

    if (ioctl(state->fd, KCOV_DISABLE, 0) < 0) {
        LOGE("kcov: KCOV_DISABLE failed: %s", strerror(errno));
        return -1;
    }

    state->enabled = false;
    return 0;
}

size_t kcov_collect(KCovState* state, uint64_t* out_pcs, size_t max_count) {
    if (!state->initialized || !state->buffer) {
        return 0;
    }

    /* buffer[0] = total entry count written by kernel */
    size_t count = __atomic_load_n(&state->buffer[0], __ATOMIC_RELAXED);

    /* prevent buffer overflow */
    if (count > state->buffer_size - 1) {
        count = state->buffer_size - 1;
    }
    if (count > max_count) {
        count = max_count;
    }

    /* copy PC addresses: buffer[1..count] */
    for (size_t i = 0; i < count; i++) {
        out_pcs[i] = state->buffer[i + 1];
    }

    return count;
}

size_t kcov_count(KCovState* state) {
    if (!state->initialized || !state->buffer) {
        return 0;
    }
    size_t count = __atomic_load_n(&state->buffer[0], __ATOMIC_RELAXED);
    if (count > state->buffer_size - 1) {
        count = state->buffer_size - 1;
    }
    return count;
}

void kcov_reset(KCovState* state) {
    if (!state->initialized || !state->buffer) {
        return;
    }
    __atomic_store_n(&state->buffer[0], 0, __ATOMIC_RELAXED);
}

void kcov_close(KCovState* state) {
    if (!state->initialized) {
        return;
    }

    if (state->enabled) {
        kcov_disable(state);
    }

    if (state->buffer && state->buffer != MAP_FAILED) {
        munmap(state->buffer, state->buffer_size * sizeof(uint64_t));
    }

    if (state->fd >= 0) {
        close(state->fd);
    }

    memset(state, 0, sizeof(KCovState));
    state->fd = -1;
    LOGI("kcov: closed");
}
