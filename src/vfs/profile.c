/* SPDX-License-Identifier: MPL-2.0 */
/* Opt-in VFS attribution. No allocation or logging on hot paths. */
#define EDGE_VFS_PROFILE_IMPLEMENTATION
#include "vfs/profile.h"
#include "kernel/arch_cpu.h"
#include "kernel/process_runtime.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"
#include "string.h"

typedef struct {
    uint64_t calls, work, hits, samples, sampled_us, maximum_us;
} vfs_profile_row_t;
static struct {
    uint64_t generation;
    int32_t pid;
    uint32_t sample_mask;
    vfs_profile_row_t rows[VFS_PROFILE_METRIC_COUNT];
    uint32_t random[VFS_PROFILE_METRIC_COUNT];
} profile;
uint64_t vfs_profile_selected_task;
static spinlock_t profile_lock;
static const char *const names[VFS_PROFILE_METRIC_COUNT] = {
    "user_string", "metadata", "search", "search_directory", "resolve",
    "mount", "path_cache", "ext4_lookup",
    "ext4_inode_cache", "ext4_readdir",
    "ext4_block", "ext4_lock_wait", "getdents", "directory_seed",
    "squashfs_lookup", "squashfs_getxattr", "path_cache_store"
};

vfs_profile_scope_t vfs_profile_begin(uint32_t metric) {
    vfs_profile_scope_t scope = {0};
    uint64_t task = __atomic_load_n(&vfs_profile_selected_task, __ATOMIC_RELAXED);
    uint64_t flags;
    if (!task || metric >= VFS_PROFILE_METRIC_COUNT ||
        (task != UINT64_MAX && task != arch_cpu_current_task())) return scope;
    flags = spin_lock_irqsave(&profile_lock);
    if (task == vfs_profile_selected_task &&
        (task == UINT64_MAX || profile.pid == kernel_current_pid())) {
        scope.generation = profile.generation;
        scope.metric = metric;
        uint32_t random = profile.random[metric];
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        profile.random[metric] = random;
        /* Randomize selection to avoid aliasing repeated pathname phases. */
        scope.sampled = profile.sample_mask != UINT32_MAX &&
            (random & profile.sample_mask) == 0;
        ++profile.rows[metric].calls;
    }
    spin_unlock_irqrestore(&profile_lock, flags);
    if (scope.sampled) scope.started_us = boottime_monotonic_us();
    return scope;
}

void vfs_profile_end(vfs_profile_scope_t *scope) {
    uint64_t elapsed, flags;
    if (!scope || !scope->generation || scope->metric >= VFS_PROFILE_METRIC_COUNT)
        return;
    elapsed = scope->sampled ? boottime_monotonic_us() - scope->started_us : 0;
    flags = spin_lock_irqsave(&profile_lock);
    if (scope->generation == profile.generation) {
        vfs_profile_row_t *row = &profile.rows[scope->metric];
        row->work += scope->work;
        row->hits += scope->hits;
        if (scope->sampled) {
            ++row->samples;
            row->sampled_us += elapsed;
            if (elapsed > row->maximum_us) row->maximum_us = elapsed;
        }
    }
    spin_unlock_irqrestore(&profile_lock, flags);
    scope->generation = 0;
}

int vfs_profile_control(const void *command, uint32_t length) {
    const char *text = command;
    uint64_t flags, task;
    int mode;
    if (!text || !length) return -1;
    if (text[length - 1u] == '\n') --length;
    mode = length == 5u && memcmp(text, "start", 5u) == 0 ? 1 :
           length == 6u && memcmp(text, "counts", 6u) == 0 ? 2 :
           length == 12u && memcmp(text, "global-start", 12u) == 0 ? 3 :
           length == 13u && memcmp(text, "global-counts", 13u) == 0 ? 4 :
           length == 4u && memcmp(text, "stop", 4u) == 0 ? 0 : -1;
    if (mode < 0) return -1;
    task = arch_cpu_current_task();
    if (mode && !task) return -1;
    flags = spin_lock_irqsave(&profile_lock);
    __atomic_store_n(&vfs_profile_selected_task, 0, __ATOMIC_RELAXED);
    ++profile.generation;
    if (!profile.generation) ++profile.generation;
    if (mode) {
        memset(profile.rows, 0, sizeof(profile.rows));
        for (uint32_t i = 0; i < VFS_PROFILE_METRIC_COUNT; ++i)
            profile.random[i] = (i + 1u) * 2654435761u;
        profile.pid = mode >= 3 ? 0 : kernel_current_pid();
        profile.sample_mask = (mode == 2 || mode == 4) ? UINT32_MAX : 15u;
        __atomic_store_n(&vfs_profile_selected_task,
                         mode >= 3 ? UINT64_MAX : task,
                         __ATOMIC_RELAXED);
    }
    spin_unlock_irqrestore(&profile_lock, flags);
    return 0;
}

static int emit_text(char *buffer, uint32_t capacity, uint32_t *used,
                     const char *text) {
    while (*text) {
        if (*used >= capacity) return -1;
        buffer[(*used)++] = *text++;
    }
    return 0;
}
static int emit_number(char *buffer, uint32_t capacity, uint32_t *used,
                       uint64_t value) {
    char digits[21];
    uint32_t count = 0;
    do { digits[count++] = '0' + value % 10u; value /= 10u; } while (value);
    while (count) {
        if (*used >= capacity) return -1;
        buffer[(*used)++] = digits[--count];
    }
    return 0;
}

int vfs_profile_render(char *buffer, uint32_t capacity) {
    vfs_profile_row_t rows[VFS_PROFILE_METRIC_COUNT];
    uint64_t flags, generation, active;
    uint32_t used = 0, pid, mask;
    if (!buffer) return -1;
    flags = spin_lock_irqsave(&profile_lock);
    memcpy(rows, profile.rows, sizeof(rows));
    generation = profile.generation;
    active = vfs_profile_selected_task != 0;
    pid = (uint32_t)profile.pid;
    mask = profile.sample_mask;
    spin_unlock_irqrestore(&profile_lock, flags);
#define TEXT(t) do { if (emit_text(buffer, capacity, &used, t) < 0) return -1; } while (0)
#define NUMBER(n) do { if (emit_number(buffer, capacity, &used, n) < 0) return -1; } while (0)
    TEXT("version 3\ngeneration "); NUMBER(generation);
    TEXT("\nselected_pid "); NUMBER(pid);
    TEXT("\nenabled "); NUMBER(active);
    TEXT("\nsample_stride "); NUMBER(mask == UINT32_MAX ? 0 : mask + 1u);
    TEXT("\nmetric calls work hits samples sampled_us maximum_us\n");
    for (uint32_t i = 0; i < VFS_PROFILE_METRIC_COUNT; ++i) {
        TEXT(names[i]); TEXT(" "); NUMBER(rows[i].calls);
        TEXT(" "); NUMBER(rows[i].work); TEXT(" "); NUMBER(rows[i].hits);
        TEXT(" "); NUMBER(rows[i].samples); TEXT(" "); NUMBER(rows[i].sampled_us);
        TEXT(" "); NUMBER(rows[i].maximum_us); TEXT("\n");
    }
#undef TEXT
#undef NUMBER
    return (int)used;
}
