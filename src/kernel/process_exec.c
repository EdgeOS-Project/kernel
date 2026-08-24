/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux exec transaction.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/exec_runtime.h"
#include "kernel/fanotify.h"
#include "kernel/landlock_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/posix_timer_runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/runtime_limits.h"
#include "sys/spinlock.h"

#define EXECUTABLE_TYPE_MASK 0170000u
#define EXECUTABLE_REGULAR_FILE 0100000u
#define EXECUTABLE_DIRECTORY 0040000u
#define EXECUTABLE_SET_USER_ID 0004000u
#define EXECUTABLE_SET_GROUP_ID 0002000u
#define EXECUTABLE_GROUP_EXECUTE 0000010u
#define EXECUTABLE_ANY_EXECUTE 0000111u
#define EXECUTABLE_SHEBANG_LIMIT 4u
#define EXEC_FILE_REFERENCE_CAPACITY (EDGE_RUNTIME_MAX_TASKS + 16u)

typedef struct exec_file_reference {
    vfs_inode_t inode;
    vfs_superblock_t *superblock;
    uint32_t references;
    uint32_t generation;
    uint8_t used;
} exec_file_reference_t;

static exec_file_reference_t
    g_exec_file_references[EXEC_FILE_REFERENCE_CAPACITY];
static spinlock_t g_exec_file_reference_lock;
static uint32_t g_exec_file_generation = 1u;

static int exec_file_handle_index(kernel_exec_file_handle_t handle,
                                  uint32_t *index,
                                  uint32_t *generation) {
    uint32_t slot;

    if (!handle || !index || !generation) return -EDGE_LINUX_EINVAL;
    slot = (uint32_t)handle;
    if (!slot || slot > EXEC_FILE_REFERENCE_CAPACITY)
        return -EDGE_LINUX_EINVAL;
    *index = slot - 1u;
    *generation = (uint32_t)(handle >> 32);
    return *generation ? 0 : -EDGE_LINUX_EINVAL;
}

int kernel_exec_file_create(vfs_superblock_t *superblock,
                            const vfs_inode_t *inode,
                            kernel_exec_file_handle_t *handle) {
    vfs_superblock_t *stable;
    uint64_t flags;
    uint32_t index;
    uint32_t generation;

    if (!superblock || !inode || !handle) return -EDGE_LINUX_EINVAL;
    stable = vfs_superblock_stable(superblock);
    if (!stable || vfs_inode_open(stable, inode) < 0)
        return -EDGE_LINUX_ENFILE;

    flags = spin_lock_irqsave(&g_exec_file_reference_lock);
    for (index = 0; index < EXEC_FILE_REFERENCE_CAPACITY; ++index)
        if (!g_exec_file_references[index].used) break;
    if (index == EXEC_FILE_REFERENCE_CAPACITY) {
        spin_unlock_irqrestore(&g_exec_file_reference_lock, flags);
        vfs_inode_close(stable, inode);
        return -EDGE_LINUX_ENFILE;
    }
    generation = g_exec_file_generation++;
    if (!generation) generation = g_exec_file_generation++;
    g_exec_file_references[index].inode = *inode;
    g_exec_file_references[index].superblock = stable;
    g_exec_file_references[index].references = 1u;
    g_exec_file_references[index].generation = generation;
    g_exec_file_references[index].used = 1u;
    *handle = ((uint64_t)generation << 32) | (index + 1u);
    spin_unlock_irqrestore(&g_exec_file_reference_lock, flags);
    return 0;
}

int kernel_exec_file_retain(kernel_exec_file_handle_t handle) {
    uint64_t flags;
    uint32_t index;
    uint32_t generation;
    int result = -EDGE_LINUX_ENOENT;

    if (exec_file_handle_index(handle, &index, &generation) < 0)
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_exec_file_reference_lock);
    if (g_exec_file_references[index].used &&
        g_exec_file_references[index].generation == generation &&
        g_exec_file_references[index].references != UINT32_MAX) {
        ++g_exec_file_references[index].references;
        result = 0;
    }
    spin_unlock_irqrestore(&g_exec_file_reference_lock, flags);
    return result;
}

void kernel_exec_file_release(kernel_exec_file_handle_t handle) {
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;
    uint64_t flags;
    uint32_t index;
    uint32_t generation;

    if (exec_file_handle_index(handle, &index, &generation) < 0) return;
    flags = spin_lock_irqsave(&g_exec_file_reference_lock);
    if (g_exec_file_references[index].used &&
        g_exec_file_references[index].generation == generation &&
        g_exec_file_references[index].references &&
        --g_exec_file_references[index].references == 0) {
        inode = g_exec_file_references[index].inode;
        superblock = g_exec_file_references[index].superblock;
        g_exec_file_references[index].used = 0;
        g_exec_file_references[index].superblock = 0;
    }
    spin_unlock_irqrestore(&g_exec_file_reference_lock, flags);
    if (superblock) vfs_inode_close(superblock, &inode);
}

int kernel_exec_file_snapshot(kernel_exec_file_handle_t handle,
                              vfs_superblock_t **superblock,
                              vfs_inode_t *inode) {
    uint64_t flags;
    uint32_t index;
    uint32_t generation;
    int result = -EDGE_LINUX_ENOENT;

    if (!superblock || !inode ||
        exec_file_handle_index(handle, &index, &generation) < 0)
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_exec_file_reference_lock);
    if (g_exec_file_references[index].used &&
        g_exec_file_references[index].generation == generation &&
        g_exec_file_references[index].references) {
        *inode = g_exec_file_references[index].inode;
        *superblock = g_exec_file_references[index].superblock;
        result = 0;
    }
    spin_unlock_irqrestore(&g_exec_file_reference_lock, flags);
    return result;
}

static uint32_t exec_string_length(const char *text, uint32_t limit) {
    uint32_t length = 0;
    if (!text) return limit;
    while (length < limit && text[length]) ++length;
    return length;
}

static int exec_string_copy(char *destination, uint32_t capacity,
                            const char *source) {
    uint32_t length;
    if (!destination || !capacity || !source)
        return -EDGE_LINUX_EINVAL;
    length = exec_string_length(source, capacity);
    if (length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
    for (uint32_t index = 0; index <= length; ++index)
        destination[index] = source[index];
    return 0;
}

static void exec_state_initialize(kernel_exec_state_t *state) {
    uint8_t *bytes = (uint8_t *)state;
    for (uint32_t index = 0; index < sizeof(*state); ++index)
        bytes[index] = 0;
}

static int exec_file_validate(const kernel_exec_state_t *state,
                              int nofollow) {
    uint32_t type;
    if (!state) return -EDGE_LINUX_EINVAL;
    type = state->file.mode & EXECUTABLE_TYPE_MASK;
    if (nofollow && type == 0120000u)
        return -EDGE_LINUX_ELOOP;
    if (type == EXECUTABLE_DIRECTORY)
        return -EDGE_LINUX_EACCES;
    if (type != EXECUTABLE_REGULAR_FILE)
        return -EDGE_LINUX_EACCES;
    if (!(state->file.mode & EXECUTABLE_ANY_EXECUTE) ||
        state->file.mount_noexec)
        return -EDGE_LINUX_EACCES;
    return 0;
}

static int exec_resolve(kernel_exec_state_t *state, int nofollow) {
    int status = process_exec_arch_resolve(state, nofollow);
    if (status < 0) return status;
    status = exec_file_validate(state, nofollow);
    if (status < 0) return status;
    status = kernel_landlock_check_path(
        state->path, EDGE_LINUX_LANDLOCK_ACCESS_FS_EXECUTE);
    if (status < 0) return status;
    status = kernel_fanotify_permission_check(
        state->path, KERNEL_FAN_OPEN_EXEC_PERM);
    if (status < 0) return status;
    status = kernel_fanotify_permission_check(
        state->path, KERNEL_FAN_OPEN_PERM);
    if (status < 0) return status;
    kernel_fanotify_notify_path(
        state->path, KERNEL_FAN_OPEN | KERNEL_FAN_OPEN_EXEC);
    return 0;
}

static int exec_parse_shebang(kernel_exec_state_t *state,
                              const char *line, uint32_t length) {
    char interpreter[256];
    char argument[256];
    uint32_t cursor = 2u;
    uint32_t interpreter_length = 0;
    uint32_t argument_length = 0;

    if (!state || !state->payload || !line || length < 2u ||
        line[0] != '#' || line[1] != '!')
        return -EDGE_LINUX_ENOEXEC;
    while (cursor < length &&
           (line[cursor] == ' ' || line[cursor] == '\t'))
        ++cursor;
    if (cursor >= length || line[cursor] != '/')
        return -EDGE_LINUX_ENOEXEC;
    while (cursor < length && line[cursor] != ' ' &&
           line[cursor] != '\t' && line[cursor] != '\n' &&
           line[cursor] != '\r') {
        if (interpreter_length + 1u >= sizeof(interpreter))
            return -EDGE_LINUX_ENOEXEC;
        interpreter[interpreter_length++] = line[cursor++];
    }
    interpreter[interpreter_length] = 0;
    while (cursor < length &&
           (line[cursor] == ' ' || line[cursor] == '\t'))
        ++cursor;
    while (cursor < length && line[cursor] != '\n' &&
           line[cursor] != '\r') {
        if (argument_length + 1u >= sizeof(argument))
            return -EDGE_LINUX_E2BIG;
        argument[argument_length++] = line[cursor++];
    }
    while (argument_length &&
           (argument[argument_length - 1u] == ' ' ||
            argument[argument_length - 1u] == '\t'))
        --argument_length;
    argument[argument_length] = 0;
    if (linux_exec_payload_prepend_script(
            state->payload, interpreter,
            argument_length ? argument : 0, state->script_path) < 0)
        return -EDGE_LINUX_E2BIG;
    if (exec_string_copy(
            state->path, state->path_capacity, interpreter) < 0 ||
        exec_string_copy(
            state->script_path, state->path_capacity, interpreter) < 0)
        return -EDGE_LINUX_ENOEXEC;
    return 0;
}

static int exec_resolve_image(kernel_exec_state_t *state, int nofollow) {
    char shebang[256];
    int status;

    for (uint32_t depth = 0; ; ++depth) {
        status = exec_resolve(state, nofollow && depth == 0u);
        if (status < 0) return status;
        status = process_exec_arch_probe_image(state);
        if (status == 0) return 0;
        if (status != -EDGE_LINUX_ENOEXEC)
            return status;
        if (depth >= EXECUTABLE_SHEBANG_LIMIT)
            return -EDGE_LINUX_ELOOP;
        status = process_exec_arch_read_image(
            state, shebang, sizeof(shebang) - 1u);
        if (status < 0) return status;
        if (status < 2 || shebang[0] != '#' || shebang[1] != '!')
            return -EDGE_LINUX_ENOEXEC;
        shebang[status] = 0;
        status = exec_parse_shebang(
            state, shebang, (uint32_t)status);
        if (status < 0) return status;
    }
}

static const char *exec_command_name(const char *path) {
    const char *name = path;
    if (!path) return "proc";
    for (const char *cursor = path; *cursor; ++cursor) {
        if (*cursor == '/') name = cursor + 1;
    }
    return name[0] ? name : "proc";
}

static int exec_prepare_credentials(kernel_exec_state_t *state) {
    kernel_exec_credentials_t *credentials;
    uint32_t old_effective_uid;
    uint32_t old_effective_gid;
    int allow_setid;
    int privilege_gain;
    int status;

    if (!state) return -EDGE_LINUX_EINVAL;
    credentials = &state->credentials;
    status = process_exec_arch_get_credentials(state, credentials);
    if (status < 0) return status;
    old_effective_uid = credentials->identity.euid;
    old_effective_gid = credentials->identity.egid;
    allow_setid =
        !credentials->no_new_privs && !state->file.mount_nosuid;
    if (allow_setid &&
        (state->file.mode & EXECUTABLE_SET_USER_ID))
        credentials->identity.euid = state->file.uid;
    if (allow_setid &&
        (state->file.mode & EXECUTABLE_SET_GROUP_ID) &&
        (state->file.mode & EXECUTABLE_GROUP_EXECUTE))
        credentials->identity.egid = state->file.gid;
    privilege_gain =
        credentials->identity.euid != old_effective_uid ||
        credentials->identity.egid != old_effective_gid;
    credentials->identity.suid = credentials->identity.euid;
    credentials->identity.sgid = credentials->identity.egid;
    credentials->identity.fsuid = credentials->identity.euid;
    credentials->identity.fsgid = credentials->identity.egid;
    credentials->dumpable = privilege_gain ? 0u : 1u;
    if (privilege_gain) credentials->parent_death_signal = 0;
    if (credentials->identity.euid == 0) {
        linux_capabilities_init_root(
            &credentials->identity.capabilities);
    } else {
        credentials->identity.capabilities.permitted = 0;
        credentials->identity.capabilities.effective = 0;
        credentials->identity.capabilities.inheritable &=
            EDGE_LINUX_CAP_FULL_SET;
        credentials->identity.capabilities.ambient = 0;
    }
    state->secure_exec = privilege_gain ? 1u : 0u;
    state->credentials_prepared = 1;
    return 0;
}

static int64_t exec_fail(kernel_exec_state_t *state, int status) {
    if (state && state->point_of_no_return) {
        kernel_exec_descriptor_source_release(
            &state->descriptor_source);
        return process_exec_arch_fatal(
            state, status < 0 ? status : -EDGE_LINUX_EIO);
    }
    if (state) {
        process_exec_arch_abort(state);
        kernel_exec_descriptor_source_release(
            &state->descriptor_source);
        kernel_exec_payload_release(&state->payload_handle);
        state->payload = 0;
    }
    return status < 0 ? status : -EDGE_LINUX_EIO;
}

int64_t kernel_process_exec(const kernel_exec_request_t *request) {
    kernel_exec_reset_configuration_t configuration;
    kernel_exec_state_t state;
    int status;

    if (!request || !request->path)
        return -EDGE_LINUX_EFAULT;
    if (!request->path[0])
        return -EDGE_LINUX_ENOENT;
    exec_state_initialize(&state);
    status = process_exec_arch_initialize(&state);
    if (status < 0) return status;
    if (!state.task || !state.path || !state.script_path ||
        state.path_capacity < KERNEL_EXEC_PATH_CAPACITY ||
        state.owner_pid <= 0 || state.process_id <= 0)
        return exec_fail(&state, -EDGE_LINUX_EIO);
    status = exec_string_copy(
        state.path, state.path_capacity, request->path);
    if (status < 0) return exec_fail(&state, status);
    status = exec_string_copy(
        state.script_path, state.path_capacity, request->path);
    if (status < 0) return exec_fail(&state, status);
    if (request->inode && request->memory_descriptor_supplied)
        return exec_fail(&state, -EDGE_LINUX_EINVAL);
    if (request->memory_descriptor_supplied) {
        status = kernel_exec_descriptor_source_acquire(
            request->memory_descriptor, &state.descriptor_source);
        if (status < 0) return exec_fail(&state, status);
        status = process_exec_arch_supply_file(
            &state, &state.descriptor_source.inode,
            state.descriptor_source.superblock);
        if (status < 0) return exec_fail(&state, status);
    } else if (request->inode) {
        status = process_exec_arch_supply_file(
            &state, request->inode, request->superblock);
        if (status < 0) return exec_fail(&state, status);
    }

    status = kernel_exec_payload_acquire(
        state.owner_pid, &state.payload_handle, &state.payload);
    if (status < 0) return exec_fail(&state, status);
    status = linux_exec_payload_capture_vector_with(
        state.payload, &state, process_exec_arch_copy_from_user,
        request->argv_user, 0);
    if (status < 0) return exec_fail(&state, status);
    status = linux_exec_payload_capture_vector_with(
        state.payload, &state, process_exec_arch_copy_from_user,
        request->envp_user, 1);
    if (status < 0) return exec_fail(&state, status);
    status = exec_resolve_image(&state, request->nofollow != 0);
    if (status < 0) return exec_fail(&state, status);
    status = linux_exec_payload_ensure_argv0(
        state.payload, state.path);
    if (status < 0) return exec_fail(&state, status);
    status = exec_prepare_credentials(&state);
    if (status < 0) return exec_fail(&state, status);

    status = process_exec_arch_prepare_image(&state);
    if (status < 0) return exec_fail(&state, status);
    state.image_prepared = 1;
    status = process_exec_arch_unshare_files(&state);
    if (status < 0) return exec_fail(&state, status);
    state.files_unshared = 1;
    status = process_exec_arch_de_thread(&state);
    if (status < 0) return exec_fail(&state, status);
    /*
     * Successful de-threading is not reversible: peer threads may already
     * have released their per-thread resources. Any later failure therefore
     * terminates the caller instead of returning into the old image.
     */
    state.point_of_no_return = 1;
    status = process_exec_arch_commit_image(&state);
    if (status < 0) return exec_fail(&state, status);
    if (!state.point_of_no_return)
        return exec_fail(&state, -EDGE_LINUX_EIO);
    state.image_committed = 1;

    configuration.detach_signal_handlers = 1;
    configuration.reset_signal_dispositions = 1;
    configuration.disable_signal_altstack = 1;
    configuration.reset_thread_state = 1;
    configuration.reset_membarrier = 1;
    configuration.reset_architecture_tls = 1;
    configuration.reset_floating_point = 1;
    status = process_exec_arch_reset_state(&state, &configuration);
    if (status < 0) return exec_fail(&state, status);
    if (!state.credentials_prepared)
        return exec_fail(&state, -EDGE_LINUX_EIO);
    status = process_exec_arch_set_credentials(
        &state, &state.credentials);
    if (status < 0) return exec_fail(&state, status);
    status = process_exec_arch_set_identity(
        &state, exec_command_name(state.path));
    if (status < 0) return exec_fail(&state, status);
    kernel_exec_descriptor_source_release(
        &state.descriptor_source);
    kernel_posix_timer_delete_process(state.process_id);
    process_exec_arch_wake_vfork_parent(&state);
    kernel_current_exec_committed();
    status = process_exec_arch_close_on_exec(&state);
    if (status < 0) return exec_fail(&state, status);
    status = process_exec_arch_enter(&state);
    return exec_fail(
        &state, status < 0 ? status : -EDGE_LINUX_EFAULT);
}
