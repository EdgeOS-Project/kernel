static void reboot_trace_puts(const char *s);
static void reboot_trace_hex(uint64_t v);
static void reboot_trace_dec(int v);

static int g_dropbear_debug_armed;

#ifndef ENODEV
#define ENODEV 19
#endif

#if EDGE_SSH_IO_DEBUG
static int debug_task_ptr_valid(const task_t *t) {
    if (!t) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        if (t == process_task_by_index(i)) return 1;
    }
    return 0;
}
#endif

static int ssh_trace_task(task_t *t) {
#if EDGE_SSH_IO_DEBUG
    if (!debug_task_ptr_valid(t) || t->state == TASK_UNUSED) return 0;
    if (strcmp(t->name, "dropbear") == 0) {
        g_dropbear_debug_armed = 1;
        return 1;
    }
    /*
     * Keep the old dropbear investigation trace narrow.  Arming tracing for
     * every later process made unrelated package-manager reads print as
     * [sshdbg], and any stale task pointer in the slow VFS path then obscured
     * the real kernel fault with impossible pid/fd/len values.
     */
    if (g_dropbear_debug_armed &&
        (strcmp(t->name, "-sh") == 0 || strcmp(t->name, "sh") == 0 ||
         strcmp(t->name, "busybox") == 0 || strcmp(t->name, "sshd") == 0)) {
        return 1;
    }
#else
    (void)t;
#endif
    return 0;
}

static int trace_initd_console_task(const task_t *t) {
    (void)t;
    return 0;
}

static int trace_vt_shell_task(const task_t *t) {
    (void)t;
    return 0;
}

static int trace_go_startup_syscall(const task_t *t, uint64_t nr) {
    (void)t;
    (void)nr;
    return 0;
}

static void exec_record_payload_for_proc(task_t *task,
                                         const linux_exec_payload_t *payload) {
    uint32_t index;
    if (!task || !payload) return;
    process_exec_storage_reset(task);
    for (index = 0; index < payload->argc && index < EDGE_EXEC_ARG_MAX; ++index) {
        const char *argument = linux_exec_payload_argument(payload, index);
        char *stored = 0;
        if (!argument || process_exec_storage_append(task, argument, &stored) < 0)
            break;
        (void)stored;
    }
    for (index = 0; index < payload->envc && index < EDGE_EXEC_ENV_MAX; ++index) {
        const char *environment = linux_exec_payload_environment(payload, index);
        char *stored = 0;
        if (!environment ||
            kernel_exec_record_append(task->exec_record, environment, 1,
                                      &stored) < 0)
            break;
        (void)stored;
    }
}

static edge_fd_t *exec_cloexec_detached_allocate(uint32_t *pages_out) {
    uint64_t bytes = sizeof(edge_fd_t) * (uint64_t)EDGE_MAX_FD;
    uint32_t pages = (uint32_t)((bytes + 4095u) / 4096u);
    edge_fd_t *entries;

    if (!pages_out || !pages) return 0;
    *pages_out = 0;
    entries = (edge_fd_t *)arch_vm_alloc_pages(pages);
    if (!entries) return 0;
    memset(entries, 0, (uint64_t)pages * 4096u);
    *pages_out = pages;
    return entries;
}

static void exec_cloexec_detached_free(edge_fd_t *entries,
                                       uint32_t pages) {
    if (!entries) return;
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page(
            (uint8_t *)entries + (uint64_t)page * 4096u);
}

static int exec_close_cloexec_descriptors(
        edge_fd_proc_t *process, task_t *task,
        edge_fd_t *detached) {
    uint64_t irq_flags;
    int status = 0;

    if (!process) return 0;
    if (!detached) return -ENOMEM;

    /*
     * Exec has already made this table private. Detach every close-on-exec
     * descriptor while holding the table lock once so a multi-descriptor
     * publication is observed either before this snapshot or after it, never
     * as a partially published set. Slow backing-object release stays outside
     * the spinlock, and descriptor numbers become reusable immediately.
     */
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
        if (!kernel_fd_table_is_open_locked(
                &process->table_runtime, (uint32_t)fd) ||
            !__atomic_load_n(
                &process->fds[fd].used, __ATOMIC_ACQUIRE) ||
            !(process->fds[fd].fd_flags & LINUX_FD_CLOEXEC))
            continue;

        detached[fd] = process->fds[fd];
        if (kernel_fd_table_detach_open_locked(
                &process->table_runtime, (uint32_t)fd) < 0) {
            memset(&detached[fd], 0, sizeof(detached[fd]));
            status = -EIO;
            break;
        }
        fd_async_input_watch_remove(&process->fds[fd]);
        memset(&process->fds[fd], 0, sizeof(process->fds[fd]));
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);

    for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
        if (!detached[fd].used) continue;
        fd_log_lifecycle(
            "close-exec", task ? task->pid : 0, fd,
            &detached[fd], 0);
        (void)fd_release_entry(&detached[fd], task, 1, 1);
        memset(&detached[fd], 0, sizeof(detached[fd]));
    }
    return status;
}

typedef struct process_exec_x86_state {
    task_t *task;
    vfs_inode_t executable;
    vfs_superblock_t *superblock;
    edge_fd_t *cloexec_detached;
    uint32_t cloexec_detached_pages;
    edge_elf_image_t elf_image;
    user_exec_image_t user_image;
    uint8_t supplied_pending;
    uint8_t supplied_active;
} process_exec_x86_state_t;

typedef char process_exec_x86_state_size_check[
    sizeof(process_exec_x86_state_t) <=
            KERNEL_EXEC_ARCHITECTURE_STATE_BYTES ? 1 : -1];

static process_exec_x86_state_t *process_exec_x86(
    kernel_exec_state_t *state) {
    return state ?
        (process_exec_x86_state_t *)state->architecture.bytes : 0;
}

int process_exec_arch_initialize(kernel_exec_state_t *state) {
    process_exec_x86_state_t *native;
    task_t *task = process_current_task();

    if (!state) return -EINVAL;
    if (!task) return -ESRCH;
    if (!task->scratch) return -EIO;
    native = process_exec_x86(state);
    memset(native, 0, sizeof(*native));
    native->task = task;
    state->task = task;
    state->path = (char *)task->scratch->xattr_scratch;
    state->script_path =
        (char *)task->scratch->xattr_scratch +
        KERNEL_EXEC_PATH_CAPACITY;
    state->path_capacity = KERNEL_EXEC_PATH_CAPACITY;
    state->owner_pid = task->pid;
    state->process_id = process_gettgid();
    return 0;
}

int process_exec_arch_supply_file(kernel_exec_state_t *state,
                                  const vfs_inode_t *inode,
                                  vfs_superblock_t *superblock) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    if (!native || !inode || !superblock) return -EINVAL;
    native->executable = *inode;
    native->superblock = superblock;
    native->supplied_pending = 1;
    return 0;
}

int process_exec_arch_current_file(vfs_inode_t *inode,
                                   vfs_superblock_t **superblock) {
    task_t *task = process_current_task();

    if (!task || !task->exec_file_handle) return -ENOENT;
    return kernel_exec_file_snapshot(
        task->exec_file_handle, superblock, inode);
}

int process_exec_arch_copy_from_user(void *context, void *destination,
                                    uint64_t source, uint64_t size) {
    kernel_exec_state_t *state = (kernel_exec_state_t *)context;
    process_exec_x86_state_t *native = process_exec_x86(state);
    return native && native->task ?
        copy_from_user(destination, source, size) : -1;
}

static int process_exec_x86_path_copy(char *destination, uint32_t capacity,
                                      const char *source) {
    uint32_t length;
    if (!destination || !capacity || !source) return -EINVAL;
    length = (uint32_t)strlen(source);
    if (length >= capacity) return -ENAMETOOLONG;
    memcpy(destination, source, length + 1u);
    return 0;
}

int process_exec_arch_resolve(kernel_exec_state_t *state, int nofollow) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    char *resolved;
    int status;

    if (!state || !native || !native->task || !state->path)
        return -EINVAL;
    if (native->supplied_pending) {
        native->supplied_pending = 0;
        native->supplied_active = 1;
        state->file.mode = native->executable.mode;
        state->file.uid = native->executable.uid;
        state->file.gid = native->executable.gid;
        state->file.size = native->executable.size;
        state->file.mount_nosuid =
            (native->superblock->mount_flags & VFS_MOUNT_NOSUID) != 0;
        state->file.mount_noexec =
            (native->superblock->mount_flags & VFS_MOUNT_NOEXEC) != 0;
        return 0;
    }
    native->supplied_active = 0;
    resolved = native->task->scratch->path_scratch[4];
    native->superblock = 0;
    if (nofollow) {
        status = vfs_resolve_nofollow(
            state->path, &native->executable, &native->superblock);
        if (status < 0) return -ENOENT;
        if ((native->executable.mode & 0xf000u) != VFS_INODE_LNK &&
            edge_resolve_symlink_components(
                state->path, resolved, KERNEL_EXEC_PATH_CAPACITY) == 0) {
            status = process_exec_x86_path_copy(
                state->path, state->path_capacity, resolved);
            if (status < 0) return status;
            native->superblock = 0;
            if (vfs_resolve_nofollow(
                    state->path, &native->executable,
                    &native->superblock) < 0)
                return -ENOENT;
        }
    } else {
        for (uint32_t depth = 0; depth < 8u; ++depth) {
            if (edge_resolve_symlink_path(
                    state->path, resolved,
                    KERNEL_EXEC_PATH_CAPACITY) < 0)
                break;
            status = process_exec_x86_path_copy(
                state->path, state->path_capacity, resolved);
            if (status < 0) return status;
        }
        if (edge_resolve_symlink_components(
                state->path, resolved,
                KERNEL_EXEC_PATH_CAPACITY) == 0) {
            status = process_exec_x86_path_copy(
                state->path, state->path_capacity, resolved);
            if (status < 0) return status;
        }
        if (vfs_resolve(
                state->path, &native->executable,
                &native->superblock, 0, 0) < 0)
            return -ENOENT;
    }
    state->file.mode = native->executable.mode;
    state->file.uid = native->executable.uid;
    state->file.gid = native->executable.gid;
    state->file.size = native->executable.size;
    state->file.mount_nosuid =
        native->superblock &&
        (native->superblock->mount_flags & VFS_MOUNT_NOSUID);
    state->file.mount_noexec =
        native->superblock &&
        (native->superblock->mount_flags & VFS_MOUNT_NOEXEC);
    return 0;
}

int process_exec_arch_probe_image(kernel_exec_state_t *state) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    if (!state || !native || !state->path) return -EINVAL;
    return (native->supplied_active ?
        elf_loader_probe_inode(
            native->superblock, &native->executable) :
        elf_loader_probe(state->path)) == 0 ? 0 : -ENOEXEC;
}

int process_exec_arch_read_image(kernel_exec_state_t *state,
                                 void *destination, uint32_t capacity) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    int result;
    if (!state || !native || !state->path || !destination || !capacity)
        return -EINVAL;
    if (native->supplied_active) {
        uint32_t length = native->executable.size < capacity ?
            native->executable.size : capacity;
        vfs_inode_t inode = native->executable;
        result = vfs_read_inode_exact(
            native->superblock, &inode, 0, destination, length) == 0 ?
            (int)length : -1;
    } else {
        result = vfs_read_file(
            state->path, (char *)destination, capacity);
    }
    return result < 0 ? -ENOEXEC : result;
}

int process_exec_arch_prepare_image(kernel_exec_state_t *state) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    if (!state || !native || !native->task || !state->payload)
        return -EINVAL;
    exec_record_payload_for_proc(native->task, state->payload);
    return 0;
}

int process_exec_arch_unshare_files(kernel_exec_state_t *state) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    int status;
    if (!native || !native->task) return -EINVAL;
    native->cloexec_detached = exec_cloexec_detached_allocate(
        &native->cloexec_detached_pages);
    if (!native->cloexec_detached) return -ENOMEM;
    status = kernel_fd_table_unshare();
    return status < 0 ? status : 0;
}

int process_exec_arch_de_thread(kernel_exec_state_t *state) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    if (!native || !native->task) return -EINVAL;
    return process_exec_de_thread_current() < 0 ? -EINVAL : 0;
}

int process_exec_arch_commit_image(kernel_exec_state_t *state) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    uint64_t new_heap;
    if (!state || !native || !native->task) return -EINVAL;

    state->point_of_no_return = 1;
    if (process_prepare_exec_current() < 0)
        return -EINVAL;
    if ((native->supplied_active ?
         elf_loader_exec_inode(
             native->superblock, &native->executable,
             state->path, &native->elf_image) :
         elf_loader_exec(state->path, &native->elf_image)) < 0)
        return -EIO;

    native->user_image.entry = native->elf_image.entry_rip;
    native->user_image.user_stack_top = native->task->user_stack_top;
    native->user_image.user_heap_base = native->task->user_heap_base;
    native->user_image.at_phdr = native->elf_image.at_phdr;
    native->user_image.at_phnum = native->elf_image.at_phnum;
    native->user_image.at_entry = native->elf_image.at_entry;
    native->user_image.at_base = native->elf_image.at_base;
    native->user_image.secure_exec = state->secure_exec;
    native->task->user_heap_limit =
        USER_HEAP_BASE_ADDR + USER_HEAP_DEFAULT_DELTA;
    if (state->file.size > 4u * 1024u * 1024u)
        native->task->user_heap_limit += USER_HEAP_PY_EXTRA_DELTA;
    native->task->user_mmap_next = native->task->user_heap_limit;
    if (native->elf_image.main_load_hi > native->task->user_heap_base &&
        native->elf_image.main_load_hi < native->task->user_heap_limit) {
        new_heap = page_align_up(
            native->elf_image.main_load_hi + PAGE_SIZE);
        if (new_heap < USER_HEAP_BASE_ADDR ||
            new_heap > native->task->user_heap_limit)
            return -ENOMEM;
        native->task->user_heap_base = new_heap;
    }
    native->task->user_brk = native->task->user_heap_base;
    return 0;
}

int process_exec_arch_reset_state(
    kernel_exec_state_t *state,
    const kernel_exec_reset_configuration_t *configuration) {
    if (!state || !configuration) return -EINVAL;
    return process_exec_reset_current(configuration) < 0 ?
        -EINVAL : 0;
}

int process_exec_arch_get_credentials(
    kernel_exec_state_t *state, kernel_exec_credentials_t *credentials) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    task_t *task;
    if (!native || !(task = native->task) || !credentials)
        return -EINVAL;
    credentials->identity.uid = task->uid;
    credentials->identity.euid = task->euid;
    credentials->identity.suid = task->suid;
    credentials->identity.fsuid = task->fsuid;
    credentials->identity.gid = task->gid;
    credentials->identity.egid = task->egid;
    credentials->identity.sgid = task->sgid;
    credentials->identity.fsgid = task->fsgid;
    linux_capabilities_copy(
        &credentials->identity.capabilities, &task->capabilities);
    credentials->parent_death_signal = task->parent_death_signal;
    credentials->no_new_privs = task->no_new_privs;
    credentials->dumpable = task->dumpable;
    return 0;
}

int process_exec_arch_set_credentials(
    kernel_exec_state_t *state,
    const kernel_exec_credentials_t *credentials) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    task_t *task;
    if (!native || !(task = native->task) || !credentials)
        return -EINVAL;
    task->uid = credentials->identity.uid;
    task->euid = credentials->identity.euid;
    task->suid = credentials->identity.suid;
    task->fsuid = credentials->identity.fsuid;
    task->gid = credentials->identity.gid;
    task->egid = credentials->identity.egid;
    task->sgid = credentials->identity.sgid;
    task->fsgid = credentials->identity.fsgid;
    linux_capabilities_copy(
        &task->capabilities, &credentials->identity.capabilities);
    task->parent_death_signal = credentials->parent_death_signal;
    task->no_new_privs = credentials->no_new_privs;
    task->dumpable = credentials->dumpable;
    return 0;
}

int process_exec_arch_set_identity(kernel_exec_state_t *state,
                                   const char *command_name) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    task_t *task;
    kernel_exec_file_handle_t new_handle;
    kernel_exec_file_handle_t old_handle;
    int status;
    if (!state || !native || !(task = native->task) ||
        !state->path || !command_name)
        return -EINVAL;
    status = kernel_exec_file_create(
        native->superblock, &native->executable, &new_handle);
    if (status < 0) return status;
    old_handle = task->exec_file_handle;
    task->exec_file_handle = new_handle;
    kernel_exec_file_release(old_handle);
    strncpy(task->name, command_name, sizeof(task->name) - 1u);
    task->name[sizeof(task->name) - 1u] = 0;
    strncpy(task->exec_path, state->path, sizeof(task->exec_path) - 1u);
    task->exec_path[sizeof(task->exec_path) - 1u] = 0;
    return 0;
}

int process_exec_arch_close_on_exec(kernel_exec_state_t *state) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    edge_fd_proc_t *process;
    int status;
    if (!native || !native->task || !native->cloexec_detached)
        return -EINVAL;
    process = fd_proc_for_pid(fd_owner_pid_current(), 0);
    status = exec_close_cloexec_descriptors(
        process, native->task, native->cloexec_detached);
    exec_cloexec_detached_free(
        native->cloexec_detached, native->cloexec_detached_pages);
    native->cloexec_detached = 0;
    native->cloexec_detached_pages = 0;
    return status;
}

void process_exec_arch_wake_vfork_parent(kernel_exec_state_t *state) {
    (void)state;
    process_exec_wake_vfork_parent_current();
}

int process_exec_arch_enter(kernel_exec_state_t *state) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    if (!state || !native || !native->task || !state->payload)
        return -EINVAL;
    return user_exec_run_payload(
        &native->user_image, state->payload, &state->payload_handle);
}

void process_exec_arch_abort(kernel_exec_state_t *state) {
    process_exec_x86_state_t *native = process_exec_x86(state);
    if (!native || !native->cloexec_detached) return;
    exec_cloexec_detached_free(
        native->cloexec_detached, native->cloexec_detached_pages);
    native->cloexec_detached = 0;
    native->cloexec_detached_pages = 0;
}

int process_exec_arch_fatal(kernel_exec_state_t *state, int status) {
    kernel_exec_payload_release(state ? &state->payload_handle : 0);
    fd_proc_release(fd_owner_pid_current());
    scheduler_kill_current_and_yield(127);
    return status < 0 ? status : -EIO;
}

static uint64_t do_sys_spawn(uint64_t path, uint64_t argv, uint64_t envp) {
#define EDGE_SPAWN_ARG_MAX 64
#define EDGE_SPAWN_STR_MAX 1024
    (void)envp;
    char kpath[256];
    char kargv_buf[EDGE_SPAWN_ARG_MAX][EDGE_SPAWN_STR_MAX];
    char *kargv[EDGE_SPAWN_ARG_MAX + 1];
    int argc = 0;
    char **uargv = (char **)(uintptr_t)argv;

    if (!path) return (uint64_t)-EINVAL;
    if (!user_range_ok(path, 1)) return (uint64_t)-EFAULT;

    int i = 0;
    for (; i < (int)sizeof(kpath) - 1; ++i) {
        char c = 0;
        if (copy_from_user(&c, path + (uint64_t)i, 1) < 0) return (uint64_t)-EFAULT;
        kpath[i] = c;
        if (!c) break;
    }
    if (i == (int)sizeof(kpath) - 1) return (uint64_t)-EINVAL;

    if (uargv) {
        while (argc < EDGE_SPAWN_ARG_MAX) {
            uint64_t p = 0;
            uint64_t slot = argv + (uint64_t)argc * sizeof(uint64_t);
            if (!user_range_ok(slot, sizeof(uint64_t))) return (uint64_t)-EFAULT;
            if (copy_from_user(&p, slot, sizeof(uint64_t)) < 0) return (uint64_t)-EFAULT;
            if (!p) break;
            if (!user_range_ok(p, 1)) return (uint64_t)-EFAULT;
            ++argc;
        }
    }
    for (int ai = 0; ai < argc; ++ai) {
        uint64_t p = 0;
        uint64_t slot = argv + (uint64_t)ai * sizeof(uint64_t);
        if (copy_from_user(&p, slot, sizeof(uint64_t)) < 0) return (uint64_t)-EFAULT;
        if (!p) {
            argc = ai;
            break;
        }
        if (copy_user_cstr(kargv_buf[ai], (int)sizeof(kargv_buf[ai]), p) < 0) return (uint64_t)-EFAULT;
        kargv[ai] = kargv_buf[ai];
    }
    if (argc == 0) {
        kargv[0] = kpath;
        argc = 1;
    }
    kargv[argc] = 0;

    /* Global pending SIGINT can leak across commands in this simplified model.
     * Drop any stale pending state before creating a new child process. */
    (void)keyboard_take_sigint_pending();
    return (uint64_t)process_spawn_exec(kpath, argc, kargv);
#undef EDGE_SPAWN_STR_MAX
#undef EDGE_SPAWN_ARG_MAX
}

static void console_line_write_char(int line_id, char ch) {
    edge_console_line_t *line = console_line_state(line_id);
    if (!line) return;
    if (line_id == console_line_default() &&
        edge_linux_tty_console_redirect_emit(ch))
        return;
    if (console_line_is_serial(line_id)) {
        /*
         * Keep the UART and framebuffer VTs as separate Linux tty devices.
         * Mirroring bytes between ttyS0 and tty1 makes independent gettys look
         * like one shared terminal: serial input can appear on the VM window,
         * VT prompts can pollute the UART log, and login state becomes hard to
         * reason about.  /dev/console may still select ttyS0, but that must not
         * imply framebuffer mirroring; userland can open /dev/tty1 explicitly
         * when it wants a visible VT in the QEMU window.
         */
        serial_console_write_raw(ch);
    } else {
        console_putchar_vt(line_id, ch);
    }
}

static void console_line_echo_input_char(int line_id, edge_console_line_t *line, int ch) {
    unsigned char uch;
    if (!line || (line->termios.c_lflag & LINUX_ECHO) == 0) return;
    if (ch == '\n') {
        if ((line->termios.c_oflag & LINUX_OPOST) != 0 &&
            (line->termios.c_oflag & LINUX_ONLCR) != 0) {
            console_line_write_char(line_id, '\r');
        }
        console_line_write_char(line_id, '\n');
        return;
    }
    if (ch == '\r' || ch == '\t') {
        console_line_write_char(line_id, (char)ch);
        return;
    }
    uch = (unsigned char)ch;
    if ((uch < 32 || uch == 127) &&
        (line->termios.c_lflag & LINUX_ECHOCTL) != 0) {
        console_line_write_char(line_id, '^');
        console_line_write_char(line_id, (char)(uch == 127 ? '?' : (uch ^ 0x40u)));
        return;
    }
    console_line_write_char(line_id, (char)ch);
}

static int console_line_reply_pop(edge_console_line_t *line) {
    int ch;
    if (!line || line->reply_pos >= line->reply_len) return -1;
    ch = (unsigned char)line->replybuf[line->reply_pos++];
    if (line->reply_pos >= line->reply_len) {
        line->reply_pos = 0;
        line->reply_len = 0;
    }
    return ch;
}

static int console_line_reply_append_uint(char *buf, int n, int max, int value) {
    char tmp[16];
    int len = 0;
    if (value < 0) value = 0;
    do {
        tmp[len++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value && len < (int)sizeof(tmp));
    while (len > 0 && n < max) buf[n++] = tmp[--len];
    return n;
}

static void console_line_queue_cursor_report(int line_id, edge_console_line_t *line) {
    int col = 0;
    int row = 0;
    int vt = line_id;
    int n;

    if (!line) return;
    if (console_line_is_serial(line_id)) vt = console_line_active_vt();
    if (vt < 1 || vt > EDGE_FB_VT_COUNT) vt = console_line_active_vt();
    fb_console_get_cursor_vt(vt, &col, &row);

    if (line->reply_pos > 0) {
        int remaining = line->reply_len - line->reply_pos;
        if (remaining > 0)
            memmove(line->replybuf, line->replybuf + line->reply_pos,
                    (size_t)remaining);
        line->reply_len = remaining > 0 ? remaining : 0;
        line->reply_pos = 0;
    }
    n = line->reply_len;

    /*
     * Linux terminal emulators answer Device Status Report ESC[6n with a
     * cursor-position report using one-based row/column numbers.  Some Alpine
     * tools issue two probes in one write, before and after moving to the
     * maximum cursor position.  Preserve every queued report in order so the
     * size probe cannot consume the second answer as login text.
     */
    if (n + 16 > (int)sizeof(line->replybuf)) return;
    line->replybuf[n++] = '\033';
    line->replybuf[n++] = '[';
    n = console_line_reply_append_uint(line->replybuf, n, (int)sizeof(line->replybuf), row + 1);
    if (n < (int)sizeof(line->replybuf)) line->replybuf[n++] = ';';
    n = console_line_reply_append_uint(line->replybuf, n, (int)sizeof(line->replybuf), col + 1);
    if (n < (int)sizeof(line->replybuf)) line->replybuf[n++] = 'R';
    line->reply_len = n;
}

static int console_line_observe_output_char(int line_id, edge_console_line_t *line, char c) {
    if (!line) return 0;
    switch (line->dsr_state) {
        case 0:
            if ((unsigned char)c == 0x1B) {
                line->dsr_state = 1;
                return 1;
            }
            return 0;
        case 1:
            if (c == '[') {
                line->dsr_state = 2;
                return 1;
            }
            console_line_write_char(line_id, '\033');
            console_line_write_char(line_id, c);
            line->dsr_state = 0;
            return 1;
        case 2:
            if (c == '6') {
                line->dsr_state = 3;
                return 1;
            }
            console_line_write_char(line_id, '\033');
            console_line_write_char(line_id, '[');
            console_line_write_char(line_id, c);
            line->dsr_state = 0;
            return 1;
        case 3:
            if (c == 'n') {
                console_line_queue_cursor_report(line_id, line);
                line->dsr_state = 0;
                return 1;
            } else {
                console_line_write_char(line_id, '\033');
                console_line_write_char(line_id, '[');
                console_line_write_char(line_id, '6');
                console_line_write_char(line_id, c);
                line->dsr_state = 0;
                return 1;
            }
        default:
            line->dsr_state = 0;
            return 0;
    }
}

static void fb_console_tty_batch_maybe_flush(void) {
    if (!g_fb_console_tty_batch_active) return;
    if (boottime_monotonic_us() < g_fb_console_tty_flush_deadline_us) return;
    g_fb_console_tty_batch_active = 0;
    if (g_fb_console_hold_count > 0) {
        g_fb_console_hold_count--;
        if (g_fb_console_hold_count == 0 && !syscall_console_active_vt_in_graphics()) {
            fb_console_set_present_enabled(1);
        }
    }
}

static uint64_t do_sys_write_console_line(int line_id, uint64_t buf, uint64_t len) {
    edge_console_line_t *line = console_line_state(line_id);
    char chunk[128];
    uint64_t done = 0;
    if (!line) return (uint64_t)-EINVAL;
    if (!buf) return (uint64_t)-EINVAL;
    if (len == 0) return 0;
    while (done < len) {
        uint64_t n = len - done;
        if (n > sizeof(chunk)) n = sizeof(chunk);
        if (copy_from_user(chunk, buf + done, n) < 0) {
            return (uint64_t)-EFAULT;
        }
        if (!console_line_is_serial(line_id)) console_output_batch_begin();
        for (uint64_t i = 0; i < n; ++i) {
            char c = chunk[i];
            if (console_line_observe_output_char(line_id, line, c)) continue;
            if (c == '\n' &&
                (line->termios.c_oflag & LINUX_OPOST) != 0 &&
                (line->termios.c_oflag & LINUX_ONLCR) != 0) {
                console_line_write_char(line_id, '\r');
            }
            console_line_write_char(line_id, c);
        }
        if (!console_line_is_serial(line_id)) console_output_batch_end();
        done += n;
    }
    return len;
}

static int console_line_get_input_char(int line_id) {
    edge_console_line_t *line = console_line_state(line_id);
    int reply = console_line_reply_pop(line);
    if (reply >= 0) {
        g_console_last_input_was_serial = 0;
        return reply;
    }
    if (console_line_is_serial(line_id)) {
        int ch = serial_console_pollchar();
        if (ch >= 0) {
            g_console_last_input_was_serial = 1;
            return ch;
        }
        return -1;
    }
    if (line_id != console_line_active_vt()) return -1;
    if (keyboard_haschar()) {
        g_console_last_input_was_serial = 0;
        return keyboard_getchar();
    }
    return -1;
}

static int console_line_get_noncanonical_char(int line_id,
                                               edge_console_line_t *line) {
    int ch;
    if (line && line->line_pos < line->line_len) {
        ch = (unsigned char)line->linebuf[line->line_pos++];
        if (line->line_pos >= line->line_len) {
            line->line_pos = 0;
            line->line_len = 0;
        }
        g_console_last_input_was_serial = 0;
        return ch;
    }
    return console_line_get_input_char(line_id);
}

static void console_input_wait_step(int line_id) {
    syscall_network_poll();
#ifdef CONFIG_USB
    usb_poll();
#endif
    if (console_line_is_serial(line_id)) {
        if (serial_console_haschar()) return;
        /*
         * Serial reads sleep on the same tty wait queue as framebuffer VTs.
         * IRQ4 drains ordinary RX traffic, while the timer-side low-rate LSR
         * probe covers QEMU socket/pty backends that do not deliver an edge.
         * Leaving getty runnable here turns an idle console into a permanent
         * syscall polling loop and steals scheduler time from desktop tasks.
         */
        console_line_sleep_for_input(line_id);
        return;
    }
    if (line_id == console_line_active_vt()) {
        /*
         * The foreground VT consumes only keyboard input.  Keep this as a
         * polling step before HLT because QEMU/i8042 can occasionally miss a
         * wake edge when input is injected quickly.
        */
        if (keyboard_haschar()) return;
        console_line_sleep_for_input(line_id);
        return;
    }
    console_line_sleep_for_input(line_id);
}

static int console_line_translate_input(int line_id, edge_console_line_t *line, int ch) {
    if (!line) return ch;
    if (ch == '\r') {
        /*
         * QEMU pty-backed serial consoles deliver Enter as carriage return.
         * BusyBox getty can temporarily run the console in a noncanonical
         * mode with ICRNL cleared while collecting login text, but its login
         * line handling still expects newline completion.  Linux's serial tty
         * stack normally gets this right through the active line discipline and
         * terminal mode setup; EdgeOS has a much smaller tty layer, so keep the
         * CR-to-NL compatibility rule local to ttyS0 rather than changing
         * framebuffer VT keyboard semantics.
         */
        if (console_line_is_serial(line_id)) return '\n';
        if ((line->termios.c_iflag & LINUX_IGNCR) != 0) return -1;
        if ((line->termios.c_iflag & LINUX_ICRNL) != 0) return '\n';
    } else if (ch == '\n' && (line->termios.c_iflag & LINUX_INLCR) != 0) {
        return '\r';
    }
    return ch;
}

static uint64_t do_sys_read_console_line(int line_id, uint64_t buf, uint64_t len) {
    task_t *cur = process_current_task();
    int cur_pgid = cur ? cur->pgid : process_getpgid(0);
    edge_console_line_t *line = console_line_state(line_id);
    static uint32_t vt_read_trace_budget = 0;
    if (!line) return (uint64_t)-EINVAL;
    if (!buf) return (uint64_t)-EINVAL;
    if (len == 0) return 0;
    if (!user_range_ok(buf, len)) return (uint64_t)-EFAULT;

    /*
     * Linux does not let a daemonized child keep consuming the old login tty
     * after it has left the session/foreground process group.  The previous
     * compact TTY behavior allowed a task with a different controlling
     * terminal to consume this line.  Enforce foreground ownership only for a
     * controlling terminal.  A session leader may still probe an explicitly
     * opened O_NOCTTY terminal before acquiring it, as agetty does.
     */
    if (cur && cur->ctty_kind != PROCESS_CTTY_NONE) {
        int task_line = -1;
        if (cur->ctty_kind == PROCESS_CTTY_CONSOLE) {
            task_line = console_line_valid(cur->ctty_id) ? cur->ctty_id : console_line_from_vt(cur->ctty_id);
        }
        if (task_line != line_id) return (uint64_t)-EIO;
        if (line->session.foreground_pgid > 0 &&
            tty_pgrp_alive(line->session.foreground_pgid) &&
            cur_pgid > 0 &&
            cur_pgid != line->session.foreground_pgid) {
            return (uint64_t)-EIO;
        }
    }

    if (line->session.foreground_pgid == 0) {
        int pg = cur_pgid;
        if (pg > 0) line->session.foreground_pgid = pg;
    }
    tty_log_read_once(cur, line->session.foreground_pgid);

    if ((line->termios.c_lflag & LINUX_ICANON) != 0) {
        uint64_t copied = 0;
        while (copied < len) {
                if (line->line_pos < line->line_len) {
                    char c = line->linebuf[line->line_pos++];
                    if (copy_to_user(buf + copied, &c, 1) < 0) return (uint64_t)-EFAULT;
                    copied++;
                    if (c == '\n') break;
                continue;
            }

            line->line_pos = 0;
            line->line_len = 0;
            line->line_drop_count = 0;
            line->line_drop_logged = 0;
            for (;;) {
                int ch = console_line_get_input_char(line_id);
                if (ch == -1) {
                    if (signal_pending_interrupt()) {
                        return copied ? copied : tty_interrupt_current_ret();
                    }
                    console_input_wait_step(line_id);
                    continue;
                }
                ch = console_line_translate_input(line_id, line, ch);
                if (ch == -1) continue;
                if (vt_read_trace_budget > 0 && line_id == console_line_active_vt()) {
                    vt_read_trace_budget--;
                    printf("[ttyread] pid=%d cmd=%s line=%d canon=1 ch=0x%x ll=%d fg=%d budget=%u\n",
                           cur ? cur->pid : -1,
                           (cur && cur->name[0]) ? cur->name : "?",
                           line_id, (unsigned)ch, line->line_len,
                           line->session.foreground_pgid,
                           (unsigned)vt_read_trace_budget);
                }
                if ((line->termios.c_lflag & LINUX_ISIG) && ch == 3) {
                    uint32_t pending = keyboard_take_sigint_pending();
                    if ((line->termios.c_lflag & LINUX_ECHO) != 0) console_line_write_char(line_id, '^'), console_line_write_char(line_id, 'C'), console_line_write_char(line_id, '\n');
                    if (pending != 0 && line->session.foreground_pgid > 0) {
                        (void)do_sys_kill((uint64_t)(int64_t)(-line->session.foreground_pgid), LINUX_SIGINT);
                    }
                    return (uint64_t)-EINTR;
                }
                if (ch == '\b' || ch == 127) {
                    if (line->line_len > 0) {
                        line->line_len--;
                        if ((line->termios.c_lflag & LINUX_ECHO) != 0) {
                            console_line_write_char(line_id, '\b');
                            console_line_write_char(line_id, ' ');
                            console_line_write_char(line_id, '\b');
                        }
                    }
                    continue;
                }
                if (line->line_len < (int)sizeof(line->linebuf) - 1) {
                    line->linebuf[line->line_len++] = (char)ch;
                    console_line_echo_input_char(line_id, line, ch);
                } else {
                    line->line_drop_count++;
                    if (!line->line_drop_logged) {
                        task_t *t = process_current_task();
                        printf("[tty][drop] pid=%d cmd=%s line=%d canonical input exceeded %u bytes; truncating until newline\n",
                               t ? t->pid : -1,
                               (t && t->name[0]) ? t->name : "?",
                               line_id,
                               (unsigned)(sizeof(line->linebuf) - 1));
                        line->line_drop_logged = 1;
                    }
                }
                if (ch == '\n') break;
            }
        }
        return copied;
    }

    {
        uint64_t count = 0;
        uint64_t minimum = line->termios.c_cc[LINUX_VMIN];
        uint64_t timeout_us =
            (uint64_t)line->termios.c_cc[LINUX_VTIME] * 100000ull;
        uint64_t deadline_us = 0;

        if (minimum > len) minimum = len;
        if (minimum == 0 && timeout_us != 0) {
            deadline_us = boottime_monotonic_us() + timeout_us;
        }

        while (count < len) {
            int ch = console_line_get_noncanonical_char(line_id, line);
            if (ch == -1) {
                uint64_t now_us;

                if (minimum == 0 && timeout_us == 0) break;
                if (count > 0 && minimum == 0) break;
                if (count >= minimum && minimum != 0) break;
                if (signal_pending_interrupt()) {
                    return count ? count : tty_interrupt_current_ret();
                }

                now_us = boottime_monotonic_us();
                if (deadline_us && now_us >= deadline_us) break;
                console_line_sleep_for_input_until(line_id, deadline_us);
                continue;
            }
            ch = console_line_translate_input(line_id, line, ch);
            if (ch == -1) continue;
            if (vt_read_trace_budget > 0 && line_id == console_line_active_vt()) {
                vt_read_trace_budget--;
                printf("[ttyread] pid=%d cmd=%s line=%d canon=0 ch=0x%x count=%llu fg=%d budget=%u\n",
                       cur ? cur->pid : -1,
                       (cur && cur->name[0]) ? cur->name : "?",
                       line_id, (unsigned)ch,
                       (unsigned long long)count,
                       line->session.foreground_pgid,
                       (unsigned)vt_read_trace_budget);
            }
            if ((line->termios.c_lflag & LINUX_ISIG) && ch == 3) {
                uint32_t pending = keyboard_take_sigint_pending();
                if (pending != 0 && line->session.foreground_pgid > 0) {
                    (void)do_sys_kill((uint64_t)(int64_t)(-line->session.foreground_pgid), LINUX_SIGINT);
                }
                return count ? count : (uint64_t)-EINTR;
            }
            console_line_echo_input_char(line_id, line, ch);
            char out = (char)ch;
            if (copy_to_user(buf + count, &out, 1) < 0) return (uint64_t)-EFAULT;
            count++;

            /*
             * Linux starts the inter-byte timer after the first byte and
             * restarts it whenever another byte arrives.  VMIN == 0 instead
             * uses one read-wide timer and completes as soon as input exists.
             */
            if (minimum != 0 && timeout_us != 0) {
                deadline_us = boottime_monotonic_us() + timeout_us;
            }
            if (minimum != 0 && count >= minimum) break;
        }
        return count;
    }
}

static uint64_t do_sys_getcwd(uint64_t buf, uint64_t size) {
    char cwd[VFS_PATH_MAX];
    uint64_t n;
    if (!buf || size == 0) return (uint64_t)-EINVAL;
    if (vfs_getcwd(cwd, sizeof(cwd)) < 0) return (uint64_t)-EIO;
    n = (uint64_t)strlen(cwd) + 1;
    if (size < n) return (uint64_t)-ERANGE;
    if (copy_to_user(buf, cwd, n) < 0) return (uint64_t)-EFAULT;
    return n;
}

static int edge_follow_symlink_components_for_path(const char *path_in, char *path, int path_sz) {
    char abs_path[256];
    char resolved[256];
    if (!path_in || !path || path_sz < 2) return -EINVAL;
    if (path_in[0] == '/') {
        strncpy(abs_path, path_in, sizeof(abs_path) - 1);
        abs_path[sizeof(abs_path) - 1] = 0;
    } else {
        if (build_at_path(LINUX_AT_FDCWD, path_in, abs_path, (int)sizeof(abs_path)) < 0) return -EINVAL;
    }
    if (edge_resolve_symlink_components(abs_path, resolved, (int)sizeof(resolved)) == 0) {
        strncpy(path, resolved, (uint32_t)(path_sz - 1));
    } else {
        strncpy(path, abs_path, (uint32_t)(path_sz - 1));
    }
    path[path_sz - 1] = 0;
    return 0;
}

static int resolve_user_path_follow(uint64_t path_u, char *path, int path_sz, vfs_inode_t *ino, vfs_superblock_t **sb) {
    char path_in[256];
    if (!path_u || !path || path_sz < 2) return -EINVAL;
    if (copy_user_cstr(path_in, sizeof(path_in), path_u) < 0) return -EFAULT;
    if (!path_in[0]) return -ENOENT;
    if (edge_follow_symlink_components_for_path(path_in, path, path_sz) < 0) return -EINVAL;
    if (vfs_resolve(path, ino, sb, 0, 0) < 0) return -ENOENT;
    return 0;
}

void arch_inotify_state_changed(int id) {
    task_t *cur = process_current_task();
    if (id < 0) return;
    for (int pi = 0; pi < EDGE_MAX_FD_PROCS; ++pi) {
        edge_fd_proc_t *fp = g_fd_procs[pi];
        if (!fp || !fp->pid) continue;
        for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
            edge_fd_t *e = &fp->fds[fd];
            if (!e->used || e->kind != FD_INOTIFY || e->pipe_id != id) continue;
            fd_wake_fd_owner_tasks(fp->pid, cur, "inotify");
            break;
        }
    }
}

void arch_fanotify_state_changed(int id) {
    task_t *cur = process_current_task();
    if (id < 0) return;
    for (int pi = 0; pi < EDGE_MAX_FD_PROCS; ++pi) {
        edge_fd_proc_t *fp = g_fd_procs[pi];
        if (!fp || !fp->pid) continue;
        for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
            edge_fd_t *e = &fp->fds[fd];
            if (!e->used || e->kind != FD_FANOTIFY ||
                e->pipe_id != id)
                continue;
            fd_wake_fd_owner_tasks(fp->pid, cur, "fanotify");
            break;
        }
    }
}

void arch_userfaultfd_state_changed(int id) {
    task_t *cur = process_current_task();
    if (id < 0) return;
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        const task_t *view = process_task_by_index(index);
        task_t *task;

        if (!view || view->state == TASK_UNUSED)
            continue;
        task = process_task_by_pid(view->pid);
        if (!task ||
                !task->userfaultfd_wait_active ||
                task->userfaultfd_wait_context != id ||
                kernel_userfaultfd_fault_pending(
                    id, task->userfaultfd_wait_ticket))
            continue;
        task->userfaultfd_wait_active = 0;
        task->userfaultfd_wait_context = -1;
        task->userfaultfd_wait_ticket = 0;
        if (task->state == TASK_BLOCKED)
            scheduler_task_make_runnable(
                task, scheduler_cpu_id());
    }
    for (int pi = 0; pi < EDGE_MAX_FD_PROCS; ++pi) {
        edge_fd_proc_t *fp = g_fd_procs[pi];
        if (!fp || !fp->pid) continue;
        for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
            edge_fd_t *e = &fp->fds[fd];
            if (!e->used || e->kind != FD_USERFAULTFD ||
                e->pipe_id != id)
                continue;
            fd_wake_fd_owner_tasks(fp->pid, cur, "userfaultfd");
            break;
        }
    }
}

void arch_userfaultfd_wait_event(int context_id, uint64_t ticket,
                                 int64_t completion_result) {
    task_t *task;

    (void)completion_result;

    while (kernel_userfaultfd_fault_pending(context_id, ticket)) {
        task = process_current_task();
        if (!task || task->is_idle) {
            wait_blocking_step();
            continue;
        }
        task->userfaultfd_wait_active = 1;
        task->userfaultfd_wait_context = context_id;
        task->userfaultfd_wait_ticket = ticket;
        scheduler_task_set_blocked(task);
        if (!kernel_userfaultfd_fault_pending(context_id, ticket))
            scheduler_task_make_runnable(task, scheduler_cpu_id());
        scheduler_yield();
    }
    task = process_current_task();
    if (task && !task->is_idle) {
        task->userfaultfd_wait_active = 0;
        task->userfaultfd_wait_context = -1;
        task->userfaultfd_wait_ticket = 0;
    }
}

int arch_userfaultfd_consume_completed_event(int64_t *completion_result) {
    (void)completion_result;
    return 0;
}

typedef struct edge_inotify_copy_context {
    uint64_t buffer;
} edge_inotify_copy_context_t;

static int edge_inotify_copy_record(void *opaque, uint64_t offset,
                                    const void *record, uint32_t length) {
    edge_inotify_copy_context_t *context =
        (edge_inotify_copy_context_t *)opaque;
    if (!context || !context->buffer ||
        context->buffer > UINT64_MAX - offset)
        return -1;
    return copy_to_user(context->buffer + offset, record, length);
}

static void edge_inotify_blocking_wait(int inotify_id) {
    kernel_inotify_state_t state;
    task_t *cur = process_current_task();

    if (!cur || cur->is_idle) {
        wait_blocking_step();
        return;
    }

    /*
     * Publish waiter membership before changing scheduler state, then recheck
     * the queue after the task is blocked.  An event arriving before the
     * waiter is blocked is caught by the recheck; an event arriving afterward
     * is handled by kernel_inotify_state_changed().  This is the same
     * condition/register/recheck ordering Linux wait queues require to avoid
     * losing an event between an empty read and schedule().
     */
    cur->fd_wait_active = 1;
    scheduler_task_set_blocked(cur);
    if (kernel_inotify_query(inotify_id, &state) < 0 ||
        state.queued_events != 0) {
        scheduler_task_make_runnable(cur, scheduler_cpu_id());
    }
    scheduler_yield();

    cur = process_current_task();
    if (cur && !cur->is_idle) cur->fd_wait_active = 0;
}

static uint64_t edge_inotify_read_obj(edge_fd_t *e, uint64_t buf_u, uint64_t len_u) {
    edge_inotify_copy_context_t context = { .buffer = buf_u };
    kernel_inotify_state_t state;
    int64_t result;
    if (!e || e->kind != FD_INOTIFY ||
        kernel_inotify_query(e->pipe_id, &state) < 0)
        return (uint64_t)-EBADF;
    for (;;) {
        result = kernel_inotify_read(
            e->pipe_id, edge_inotify_copy_record, &context, len_u);
        if (result != -EDGE_LINUX_EAGAIN)
            return (uint64_t)result;
        if ((e->flags & LINUX_O_NONBLOCK) != 0) return (uint64_t)-EAGAIN;
        if (signal_pending_interrupt()) return tty_interrupt_current_ret();
        edge_inotify_blocking_wait(e->pipe_id);
    }
}

typedef struct edge_fanotify_copy_context {
    uint64_t buffer;
} edge_fanotify_copy_context_t;

static int edge_fanotify_copy_record(void *opaque, uint64_t offset,
                                     const void *record, uint32_t length) {
    edge_fanotify_copy_context_t *context =
        (edge_fanotify_copy_context_t *)opaque;
    if (!context || !context->buffer ||
        context->buffer > UINT64_MAX - offset)
        return -1;
    return copy_to_user(context->buffer + offset, record, length);
}

static uint64_t edge_fanotify_read_obj(edge_fd_t *e, uint64_t buffer,
                                       uint64_t length) {
    edge_fanotify_copy_context_t context = { .buffer = buffer };
    kernel_fanotify_state_t state;
    int64_t result;

    if (!e || e->kind != FD_FANOTIFY ||
        kernel_fanotify_query(e->pipe_id, &state) < 0)
        return (uint64_t)-EBADF;
    for (;;) {
        result = kernel_fanotify_read(
            e->pipe_id, edge_fanotify_copy_record, &context, length);
        if (result != -EDGE_LINUX_EAGAIN)
            return (uint64_t)result;
        if ((e->flags & LINUX_O_NONBLOCK) != 0)
            return (uint64_t)-EAGAIN;
        if (signal_pending_interrupt()) return tty_interrupt_current_ret();
        {
            task_t *cur = process_current_task();
            if (!cur || cur->is_idle) {
                wait_blocking_step();
            } else {
                cur->fd_wait_active = 1;
                scheduler_task_set_blocked(cur);
                if (kernel_fanotify_query(e->pipe_id, &state) < 0 ||
                    state.queued_events != 0)
                    scheduler_task_make_runnable(cur, scheduler_cpu_id());
                scheduler_yield();
                cur = process_current_task();
                if (cur && !cur->is_idle) cur->fd_wait_active = 0;
            }
        }
    }
}

static uint64_t edge_userfaultfd_read_obj(edge_fd_t *e, uint64_t buffer,
                                          uint64_t length) {
    edge_fanotify_copy_context_t context = { .buffer = buffer };
    kernel_userfaultfd_state_t state;
    int64_t result;

    if (!e || e->kind != FD_USERFAULTFD ||
        kernel_userfaultfd_query(e->pipe_id, &state) < 0)
        return (uint64_t)-EBADF;
    for (;;) {
        result = kernel_userfaultfd_read(
            e->pipe_id, edge_fanotify_copy_record, &context, length);
        if (result != -EDGE_LINUX_EAGAIN)
            return (uint64_t)result;
        if ((e->flags & LINUX_O_NONBLOCK) != 0)
            return (uint64_t)-EAGAIN;
        if (signal_pending_interrupt()) return tty_interrupt_current_ret();
        {
            task_t *cur = process_current_task();
            if (!cur || cur->is_idle) {
                wait_blocking_step();
            } else {
                cur->fd_wait_active = 1;
                scheduler_task_set_blocked(cur);
                if (kernel_userfaultfd_query(e->pipe_id, &state) < 0 ||
                    state.queued_events != 0)
                    scheduler_task_make_runnable(cur, scheduler_cpu_id());
                scheduler_yield();
                cur = process_current_task();
                if (cur && !cur->is_idle) cur->fd_wait_active = 0;
            }
        }
    }
}

static uint64_t edge_perf_event_read_obj(int descriptor, edge_fd_t *e,
                                         uint64_t buffer, uint64_t length) {
    kernel_task_scratch_t *scratch = arch_task_scratch_current();
    uint64_t *values;
    uint32_t capacity;
    int64_t result;

    if (!e || e->kind != FD_PERF_EVENT)
        return (uint64_t)-EBADF;
    if (!buffer) return (uint64_t)-EFAULT;
    if (!scratch) return (uint64_t)-EIO;
    values = scratch->perf_event_values;
    capacity = length / sizeof(uint64_t) >
        sizeof(scratch->perf_event_values) /
            sizeof(scratch->perf_event_values[0]) ?
        (uint32_t)(sizeof(scratch->perf_event_values) /
                   sizeof(scratch->perf_event_values[0])) :
        (uint32_t)(length / sizeof(uint64_t));
    result = kernel_perf_event_read_descriptor(
        descriptor, values, capacity);
    if (result < 0) return (uint64_t)result;
    if (copy_to_user(buffer, values, (uint64_t)result) < 0)
        return (uint64_t)-EFAULT;
    return (uint64_t)result;
}

void edge_inotify_notify_path(const char *path, uint32_t mask, const char *name) {
    char event_path[VFS_PATH_MAX];
    if (!path || !path[0]) return;
    if (path[0] == '/') {
        strncpy(event_path, path, sizeof(event_path) - 1);
        event_path[sizeof(event_path) - 1] = 0;
    } else if (build_at_path(LINUX_AT_FDCWD, path, event_path, (int)sizeof(event_path)) < 0) {
        return;
    }
    kernel_inotify_notify_path(event_path, mask, name);
}

void edge_inotify_notify_move(const char *old_path, const char *new_path) {
    char old_abs[VFS_PATH_MAX];
    char new_abs[VFS_PATH_MAX];
    if (!old_path || !new_path) return;
    if (old_path[0] == '/') {
        strncpy(old_abs, old_path, sizeof(old_abs) - 1);
        old_abs[sizeof(old_abs) - 1] = 0;
    } else if (build_at_path(LINUX_AT_FDCWD, old_path, old_abs, (int)sizeof(old_abs)) < 0) {
        return;
    }
    if (new_path[0] == '/') {
        strncpy(new_abs, new_path, sizeof(new_abs) - 1);
        new_abs[sizeof(new_abs) - 1] = 0;
    } else if (build_at_path(LINUX_AT_FDCWD, new_path, new_abs, (int)sizeof(new_abs)) < 0) {
        return;
    }
    kernel_inotify_notify_move(old_abs, new_abs);
}

static uint64_t do_sys_chdir(uint64_t path_u) {
    char path[256];
    vfs_inode_t ino;
    int rc = resolve_user_path_follow(path_u, path, sizeof(path), &ino, 0);
    if (rc < 0) return (uint64_t)rc;
    if ((ino.mode & 0xF000u) != VFS_INODE_DIR) return (uint64_t)-ENOTDIR;
    return vfs_chdir(path) == 0 ? 0 : (uint64_t)-EINVAL;
}

static uint64_t do_sys_ls(uint64_t path_u, uint64_t longf) {
    char path[256];
    if (!path_u) {
        vfs_list(0, (int)longf);
        return 0;
    }
    if (copy_user_cstr(path, sizeof(path), path_u) < 0) return (uint64_t)-EFAULT;
    vfs_list(path, (int)longf);
    return 0;
}

static uint64_t do_sys_mkdir(uint64_t path_u) {
    char path[256];
    vfs_inode_t ino;
    if (!path_u) return (uint64_t)-EINVAL;
    if (copy_user_cstr(path, sizeof(path), path_u) < 0) return (uint64_t)-EFAULT;
    if (vfs_resolve(path, &ino, 0, 0, 0) == 0) return (uint64_t)-EEXIST;
    return vfs_mkdir(path) == 0 ? 0 : (uint64_t)-ENOENT;
}

static uint64_t do_sys_touch(uint64_t path_u) {
    char path[256];
    if (!path_u) return (uint64_t)-EINVAL;
    if (copy_user_cstr(path, sizeof(path), path_u) < 0) return (uint64_t)-EFAULT;
    return vfs_touch(path) == 0 ? 0 : (uint64_t)-EINVAL;
}

static uint64_t do_sys_unlink(uint64_t path_u) {
    char path[256];
    vfs_inode_t ino;
    int bind_idx;
    int bind_sock = -1;
    if (!path_u) return (uint64_t)-EINVAL;
    if (copy_user_cstr(path, sizeof(path), path_u) < 0) return (uint64_t)-EFAULT;
    if (vfs_resolve(path, &ino, 0, 0, 0) < 0) return (uint64_t)-ENOENT;
    if ((ino.mode & 0xF000u) == VFS_INODE_DIR) return (uint64_t)-EISDIR;
    bind_idx = unix_binding_find_path(path);
    if (bind_idx >= 0) bind_sock = g_unix_bindings[bind_idx].sock_id;
    x11_unix_trace_binding("unlink-enter", path, -1, bind_sock, 0);
    if (vfs_unlink(path) < 0) {
        x11_unix_trace_binding("unlink-vfs-fail", path, -1, bind_sock, -EIO);
        return (uint64_t)-EIO;
    }
    unix_binding_unregister_path(path);
    return 0;
}

static uint64_t do_sys_cat(uint64_t path_u) {
    char path[256];
    static char buf[65536];
    if (!path_u) return (uint64_t)-EINVAL;
    if (copy_user_cstr(path, sizeof(path), path_u) < 0) return (uint64_t)-EFAULT;
    int n = vfs_read_file(path, buf, sizeof(buf));
    if (n < 0) return (uint64_t)-EINVAL;
    for (int i = 0; i < n; ++i) console_putchar(buf[i]);
    if (n == 0 || buf[n - 1] != '\n') console_putchar('\n');
    return 0;
}

static uint64_t do_sys_statfs(uint64_t path_u, uint64_t total_u, uint64_t used_u) {
    char path[256];
    uint32_t total_kb = 0, used_kb = 0;
    const char *p = 0;
    if (path_u) {
        if (copy_user_cstr(path, sizeof(path), path_u) < 0) return (uint64_t)-EFAULT;
        p = path;
    }
    if (vfs_statfs_path(p ? p : "", &total_kb, &used_kb) < 0) return (uint64_t)-EINVAL;
    if (total_u && copy_to_user(total_u, &total_kb, sizeof(total_kb)) < 0) return (uint64_t)-EFAULT;
    if (used_u && copy_to_user(used_u, &used_kb, sizeof(used_kb)) < 0) return (uint64_t)-EFAULT;
    return 0;
}

static uint64_t do_sys_meminfo(uint64_t total_u, uint64_t used_u, uint64_t free_u) {
    uint64_t t = meminfo_total_bytes();
    uint64_t u = meminfo_used_bytes();
    uint64_t f = meminfo_free_bytes();
    if (total_u && copy_to_user(total_u, &t, sizeof(t)) < 0) return (uint64_t)-EFAULT;
    if (used_u && copy_to_user(used_u, &u, sizeof(u)) < 0) return (uint64_t)-EFAULT;
    if (free_u && copy_to_user(free_u, &f, sizeof(f)) < 0) return (uint64_t)-EFAULT;
    return 0;
}

static uint64_t do_sys_mounts(void) {
    vfs_list_mounts();
    return 0;
}

static uint64_t do_sys_mount(uint64_t src_u, uint64_t target_u, uint64_t fs_u) {
    char src[256];
    char target[256];
    char fsname[32];
    vfs_inode_t ino;
    block_device_t *bdev = 0;

    if (!src_u || !target_u) return (uint64_t)-EINVAL;
    if (copy_user_cstr(src, sizeof(src), src_u) < 0) return (uint64_t)-EFAULT;
    if (copy_user_cstr(target, sizeof(target), target_u) < 0) return (uint64_t)-EFAULT;
    if (fs_u) {
        if (copy_user_cstr(fsname, sizeof(fsname), fs_u) < 0) return (uint64_t)-EFAULT;
    } else {
        strcpy(fsname, "ext4");
    }

    if (vfs_resolve(src, &ino, 0, 0, 0) < 0) return (uint64_t)-EINVAL;
    if (vfs_inode_get_block_device(&ino, &bdev) < 0) return (uint64_t)-EINVAL;
    (void)vfs_mkdir(target);
    return vfs_mount_blockdev(bdev, target, fsname) == 0 ? 0 : (uint64_t)-EINVAL;
}

static uint64_t do_sys_shutdown(void) {
    __asm__ __volatile__("cli");
    for (;;) __asm__ __volatile__("hlt");
    return 0;
}

static void edge_machine_halt(void) {
    __asm__ __volatile__("cli");
    for (;;) __asm__ __volatile__("hlt");
}

static void edge_machine_poweroff(void) {
    __asm__ __volatile__("cli");

#ifdef CONFIG_ACPI
    if (acpi_poweroff() == 0) {
        for (;;) __asm__ __volatile__("hlt");
    }
#endif

    /* Last-resort emulator ports used only when firmware S5 data is absent. */
    outports(0x604, 0x2000);
    outports(0xB004, 0x2000);
    outports(0x4004, 0x3400);

    edge_machine_halt();
}

static void edge_machine_restart(void) {
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) null_idtr = {0, 0};

    __asm__ __volatile__("cli");

    /* QEMU/modern chipsets: reset control register. */
    outportb(0xCF9, 0x02);
    outportb(0xCF9, 0x06);

    for (int i = 0; i < 100000; ++i) {
        if ((inportb(0x64) & 0x02u) == 0) break;
    }
    outportb(0x64, 0xFE);

    /* Fallback for emulators/firmware that ignore the 8042 reset pulse. */
    __asm__ __volatile__("lidt %0" : : "m"(null_idtr));
    __asm__ __volatile__("int3");
    for (;;) __asm__ __volatile__("hlt");
}

static void reboot_trace_puts(const char *s) {
    if (!s) return;
    while (*s) serial_console_write_raw(*s++);
}

static void reboot_trace_hex(uint64_t v) {
    static const char hex[] = "0123456789abcdef";
    reboot_trace_puts("0x");
    for (int i = 15; i >= 0; --i) {
        serial_console_write_raw(hex[(v >> ((uint64_t)i * 4u)) & 0xfu]);
    }
}

static void reboot_trace_dec(int v) {
    char buf[16];
    int n = 0;
    unsigned int u;
    if (v < 0) {
        serial_console_write_raw('-');
        u = (unsigned int)(-v);
    } else {
        u = (unsigned int)v;
    }
    do {
        buf[n++] = (char)('0' + (u % 10u));
        u /= 10u;
    } while (u && n < (int)sizeof(buf));
    while (n > 0) serial_console_write_raw(buf[--n]);
}

int64_t edge_system_runtime_power_action(kernel_power_action_t action) {
    task_t *cur = process_current_task();

    reboot_trace_puts("[reboot-sys] pid=");
    reboot_trace_dec(cur ? cur->pid : -1);
    reboot_trace_puts(" name=");
    reboot_trace_puts(cur ? cur->name : "?");
    reboot_trace_puts(" cmd=");
    reboot_trace_hex((uint32_t)action);
    reboot_trace_puts("\n");

    switch (action) {
        case KERNEL_POWER_RESTART:
            edge_machine_restart();
            return -EIO;
        case KERNEL_POWER_OFF:
            edge_machine_poweroff();
            return -EIO;
        case KERNEL_POWER_HALT:
            edge_machine_halt();
            return -EIO;
        default:
            return -EINVAL;
    }
}

static uint64_t do_sys_ps(void) {
    process_list_print();
    return 0;
}

static void edge_signal_sender_info(struct edge_linux_siginfo_min *information,
                                    int signal, int code) {
    task_t *sender = process_current_task();
    if (!information) return;
    memset(information, 0, sizeof(*information));
    information->si_signo = signal;
    information->si_code = code;
    information->si_pid = sender ? sender->pid : 0;
    information->si_uid = sender ? (int32_t)sender->uid : 0;
}

static uint64_t do_sys_kill(uint64_t pid, uint64_t sig) {
    int ipid = (int)pid;
    int global_pid = ipid;
    int isig = (int)sig;
    struct edge_linux_siginfo_min information;
    if (ipid == 0) return (uint64_t)-EINVAL;
    if (ipid > 0) {
        task_t *current = process_current_task();
        uint32_t pid_namespace = current ? current->namespaces.pid : 0u;

        if (edge_pid_namespace_visible_to_global(
                pid_namespace, ipid, &global_pid) < 0)
            return (uint64_t)-ESRCH;
    }
    if (isig == 0) {
        if (ipid > 0)
            return process_get_task(global_pid) ? 0 : (uint64_t)-ESRCH;
        for (int i = 0; i < PROC_MAX_TASKS; ++i) {
            const task_t *t = process_task_by_index(i);
            if (!t || t->state == TASK_UNUSED) continue;
            if (t->pgid == -ipid) return 0;
        }
        return (uint64_t)-ESRCH;
    }
    if (isig != LINUX_SIGTERM && isig != LINUX_SIGKILL &&
        isig != LINUX_SIGINT && isig != LINUX_SIGABRT &&
        isig != LINUX_SIGQUIT && isig != LINUX_SIGALRM &&
        isig != LINUX_SIGCHLD && isig != LINUX_SIGIO &&
        isig != LINUX_SIGUSR1 && isig != LINUX_SIGUSR2 &&
        isig != LINUX_SIGCONT && isig != LINUX_SIGSTOP &&
        isig != LINUX_SIGTSTP && isig != LINUX_SIGTTIN &&
        isig != LINUX_SIGTTOU &&
        !linux_sig_is_rt((uint64_t)isig)) {
        return (uint64_t)-EINVAL;
    }
    edge_signal_sender_info(&information, isig, 0);
    if (ipid > 0) {
        const task_t *target = process_get_task(global_pid);
        int result;

        /*
         * A zombie remains an existing process until wait reaps it.  Linux
         * therefore accepts kill(pid, sig) during this interval even though
         * no signal can alter the already completed exit.  Chromium relies
         * on this when a short-lived zygote child exits before its parent can
         * complete the startup handshake and issue its cleanup SIGKILL.
         */
        if (target && target->state == TASK_ZOMBIE) return 0;
        result = process_send_signal_info(global_pid, isig, &information);
        if (result == -EDGE_LINUX_EAGAIN) return (uint64_t)-EAGAIN;
        return result == 0 ? 0 : (uint64_t)-ESRCH;
    }
    return process_send_signal_pgid_info(-ipid, isig, &information) == 0 ?
           0 : (uint64_t)-ESRCH;
}

static int socket_try_fill_ping_hw_reply(edge_socket_t *s) {
    uint32_t ip_len;
    uint32_t src_ip_be = 0;
    uint8_t src_ip6[16];
    int rc;

    if (!s) return 0;
    if (s->rx_len > 0) return 1;
    if (!(s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6)) return 0;
    if (!(s->type == LINUX_SOCK_RAW || s->type == LINUX_SOCK_DGRAM)) return 0;
    if (s->domain == LINUX_AF_INET && s->protocol != LINUX_IPPROTO_ICMP)
        return 0;
    if (s->domain == LINUX_AF_INET6 &&
        s->protocol != LINUX_IPPROTO_ICMPV6)
        return 0;

    if (s->domain == LINUX_AF_INET && s->ping_hw) {
        ip_len = socket_rx_capacity(s);
        rc = lwip_stack_recv_icmp_reply_for_id(s->ping_id_be, s->rx_buf, &ip_len, &src_ip_be);
        if (rc <= 0) return 0;

        if (s->type == LINUX_SOCK_DGRAM && ip_len >= 20) {
            uint32_t ihl = (uint32_t)(s->rx_buf[0] & 0x0Fu) * 4u;
            if (ihl >= 20 && ihl <= ip_len) {
                memmove(s->rx_buf, s->rx_buf + ihl, ip_len - ihl);
                ip_len -= ihl;
            }
        }

        s->rx_len = ip_len;
        {
            struct edge_sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = LINUX_AF_INET;
            sin.sin_addr = src_ip_be;
            memcpy(s->rx_peer, &sin, sizeof(sin));
            s->rx_peer_len = sizeof(sin);
        }
        return 1;
    }

    if (s->domain == LINUX_AF_INET6 && s->ping_hw) {
        ip_len = socket_rx_capacity(s);
        rc = lwip_stack_recv_icmpv6_reply_for_id(s->ping_id_be, s->rx_buf, &ip_len, src_ip6);
        if (rc <= 0) return 0;
        if (s->type == LINUX_SOCK_RAW && ip_len > 0u &&
            !kernel_socket_icmp6_filter_allows(
                &s->option_state, s->rx_buf[0]))
            return 0;

        s->rx_len = ip_len;
        sockaddr_in6_to_user_peer(s, src_ip6, 0, 0);
        return 1;
    }

    if (s->domain == LINUX_AF_INET) {
        ip_len = socket_rx_capacity(s);
        rc = lwip_stack_recv_icmp_packet(s->rx_buf, &ip_len, &src_ip_be);
        if (rc <= 0) return 0;

        if (s->type == LINUX_SOCK_DGRAM && ip_len >= 20) {
            uint32_t ihl = (uint32_t)(s->rx_buf[0] & 0x0Fu) * 4u;
            if (ihl >= 20 && ihl <= ip_len) {
                memmove(s->rx_buf, s->rx_buf + ihl, ip_len - ihl);
                ip_len -= ihl;
            }
        }

        s->rx_len = ip_len;
        {
            struct edge_sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = LINUX_AF_INET;
            sin.sin_addr = src_ip_be;
            memcpy(s->rx_peer, &sin, sizeof(sin));
            s->rx_peer_len = sizeof(sin);
        }
        return 1;
    }

    return 0;
}

static int socket_try_fill_packet_frame(edge_socket_t *s) {
    uint8_t frame[1600];
    uint32_t frame_len;
    const uint8_t *payload;
    uint32_t payload_len;
    int rc;

    if (!s) return 0;
    if (s->rx_len > 0) return 1;
    if (s->domain != LINUX_AF_PACKET) return 0;
    if (!(s->type == LINUX_SOCK_RAW || s->type == LINUX_SOCK_DGRAM)) return 0;

    frame_len = sizeof(frame);
    rc = lwip_stack_recv_packet_frame(frame, &frame_len);
    if (rc <= 0) return 0;
    payload = frame;
    payload_len = frame_len;

    /*
     * Linux AF_PACKET SOCK_DGRAM sockets expose "cooked" packets: the device
     * link-layer header is not part of the byte stream returned to userspace.
     * BusyBox udhcpc uses this mode and expects an IPv4 packet beginning at the
     * IP header.  SOCK_RAW keeps the full Ethernet frame for packet sniffers
     * and tools that intentionally requested L2 access.
     */
    if (s->type == LINUX_SOCK_DGRAM && frame_len >= 14 &&
        ((frame[12] == 0x08 && frame[13] == 0x00) ||
         (frame[12] == 0x86 && frame[13] == 0xdd) ||
         (frame[12] == 0x08 && frame[13] == 0x06))) {
        payload = frame + 14;
        payload_len = frame_len - 14;
    }

    if (payload_len > socket_rx_capacity(s)) return 0;
    memcpy(s->rx_buf, payload, payload_len);
    s->rx_len = payload_len;
    s->rx_peer_len = 0;
    return 1;
}

void syscall_network_poll(void) {
    static kernel_socket_external_readiness_t producers_seen;
    static volatile uint8_t poll_active;
    uint64_t packet_frame_sequence;
    uint64_t icmp_sequence;
    uint64_t packet_ring_sequence;
    uint8_t expected = 0u;

    if (!__atomic_compare_exchange_n(
            &poll_active, &expected, 1u, 0,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        /*
         * A caller may already have consumed the shared deferred-work latch.
         * Preserve that notification when another CPU owns this bounded poll
         * turn; the owner or the next syscall boundary will service it.
         */
        scheduler_request_deferred_work();
        return;
    }

    lwip_stack_poll();
    socket_expire_connect_timeouts();
    packet_frame_sequence =
        lwip_stack_packet_frame_readiness_sequence();
    icmp_sequence = lwip_stack_icmp_readiness_sequence();
    packet_ring_sequence = edge_linux_packet_readiness_sequence();
    if (!(kernel_socket_external_readiness_observe(
              &producers_seen, packet_frame_sequence,
              icmp_sequence, packet_ring_sequence) &
          KERNEL_SOCKET_READINESS_READ_CHANGED)) {
        __atomic_store_n(&poll_active, 0u, __ATOMIC_RELEASE);
        return;
    }
    for (int socket_index = 0;
         socket_index < EDGE_MAX_SOCKETS; ++socket_index) {
        edge_socket_t *socket = &g_sockets[socket_index];
        uint64_t observed_packet_frame = 0u;
        uint64_t observed_icmp = 0u;
        uint64_t observed_ring = 0u;
        uint32_t changed;
        int readable = 0;

        if (!socket->used) continue;
        if (socket->domain == LINUX_AF_PACKET) {
            observed_packet_frame = packet_frame_sequence;
            if (socket->packet_handle >= 0)
                observed_ring =
                    edge_linux_packet_ring_readiness_sequence(
                        socket->packet_handle);
        } else if (socket_is_icmp_reader(socket)) {
            observed_icmp = icmp_sequence;
        } else {
            continue;
        }
        changed = kernel_socket_external_readiness_observe(
            &socket->external_readiness,
            observed_packet_frame, observed_icmp, observed_ring);
        if (!(changed & KERNEL_SOCKET_READINESS_READ_CHANGED))
            continue;
        if (socket->domain == LINUX_AF_PACKET) {
            readable = socket_try_fill_packet_frame(socket);
            if (socket->packet_handle >= 0 &&
                edge_linux_packet_ring_ready(socket->packet_handle))
                readable = 1;
        } else {
            readable = socket_try_fill_ping_hw_reply(socket);
        }
        if (readable)
            fd_wake_socket_waiters_events(
                socket_index, LINUX_POLLIN | LINUX_POLLPRI |
                              LINUX_POLLRDNORM | LINUX_POLLRDBAND);
    }
    __atomic_store_n(&poll_active, 0u, __ATOMIC_RELEASE);
}

typedef struct edge_signalfd_copy_context {
    uint64_t buffer;
} edge_signalfd_copy_context_t;

static int edge_signalfd_copy_record(
    void *opaque, uint64_t offset,
    const struct edge_linux_signalfd_siginfo *information) {
    edge_signalfd_copy_context_t *context =
        (edge_signalfd_copy_context_t *)opaque;
    if (!context || !context->buffer ||
        context->buffer > UINT64_MAX - offset)
        return -1;
    return copy_to_user(context->buffer + offset, information,
                        sizeof(*information));
}

static int console_line_pollin_ready(int line_id);
static int g_x11_poll_trace_budget = EDGE_X11_BOOT_TRACE ? 160 : 0;
static int g_gui_poll_ready_trace_budget = 0;
static int g_xfce_poll_detail_trace_budget = EDGE_XFCE_POLL_DETAIL_TRACE ? 160 : 0;
static int g_xfce_socket_poll_diag_budget = EDGE_GUI_DEEP_TRACE ? 8 : 0;
static int g_gui_poll_ready_list_trace_budget = EDGE_GUI_DEEP_TRACE ? 12 : 0;
static int g_gui_pty_trace_budget = EDGE_PTY_DIAG_TRACE ? 96 : 0;
static int g_pty_open_trace_budget = EDGE_PTY_DIAG_TRACE ? 192 : 0;
static int g_pty_stat_trace_budget = EDGE_PTY_DIAG_TRACE ? 128 : 0;

static int gui_poll_task(const task_t *t) {
#if EDGE_XFCE_TRACE
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "InputThread") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "xfconfd") == 0 ||
           strcmp(t->name, "Thunar") == 0 ||
           strcmp(t->name, "Terminal") == 0 ||
           strcmp(t->name, "xfce4-terminal") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0;
#else
    (void)t;
    return 0;
#endif
}

static int x11_poll_trace_task(const task_t *t) {
#if EDGE_X11_TRACE || EDGE_XFCE_TRACE || EDGE_X11_BOOT_TRACE
    if (!t || !t->name[0]) return 0;
#if EDGE_X11_TRACE
    return strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "InputThread") == 0 ||
           strcmp(t->name, "xrdb") == 0 ||
           strcmp(t->name, "xsetroot") == 0 ||
           strcmp(t->name, "twm") == 0 ||
           strcmp(t->name, "xterm") == 0 ||
           strcmp(t->name, "xclock") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "dbus-launch") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0 ||
           strcmp(t->name, "xwininfo") == 0 ||
           strcmp(t->name, "xdpyinfo") == 0 ||
           strcmp(t->name, "xdotool") == 0;
#elif EDGE_X11_BOOT_TRACE
    return strcmp(t->name, "xrdb") == 0;
#else
    /*
     * Keep XFCE poll tracing on the session/DBus side.  The X server itself is
     * already known to move data correctly, and tracing every Xorg poll through
     * UART delays the slow GTK/XFCE startup path enough to hide the real bug.
     */
    return strcmp(t->name, "xclock") == 0 ||
           strcmp(t->name, "xterm") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "dbus-launch") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0;
#endif
#else
    (void)t;
    return 0;
#endif
}

static int gui_hot_poll_task(const task_t *t) {
    if (!t || !t->name[0]) return 0;
    /* Most tasks, including browser renderer and worker threads, cannot match
     * this legacy desktop compatibility set.  Reject them before entering a
     * chain of string comparisons on every ready poll/epoll syscall. */
    switch (t->name[0]) {
        case 'X':
            return strcmp(t->name, "Xorg") == 0;
        case 'I':
            return strcmp(t->name, "InputThread") == 0;
        case 'x':
            return strcmp(t->name, "xfce4-session") == 0 ||
                   strcmp(t->name, "xfwm4") == 0 ||
                   strcmp(t->name, "xfsettingsd") == 0 ||
                   strcmp(t->name, "xfdesktop") == 0 ||
                   strcmp(t->name, "xfce4-panel") == 0 ||
                   strcmp(t->name, "xfce4-terminal") == 0;
        case 'T':
            return strcmp(t->name, "Thunar") == 0;
        case 'd':
            return strcmp(t->name, "dbus-launch") == 0 ||
                   strcmp(t->name, "dbus-daemon") == 0;
        case 'a':
            return strcmp(t->name, "at-spi-bus-launcher") == 0 ||
                   strcmp(t->name, "at-spi2-registryd") == 0;
        default:
            return 0;
    }
}

static int xfce_poll_detail_task(const task_t *t) {
#if EDGE_XFCE_POLL_DETAIL_TRACE
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfce4-terminal") == 0 ||
           strcmp(t->name, "Thunar") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "xfwm4") == 0;
#else
    (void)t;
    return 0;
#endif
}

static void xfce_poll_detail_log(const task_t *cur, int fd, edge_fd_t *e,
                                 int16_t events, int16_t revents) {
    uint64_t eventfd_counter = 0;
    int socket_peer = -1;
    uint32_t socket_rx = 0;
    uint64_t socket_rseq = 0;
    uint64_t socket_wseq = 0;
    if (g_xfce_poll_detail_trace_budget <= 0 || !xfce_poll_detail_task(cur) || revents == 0) return;
    if (e && e->kind == FD_EVENTFD) {
        eventfd_counter = eventfd_counter_snapshot(e->pipe_id);
    } else if (e && e->kind == FD_SOCKET &&
               e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_SOCKETS &&
               g_sockets[e->pipe_id].used) {
        edge_socket_t *s = &g_sockets[e->pipe_id];
        socket_peer = s->unix_peer_id;
        socket_rx = s->rx_len;
        kernel_socket_readiness_snapshot(
            &s->readiness, &socket_rseq, &socket_wseq);
    }
    printf("[xfce-poll] pid=%d cmd=%s fd=%d kind=%d id=%d ev=0x%x rev=0x%x fl=0x%x path=%s evcnt=%llu peer=%d rx=%u rseq=%llu wseq=%llu budget=%d\n",
           cur ? cur->pid : -1, cur ? cur->name : "?",
           fd, e ? (int)e->kind : -1, e ? e->pipe_id : -1,
           (unsigned)events, (unsigned)revents,
           e ? (unsigned)e->flags : 0,
           (e && e->path[0]) ? e->path : "-",
           (unsigned long long)eventfd_counter,
           socket_peer, socket_rx,
           (unsigned long long)socket_rseq,
           (unsigned long long)socket_wseq,
           g_xfce_poll_detail_trace_budget - 1);
    g_xfce_poll_detail_trace_budget--;
}

static void gui_ready_detail_log(const char *op, const task_t *cur, int fd,
                                 edge_fd_t *e, int events, int revents,
                                 int ready_count, int nfds) {
    uint64_t eventfd_counter = 0;
    uint64_t timerfd_exp = 0;
    int epoll_watch = -1;
    int socket_peer = -1;
    uint32_t socket_rx = 0;
    uint64_t socket_rseq = 0;
    uint64_t socket_wseq = 0;

    if (g_gui_ready_detail_trace_budget <= 0 || !gui_diag_task(cur) || revents == 0) return;
    if (e && e->kind == FD_EVENTFD) {
        eventfd_counter = eventfd_counter_snapshot(e->pipe_id);
    } else if (e && e->kind == FD_TIMERFD) {
        timerfd_exp = timerfd_expiration_snapshot(e->pipe_id);
    } else if (e && e->kind == FD_EPOLL) {
        kernel_epoll_object_snapshot_t epoll;
        if (kernel_epoll_object_snapshot(e->pipe_id, &epoll) == 0)
            epoll_watch = epoll.nwatch;
    } else if (e && e->kind == FD_SOCKET &&
               e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_SOCKETS &&
               g_sockets[e->pipe_id].used) {
        edge_socket_t *s = &g_sockets[e->pipe_id];
        socket_peer = s->unix_peer_id;
        socket_rx = s->rx_len;
        kernel_socket_readiness_snapshot(
            &s->readiness, &socket_rseq, &socket_wseq);
    }
    printf("[gui-ready] op=%s pid=%d cmd=%s fd=%d kind=%d id=%d ev=0x%x rev=0x%x ready=%d nfds=%d fl=0x%x path=%s evcnt=%llu texp=%llu epn=%d peer=%d rx=%u rseq=%llu wseq=%llu budget=%d\n",
           op ? op : "?",
           cur ? cur->pid : -1, cur ? cur->name : "?",
           fd, e ? (int)e->kind : -1, e ? e->pipe_id : -1,
           (unsigned)events, (unsigned)revents, ready_count, nfds,
           e ? (unsigned)e->flags : 0,
           (e && e->path[0]) ? e->path : "-",
           (unsigned long long)eventfd_counter,
           (unsigned long long)timerfd_exp, epoll_watch,
           socket_peer, socket_rx,
           (unsigned long long)socket_rseq,
           (unsigned long long)socket_wseq,
           g_gui_ready_detail_trace_budget - 1);
    g_gui_ready_detail_trace_budget--;
}

static void x11_trace_socket_poll(task_t *cur, const char *op, int fd, edge_fd_t *e,
                                  int events, int rev) {
    if (!x11_poll_trace_task(cur) || g_x11_poll_trace_budget-- <= 0) return;
    if (!e || e->kind != FD_SOCKET || e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS) return;
    edge_socket_t *s = &g_sockets[e->pipe_id];
    printf("[x11dbg] %s pid=%d cmd=%s fd=%d sid=%d ev=0x%x rev=0x%x used=%d listen=%d pending=%d rx=%u closed=%d peer=%d\n",
           op, cur ? cur->pid : -1, cur ? cur->name : "?",
           fd, e->pipe_id, events, rev, s->used, s->listening,
           socket_pending_count(s), s->rx_len, s->closed,
           s->unix_peer_id);
}

static void xfce_socket_poll_diag(edge_fd_t *e, int events, int rev) {
    task_t *cur = process_current_task();
    edge_socket_t *s;
    uint64_t read_sequence;
    uint64_t write_sequence;
    int suspicious_read;

    if (g_xfce_socket_poll_diag_budget <= 0 || rev == 0) return;
    if (!cur || !gui_hot_poll_task(cur)) return;
    if (!e || e->kind != FD_SOCKET ||
        e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS) {
        return;
    }
    s = &g_sockets[e->pipe_id];
    if (!s->used) return;

    /*
     * XFCE/GTK/Xorg event loops should see poll readiness that agrees with the
     * next nonblocking socket operation.  A readable result with no queued
     * bytes and no EOF/error is a red flag: userland will immediately retry
     * recvmsg(), get EAGAIN, and spin.  Keep this log bounded because the X11
     * socket path is extremely hot once a full desktop starts.
     */
    suspicious_read = (rev & (LINUX_POLLIN | LINUX_POLLPRI)) &&
                      s->rx_len == 0 &&
                      !(s->type == LINUX_SOCK_STREAM && (s->rx_closed || s->closed)) &&
                      !(s->listening &&
                        socket_pending_count(s) > 0);
    if (!suspicious_read) return;
    kernel_socket_readiness_snapshot(
        &s->readiness, &read_sequence, &write_sequence);

    printf("[xfce-sockpoll] pid=%d cmd=%s sid=%d ev=0x%x rev=0x%x "
           "domain=%d type=%d listen=%d pending=%d rx=%u closed=%d "
           "rxclosed=%d peer=%d rseq=%llu wseq=%llu suspicious=%d budget=%d\n",
           cur->pid, cur->name, e->pipe_id, (unsigned)events,
           (unsigned)rev, s->domain, s->type, s->listening,
           socket_pending_count(s), s->rx_len, s->closed,
           s->rx_closed,
           s->unix_peer_id,
           (unsigned long long)read_sequence,
           (unsigned long long)write_sequence,
           suspicious_read, g_xfce_socket_poll_diag_budget - 1);
    g_xfce_socket_poll_diag_budget--;
}

static uint32_t anonymous_fd_ready_events(edge_fd_t *descriptor) {
    kernel_anonymous_fd_poll_state_t poll_state;

    memset(&poll_state, 0, sizeof(poll_state));
    poll_state.valid = 1;
    if (descriptor->kind == FD_EVENTFD) {
        kernel_eventfd_state_t state;
        poll_state.kind = KERNEL_ANONYMOUS_FD_EVENT;
        if (!eventfd_snapshot(descriptor->pipe_id, &state))
            poll_state.valid = 0;
        else
            poll_state.counter = state.counter;
    } else if (descriptor->kind == FD_TIMERFD) {
        kernel_timerfd_state_t state;
        poll_state.kind = KERNEL_ANONYMOUS_FD_TIMER;
        if (!timerfd_snapshot(descriptor->pipe_id, &state))
            poll_state.valid = 0;
        else {
            poll_state.counter = state.expirations;
            poll_state.canceled = state.canceled;
        }
    } else if (descriptor->kind == FD_SIGNALFD) {
        kernel_signalfd_state_t state;
        poll_state.kind = KERNEL_ANONYMOUS_FD_SIGNAL;
        if (kernel_signalfd_query(descriptor->pipe_id, &state) < 0)
            poll_state.valid = 0;
        else
            poll_state.pending =
                kernel_signalfd_current_pending(state.mask);
    } else if (descriptor->kind == FD_INOTIFY) {
        kernel_inotify_state_t state;
        poll_state.kind = KERNEL_ANONYMOUS_FD_INOTIFY;
        if (kernel_inotify_query(descriptor->pipe_id, &state) < 0)
            poll_state.valid = 0;
        else
            poll_state.pending = state.queued_events != 0;
    } else if (descriptor->kind == FD_FANOTIFY) {
        kernel_fanotify_state_t state;
        poll_state.kind = KERNEL_ANONYMOUS_FD_FANOTIFY;
        if (kernel_fanotify_query(descriptor->pipe_id, &state) < 0)
            poll_state.valid = 0;
        else
            poll_state.pending = state.queued_events != 0;
    } else if (descriptor->kind == FD_USERFAULTFD) {
        kernel_userfaultfd_state_t state;
        poll_state.kind = KERNEL_ANONYMOUS_FD_USERFAULTFD;
        if (kernel_userfaultfd_query(descriptor->pipe_id, &state) < 0)
            poll_state.valid = 0;
        else
            poll_state.pending = state.queued_events != 0;
    } else if (descriptor->kind == FD_PERF_EVENT) {
        kernel_perf_event_state_t state;
        poll_state.kind = KERNEL_ANONYMOUS_FD_PERF_EVENT;
        if (kernel_perf_event_query(descriptor->pipe_id, &state) < 0)
            poll_state.valid = 0;
    } else if (descriptor->kind == FD_PIDFD) {
        const task_t *task = process_get_task(descriptor->pipe_id);
        poll_state.kind = KERNEL_ANONYMOUS_FD_PID;
        poll_state.pending = !task || task->state == TASK_ZOMBIE;
    } else if (descriptor->kind == FD_MQUEUE) {
        kernel_posix_mq_state_t state;
        poll_state.kind = KERNEL_ANONYMOUS_FD_MESSAGE_QUEUE;
        if (kernel_posix_mq_query(descriptor->pipe_id, &state) < 0)
            poll_state.valid = 0;
        else {
            poll_state.pending = state.readable;
            poll_state.writable = state.writable;
        }
    } else if (descriptor->kind == FD_IO_URING) {
        poll_state.kind = KERNEL_ANONYMOUS_FD_IO_URING;
        poll_state.pending =
            kernel_io_uring_completion_count(descriptor->pipe_id) != 0;
    } else if (descriptor->kind == FD_SECCOMP) {
        edge_seccomp_listener_state_t state;
        poll_state.kind = KERNEL_ANONYMOUS_FD_SECCOMP;
        if (edge_seccomp_listener_query(descriptor->pipe_id, &state) < 0)
            poll_state.valid = 0;
        else {
            poll_state.pending = state.queued != 0;
            poll_state.writable = state.delivered != 0;
            poll_state.canceled = state.detached;
        }
    } else {
        poll_state.valid = 0;
    }
    return kernel_anonymous_fd_poll_events(&poll_state);
}

static int pty_poll_state_snapshot(edge_fd_t *descriptor,
                                   kernel_pty_poll_state_t *state) {
    edge_pty_t *pty;

    if (!state) return -1;
    memset(state, 0, sizeof(*state));
    if (descriptor->pipe_id < 0 ||
        descriptor->pipe_id >= EDGE_MAX_PTYS)
        return -1;
    pty = &g_ptys[descriptor->pipe_id];
    state->valid = pty->used;
    state->capacity = EDGE_PTY_BUF_SIZE;
    state->read_count = descriptor->kind == FD_PTY_MASTER ?
                        pty->s2m_count : pty->m2s_count;
    state->write_count = descriptor->kind == FD_PTY_MASTER ?
                         pty->m2s_count : pty->s2m_count;
    state->peer_references = descriptor->kind == FD_PTY_MASTER ?
                             pty->refs_slave : pty->refs_master;
    return 0;
}

static uint32_t pty_ready_events(edge_fd_t *descriptor) {
    kernel_pty_poll_state_t state;

    if (pty_poll_state_snapshot(descriptor, &state) < 0)
        return KERNEL_PTY_POLL_NVAL;
    return kernel_pty_poll_events(&state);
}

static int poll_fd_revents(edge_fd_t *e, int16_t events) {
    int16_t rev = 0;
    int bridge_cdev = 0;
    const int16_t read_events = LINUX_POLLIN | LINUX_POLLPRI |
                                LINUX_POLLRDNORM | LINUX_POLLRDBAND |
                                LINUX_POLLRDHUP;
    const int16_t write_events = LINUX_POLLOUT |
                                 LINUX_POLLWRNORM | LINUX_POLLWRBAND;
    if (!e) return LINUX_POLLNVAL;

    if (e->kind == FD_TUN) {
        uint64_t identity = file_ref_identity(e->file_ref);

        if ((events & read_events) && edge_linux_tun_read_ready(identity))
            rev |= LINUX_POLLIN;
        if ((events & write_events) && edge_linux_tun_write_ready(identity))
            rev |= LINUX_POLLOUT;
    }

#ifdef CONFIG_FUSE_FS
    if (e->kind == FD_VFS &&
        (e->inode.mode & 0xf000u) == VFS_INODE_CHR &&
        edge_fuse_is_device(e->inode.rdev)) {
        int fuse_events = edge_fuse_device_poll(
            file_ref_identity(e->file_ref), (uint32_t)(uint16_t)events);
        if (fuse_events >= 0) {
            rev |= (int16_t)fuse_events;
            return (int16_t)kernel_wait_poll_project(
                (uint32_t)(uint16_t)rev, events);
        }
    }
#endif

#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if (e->kind == FD_VFS &&
        (e->inode.mode & 0xf000u) == VFS_INODE_CHR) {
        uint32_t bridge_events = 0;
        int bridge_status =
            bsd_bridge_cdev_poll_session(
                e->inode.rdev, file_ref_identity(e->file_ref),
                &bridge_events);

        if (bridge_status == 0) {
            bridge_cdev = 1;
            if (bridge_events & BSD_BRIDGE_CDEV_POLL_READ)
                rev |= LINUX_POLLIN;
            if (bridge_events & BSD_BRIDGE_CDEV_POLL_WRITE)
                rev |= LINUX_POLLOUT;
            if (bridge_events & BSD_BRIDGE_CDEV_POLL_HANGUP)
                rev |= LINUX_POLLHUP;
        }
    }
#endif

    /*
     * Procfs mount monitor files are readable snapshots, but Linux readiness
     * on them describes mount topology changes rather than text availability.
     */
    if (fd_is_mount_event_source(e)) {
        if (!fd_mount_monitor_pending(e)) return 0;
        return (int16_t)kernel_wait_poll_project(
            LINUX_POLLERR | LINUX_POLLPRI, events);
    }

    if (e->kind == FD_EVENTFD || e->kind == FD_TIMERFD ||
        e->kind == FD_SIGNALFD || e->kind == FD_INOTIFY ||
        e->kind == FD_FANOTIFY || e->kind == FD_USERFAULTFD ||
        e->kind == FD_PERF_EVENT ||
        e->kind == FD_PIDFD || e->kind == FD_MQUEUE ||
        e->kind == FD_IO_URING || e->kind == FD_SECCOMP) {
        uint32_t anonymous_events = anonymous_fd_ready_events(e);
        rev |= (int16_t)anonymous_events;
    }

    if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) {
        uint32_t pty_events = pty_ready_events(e);
        rev |= (int16_t)pty_events;
    }

    if (e->kind == FD_PIPE_R || e->kind == FD_PIPE_W ||
        e->kind == FD_PIPE_RW) {
        edge_pipe_t *pipe =
            e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_PIPES ?
            &g_pipes[e->pipe_id] : 0;
        uint32_t pipe_events = kernel_pipe_poll_events(
            e->kind == FD_PIPE_R || e->kind == FD_PIPE_RW ? pipe : 0,
            e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW ? pipe : 0,
            e->kind == FD_PIPE_R || e->kind == FD_PIPE_RW,
            e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW);
        rev |= (int16_t)pipe_events;
        if ((pipe_events & KERNEL_PIPE_POLL_HUP) &&
            g_pipe_hup_trace_budget > 0 &&
            gui_diag_task(process_current_task())) {
            task_t *cur = process_current_task();
            g_pipe_hup_trace_budget--;
            printf("[pipe-hup] pid=%d cmd=%s fdkind=%d id=%d ev=0x%x rev=0x%x count=%u r=%u w=%u budget=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   (int)e->kind, e->pipe_id, (unsigned)events,
                   (unsigned)rev, pipe ? pipe->count : 0,
                   pipe ? pipe->readers : 0,
                   pipe ? pipe->writers : 0,
                   g_pipe_hup_trace_budget);
        }
    }

    if (e->kind == FD_SOCKET) {
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS || !g_sockets[e->pipe_id].used) {
            return LINUX_POLLNVAL;
        } else {
            edge_socket_t *s = &g_sockets[e->pipe_id];
            kernel_socket_poll_state_t socket_state;
            int extra_readable = 0;
            socket_maybe_timeout_connect(s);
            if (s->tcp_fin_pending) socket_drain_deferred_fin(s);
            else socket_maybe_promote_deferred_fin(s);
            if (events & read_events) {
                (void)socket_try_fill_packet_frame(s);
                if (s->packet_handle >= 0 &&
                    edge_linux_packet_ring_ready(s->packet_handle))
                    extra_readable = 1;
                (void)socket_try_fill_ping_hw_reply(s);
                socket_try_refill_tcp_refused(s);
            }
            socket_poll_state_snapshot(s, extra_readable, &socket_state);
            rev |= (int16_t)kernel_socket_poll_events(&socket_state);
        }
    }

    if (e->kind == FD_EPOLL &&
        !kernel_epoll_object_exists(e->pipe_id))
        rev |= LINUX_POLLNVAL;

    if (events & read_events) {
        if (e->kind == FD_CONSOLE) {
            /*
             * FD_CONSOLE is not always the foreground framebuffer VT.  Alpine's
             * serial getty has stdio on /dev/console mapped to ttyS0, while
             * Xorg keeps a real VT fd open for /dev/ttyN.  Poll/select must
             * report readiness for the descriptor's own tty line; otherwise a
             * serial shell can end up waiting for keyboard input, or an X
             * server can be woken for the wrong terminal and block in read().
             */
            if (console_line_pollin_ready(console_line_from_fd_entry(e)))
                rev |= LINUX_POLLIN;
        } else if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) {
            /* PTY readiness was normalized before the per-class branches. */
        } else if (e->kind == FD_PIPE_R || e->kind == FD_PIPE_RW) {
            /* Pipe readiness was normalized before the per-class branches. */
        } else if (e->kind == FD_SOCKET) {
            /* Socket readiness was normalized before the per-class branches. */
        } else if (e->kind == FD_EVENTFD || e->kind == FD_TIMERFD ||
                   e->kind == FD_SIGNALFD || e->kind == FD_INOTIFY ||
                   e->kind == FD_FANOTIFY ||
                   e->kind == FD_USERFAULTFD ||
                   e->kind == FD_PERF_EVENT ||
                   e->kind == FD_PIDFD || e->kind == FD_MQUEUE ||
                   e->kind == FD_IO_URING ||
                   e->kind == FD_SECCOMP) {
            /* Anonymous descriptor readiness was normalized above. */
        } else if (e->kind == FD_EPOLL) {
            if (kernel_epoll_object_exists(e->pipe_id) &&
                epoll_post_register_ready(
                         fd_proc_with_stdio(), e->pipe_id))
                rev |= LINUX_POLLIN;
        } else if (e->kind == FD_TUN) {
            /* TUN readiness was normalized above. */
        } else if (!bridge_cdev) {
            if (e->kind == FD_VFS && path_is_console_tty(e->path)) {
                if (console_line_pollin_ready(console_line_from_fd_entry(e)))
                    rev |= LINUX_POLLIN;
            } else if (e->kind == FD_VFS && path_is_serial_tty(e->path)) {
                if (console_line_pollin_ready(console_line_from_fd_entry(e)))
                    rev |= LINUX_POLLIN;
            } else if (e->kind == FD_VFS && path_is_mouse_input(e->path)) {
                if (keyboard_mouse_pending() > 0) rev |= LINUX_POLLIN;
            } else if (e->kind == FD_VFS && path_is_event_input(e->path)) {
                int event_id = path_input_event_index(e->path);
                int tail = fd_description_input_tail(e);
                int access = edge_linux_input_description_may_read(
                    (uint32_t)event_id, file_ref_locator(e->file_ref));
                int pending = access > 0 ? keyboard_event_pending_from(
                    event_id, tail) : 0;
                /*
                 * evdev readers consume whole struct input_event records.  Linux
                 * only reports the fd readable when a complete record can be
                 * read; advertising readiness for a partial record lets Xorg
                 * enter a blocking read and stop accepting X11 clients.
                 */
                if (pending >= (int)EDGE_LINUX_INPUT_EVENT_SIZE)
                    rev |= LINUX_POLLIN;
                if (access < 0)
                    rev |= LINUX_POLLERR | LINUX_POLLHUP;
            } else if (e->kind == FD_VFS && path_is_kmsg_device(e->path)) {
                if (bootlog_kmsg_has_record(fd_description_offset(e)))
                    rev |= LINUX_POLLIN;
            } else if (e->kind == FD_VFS && path_is_alsa_device(e->path)) {
                /*
                 * Playback PCM fds are normally waited for POLLOUT.  Reporting
                 * read readiness on /dev/snd/pcmC0D0p makes ALSA-lib based
                 * sound servers try read paths that Linux would not expose on
                 * a playback-only device.
                 */
                if (alsa_poll_read_ready(e->path)) rev |= LINUX_POLLIN;
            } else if (e->kind == FD_VFS &&
                       edge_drm_path_is_card(e->path)) {
                if (edge_drm_poll_readable(
                        file_ref_identity(e->file_ref)))
                    rev |= LINUX_POLLIN;
            } else if (e->kind == FD_VFS &&
                       path_is_uinput_device(e->path)) {
                rev |= LINUX_POLLIN;
            } else if (e->kind == FD_VFS &&
                       edge_drm_path_is_render(e->path)) {
                /* Render nodes only report completion events when enabled. */
            } else if (e->kind == FD_VFS &&
                       path_is_dri_device(e->path)) {
                rev |= LINUX_POLLERR | LINUX_POLLHUP;
            } else {
                rev |= LINUX_POLLIN;
            }
        }
    }

    if (events & write_events) {
        if (e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW) {
            /* Pipe readiness was normalized before the per-class branches. */
        } else if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) {
            /* PTY readiness was normalized before the write branch. */
        } else if (e->kind == FD_EVENTFD || e->kind == FD_TIMERFD ||
                   e->kind == FD_SIGNALFD || e->kind == FD_INOTIFY ||
                   e->kind == FD_FANOTIFY ||
                   e->kind == FD_USERFAULTFD ||
                   e->kind == FD_PERF_EVENT ||
                   e->kind == FD_PIDFD) {
            /* Anonymous descriptor readiness was normalized above. */
        } else if (e->kind == FD_EPOLL) {
            /* These anonymous descriptors never expose a writable stream. */
        } else if (e->kind == FD_TUN) {
            /* TUN readiness was normalized above. */
        } else if (!bridge_cdev) {
            if (e->kind == FD_SOCKET && e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_SOCKETS) {
                /* Socket readiness was normalized before the write branch. */
            } else if (e->kind == FD_VFS &&
                       path_is_alsa_device(e->path)) {
                if (alsa_poll_write_ready(e->path))
                    rev |= LINUX_POLLOUT;
            } else if (!(e->kind == FD_VFS &&
                         path_is_dri_device(e->path))) {
                rev |= LINUX_POLLOUT;
            }
        }
    }

    rev = (int16_t)kernel_wait_poll_project(
        (uint32_t)(uint16_t)rev, events);
    x11_trace_socket_poll(process_current_task(), "poll-revents", -1, e, events, rev);
    xfce_socket_poll_diag(e, events, rev);
    if (rev != 0 && g_gui_poll_ready_trace_budget > 0 &&
        gui_poll_task(process_current_task())) {
        int pending = -1;
        uint64_t eventfd_counter = 0;
        int socket_peer = -1;
        uint32_t socket_rx = 0;
        uint64_t socket_rseq = 0;
        uint64_t socket_wseq = 0;
        if (e->kind == FD_VFS && path_is_event_input(e->path)) {
            int event_id = path_input_event_index(e->path);
            int tail = fd_description_input_tail(e);
            pending = keyboard_event_pending_from(
                event_id, tail);
        } else if (e->kind == FD_VFS && path_is_mouse_input(e->path)) {
            pending = keyboard_mouse_pending();
        } else if (e->kind == FD_EVENTFD) {
            eventfd_counter = eventfd_counter_snapshot(e->pipe_id);
        } else if (e->kind == FD_SOCKET &&
                   e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_SOCKETS &&
                   g_sockets[e->pipe_id].used) {
            edge_socket_t *s = &g_sockets[e->pipe_id];
            socket_peer = s->unix_peer_id;
            socket_rx = s->rx_len;
            kernel_socket_readiness_snapshot(
                &s->readiness, &socket_rseq, &socket_wseq);
        }
        printf("[pollready] pid=%d cmd=%s kind=%d path=%s id=%d ev=0x%x rev=0x%x pending=%d fl=0x%x evcnt=%llu peer=%d rx=%u rseq=%llu wseq=%llu\n",
               process_getpid(),
               process_current_task() ? process_current_task()->name : "?",
               (int)e->kind, e->path[0] ? e->path : "-",
               e->pipe_id, (unsigned)events, (unsigned)rev, pending,
               (unsigned)e->flags, (unsigned long long)eventfd_counter,
               socket_peer, socket_rx,
               (unsigned long long)socket_rseq,
               (unsigned long long)socket_wseq);
        g_gui_poll_ready_trace_budget--;
    }
    return rev;
}

static uint64_t fd_epoll_ready_seq(edge_fd_t *e, int16_t events) {
    const int16_t read_events =
        LINUX_POLLIN | LINUX_POLLPRI | LINUX_POLLRDNORM |
        LINUX_POLLRDBAND | LINUX_POLLRDHUP;
    const int16_t write_events =
        LINUX_POLLOUT | LINUX_POLLWRNORM | LINUX_POLLWRBAND;

#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if (e && e->kind == FD_VFS &&
        (e->inode.mode & 0xf000u) == VFS_INODE_CHR) {
        uint64_t read_sequence = 0;
        uint64_t write_sequence = 0;

        if (bsd_bridge_cdev_poll_sequences(
                e->inode.rdev, &read_sequence,
                &write_sequence) == 0) {
            if (events & read_events)
                return read_sequence;
            if (events & write_events)
                return write_sequence;
        }
    }
#endif

    if (e && e->kind == FD_TUN) {
        uint64_t identity = file_ref_identity(e->file_ref);

        if (events & read_events)
            return edge_linux_tun_read_sequence(identity);
        if (events & write_events)
            return edge_linux_tun_write_sequence(identity);
    }

    if (e && e->kind == FD_EVENTFD &&
        (events & read_events)) {
        kernel_eventfd_state_t state;
        if (eventfd_snapshot(e->pipe_id, &state))
            return state.write_sequence;
    }
    if (e && e->kind == FD_TIMERFD && (events & read_events)) {
        kernel_timerfd_state_t state;
        if (kernel_timerfd_query(e->pipe_id, &state) == 0)
            return state.readiness_sequence;
    }
    if (e && e->kind == FD_INOTIFY && (events & read_events)) {
        kernel_inotify_state_t state;
        if (kernel_inotify_query(e->pipe_id, &state) == 0)
            return state.readiness_sequence;
    }
    if (e && e->kind == FD_FANOTIFY && (events & read_events)) {
        kernel_fanotify_state_t state;
        if (kernel_fanotify_query(e->pipe_id, &state) == 0)
            return state.readiness_sequence;
    }
    if (e && e->kind == FD_USERFAULTFD && (events & read_events)) {
        kernel_userfaultfd_state_t state;
        if (kernel_userfaultfd_query(e->pipe_id, &state) == 0)
            return state.readiness_sequence;
    }
    if (e && (e->kind == FD_PIPE_R ||
              e->kind == FD_PIPE_W ||
              e->kind == FD_PIPE_RW) &&
        e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_PIPES &&
        g_pipes[e->pipe_id].used) {
        if (events & read_events)
            return g_pipes[e->pipe_id].read_ready_sequence;
        if (events & write_events)
            return g_pipes[e->pipe_id].write_ready_sequence;
    }
    if (e && e->kind == FD_VFS && path_is_event_input(e->path) &&
        (events & read_events)) {
        return keyboard_event_sequence(path_input_event_index(e->path));
    }
    if (e && e->kind == FD_VFS && edge_drm_path_is_card(e->path) &&
        (events & read_events)) {
        return edge_drm_readiness_sequence(
            file_ref_identity(e->file_ref));
    }
    if (e && fd_is_mount_event_source(e) &&
        (events & read_events)) {
        uint32_t namespace_id;
        uint32_t observed_generation;
        if (fd_mount_monitor_snapshot(
                e, &namespace_id, &observed_generation)) {
            (void)observed_generation;
            return vfs_mount_namespace_event_generation(namespace_id);
        }
    }
    if (!e || e->kind != FD_SOCKET) return 0;
    if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS) return 0;
    if (!g_sockets[e->pipe_id].used) return 0;
    if (events & read_events)
        return __atomic_load_n(
            &g_sockets[e->pipe_id].readiness.read_sequence,
            __ATOMIC_ACQUIRE);
    if (events & write_events)
        return __atomic_load_n(
            &g_sockets[e->pipe_id].readiness.write_sequence,
            __ATOMIC_ACQUIRE);
    return 0;
}

static uint32_t fd_epoll_socket_read_seq(edge_fd_t *e) {
    if (!e || e->kind != FD_SOCKET) return 0;
    if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS) return 0;
    if (!g_sockets[e->pipe_id].used) return 0;
    return (uint32_t)__atomic_load_n(
        &g_sockets[e->pipe_id].readiness.read_sequence,
        __ATOMIC_ACQUIRE);
}

static uint32_t fd_epoll_socket_write_seq(edge_fd_t *e) {
    if (!e || e->kind != FD_SOCKET) return 0;
    if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS) return 0;
    if (!g_sockets[e->pipe_id].used) return 0;
    return (uint32_t)__atomic_load_n(
        &g_sockets[e->pipe_id].readiness.write_sequence,
        __ATOMIC_ACQUIRE);
}

static uint32_t fd_epoll_socket_rx_len(edge_fd_t *e) {
    if (!e || e->kind != FD_SOCKET) return 0;
    if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS) return 0;
    if (!g_sockets[e->pipe_id].used) return 0;
    return g_sockets[e->pipe_id].rx_len;
}

typedef enum x86_epoll_vfs_source_kind {
    X86_EPOLL_VFS_GENERIC = 0,
    X86_EPOLL_VFS_MOUNT_MONITOR,
    X86_EPOLL_VFS_CONSOLE,
    X86_EPOLL_VFS_MOUSE,
    X86_EPOLL_VFS_EVENT,
    X86_EPOLL_VFS_KMSG,
    X86_EPOLL_VFS_ALSA_TIMER,
    X86_EPOLL_VFS_ALSA_OTHER,
    X86_EPOLL_VFS_DRI,
    X86_EPOLL_VFS_UINPUT,
} x86_epoll_vfs_source_kind_t;

#define X86_WAIT_CAPTURED_SOURCE_TAG ((uintptr_t)1u)

_Static_assert(_Alignof(kernel_epoll_target_source_t) >= 2,
               "captured epoll sources must support pointer tagging");
_Static_assert(_Alignof(edge_fd_t) >= 2,
               "direct wait sources must not use the captured-source tag");

static uint32_t x86_epoll_vfs_source_kind(const edge_fd_t *entry) {
    if (!entry || entry->kind != FD_VFS)
        return X86_EPOLL_VFS_GENERIC;
    if (fd_is_mount_event_source(entry))
        return X86_EPOLL_VFS_MOUNT_MONITOR;
    if (path_is_console_tty(entry->path) ||
        path_is_serial_tty(entry->path))
        return X86_EPOLL_VFS_CONSOLE;
    if (path_is_mouse_input(entry->path))
        return X86_EPOLL_VFS_MOUSE;
    if (path_is_event_input(entry->path))
        return X86_EPOLL_VFS_EVENT;
    if (path_is_kmsg_device(entry->path))
        return X86_EPOLL_VFS_KMSG;
    if (path_is_alsa_device(entry->path))
        return alsa_path_kind(entry->path) == EDGE_ALSA_NODE_TIMER ?
            X86_EPOLL_VFS_ALSA_TIMER :
            X86_EPOLL_VFS_ALSA_OTHER;
    if (path_is_dri_device(entry->path))
        return X86_EPOLL_VFS_DRI;
    if (path_is_uinput_device(entry->path))
        return X86_EPOLL_VFS_UINPUT;
    return X86_EPOLL_VFS_GENERIC;
}

static int x86_epoll_target_source_encode(
        const edge_fd_t *entry, uint64_t expected_description_id,
        kernel_epoll_target_source_t *source) {
    uint32_t source_flags = 0;
    int32_t primary_object_id;

    if (!entry || !entry->used || entry->kind <= FD_NONE ||
        entry->kind > FD_NAMESPACE || entry->file_ref <= 0 ||
        !expected_description_id || !source)
        return -EBADF;

    primary_object_id = entry->pipe_id;
    if (entry->kind == FD_VFS) {
        source_flags = x86_epoll_vfs_source_kind(entry);
        if (source_flags == X86_EPOLL_VFS_CONSOLE)
            primary_object_id = console_line_from_fd_entry(entry);
        else if (source_flags == X86_EPOLL_VFS_EVENT)
            primary_object_id = path_input_event_index(entry->path);
        else if (source_flags == X86_EPOLL_VFS_DRI)
            primary_object_id =
                edge_drm_path_is_render(entry->path) ? 128 : 0;
    } else if (entry->kind == FD_NAMESPACE) {
        source_flags = entry->namespace_kind;
        primary_object_id = (int32_t)entry->namespace_id;
    }

    memset(source, 0, sizeof(*source));
    source->kind = (uint32_t)entry->kind;
    source->flags = source_flags;
    source->primary_object_id = primary_object_id;
    source->secondary_object_id = entry->file_ref;
    source->cookie = expected_description_id;
    return 0;
}

static int x86_epoll_target_source_capture(
        edge_fd_proc_t *process, int descriptor,
        uint64_t expected_description_id,
        kernel_epoll_target_source_t *source) {
    kernel_epoll_target_source_t captured;
    edge_fd_t snapshot;
    uint64_t irq_flags;
    int status;

    if (!process || !source || descriptor < 0 ||
        descriptor >= EDGE_MAX_FD || !expected_description_id)
        return -EBADF;
    memset(source, 0, sizeof(*source));
    memset(&captured, 0, sizeof(captured));
    memset(&snapshot, 0, sizeof(snapshot));

    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &process->table_runtime, (uint32_t)descriptor) ||
        !__atomic_load_n(
            &process->fds[descriptor].used, __ATOMIC_ACQUIRE)) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }
    snapshot = process->fds[descriptor];
    if (file_ref_identity(snapshot.file_ref) !=
        expected_description_id) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }
    status = x86_epoll_target_source_encode(
        &snapshot, expected_description_id, &captured);
    if (status < 0) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return status;
    }
    /*
     * This is a backing-object lifetime reference, not another installed
     * descriptor or open-file-description reference. The common epoll layer
     * detaches the source before the final real descriptor reference drops,
     * preserving the last pipe/PTY/socket endpoint transition while also
     * covering an ADD-versus-close race.
     */
    if (fd_add_backing_object(&snapshot) < 0) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);

    *source = captured;
    return 0;
}

static int x86_epoll_source_to_entry(
        const kernel_epoll_target_source_t *source,
        edge_fd_t *entry) {
    if (!source || !entry || source->kind <= FD_NONE ||
        source->kind > FD_NAMESPACE ||
        source->secondary_object_id <= 0 || !source->cookie)
        return -EBADF;
    if (file_ref_identity(source->secondary_object_id) !=
        source->cookie)
        return -EBADF;

    memset(entry, 0, sizeof(*entry));
    entry->used = 1;
    entry->kind = (edge_fd_kind_t)source->kind;
    entry->file_ref = source->secondary_object_id;
    entry->pipe_id = source->primary_object_id;

    if (entry->kind == FD_NAMESPACE) {
        entry->namespace_kind = (uint8_t)source->flags;
        entry->namespace_id =
            (uint32_t)source->primary_object_id;
    } else if (entry->kind == FD_VFS) {
        switch ((x86_epoll_vfs_source_kind_t)source->flags) {
            case X86_EPOLL_VFS_MOUNT_MONITOR:
                break;
            case X86_EPOLL_VFS_CONSOLE:
                entry->kind = FD_CONSOLE;
                break;
            case X86_EPOLL_VFS_MOUSE:
                strncpy(entry->path, "/dev/input/mice",
                        sizeof(entry->path) - 1u);
                break;
            case X86_EPOLL_VFS_EVENT:
                if (source->primary_object_id < 0 ||
                    source->primary_object_id > 31)
                    return -EBADF;
                memcpy(entry->path, "/dev/input/event", 16u);
                if (source->primary_object_id >= 10) {
                    entry->path[16] = (char)(
                        '0' + source->primary_object_id / 10);
                    entry->path[17] = (char)(
                        '0' + source->primary_object_id % 10);
                    entry->path[18] = 0;
                } else {
                    entry->path[16] = (char)(
                        '0' + source->primary_object_id);
                    entry->path[17] = 0;
                }
                break;
            case X86_EPOLL_VFS_KMSG:
                strncpy(entry->path, "/dev/kmsg",
                        sizeof(entry->path) - 1u);
                break;
            case X86_EPOLL_VFS_ALSA_TIMER:
                strncpy(entry->path, EDGE_ALSA_PATH_TIMER,
                        sizeof(entry->path) - 1u);
                break;
            case X86_EPOLL_VFS_ALSA_OTHER:
                strncpy(entry->path, EDGE_ALSA_PATH_PCM_PLAYBACK,
                        sizeof(entry->path) - 1u);
                break;
            case X86_EPOLL_VFS_DRI:
                if (source->primary_object_id == 0)
                    strncpy(entry->path, "/dev/dri/card0",
                            sizeof(entry->path) - 1u);
                else if (source->primary_object_id == 128)
                    strncpy(entry->path, EDGE_VIRTGPU_RENDER_PATH,
                            sizeof(entry->path) - 1u);
                else
                    return -EBADF;
                break;
            case X86_EPOLL_VFS_UINPUT:
                strncpy(entry->path, "/dev/uinput",
                        sizeof(entry->path) - 1u);
                break;
            case X86_EPOLL_VFS_GENERIC:
            default:
                break;
        }
    }
    return 0;
}

static void x86_epoll_target_source_release(
        const kernel_epoll_target_source_t *source) {
    edge_fd_t retained;

    if (!source || source->kind <= FD_NONE ||
        source->kind > FD_NAMESPACE)
        return;
    memset(&retained, 0, sizeof(retained));
    retained.used = 1;
    retained.kind = (edge_fd_kind_t)source->kind;
    retained.file_ref = source->secondary_object_id;
    retained.pipe_id = source->primary_object_id;
    if (retained.kind == FD_NAMESPACE) {
        retained.namespace_kind = (uint8_t)source->flags;
        retained.namespace_id =
            (uint32_t)source->primary_object_id;
    }
    fd_drop_backing_object(&retained);
}

static int x86_epoll_watch_source_entry(
        const kernel_epoll_watch_t *watch, edge_fd_t *entry) {
    if (!watch || !watch->source_captured) return -EBADF;
    return x86_epoll_source_to_entry(&watch->source, entry);
}

static const kernel_epoll_target_source_t *
x86_wait_captured_source(const kernel_wait_source_t *source) {
    uintptr_t token;

    if (!source || !source->backend_token) return 0;
    token = (uintptr_t)source->backend_token;
    if (!(token & X86_WAIT_CAPTURED_SOURCE_TAG)) return 0;
    return (const kernel_epoll_target_source_t *)
        (token & ~X86_WAIT_CAPTURED_SOURCE_TAG);
}

static const void *x86_wait_captured_source_token(
        const kernel_epoll_target_source_t *source) {
    return (const void *)(
        (uintptr_t)source | X86_WAIT_CAPTURED_SOURCE_TAG);
}

static int x86_wait_source_entry(const kernel_wait_source_t *source,
                                 edge_fd_t *stable_entry,
                                 edge_fd_t **entry) {
    const kernel_epoll_target_source_t *captured =
        x86_wait_captured_source(source);

    if (!source || !entry) return -EBADF;
    if (!captured) {
        *entry = (edge_fd_t *)source->backend_token;
        return *entry ? 0 : -EBADF;
    }
    if (!stable_entry ||
        x86_epoll_source_to_entry(captured, stable_entry) < 0) {
        *entry = 0;
        return -EBADF;
    }
    *entry = stable_entry;
    return 0;
}

int edge_procfs_epoll_watch_snapshot(int pid, int fd, int index,
                                     int *nwatch_out, int *watch_fd_out,
                                     uint32_t *events_out, int *kind_out,
                                     int *target_out, uint32_t *revents_out,
                                     uint32_t *ready_delivered_out,
                                     uint32_t *read_seq_delivered_out,
                                     uint32_t *write_seq_delivered_out,
                                     int *oneshot_disabled_out,
                                     uint32_t *socket_rx_out,
                                     uint32_t *socket_read_seq_out,
                                     uint32_t *socket_write_seq_out,
                                     uint64_t *eventfd_counter_out,
                                     uint64_t *timerfd_exp_out) {
    const task_t *t;
    edge_fd_proc_t *p;
    edge_fd_t *e;
    kernel_epoll_object_snapshot_t epoll;
    kernel_epoll_watch_snapshot_t watch;
    const edge_epoll_watch_t *w;
    edge_fd_t stable_watch_entry;
    edge_fd_t *we;
    int owner_pid = pid;
    int16_t req = 0;
    int16_t rev = 0;

    if (fd < 0 || fd >= EDGE_MAX_FD || index < 0) return -1;
    t = process_get_task(pid);
    if (!t || t->state == TASK_UNUSED) return -1;
    if (t->fd_owner_pid > 0) owner_pid = t->fd_owner_pid;
    p = fd_proc_for_pid(owner_pid, 0);
    e = fd_get(p, fd);
    if (!e || e->kind != FD_EPOLL ||
        e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_EPOLLS) {
        return -1;
    }
    if (kernel_epoll_object_snapshot(e->pipe_id, &epoll) < 0)
        return -1;
    if (nwatch_out) *nwatch_out = epoll.nwatch;
    if (index >= epoll.nwatch) return 1;
    {
        int active = 0;
        int slot = -1;
        for (int candidate = 0;
             candidate < epoll.entry_high_water;
             ++candidate) {
            kernel_epoll_watch_snapshot_t candidate_watch;
            if (kernel_epoll_watch_snapshot(
                    e->pipe_id, (uint16_t)candidate,
                    &candidate_watch) <= 0)
                continue;
            if (active++ == index) {
                slot = candidate;
                break;
            }
        }
        if (slot < 0) return 1;
        if (kernel_epoll_watch_snapshot(
                e->pipe_id, (uint16_t)slot, &watch) <= 0)
            return 1;
        w = &watch.watch;
    }
    we = x86_epoll_watch_source_entry(
             w, &stable_watch_entry) == 0 ?
         &stable_watch_entry : 0;
    if (w->events & (LINUX_EPOLLIN | LINUX_EPOLLPRI |
                     LINUX_EPOLLRDNORM | LINUX_EPOLLRDBAND)) {
        req |= LINUX_POLLIN | LINUX_POLLPRI |
               LINUX_POLLRDNORM | LINUX_POLLRDBAND;
    }
    if (w->events & (LINUX_EPOLLOUT | LINUX_EPOLLWRNORM |
                     LINUX_EPOLLWRBAND)) {
        req |= LINUX_POLLOUT | LINUX_POLLWRNORM | LINUX_POLLWRBAND;
    }
    if (w->events & LINUX_EPOLLRDHUP) req |= LINUX_POLLRDHUP;
    if (we) rev = poll_fd_revents(we, req);

    if (watch_fd_out) *watch_fd_out = w->fd;
    if (events_out) *events_out = w->events;
    if (kind_out) *kind_out = we ? (int)we->kind : -1;
    if (target_out) *target_out = we ? we->pipe_id : -1;
    if (revents_out) *revents_out = (uint32_t)(uint16_t)rev;
    if (ready_delivered_out) *ready_delivered_out = w->ready_delivered;
    if (read_seq_delivered_out)
        *read_seq_delivered_out =
            (uint32_t)w->read_ready_seq_delivered;
    if (write_seq_delivered_out)
        *write_seq_delivered_out =
            (uint32_t)w->write_ready_seq_delivered;
    if (oneshot_disabled_out) *oneshot_disabled_out = w->oneshot_disabled;
    if (socket_rx_out) *socket_rx_out = fd_epoll_socket_rx_len(we);
    if (socket_read_seq_out) *socket_read_seq_out = fd_epoll_socket_read_seq(we);
    if (socket_write_seq_out) *socket_write_seq_out = fd_epoll_socket_write_seq(we);
    if (eventfd_counter_out) {
        *eventfd_counter_out = 0;
        if (we && we->kind == FD_EVENTFD)
            *eventfd_counter_out = eventfd_counter_snapshot(we->pipe_id);
    }
    if (timerfd_exp_out) {
        *timerfd_exp_out = 0;
        if (we && we->kind == FD_TIMERFD)
            *timerfd_exp_out =
                timerfd_expiration_snapshot(we->pipe_id);
    }
    return 0;
}

typedef kernel_wait_plan_t edge_fd_wait_plan_t;

_Static_assert(KERNEL_WAIT_POLLIN == LINUX_POLLIN,
               "shared wait POLLIN ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLPRI == LINUX_POLLPRI,
               "shared wait POLLPRI ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLOUT == LINUX_POLLOUT,
               "shared wait POLLOUT ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLERR == LINUX_POLLERR,
               "shared wait POLLERR ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLHUP == LINUX_POLLHUP,
               "shared wait POLLHUP ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLNVAL == LINUX_POLLNVAL,
               "shared wait POLLNVAL ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLRDNORM == LINUX_POLLRDNORM,
               "shared wait POLLRDNORM ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLRDBAND == LINUX_POLLRDBAND,
               "shared wait POLLRDBAND ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLWRNORM == LINUX_POLLWRNORM,
               "shared wait POLLWRNORM ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLWRBAND == LINUX_POLLWRBAND,
               "shared wait POLLWRBAND ABI mismatch");
_Static_assert(KERNEL_WAIT_POLLRDHUP == LINUX_POLLRDHUP,
               "shared wait POLLRDHUP ABI mismatch");

static int x86_wait_source_from_entry(const edge_fd_t *entry,
                                      kernel_wait_source_t *source) {
    if (!entry || !source) return -1;
    memset(source, 0, sizeof(*source));
    source->object_index = entry->pipe_id;
    source->backend_token = entry;

    if (fd_is_mount_event_source(entry)) {
        source->kind = KERNEL_WAIT_SOURCE_OWNER_WAKE;
        return 0;
    }
    switch (entry->kind) {
        case FD_EPOLL:
            source->kind = KERNEL_WAIT_SOURCE_EPOLL;
            break;
        case FD_SOCKET:
            source->kind = KERNEL_WAIT_SOURCE_SOCKET;
            break;
        case FD_EVENTFD:
            source->kind = KERNEL_WAIT_SOURCE_EVENTFD;
            break;
        case FD_PIPE_R:
            source->kind = KERNEL_WAIT_SOURCE_PIPE_READ;
            break;
        case FD_PIPE_W:
            source->kind = KERNEL_WAIT_SOURCE_PIPE_WRITE;
            break;
        case FD_PIPE_RW:
            source->kind = KERNEL_WAIT_SOURCE_PIPE_READ_WRITE;
            break;
        case FD_TIMERFD:
            source->kind = KERNEL_WAIT_SOURCE_TIMERFD;
            break;
        case FD_INOTIFY:
            source->kind = KERNEL_WAIT_SOURCE_INOTIFY;
            break;
        case FD_FANOTIFY:
        case FD_USERFAULTFD:
        case FD_PERF_EVENT:
            source->kind = KERNEL_WAIT_SOURCE_OWNER_WAKE;
            break;
        case FD_SIGNALFD:
        case FD_PIDFD:
        case FD_TUN:
            source->kind = KERNEL_WAIT_SOURCE_OWNER_WAKE;
            break;
        default:
            source->kind = KERNEL_WAIT_SOURCE_UNSUPPORTED;
            break;
    }
    return 0;
}

static int x86_wait_source_from_captured(
        const kernel_epoll_target_source_t *captured,
        kernel_wait_source_t *source) {
    if (!captured || !source ||
        captured->kind <= FD_NONE ||
        captured->kind > FD_NAMESPACE ||
        captured->secondary_object_id <= 0 ||
        file_ref_identity(captured->secondary_object_id) !=
            captured->cookie)
        return -1;

    memset(source, 0, sizeof(*source));
    source->object_index = captured->primary_object_id;
    source->backend_token =
        x86_wait_captured_source_token(captured);

    if (captured->kind == FD_VFS &&
        captured->flags == X86_EPOLL_VFS_MOUNT_MONITOR) {
        source->kind = KERNEL_WAIT_SOURCE_OWNER_WAKE;
        return 0;
    }
    switch ((edge_fd_kind_t)captured->kind) {
        case FD_EPOLL:
            source->kind = KERNEL_WAIT_SOURCE_EPOLL;
            break;
        case FD_SOCKET:
            source->kind = KERNEL_WAIT_SOURCE_SOCKET;
            break;
        case FD_EVENTFD:
            source->kind = KERNEL_WAIT_SOURCE_EVENTFD;
            break;
        case FD_PIPE_R:
            source->kind = KERNEL_WAIT_SOURCE_PIPE_READ;
            break;
        case FD_PIPE_W:
            source->kind = KERNEL_WAIT_SOURCE_PIPE_WRITE;
            break;
        case FD_PIPE_RW:
            source->kind = KERNEL_WAIT_SOURCE_PIPE_READ_WRITE;
            break;
        case FD_TIMERFD:
            source->kind = KERNEL_WAIT_SOURCE_TIMERFD;
            break;
        case FD_INOTIFY:
            source->kind = KERNEL_WAIT_SOURCE_INOTIFY;
            break;
        case FD_FANOTIFY:
        case FD_USERFAULTFD:
        case FD_PERF_EVENT:
            source->kind = KERNEL_WAIT_SOURCE_OWNER_WAKE;
            break;
        case FD_SIGNALFD:
        case FD_PIDFD:
        case FD_TUN:
            source->kind = KERNEL_WAIT_SOURCE_OWNER_WAKE;
            break;
        default:
            source->kind = KERNEL_WAIT_SOURCE_UNSUPPORTED;
            break;
    }
    return 0;
}

static int x86_wait_resolve_descriptor(void *context, int32_t descriptor,
                                       kernel_wait_source_t *source) {
    return x86_wait_source_from_entry(
        fd_get((edge_fd_proc_t *)context, descriptor), source);
}

static int x86_wait_resolve_epoll_watch(
        void *context, const kernel_epoll_watch_t *watch,
        kernel_wait_source_t *source) {
    (void)context;
    if (!watch || !watch->source_captured) return -1;
    return x86_wait_source_from_captured(
        &watch->source, source);
}

static int x86_wait_observe_source(
        void *context, const kernel_wait_source_t *source,
        int16_t requested_events,
        kernel_wait_observation_t *observation) {
    edge_fd_t stable_entry;
    edge_fd_t *entry = 0;
    const int16_t read_events =
        LINUX_POLLIN | LINUX_POLLPRI |
        LINUX_POLLRDNORM | LINUX_POLLRDBAND |
        LINUX_POLLRDHUP;
    const int16_t write_events =
        LINUX_POLLOUT | LINUX_POLLWRNORM |
        LINUX_POLLWRBAND;

    (void)context;
    if (!observation ||
        x86_wait_source_entry(
            source, &stable_entry, &entry) < 0)
        return -1;
    memset(observation, 0, sizeof(*observation));
    observation->events = (uint32_t)(uint16_t)poll_fd_revents(
        entry, requested_events);
    observation->read_sequence =
        fd_epoll_ready_seq(entry, read_events);
    observation->write_sequence =
        fd_epoll_ready_seq(entry, write_events);
    return 0;
}

static kernel_wait_registration_t x86_wait_register_source(
        void *context, const kernel_wait_source_t *source,
        int16_t events, int32_t waiter_pid) {
    const kernel_epoll_target_source_t *captured;
    const int16_t read_events = LINUX_POLLIN | LINUX_POLLRDNORM;
    const int16_t write_events = LINUX_POLLOUT | LINUX_POLLWRNORM;

    (void)context;
    if (!source) return KERNEL_WAIT_REGISTRATION_FAILED;
    captured = x86_wait_captured_source(source);
    if (captured &&
        file_ref_identity(captured->secondary_object_id) !=
            captured->cookie)
        return KERNEL_WAIT_REGISTRATION_FAILED;

    switch (source->kind) {
        case KERNEL_WAIT_SOURCE_SOCKET: {
            const edge_socket_t *socket;
            kernel_wait_registration_t registration;

            if (waiter_pid <= 0 ||
                source->object_index < 0 ||
                source->object_index >= EDGE_MAX_SOCKETS ||
                !g_sockets[source->object_index].used)
                return KERNEL_WAIT_REGISTRATION_FAILED;
            socket = &g_sockets[source->object_index];
            registration = socket_waiter_add(
                    source->object_index, waiter_pid,
                    (uint16_t)events) == 0 ?
                KERNEL_WAIT_REGISTRATION_EXACT :
                KERNEL_WAIT_REGISTRATION_BEST_EFFORT;
            if ((socket->domain == LINUX_AF_INET ||
                 socket->domain == LINUX_AF_INET6) &&
                socket->type == LINUX_SOCK_RAW &&
                !socket_is_icmp_reader(socket))
                return KERNEL_WAIT_REGISTRATION_BEST_EFFORT;
            return registration;
        }
        case KERNEL_WAIT_SOURCE_EVENTFD: {
            kernel_eventfd_state_t state;
            if (!eventfd_snapshot(source->object_index, &state) ||
                waiter_pid <= 0)
                return KERNEL_WAIT_REGISTRATION_FAILED;
            if ((events & read_events) &&
                eventfd_read_waiter_add(
                    source->object_index, waiter_pid) < 0)
                return KERNEL_WAIT_REGISTRATION_BEST_EFFORT;
            if ((events & write_events) &&
                eventfd_write_waiter_add(
                    source->object_index, waiter_pid) < 0)
                return KERNEL_WAIT_REGISTRATION_BEST_EFFORT;
            return KERNEL_WAIT_REGISTRATION_EXACT;
        }
        case KERNEL_WAIT_SOURCE_PIPE_READ:
        case KERNEL_WAIT_SOURCE_PIPE_WRITE:
        case KERNEL_WAIT_SOURCE_PIPE_READ_WRITE: {
            int register_read;
            int register_write;
            if (source->object_index < 0 ||
                source->object_index >= EDGE_MAX_PIPES ||
                !g_pipes[source->object_index].used ||
                waiter_pid <= 0)
                return KERNEL_WAIT_REGISTRATION_FAILED;
            register_read =
                source->kind == KERNEL_WAIT_SOURCE_PIPE_READ ||
                source->kind == KERNEL_WAIT_SOURCE_PIPE_READ_WRITE;
            register_write =
                source->kind == KERNEL_WAIT_SOURCE_PIPE_WRITE ||
                source->kind == KERNEL_WAIT_SOURCE_PIPE_READ_WRITE;
            if (events & read_events) register_read = 1;
            if (events & write_events) register_write = 1;
            if (register_read &&
                pipe_read_waiter_add(
                    source->object_index, waiter_pid) < 0)
                return KERNEL_WAIT_REGISTRATION_BEST_EFFORT;
            if (register_write &&
                pipe_write_waiter_add(
                    source->object_index, waiter_pid) < 0)
                return KERNEL_WAIT_REGISTRATION_BEST_EFFORT;
            return KERNEL_WAIT_REGISTRATION_EXACT;
        }
        case KERNEL_WAIT_SOURCE_INOTIFY: {
            kernel_inotify_state_t state;
            /*
             * Queue publication calls kernel_inotify_state_changed(), which
             * wakes every blocked task sharing this descriptor table. The
             * checked block path publishes fd_wait_active before its final
             * readiness rescan, so an event cannot be lost on either side of
             * the TASK_BLOCKED transition. The query only validates that the
             * common inotify object still exists.
             */
            return kernel_inotify_query(
                       source->object_index, &state) < 0 ?
                   KERNEL_WAIT_REGISTRATION_FAILED :
                   KERNEL_WAIT_REGISTRATION_EXACT;
        }
        default:
            return KERNEL_WAIT_REGISTRATION_FAILED;
    }

    return KERNEL_WAIT_REGISTRATION_FAILED;
}

static const kernel_wait_backend_ops_t g_x86_wait_backend_ops = {
    .resolve_descriptor = x86_wait_resolve_descriptor,
    .resolve_epoll_watch = x86_wait_resolve_epoll_watch,
    .observe_source = x86_wait_observe_source,
    .register_waiter = x86_wait_register_source,
};

static void fd_wait_plan_init(edge_fd_wait_plan_t *plan,
                              edge_fd_proc_t *process, int waiter_pid) {
    kernel_wait_plan_init(
        plan, &g_x86_wait_backend_ops, process, waiter_pid);
}

static void fd_wait_plan_mark_inexact(edge_fd_wait_plan_t *plan) {
    kernel_wait_plan_mark_inexact(plan);
}

static void poll_wait_plan_build(edge_fd_wait_plan_t *plan,
                                 edge_fd_proc_t *process,
                                 const edge_pollfd_t *pfds, int nfds,
                                 int waiter_pid) {
    fd_wait_plan_init(plan, process, waiter_pid);
    if (!process || !pfds) {
        fd_wait_plan_mark_inexact(plan);
        return;
    }
    for (int index = 0; index < nfds; ++index) {
        if (pfds[index].fd < 0) continue;
        kernel_wait_plan_collect_descriptor(
            plan, pfds[index].fd, pfds[index].events);
    }
}

static void select_wait_plan_build(edge_fd_wait_plan_t *plan,
                                   edge_fd_proc_t *process, int nfds,
                                   const uint8_t *read_set,
                                   const uint8_t *write_set,
                                   const uint8_t *except_set,
                                   int waiter_pid) {
    fd_wait_plan_init(plan, process, waiter_pid);
    if (!process || !read_set || !write_set || !except_set) {
        fd_wait_plan_mark_inexact(plan);
        return;
    }
    for (int descriptor = 0; descriptor < nfds; ++descriptor) {
        uint8_t requested_sets = 0;
        int16_t events;
        if (fdset_test(read_set, descriptor))
            requested_sets |= KERNEL_WAIT_SELECT_READ;
        if (fdset_test(write_set, descriptor))
            requested_sets |= KERNEL_WAIT_SELECT_WRITE;
        if (fdset_test(except_set, descriptor))
            requested_sets |= KERNEL_WAIT_SELECT_EXCEPT;
        events = kernel_wait_select_to_poll_events(requested_sets);
        if (!events) continue;
        kernel_wait_plan_collect_descriptor(plan, descriptor, events);
    }
}

static void epoll_wait_plan_build(edge_fd_wait_plan_t *plan,
                                  edge_fd_proc_t *process, int epoll_index,
                                  int waiter_pid) {
    fd_wait_plan_init(plan, process, waiter_pid);
    kernel_wait_plan_collect_epoll(plan, epoll_index);
}

static void gui_poll_wait_trace(const char *sys, task_t *cur, edge_fd_proc_t *p,
                                const edge_pollfd_t *pfds, int nfds,
                                uint64_t deadline_us, int only_kernel_wakeup_fds,
                                int needs_periodic_rescan) {
    int logged = 0;
    if (g_gui_wait_fd_trace_budget <= 0 || !gui_diag_task(cur) || !p || !pfds)
        return;
    printf("[poll-wait] sys=%s pid=%d cmd=%s nfds=%d deadline=%llu only=%d periodic=%d",
           sys ? sys : "poll",
           cur ? cur->pid : -1,
           cur ? cur->name : "?",
           nfds,
           (unsigned long long)deadline_us,
           only_kernel_wakeup_fds,
           needs_periodic_rescan);
    for (int i = 0; i < nfds && logged < 4; ++i) {
        int fd = pfds[i].fd;
        edge_fd_t *e;
        uint64_t eventfd_counter = 0;
        uint32_t pipe_count = 0;
        uint32_t socket_rx = 0;
        uint32_t socket_packets = 0;
        int socket_type = 0;
        int socket_peer = -1;
        if (fd < 0) continue;
        e = fd_get(p, fd);
        if (e && e->kind == FD_EVENTFD) {
            eventfd_counter = eventfd_counter_snapshot(e->pipe_id);
        } else if (e && (e->kind == FD_PIPE_R || e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW) &&
                   e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_PIPES &&
                   g_pipes[e->pipe_id].used) {
            pipe_count = g_pipes[e->pipe_id].count;
        } else if (e && e->kind == FD_SOCKET &&
                   e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_SOCKETS &&
                   g_sockets[e->pipe_id].used) {
            socket_rx = g_sockets[e->pipe_id].rx_len;
            socket_packets = g_sockets[e->pipe_id].packet_count;
            socket_type = g_sockets[e->pipe_id].type;
            socket_peer = g_sockets[e->pipe_id].unix_peer_id;
        }
        printf(" fd%d=%d:%s/%d ev=0x%x rev=0x%x fl=0x%x cnt=%llu pcnt=%u rx=%u stype=%d spkts=%u peer=%d",
               i, fd, e ? fd_kind_name(e->kind) : "bad",
               e ? e->pipe_id : -1,
               (unsigned)pfds[i].events,
               (unsigned)pfds[i].revents,
               e ? (unsigned)e->flags : 0u,
               (unsigned long long)eventfd_counter,
               pipe_count, socket_rx, socket_type, socket_packets,
               socket_peer);
        logged++;
    }
    printf(" budget=%d\n", g_gui_wait_fd_trace_budget - 1);
    g_gui_wait_fd_trace_budget--;
}

static int poll_rescan_ready(edge_fd_proc_t *p, edge_pollfd_t *pfds,
                             int nfds) {
    if (!p || !pfds) return 0;
    return kernel_wait_poll_evaluate(
        &g_x86_wait_backend_ops, p, pfds, (uint32_t)nfds);
}

static void fd_wait_shorten_current_deadline(uint64_t deadline_us) {
    task_t *current = process_current_task();
    if (!current || current->is_idle || !deadline_us) return;
    if (!current->sleep_wait_active ||
        deadline_us < current->sleep_deadline_us) {
        current->sleep_deadline_us = deadline_us;
        current->sleep_wait_active = 1;
    }
}

typedef struct poll_wait_post_block_context {
    edge_fd_proc_t *process;
    edge_pollfd_t *pfds;
    int nfds;
    uint64_t start_us;
    int64_t timeout_us;
} poll_wait_post_block_context_t;

static int poll_wait_post_block(void *opaque) {
    poll_wait_post_block_context_t *context =
        (poll_wait_post_block_context_t *)opaque;
    edge_fd_wait_plan_t plan;
    task_t *current = process_current_task();
    uint64_t deadline;

    if (!context || !current) return 1;
    /*
     * Recollect after publishing TASK_BLOCKED.  An epoll_ctl() racing with the
     * first collection either woke this blocked task or is reflected here, so a
     * newly installed non-ready watch is registered before its first transition.
     */
    poll_wait_plan_build(
        &plan, context->process, context->pfds, context->nfds, current->pid);
    deadline = kernel_wait_plan_deadline(
        &plan, context->start_us, context->timeout_us,
        boottime_monotonic_us());
    fd_wait_shorten_current_deadline(deadline);
    if (deadline && boottime_monotonic_us() >= deadline) return 1;
    return poll_rescan_ready(
        context->process, context->pfds, context->nfds) > 0;
}

static int fd_is_console_input_fd(edge_fd_t *e) {
    if (!e) return 0;
    if (e->kind == FD_CONSOLE) return 1;
    if (e->kind == FD_VFS && path_is_tty_device(e->path)) return 1;
    return 0;
}

static int poll_console_wait_line(edge_pollfd_t *pfds, int nfds) {
    edge_fd_proc_t *p;
    if (!pfds || nfds <= 0) return -1;
    p = fd_proc_with_stdio();
    if (!p) return -1;
    for (int i = 0; i < nfds; ++i) {
        int fd = pfds[i].fd;
        edge_fd_t *e;
        if (fd < 0) continue;
        if ((pfds[i].events & (LINUX_POLLIN | LINUX_POLLPRI | LINUX_POLLRDNORM | LINUX_POLLRDBAND)) == 0) continue;
        e = fd_get(p, fd);
        if (fd_is_console_input_fd(e)) return console_line_from_fd_entry(e);
    }
    return -1;
}

static int poll_waits_only_on_console_input(
        edge_fd_proc_t *process, const edge_pollfd_t *poll_fds,
        int descriptor_count, int line_id) {
    int saw_console = 0;

    if (!process || !poll_fds || line_id < 0) return 0;
    for (int index = 0; index < descriptor_count; ++index) {
        const edge_pollfd_t *poll_fd = &poll_fds[index];
        edge_fd_t *entry;
        int16_t read_events =
            LINUX_POLLIN | LINUX_POLLPRI |
            LINUX_POLLRDNORM | LINUX_POLLRDBAND;

        if (poll_fd->fd < 0) continue;
        entry = fd_get(process, poll_fd->fd);
        if ((poll_fd->events & ~read_events) != 0 ||
            (poll_fd->events & read_events) == 0 ||
            !fd_is_console_input_fd(entry) ||
            console_line_from_fd_entry(entry) != line_id)
            return 0;
        saw_console = 1;
    }
    return saw_console;
}

static int select_console_wait_line(edge_fd_proc_t *p, int n,
                                    const uint8_t *rin) {
    if (!p || !rin || n <= 0) return -1;
    for (int fd = 0; fd < n; ++fd) {
        edge_fd_t *e;
        if (!fdset_test(rin, fd)) continue;
        e = fd_get(p, fd);
        if (fd_is_console_input_fd(e))
            return console_line_from_fd_entry(e);
    }
    return -1;
}

static int select_waits_only_on_console_input(
        edge_fd_proc_t *p, int n, const uint8_t *rin,
        const uint8_t *win, const uint8_t *ein, int line_id) {
    int saw_console = 0;
    if (!p || !rin || !win || !ein) return 0;
    for (int fd = 0; fd < n; ++fd) {
        edge_fd_t *e;
        int read = fdset_test(rin, fd);
        int write = fdset_test(win, fd);
        int except = fdset_test(ein, fd);
        if (!read && !write && !except) continue;
        e = fd_get(p, fd);
        if (!read || write || except || !fd_is_console_input_fd(e) ||
            console_line_from_fd_entry(e) != line_id)
            return 0;
        saw_console = 1;
    }
    return saw_console;
}

static int console_line_pollin_ready(int line_id) {
    edge_console_line_t *line = console_line_state(line_id);
    if (!line) return 0;
    if (line->reply_pos < line->reply_len) return 1;
    if ((line->termios.c_lflag & LINUX_ICANON) != 0) {
        for (int i = line->line_pos; i < line->line_len; ++i) {
            if (line->linebuf[i] == '\n') return 1;
        }
        /*
         * EdgeOS currently performs canonical line editing in read(), not in
         * an interrupt-side tty flip buffer.  A poll/select waiter still has
         * to wake when raw tty bytes arrive so the subsequent read can cook
         * them into linebuf.  Do not report readiness with no raw input: Xorg
         * keeps VT fds open, and unconditional tty readability lets it block
         * the X server on an empty terminal read.
         */
        if (console_line_is_serial(line_id)) return serial_console_probechar();
        if (line_id == console_line_active_vt()) return keyboard_haschar();
        return 0;
    }
    if (console_line_is_serial(line_id)) return serial_console_probechar();
    if (line_id == console_line_active_vt()) return keyboard_haschar();
    return 0;
}

static uint64_t do_sys_poll(uint64_t fds_u, uint64_t nfds_u,
                            int64_t timeout_microseconds) {
    int nfds;
    /*
     * Full desktop stacks can have many dbus, X11, timer, event, and helper
     * descriptors in one GLib poll set.  Keep this fixed-size for now, but do
     * not cap it at the tiny command-line-client case; Linux permits much
     * larger sets up to RLIMIT_NOFILE.
     */
    edge_pollfd_t pfds[KERNEL_WAIT_DESCRIPTOR_MAX];
    uint64_t start_us;
    task_t *cur = process_current_task();

    if (nfds_u > sizeof(pfds) / sizeof(pfds[0]))
        return (uint64_t)-EINVAL;
    nfds = (int)nfds_u;
    if (nfds && (!fds_u ||
        copy_from_user(pfds, fds_u,
                       (uint64_t)nfds * sizeof(pfds[0])) < 0))
        return (uint64_t)-EFAULT;
    if (ssh_trace_task(cur)) {
        printf("[sshdbg] poll-enter pid=%d cmd=%s nfds=%d timeout_us=%lld fd0=%d ev0=0x%x\n",
               cur ? cur->pid : -1, cur ? cur->name : "?", nfds,
               (long long)timeout_microseconds,
               nfds > 0 ? pfds[0].fd : -1, nfds > 0 ? (unsigned)pfds[0].events : 0);
    }
    int console_input_wait_line = poll_console_wait_line(pfds, nfds);

    start_us = boottime_monotonic_us();
    for (;;) {
        int ready;
        int ready_seen = 0;
        edge_fd_proc_t *p = fd_proc_with_stdio();

        lwip_stack_poll();
#ifdef CONFIG_USB
        /*
         * Linux input clients such as Xorg normally block in poll/select on
         * /dev/input/event*.  EdgeOS' current xHCI stack is poll driven, so
         * progress USB once before checking descriptor readiness.  Blocking
         * read paths already do this through wait_blocking_step(); the wait
         * syscalls need the same behavior or GUI input can appear dead while
         * the process is sleeping inside poll/select.
         */
        usb_poll();
#endif
        /*
         * QEMU window/HMP keyboard input can arrive through the default i8042
         * controller even when a USB keyboard is also present.  Xorg waits on
         * evdev fds rather than /dev/tty, so no console read may occur to drain
         * the PS/2 output buffer.  Draining here lets keyboard_handle_scancode()
         * publish Linux input events before the poll readiness scan.
         */
        keyboard_poll_controller();

        ready = kernel_wait_poll_evaluate(
            &g_x86_wait_backend_ops, p, pfds, (uint32_t)nfds);
        if (ready < 0) return (uint64_t)(int64_t)ready;
        for (int i = 0; i < nfds; ++i) {
            int fd = pfds[i].fd;
            int16_t ev = pfds[i].events;
            int16_t rev = pfds[i].revents;

            if (fd >= 0) {
                edge_fd_t *e = fd_get(p, fd);
                x11_trace_socket_poll(cur, "poll-scan", fd, e, ev, rev);
                xfce_poll_detail_log(cur, fd, e, ev, rev);
                if (rev != 0) ++ready_seen;
                if (rev != 0)
                    gui_ready_detail_log(
                        "poll", cur, fd, e, ev, rev,
                        ready_seen, nfds);
                if (rev != 0 && g_gui_poll_ready_list_trace_budget > 0 &&
                    gui_diag_task(cur)) {
                    uint64_t eventfd_counter = 0;
                    int socket_peer = -1;
                    uint32_t socket_rx = 0;
                    uint64_t socket_rseq = 0;
                    uint64_t socket_wseq = 0;

                    if (e && e->kind == FD_EVENTFD) {
                        eventfd_counter =
                            eventfd_counter_snapshot(e->pipe_id);
                    } else if (e && e->kind == FD_SOCKET &&
                               e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_SOCKETS &&
                               g_sockets[e->pipe_id].used) {
                        edge_socket_t *s = &g_sockets[e->pipe_id];
                        socket_peer = s->unix_peer_id;
                        socket_rx = s->rx_len;
                        kernel_socket_readiness_snapshot(
                            &s->readiness,
                            &socket_rseq, &socket_wseq);
                    }
                    /*
                     * XFCE/GLib spins are usually one descriptor in a larger
                     * ppoll() set reporting readiness that the next nonblocking
                     * operation cannot consume.  Keep this ready-list trace
                     * bounded and fd-generic: it should identify bad Linux ABI
                     * readiness without depending on Alpine paths or XFCE
                     * policy.
                     */
                    printf("[poll-list] pid=%d cmd=%s idx=%d fd=%d kind=%d id=%d ev=0x%x rev=0x%x ready=%d/%d fl=0x%x path=%s evcnt=%llu peer=%d rx=%u rseq=%llu wseq=%llu budget=%d\n",
                           cur ? cur->pid : -1, cur ? cur->name : "?",
                           i, fd, e ? (int)e->kind : -1, e ? e->pipe_id : -1,
                           (unsigned)ev, (unsigned)rev, ready_seen, nfds,
                           e ? (unsigned)e->flags : 0,
                           (e && e->path[0]) ? e->path : "-",
                           (unsigned long long)eventfd_counter,
                           socket_peer, socket_rx,
                           (unsigned long long)socket_rseq,
                           (unsigned long long)socket_wseq,
                           g_gui_poll_ready_list_trace_budget - 1);
                    g_gui_poll_ready_list_trace_budget--;
                }
            }
        }

        if (ready > 0) {
            int ready_ret = ready;
            if (ready_ret > nfds) {
                static int poll_bad_ready_budget = 16;
                if (poll_bad_ready_budget-- > 0) {
                    printf("[poll-abi] pid=%d cmd=%s bad-ready=%d nfds=%d fd0=%d rev0=0x%x budget=%d\n",
                           cur ? cur->pid : -1, cur ? cur->name : "?",
                           ready_ret, nfds,
                           nfds > 0 ? pfds[0].fd : -1,
                           nfds > 0 ? (unsigned)pfds[0].revents : 0,
                           poll_bad_ready_budget);
                }
                ready_ret = nfds;
            }
            if (ssh_trace_task(cur)) {
                printf("[sshdbg] poll-ready pid=%d cmd=%s ready=%d fd0=%d rev0=0x%x\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       ready_ret, nfds > 0 ? pfds[0].fd : -1,
                       nfds > 0 ? (unsigned)pfds[0].revents : 0);
            }
            if (x11_poll_trace_task(cur) && g_x11_poll_trace_budget-- > 0) {
                printf("[x11dbg] poll-ready pid=%d cmd=%s ready=%d nfds=%d\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       ready_ret, nfds);
            }
            /*
             * A ready poll result is a hot userspace path.  Linux preempts
             * processes that repeatedly observe immediately writable/readable
             * descriptors, but EdgeOS currently runs syscalls cooperatively
             * until they block or yield.  Full desktops expose that difference:
             * Xorg/GTK/DBus loops can see AF_UNIX POLLOUT forever and starve
             * the session manager, serial shell, and input polling even though
             * each individual poll result is Linux-compatible.  Yield only for
             * known GUI event-loop tasks so command-line poll throughput stays
             * unchanged while unmodified Linux desktops get scheduler fairness.
             */
            if (nfds && copy_to_user(fds_u, pfds,
                                     (uint64_t)nfds * sizeof(pfds[0])) < 0)
                return (uint64_t)-EFAULT;
            for (int index = 0; index < nfds; ++index) {
                edge_fd_t *entry;
                if (!pfds[index].revents || pfds[index].fd < 0) continue;
                entry = fd_get(p, pfds[index].fd);
                if (fd_is_mount_event_source(entry))
                    fd_mount_monitor_acknowledge(entry);
            }
            if (gui_hot_poll_task(cur)) wait_gui_ready_preempt_step();
            return (uint64_t)ready_ret;
        }

        /*
         * Linux reports already-visible readiness before an interrupting
         * signal. This ordering also prevents a ready descriptor and a signal
         * arriving together from spuriously turning poll() into EINTR.
         */
        if (signal_pending_interrupt()) return tty_interrupt_current_ret();

        if (timeout_microseconds == 0) {
            if (x11_poll_trace_task(cur) && g_x11_poll_trace_budget-- > 0) {
                printf("[x11dbg] poll-timeout0 pid=%d cmd=%s nfds=%d fd0=%d ev0=0x%x rev0=0x%x\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       nfds, nfds > 0 ? pfds[0].fd : -1,
                       nfds > 0 ? (unsigned)pfds[0].events : 0,
                       nfds > 0 ? (unsigned)pfds[0].revents : 0);
            }
            if (ssh_trace_task(cur)) {
                printf("[sshdbg] poll-timeout0 pid=%d cmd=%s\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?");
            }
            if (nfds && copy_to_user(fds_u, pfds,
                                     (uint64_t)nfds * sizeof(pfds[0])) < 0)
                return (uint64_t)-EFAULT;
            return 0;
        }
        if (timeout_microseconds > 0) {
            uint64_t now_us = boottime_monotonic_us();
            if (now_us - start_us >= (uint64_t)timeout_microseconds) {
                if (ssh_trace_task(cur)) {
                    printf("[sshdbg] poll-timeout pid=%d cmd=%s\n",
                           cur ? cur->pid : -1, cur ? cur->name : "?");
                }
                if (nfds && copy_to_user(fds_u, pfds,
                                         (uint64_t)nfds * sizeof(pfds[0])) < 0)
                    return (uint64_t)-EFAULT;
                return 0;
            }
        }
        if (console_input_wait_line >= 0 &&
            poll_waits_only_on_console_input(
                p, pfds, nfds, console_input_wait_line)) {
            console_line_sleep_for_input_until(
                console_input_wait_line,
                kernel_wait_deadline_from_timeout(
                    start_us, timeout_microseconds));
        }
        else {
            if (cur) {
                edge_fd_wait_plan_t plan;
                poll_wait_post_block_context_t post_block_context = {
                    .process = p,
                    .pfds = pfds,
                    .nfds = nfds,
                    .start_us = start_us,
                    .timeout_us = timeout_microseconds,
                };
                uint64_t deadline_us;
                poll_wait_plan_build(
                    &plan, p, pfds, nfds, cur->pid);
                deadline_us = kernel_wait_plan_deadline(
                    &plan, start_us, timeout_microseconds,
                    boottime_monotonic_us());
                /*
                 * Linux wait queues use the prepare-to-wait pattern: link the
                 * waiter, then re-check the condition before scheduling.  If
                 * an AF_UNIX packet or eventfd write lands between EdgeOS' first
                 * readiness scan and waiter registration, no wakeup callback saw
                 * this task yet.  Sleeping here would strand X11/DBus clients in
                 * poll() even though their fd is already readable.  Keep this
                 * generic for all poll waiters; do not paper over missed X11
                 * events in userspace.
                 */
                if (poll_rescan_ready(p, pfds, nfds) > 0) {
                    waiter_remove_pid(cur->pid);
                    continue;
                }
                gui_poll_wait_trace(
                    "poll", cur, p, pfds, nfds, deadline_us,
                    plan.all_sources_exact,
                    plan.needs_periodic_rescan);
                socket_blocking_wait_step_checked(
                    deadline_us, poll_wait_post_block,
                    &post_block_context);
            } else {
                socket_blocking_wait_step(
                    kernel_wait_bounded_rescan_deadline(
                        start_us, timeout_microseconds,
                        boottime_monotonic_us()));
            }
        }
    }
}

int64_t arch_poll_wait_descriptors(uint64_t user_poll_fds,
                                   uint64_t descriptor_count,
                                   int64_t timeout_microseconds,
                                   uint64_t user_timeout,
                                   int replace_signal_mask,
                                   uint64_t signal_mask,
                                   void *user_registers) {
    task_t *cur = process_current_task();
    uint64_t start_microseconds = boottime_monotonic_us();
    uint64_t deadline_microseconds = UINT64_MAX;
    uint64_t old_sigmask = 0;
    uint64_t ret;
    (void)user_registers;
    if (timeout_microseconds >= 0) {
        uint64_t duration = (uint64_t)timeout_microseconds;
        deadline_microseconds =
            start_microseconds > UINT64_MAX - duration ? UINT64_MAX :
                                                         start_microseconds + duration;
    }
    if (replace_signal_mask && cur) {
        /*
         * Linux ppoll() atomically installs a temporary signal mask while the
         * wait is in progress, then restores the caller's mask before returning.
         * GLib relies on this to avoid signal races around its main loop; simply
         * ignoring the argument makes otherwise quiet desktop processes take
         * spurious EINTR paths and retry in tight loops.
         */
        old_sigmask = cur->sigmask;
        task_install_wait_sigmask(cur, signal_mask);
    }
    ret = do_sys_poll(user_poll_fds, descriptor_count,
                      timeout_microseconds);
    if (replace_signal_mask && cur) {
        task_restore_wait_sigmask_unless(cur, (int64_t)ret == -(int64_t)EINTR);
    }
    if (user_timeout) {
        linux_timespec64_t remaining;
        uint64_t now = boottime_monotonic_us();
        uint64_t remaining_microseconds =
            now >= deadline_microseconds ? 0 : deadline_microseconds - now;
        linux_timespec_from_microseconds(remaining_microseconds, &remaining);
        if (copy_to_user(user_timeout, &remaining, sizeof(remaining)) < 0)
            ret = (uint64_t)-EFAULT;
    }
    if ((int64_t)ret < 0 && gui_diag_task(cur)) {
        static int ppoll_neg_budget = EDGE_GUI_DEEP_TRACE ? 48 : 0;
        if (ppoll_neg_budget-- > 0) {
            printf("[ppoll-abi] pid=%d cmd=%s nfds=%llu timeout_us=%lld ret=%d sigmask=%d old=0x%x new=0x%x pending=0x%x alrm=%u chld=%u io=%u rtmin=%u budget=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   (unsigned long long)descriptor_count,
                   (long long)timeout_microseconds, (int)(int64_t)ret,
                   replace_signal_mask,
                   (uint32_t)old_sigmask, (uint32_t)signal_mask,
                   task_pending_signal_bits(cur),
                   cur ? (unsigned)((task_pending_signal_mask(cur) &
                                     edge_linux_signal_mask_bit(LINUX_SIGALRM)) != 0) : 0,
                   cur ? (unsigned)((task_pending_signal_mask(cur) &
                                     edge_linux_signal_mask_bit(LINUX_SIGCHLD)) != 0) : 0,
                   cur ? (unsigned)((task_pending_signal_mask(cur) &
                                     edge_linux_signal_mask_bit(LINUX_SIGIO)) != 0) : 0,
                   cur ? (unsigned)((task_pending_signal_mask(cur) &
                                     edge_linux_signal_mask_bit(
                                         EDGE_LINUX_SIGRTMIN_KERNEL + 2u)) != 0) : 0,
                   ppoll_neg_budget);
        }
    }
    return (int64_t)ret;
}

static int select_rescan_ready(edge_fd_proc_t *p, int n,
                               const uint8_t *rin, const uint8_t *win, const uint8_t *ein) {
    if (!p) return 0;
    return kernel_wait_select_evaluate(
        &g_x86_wait_backend_ops, p, (uint32_t)n,
        rin, win, ein, 0, 0, 0);
}

static int select_allocated_descriptor_limit(
    edge_fd_proc_t *process, int requested) {
    uint32_t allocated_limit;
    uint64_t irq_flags;

    if (!process || requested <= 0) return requested;
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    allocated_limit = kernel_fd_table_allocated_limit_locked(
        &process->table_runtime);
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    return requested > (int)allocated_limit ?
        (int)allocated_limit : requested;
}

typedef struct select_wait_post_block_context {
    edge_fd_proc_t *process;
    int nfds;
    const uint8_t *read_set;
    const uint8_t *write_set;
    const uint8_t *except_set;
    uint64_t start_us;
    int64_t timeout_us;
} select_wait_post_block_context_t;

static int select_wait_post_block(void *opaque) {
    select_wait_post_block_context_t *context =
        (select_wait_post_block_context_t *)opaque;
    edge_fd_wait_plan_t plan;
    task_t *current = process_current_task();
    uint64_t deadline;

    if (!context || !current) return 1;
    select_wait_plan_build(
        &plan, context->process, context->nfds,
        context->read_set, context->write_set, context->except_set,
        current->pid);
    deadline = kernel_wait_plan_deadline(
        &plan, context->start_us, context->timeout_us,
        boottime_monotonic_us());
    fd_wait_shorten_current_deadline(deadline);
    if (deadline && boottime_monotonic_us() >= deadline) return 1;
    return select_rescan_ready(
        context->process, context->nfds, context->read_set,
        context->write_set, context->except_set) != 0;
}

static uint64_t do_sys_select(uint64_t n_u, uint64_t rfds_u,
                              uint64_t wfds_u, uint64_t efds_u,
                              int64_t timeout_microseconds) {
    int n = (int)n_u;
    uint32_t nbytes;
    uint64_t start_us = boottime_monotonic_us();
    uint8_t rin[EDGE_SELECT_FD_BYTES];
    uint8_t win[EDGE_SELECT_FD_BYTES];
    uint8_t ein[EDGE_SELECT_FD_BYTES];
    uint8_t rout[EDGE_SELECT_FD_BYTES];
    uint8_t wout[EDGE_SELECT_FD_BYTES];
    uint8_t eout[EDGE_SELECT_FD_BYTES];
    task_t *cur = process_current_task();
    edge_fd_proc_t *p;
    int scan_n;

    if (n < 0 || n > EDGE_SELECT_FD_MAX) return (uint64_t)-EINVAL;
    nbytes = (uint32_t)(((n + 63) / 64) * sizeof(uint64_t));
    if (nbytes > EDGE_SELECT_FD_BYTES) return (uint64_t)-EINVAL;
    memset(rin, 0, sizeof(rin));
    memset(win, 0, sizeof(win));
    memset(ein, 0, sizeof(ein));

    if (rfds_u && nbytes && copy_from_user(rin, rfds_u, nbytes) < 0) return (uint64_t)-EFAULT;
    if (wfds_u && nbytes && copy_from_user(win, wfds_u, nbytes) < 0) return (uint64_t)-EFAULT;
    if (efds_u && nbytes && copy_from_user(ein, efds_u, nbytes) < 0) return (uint64_t)-EFAULT;

    p = fd_proc_with_stdio();
    scan_n = select_allocated_descriptor_limit(p, n);
    if (ssh_trace_task(cur)) {
        printf("[sshdbg] select-enter pid=%d cmd=%s n=%d timeout_us=%lld rfds=%d wfds=%d efds=%d fd0r=%d\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               n, (long long)timeout_microseconds,
               rfds_u ? 1 : 0, wfds_u ? 1 : 0, efds_u ? 1 : 0,
               (rfds_u && n > 0) ? fdset_test(rin, 0) : 0);
    }
    for (;;) {
        int ready = 0;
        memcpy(rout, rin, sizeof(rout));
        memcpy(wout, win, sizeof(wout));
        memcpy(eout, ein, sizeof(eout));

        lwip_stack_poll();
#ifdef CONFIG_USB
        usb_poll();
#endif
        keyboard_poll_controller();

        ready = kernel_wait_select_evaluate(
            &g_x86_wait_backend_ops, p, (uint32_t)scan_n,
            rin, win, ein, rout, wout, eout);
        if (ready < 0) return (uint64_t)(int64_t)ready;

        if (ready > 0) {
            if (ssh_trace_task(cur)) {
                printf("[sshdbg] select-ready pid=%d cmd=%s ready=%d fd0r=%d\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       ready, n > 0 ? fdset_test(rout, 0) : 0);
            }
            if (x11_poll_trace_task(cur) && g_x11_poll_trace_budget-- > 0) {
                printf("[x11dbg] select-ready pid=%d cmd=%s ready=%d n=%d\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       ready, n);
            }
            /*
             * Do not yield on an immediately-ready select result.  Woken
             * waiters are queued by the fd/socket wake paths, while X11/XCB
             * clients depend on cheap readiness probes for acceptable latency.
             */
            if (rfds_u && nbytes && copy_to_user(rfds_u, rout, nbytes) < 0) return (uint64_t)-EFAULT;
            if (wfds_u && nbytes && copy_to_user(wfds_u, wout, nbytes) < 0) return (uint64_t)-EFAULT;
            if (efds_u && nbytes && copy_to_user(efds_u, eout, nbytes) < 0) return (uint64_t)-EFAULT;
            for (int fd = 0; fd < scan_n; ++fd) {
                edge_fd_t *entry;
                if (!fdset_test(rout, fd) &&
                    !fdset_test(wout, fd) &&
                    !fdset_test(eout, fd))
                    continue;
                entry = fd_get(p, fd);
                if (fd_is_mount_event_source(entry))
                    fd_mount_monitor_acknowledge(entry);
            }
            return (uint64_t)ready;
        }

        if (signal_pending_interrupt()) return tty_interrupt_current_ret();

        if (timeout_microseconds == 0) {
            if (rfds_u && nbytes && copy_to_user(rfds_u, rout, nbytes) < 0) return (uint64_t)-EFAULT;
            if (wfds_u && nbytes && copy_to_user(wfds_u, wout, nbytes) < 0) return (uint64_t)-EFAULT;
            if (efds_u && nbytes && copy_to_user(efds_u, eout, nbytes) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (timeout_microseconds > 0) {
            uint64_t now_us = boottime_monotonic_us();
            if (now_us - start_us >= (uint64_t)timeout_microseconds) {
                if (rfds_u && nbytes && copy_to_user(rfds_u, rout, nbytes) < 0) return (uint64_t)-EFAULT;
                if (wfds_u && nbytes && copy_to_user(wfds_u, wout, nbytes) < 0) return (uint64_t)-EFAULT;
                if (efds_u && nbytes && copy_to_user(efds_u, eout, nbytes) < 0) return (uint64_t)-EFAULT;
                return 0;
            }
        }
        {
            int console_input_wait_line =
                select_console_wait_line(p, scan_n, rin);
            if (console_input_wait_line >= 0) {
                edge_console_line_t *line =
                    console_line_state(console_input_wait_line);
                int waiter_conflict =
                    line && line->read_wait_pid > 0 && cur &&
                    line->read_wait_pid != cur->pid;
                uint64_t deadline_us =
                    kernel_wait_deadline_from_timeout(
                        start_us, timeout_microseconds);
                /*
                 * pselect() is the normal idle path for getty and interactive
                 * shells.  A console-only set can sleep until the tty wakeup;
                 * a mixed set also needs a bounded rescan for its non-console
                 * descriptors until every fd kind has a shared wait source.
                 * Keeping either case runnable turns an idle desktop into a
                 * full-vCPU polling loop.
                 */
                if (!select_waits_only_on_console_input(
                        p, scan_n, rin, win, ein,
                        console_input_wait_line) ||
                    waiter_conflict) {
                    deadline_us = kernel_wait_deadline_min(
                        deadline_us,
                        kernel_wait_bounded_rescan_deadline(
                            start_us, timeout_microseconds,
                            boottime_monotonic_us()));
                }
                if (waiter_conflict) {
                    /*
                     * Each compact console line currently has one exact
                     * reader slot.  Do not overwrite another blocked reader:
                     * keep that exact wakeup intact and let this additional
                     * waiter use the bounded compatibility rescan.
                     */
                    socket_blocking_wait_step(deadline_us);
                } else {
                    console_line_sleep_for_input_until(
                        console_input_wait_line, deadline_us);
                }
                continue;
            }
        }
        if (cur) {
            edge_fd_wait_plan_t plan;
            select_wait_post_block_context_t post_block_context = {
                .process = p,
                .nfds = scan_n,
                .read_set = rin,
                .write_set = win,
                .except_set = ein,
                .start_us = start_us,
                .timeout_us = timeout_microseconds,
            };
            uint64_t deadline_us;
            select_wait_plan_build(
                &plan, p, scan_n, rin, win, ein, cur->pid);
            deadline_us = kernel_wait_plan_deadline(
                &plan, start_us, timeout_microseconds,
                boottime_monotonic_us());
            if (select_rescan_ready(p, scan_n, rin, win, ein) != 0) {
                waiter_remove_pid(cur->pid);
                continue;
            }
            socket_blocking_wait_step_checked(
                deadline_us, select_wait_post_block,
                &post_block_context);
        } else {
            socket_blocking_wait_step(
                kernel_wait_bounded_rescan_deadline(
                    start_us, timeout_microseconds,
                    boottime_monotonic_us()));
        }
    }
}

static int select_write_remaining_timeout(uint64_t user_timeout,
                                          uint32_t timeout_format,
                                          uint64_t deadline_microseconds) {
    uint64_t now;
    uint64_t remaining_microseconds;

    if (!user_timeout || timeout_format == KERNEL_WAIT_TIMEOUT_NONE) return 0;
    now = boottime_monotonic_us();
    remaining_microseconds = now >= deadline_microseconds ? 0 :
                                                        deadline_microseconds - now;
    if (timeout_format == KERNEL_WAIT_TIMEOUT_TIMESPEC) {
        linux_timespec64_t remaining;
        linux_timespec_from_microseconds(remaining_microseconds, &remaining);
        return copy_to_user(user_timeout, &remaining, sizeof(remaining)) < 0 ?
               -EFAULT : 0;
    }
    if (timeout_format == KERNEL_WAIT_TIMEOUT_TIMEVAL) {
        linux_timeval64_t remaining;
        linux_timeval_from_microseconds(remaining_microseconds, &remaining);
        return copy_to_user(user_timeout, &remaining, sizeof(remaining)) < 0 ?
               -EFAULT : 0;
    }
    return -EINVAL;
}

int64_t arch_select_wait_descriptors(uint64_t descriptor_count,
                                     uint64_t user_read_set,
                                     uint64_t user_write_set,
                                     uint64_t user_except_set,
                                     int64_t timeout_microseconds,
                                     uint64_t user_timeout,
                                     uint32_t timeout_format,
                                     int replace_signal_mask,
                                     uint64_t signal_mask,
                                     void *user_registers) {
    task_t *cur = process_current_task();
    uint64_t start_microseconds = boottime_monotonic_us();
    uint64_t deadline_microseconds = UINT64_MAX;
    uint64_t old_signal_mask = 0;
    uint64_t result;
    int timeout_status;

    (void)user_registers;
    if (timeout_microseconds >= 0) {
        uint64_t duration = (uint64_t)timeout_microseconds;
        deadline_microseconds =
            start_microseconds > UINT64_MAX - duration ? UINT64_MAX :
                                                         start_microseconds + duration;
    }
    if (replace_signal_mask && cur) {
        old_signal_mask = cur->sigmask;
        task_install_wait_sigmask(cur, signal_mask);
    }
    result = do_sys_select(descriptor_count, user_read_set, user_write_set,
                           user_except_set, timeout_microseconds);
    if (replace_signal_mask && cur)
        task_restore_wait_sigmask_unless(
            cur, (int64_t)result == -(int64_t)EINTR);

    timeout_status = select_write_remaining_timeout(
        user_timeout, timeout_format, deadline_microseconds);
    if (timeout_status < 0) result = (uint64_t)(int64_t)timeout_status;
    if ((int64_t)result < 0 && gui_diag_task(cur)) {
        static int pselect_neg_budget = EDGE_GUI_DEEP_TRACE ? 48 : 12;
        if (pselect_neg_budget-- > 0) {
            printf("[pselect-abi] pid=%d cmd=%s nfds=%llu timeout_us=%lld ret=%d sigmask=%d old=0x%x new=0x%x pending=0x%x budget=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   (unsigned long long)descriptor_count,
                   (long long)timeout_microseconds,
                   (int)(int64_t)result, replace_signal_mask,
                   (uint32_t)old_signal_mask, (uint32_t)signal_mask,
                   task_pending_signal_bits(cur), pselect_neg_budget);
        }
    }
    return (int64_t)result;
}

static uint64_t do_sys_sleep_until_us(uint64_t target_us) {
    for (;;) {
        task_t *cur;
        uint64_t now_us = boottime_monotonic_us();
        if (now_us >= target_us) {
            cur = process_current_task();
            if (cur) {
                if (g_sleep_trace_budget > 0) {
                    printf("[sleepdbg] return pid=%d cmd=%s now=%llu target=%llu state=%d budget=%d\n",
                           cur->pid, cur->name,
                           (unsigned long long)now_us,
                           (unsigned long long)target_us,
                           (int)cur->state,
                           g_sleep_trace_budget - 1);
                    g_sleep_trace_budget--;
                }
                cur->sleep_wait_active = 0;
                cur->sleep_deadline_us = 0;
            }
            return 0;
        }
        if (signal_pending_interrupt()) {
            cur = process_current_task();
            if (cur) {
                cur->sleep_wait_active = 0;
                cur->sleep_deadline_us = 0;
            }
            return tty_interrupt_current_ret();
        }
        lwip_stack_poll();
#ifdef CONFIG_USB
        usb_poll();
#endif
        keyboard_poll_controller();
        cur = process_current_task();
        if (!cur || cur->is_idle) {
            wait_blocking_step();
            continue;
        }
        if (cur->state == TASK_ZOMBIE) {
            cur->sleep_wait_active = 0;
            cur->sleep_deadline_us = 0;
            return (uint64_t)-EINTR;
        }
        /*
         * Linux sleep syscalls remove the task from the run queue until either
         * a signal arrives or the timeout expires.  Busy-yielding here kept
         * daemons such as crond permanently runnable and consumed a vCPU while
         * the guest was otherwise idle.
         */
        if (g_sleep_trace_budget > 0) {
            printf("[sleepdbg] block pid=%d cmd=%s now=%llu target=%llu cpu=%u assigned=%d state=%d budget=%d\n",
                   cur->pid, cur->name,
                   (unsigned long long)now_us,
                   (unsigned long long)target_us,
                   scheduler_cpu_id(),
                   cur->assigned_cpu,
                   (int)cur->state,
                   g_sleep_trace_budget - 1);
            g_sleep_trace_budget--;
        }
        cur->sleep_deadline_us = target_us;
        cur->sleep_wait_active = 1;
        scheduler_task_set_blocked(cur);
        scheduler_yield();
    }
}

static uint64_t do_sys_sleep(uint64_t ms) {
    uint64_t now_us;
    if (ms == 0) return 0;
    now_us = boottime_monotonic_us();
    return do_sys_sleep_until_us(now_us + ms * 1000ull);
}

static uint64_t do_sys_dmesg(void) {
    char chunk[512];
    uint32_t off = 0;
    uint32_t n = bootlog_buffer_size();
    while (off < n) {
        uint32_t r = bootlog_read(off, chunk, sizeof(chunk));
        if (r == 0) break;
        for (uint32_t i = 0; i < r; ++i) console_putchar(chunk[i]);
        off += r;
    }
    return 0;
}

static uint64_t do_sys_stat(uint64_t path_u) {
    char path[256];
    vfs_inode_t ino;
    if (!path_u) return (uint64_t)-EINVAL;
    if (resolve_user_path_follow(path_u, path, sizeof(path), &ino, 0) < 0) return (uint64_t)-EINVAL;
    if (vfs_resolve(path, &ino, 0, 0, 0) < 0) return (uint64_t)-EINVAL;
    printf("  File: %s\n", path);
    printf("  Size: %d\n", (int)ino.size);
    printf("Inode: %d\n", (int)ino.ino);
    printf(" Mode: %x\n", (int)ino.mode);
    return 0;
}

static uint64_t do_sys_mv(uint64_t src_u, uint64_t dst_u) {
    char src[256], dst[256];
    static char tmp[131072];
    int n;
    if (!src_u || !dst_u) return (uint64_t)-EINVAL;
    if (copy_user_cstr(src, sizeof(src), src_u) < 0) return (uint64_t)-EFAULT;
    if (copy_user_cstr(dst, sizeof(dst), dst_u) < 0) return (uint64_t)-EFAULT;
    n = vfs_read_file(src, tmp, sizeof(tmp));
    if (n < 0) return (uint64_t)-EINVAL;
    if (vfs_write_file(dst, tmp, (uint32_t)n) < 0) return (uint64_t)-EINVAL;
    if (vfs_unlink(src) < 0) return (uint64_t)-EINVAL;
    return 0;
}

static uint64_t do_sys_writefile(uint64_t path_u, uint64_t buf_u, uint64_t len) {
    char path[256];
    static char tmp[131072];
    if (!path_u) return (uint64_t)-EINVAL;
    if (len > sizeof(tmp)) return (uint64_t)-EINVAL;
    if (copy_user_cstr(path, sizeof(path), path_u) < 0) return (uint64_t)-EFAULT;
    if (len && (!buf_u || copy_from_user(tmp, buf_u, len) < 0)) return (uint64_t)-EFAULT;
    return vfs_write_file(path, tmp, (uint32_t)len) < 0 ? (uint64_t)-EINVAL : 0;
}

static uint64_t do_sys_readfile(uint64_t path_u, uint64_t buf_u, uint64_t max_len) {
    char path[256];
    static char tmp[131072];
    int n;
    if (!path_u || !buf_u) return (uint64_t)-EINVAL;
    if (max_len == 0) return 0;
    if (max_len > sizeof(tmp)) max_len = sizeof(tmp);
    if (copy_user_cstr(path, sizeof(path), path_u) < 0) return (uint64_t)-EFAULT;
    n = vfs_read_file(path, tmp, (uint32_t)max_len);
    if (n < 0) return (uint64_t)-EINVAL;
    if (copy_to_user(buf_u, tmp, (uint64_t)n) < 0) return (uint64_t)-EFAULT;
    return (uint64_t)n;
}

static int dev_fd_path_number(const char *path, int *fd_out);

static int dev_fd_path_number(const char *path, int *fd_out) {
    const char *n = 0;
    int fd = 0;
    if (!path || !fd_out) return -1;
    if (strcmp(path, "/dev/stdin") == 0) {
        *fd_out = 0;
        return 0;
    }
    if (strcmp(path, "/dev/stdout") == 0) {
        *fd_out = 1;
        return 0;
    }
    if (strcmp(path, "/dev/stderr") == 0) {
        *fd_out = 2;
        return 0;
    }
    if (strncmp(path, "/dev/fd/", 8) == 0) n = path + 8;
    else if (strncmp(path, "/proc/self/fd/", 14) == 0) n = path + 14;
    else return -1;
    if (!n[0]) return -1;
    for (const char *p = n; *p; ++p) {
        if (*p < '0' || *p > '9') return -1;
        fd = fd * 10 + (*p - '0');
        if (fd > 1000000) return -1;
    }
    *fd_out = fd;
    return 0;
}

static uint64_t do_sys_dup(uint64_t fd_u);

#define EDGE_NAMED_FIFO_MAX EDGE_MAX_PIPES

typedef struct {
    int used;
    int pipe_id;
    vfs_superblock_t *superblock;
    uint64_t inode;
    uint32_t generation;
} edge_named_fifo_t;

static edge_named_fifo_t g_named_fifos[EDGE_NAMED_FIFO_MAX];

static int named_fifo_pipe_for_inode(vfs_superblock_t *superblock,
                                     const vfs_inode_t *inode,
                                     int create) {
    int free_idx = -1;
    if (!superblock || !inode) return -1;
    for (int i = 0; i < EDGE_NAMED_FIFO_MAX; ++i) {
        edge_named_fifo_t *nf = &g_named_fifos[i];
        if (nf->used) {
            if (nf->pipe_id < 0 || nf->pipe_id >= EDGE_MAX_PIPES || !g_pipes[nf->pipe_id].used) {
                memset(nf, 0, sizeof(*nf));
            } else if (vfs_superblock_same_filesystem(
                           nf->superblock, superblock) &&
                       nf->inode == inode->ino &&
                       nf->generation == inode->generation) {
                return nf->pipe_id;
            }
        }
        if (!nf->used && free_idx < 0) free_idx = i;
    }
    if (!create || free_idx < 0) return -1;
    {
        int pid = pipe_alloc();
        if (pid < 0) return -1;
        g_named_fifos[free_idx].used = 1;
        g_named_fifos[free_idx].pipe_id = pid;
        g_named_fifos[free_idx].superblock =
            vfs_superblock_stable(superblock);
        g_named_fifos[free_idx].inode = inode->ino;
        g_named_fifos[free_idx].generation = inode->generation;
        return pid;
    }
}

static void fifo_pending_reader_begin(edge_pipe_t *pp) {
    if (!pp) return;
    if (kernel_pipe_endpoint_retain(pp, 1, 0) < 0) return;
    if (kernel_pipe_pending_retain(pp, 1, 0) < 0)
        (void)kernel_pipe_endpoint_drop(pp, 1, 0, 0, 0, 0);
}

static void fifo_pending_writer_begin(edge_pipe_t *pp) {
    if (!pp) return;
    if (kernel_pipe_endpoint_retain(pp, 0, 1) < 0) return;
    if (kernel_pipe_pending_retain(pp, 0, 1) < 0)
        (void)kernel_pipe_endpoint_drop(pp, 0, 1, 0, 0, 0);
}

static void fifo_pending_reader_cancel(int pipe_id) {
    edge_pipe_t *pp;
    if (pipe_id < 0 || pipe_id >= EDGE_MAX_PIPES) return;
    pp = &g_pipes[pipe_id];
    if (!pp->used) return;
    (void)kernel_pipe_pending_drop(pp, 1, 0);
    pipe_drop_reader(pipe_id);
}

static void fifo_pending_writer_cancel(int pipe_id) {
    edge_pipe_t *pp;
    if (pipe_id < 0 || pipe_id >= EDGE_MAX_PIPES) return;
    pp = &g_pipes[pipe_id];
    if (!pp->used) return;
    (void)kernel_pipe_pending_drop(pp, 0, 1);
    pipe_drop_writer(pipe_id);
}

static void fifo_pending_reader_commit(edge_pipe_t *pp) {
    if (!pp) return;
    (void)kernel_pipe_pending_drop(pp, 1, 0);
}

static void fifo_pending_writer_commit(edge_pipe_t *pp) {
    if (!pp) return;
    (void)kernel_pipe_pending_drop(pp, 0, 1);
}

static int fifo_installed_readers(const edge_pipe_t *pp) {
    int readers;
    if (!pp) return 0;
    readers = pp->readers - pp->pending_readers;
    return readers > 0 ? readers : 0;
}

static int fifo_reader_open_ready_after_block(void *context) {
    edge_pipe_t *pipe = (edge_pipe_t *)context;

    return !pipe || !pipe->used || pipe->writers > 0;
}

static int fifo_writer_open_ready_after_block(void *context) {
    edge_pipe_t *pipe = (edge_pipe_t *)context;

    return !pipe || !pipe->used || fifo_installed_readers(pipe) > 0;
}

static uint64_t open_fifo_pipe_fd(edge_fd_proc_t *p, const char *path,
                                  int flags, int pid) {
    int acc = flags & LINUX_O_ACCMODE;
    int want_read = (acc == 0 || acc == LINUX_O_RDWR);
    int want_write = (acc == LINUX_O_WRONLY || acc == LINUX_O_RDWR);
    edge_pipe_t *pp;
    int fd;
    edge_fd_t *e;
    task_t *cur = process_current_task();

    if (!p || pid < 0 || pid >= EDGE_MAX_PIPES) return (uint64_t)-ENOMEM;
    pp = &g_pipes[pid];
    if (!pp->used) return (uint64_t)-ENOMEM;
    if (!want_read && !want_write) want_read = 1;

    if (want_write && !want_read && pp->readers == 0 && (flags & LINUX_O_NONBLOCK)) {
        return (uint64_t)-ENXIO;
    }

    if (want_read && !want_write) {
        fifo_pending_reader_begin(pp);
        fd_wake_pipe_waiters(pid);
        while (pp->writers == 0 && !(flags & LINUX_O_NONBLOCK)) {
            if (signal_pending_interrupt()) {
                fifo_pending_reader_cancel(pid);
                return tty_interrupt_current_ret();
            }
            pipe_read_waiter_add(pid, cur ? cur->pid : 0);
            if (!pp->used) return (uint64_t)-EIO;
            if (pp->writers > 0) {
                if (cur) waiter_remove_pid(cur->pid);
                break;
            }
            socket_blocking_wait_step_checked(
                0, fifo_reader_open_ready_after_block, pp);
        }
    } else if (want_write && !want_read) {
        fifo_pending_writer_begin(pp);
        fd_wake_pipe_waiters(pid);
        while (fifo_installed_readers(pp) == 0 && !(flags & LINUX_O_NONBLOCK)) {
            if (signal_pending_interrupt()) {
                fifo_pending_writer_cancel(pid);
                return tty_interrupt_current_ret();
            }
            pipe_write_waiter_add(pid, cur ? cur->pid : 0);
            if (!pp->used) return (uint64_t)-EIO;
            if (fifo_installed_readers(pp) > 0) {
                if (cur) waiter_remove_pid(cur->pid);
                break;
            }
            socket_blocking_wait_step_checked(
                0, fifo_writer_open_ready_after_block, pp);
        }
    } else {
        if (kernel_pipe_endpoint_retain(pp, 1, 1) < 0)
            return (uint64_t)-ENFILE;
        fd_wake_pipe_waiters(pid);
    }

    fd = fd_alloc(p, 0);
    if (fd < 0) {
        if (want_read && !want_write) fifo_pending_reader_cancel(pid);
        else if (want_write && !want_read) fifo_pending_writer_cancel(pid);
        else {
            if (want_read) pipe_drop_reader(pid);
            if (want_write) pipe_drop_writer(pid);
        }
        return (uint64_t)-EMFILE;
    }
    e = &p->fds[fd];
    e->file_ref = file_ref_alloc((uint32_t)flags);
    if (!e->file_ref) {
        if (want_read && !want_write) fifo_pending_reader_cancel(pid);
        else if (want_write && !want_read) fifo_pending_writer_cancel(pid);
        else {
            if (want_read) pipe_drop_reader(pid);
            if (want_write) pipe_drop_writer(pid);
        }
        fd_abort_reserved(p, fd);
        return (uint64_t)-ENFILE;
    }
    e->kind = want_read && want_write ? FD_PIPE_RW : (want_read ? FD_PIPE_R : FD_PIPE_W);
    e->flags = flags;
    e->fd_flags = (flags & LINUX_O_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    e->pipe_id = pid;
    fd_description_set_offset(e, 0);
    strncpy(e->path, path, sizeof(e->path) - 1);
    e->path[sizeof(e->path) - 1] = 0;
    if (want_read && !want_write) fifo_pending_reader_commit(pp);
    else if (want_write && !want_read) fifo_pending_writer_commit(pp);
    if (fd_publish(p, fd) < 0) {
        if (want_read) pipe_drop_reader(pid);
        if (want_write) pipe_drop_writer(pid);
        (void)file_ref_put(e->file_ref);
        fd_abort_reserved(p, fd);
        return (uint64_t)-EBADF;
    }
    fd_wake_pipe_waiters(pid);
    return (uint64_t)fd;
}

static uint64_t open_fifo_fd(edge_fd_proc_t *p, const char *path, int flags,
                             const vfs_inode_t *inode,
                             vfs_superblock_t *superblock) {
    return open_fifo_pipe_fd(
        p, path, flags,
        named_fifo_pipe_for_inode(superblock, inode, 1));
}

static int namespace_path_target(const char *path, const task_t **target_out,
                                 edge_namespace_kind_t *kind_out) {
    const task_t *target;
    int owner_tgid;
    int target_tid;

    if (!path || !target_out || !kind_out)
        return 0;
    if (!kernel_linux_namespace_path_parse(
            path, process_gettgid(), process_gettid(), &owner_tgid,
            &target_tid, kind_out))
        return 0;
    target = process_get_task(target_tid);
    if (!target || target->state == TASK_UNUSED ||
        (target->tgid > 0 ? target->tgid : target->pid) != owner_tgid)
        return 0;
    *target_out = target;
    return 1;
}

static uint64_t open_namespace_id_fd(
    edge_fd_proc_t *proc, edge_namespace_kind_t kind, uint32_t namespace_id,
    const kernel_vfs_open_request_t *request, const char *path) {
    edge_fd_t *entry;
    uint64_t inode;
    uint32_t flags;
    int fd;

    if (!request) {
        edge_namespace_handle_release(kind, namespace_id);
        return (uint64_t)-EIO;
    }
    flags = request->linux_flags;
    if (request->flags & KERNEL_VFS_OPEN_NOFOLLOW) {
        edge_namespace_handle_release(kind, namespace_id);
        return (uint64_t)-ELOOP;
    }
    if (!(request->flags & KERNEL_VFS_OPEN_PATH) &&
        request->access_mode != LINUX_O_RDONLY) {
        edge_namespace_handle_release(kind, namespace_id);
        return (uint64_t)-EACCES;
    }
    if (request->flags &
        (KERNEL_VFS_OPEN_CREATE | KERNEL_VFS_OPEN_EXCLUSIVE |
         KERNEL_VFS_OPEN_TRUNCATE | KERNEL_VFS_OPEN_DIRECTORY |
         KERNEL_VFS_OPEN_TMPFILE)) {
        edge_namespace_handle_release(kind, namespace_id);
        return (uint64_t)-EINVAL;
    }
    if (!proc) {
        edge_namespace_handle_release(kind, namespace_id);
        return (uint64_t)-ENOENT;
    }
    inode = edge_namespace_handle_inode(kind, namespace_id);
    if (!inode) {
        edge_namespace_handle_release(kind, namespace_id);
        return (uint64_t)-ENOENT;
    }
    fd = fd_alloc(proc, 0);
    if (fd < 0) {
        edge_namespace_handle_release(kind, namespace_id);
        return (uint64_t)-EMFILE;
    }
    entry = &proc->fds[fd];
    entry->file_ref = file_ref_alloc((uint32_t)flags);
    if (!entry->file_ref) {
        fd_abort_reserved(proc, fd);
        edge_namespace_handle_release(kind, namespace_id);
        return (uint64_t)-ENFILE;
    }
    entry->kind = FD_NAMESPACE;
    entry->flags = flags;
    entry->fd_flags =
        (request->flags & KERNEL_VFS_OPEN_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    entry->namespace_kind = (uint8_t)kind;
    entry->namespace_id = namespace_id;
    entry->pipe_id = -1;
    entry->inode.mode = (uint16_t)(VFS_INODE_FILE | 0444);
    entry->inode.ino = (uint32_t)inode;
    strncpy(entry->path, path, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = 0;
    if (fd_publish(proc, fd) < 0) {
        (void)file_ref_put(entry->file_ref);
        edge_namespace_handle_release(kind, namespace_id);
        fd_abort_reserved(proc, fd);
        return (uint64_t)-EBADF;
    }
    return (uint64_t)fd;
}

static uint64_t open_namespace_fd(edge_fd_proc_t *proc,
                                  const task_t *target,
                                  edge_namespace_kind_t kind,
                                  const kernel_vfs_open_request_t *request,
                                  const char *path) {
    uint32_t namespace_id;

    if (!target || edge_namespace_handle_acquire(
            &target->namespaces, kind, &namespace_id) < 0)
        return (uint64_t)-ENOENT;
    return open_namespace_id_fd(
        proc, kind, namespace_id, request, path);
}

static uint64_t open_tun_fd(
    edge_fd_proc_t *process, const kernel_vfs_open_request_t *request) {
    edge_fd_t *entry;
    uint64_t identity;
    int descriptor;

    if (!process || !request) return (uint64_t)-EIO;
    if (request->flags &
        (KERNEL_VFS_OPEN_PATH | KERNEL_VFS_OPEN_NOFOLLOW |
         KERNEL_VFS_OPEN_CREATE | KERNEL_VFS_OPEN_EXCLUSIVE |
         KERNEL_VFS_OPEN_TRUNCATE | KERNEL_VFS_OPEN_DIRECTORY |
         KERNEL_VFS_OPEN_TMPFILE))
        return (uint64_t)-EINVAL;
    descriptor = fd_alloc(process, 0);
    if (descriptor < 0) return (uint64_t)-EMFILE;
    entry = &process->fds[descriptor];
    entry->file_ref = file_ref_alloc(request->linux_flags);
    if (!entry->file_ref) {
        fd_abort_reserved(process, descriptor);
        return (uint64_t)-ENFILE;
    }
    identity = file_ref_identity(entry->file_ref);
    if (!identity || edge_linux_tun_open(identity) < 0) {
        (void)file_ref_put(entry->file_ref);
        fd_abort_reserved(process, descriptor);
        return (uint64_t)-ENFILE;
    }
    edge_linux_tun_set_wake_callback(fd_wake_tun_description);
    entry->kind = FD_TUN;
    entry->flags = (int)request->linux_flags;
    entry->fd_flags =
        (request->flags & KERNEL_VFS_OPEN_CLOEXEC) ?
            LINUX_FD_CLOEXEC : 0;
    entry->pipe_id = -1;
    entry->inode.mode = (uint16_t)(VFS_INODE_CHR | 0666u);
    entry->inode.rdev = linux_makedev(10, 200);
    strncpy(entry->path, EDGE_LINUX_TUN_PATH, sizeof(entry->path) - 1u);
    entry->path[sizeof(entry->path) - 1u] = 0;
    if (fd_publish(process, descriptor) < 0) {
        edge_linux_tun_close(identity);
        (void)file_ref_put(entry->file_ref);
        fd_abort_reserved(process, descriptor);
        return (uint64_t)-EBADF;
    }
    return (uint64_t)descriptor;
}

int64_t arch_vfs_open_special(
    const kernel_vfs_open_request_t *request, const char *path,
    int *handled) {
    int flags;
    edge_fd_proc_t *p;

    if (!request || !path || !handled) return (uint64_t)-EIO;
    *handled = 1;
    flags = (int)request->linux_flags;
    p = fd_proc_for_pid_empty(fd_owner_pid_current(), 1);
    if (!p) return (uint64_t)-ENOMEM;

    if (strcmp(path, EDGE_LINUX_TUN_PATH) == 0)
        return (int64_t)open_tun_fd(p, request);

    {
        const task_t *namespace_target = 0;
        edge_namespace_kind_t namespace_kind;
        if (namespace_path_target(path, &namespace_target, &namespace_kind))
            return open_namespace_fd(p, namespace_target, namespace_kind,
                                     request, path);
    }
    {
        edge_namespace_kind_t namespace_kind;
        uint32_t namespace_id;
        if (kernel_linux_namespace_mount_acquire(
                path, &namespace_kind, &namespace_id) > 0)
            return open_namespace_id_fd(
                p, namespace_kind, namespace_id, request, path);
    }
    {
        int alias_fd = -1;
        if (dev_fd_path_number(path, &alias_fd) == 0) {
            uint64_t r = do_sys_dup((uint64_t)alias_fd);
            if ((int64_t)r < 0) return r;
            if (request->flags & KERNEL_VFS_OPEN_CLOEXEC) {
                edge_fd_t *e = fd_get(p, (int)r);
                if (e) e->fd_flags |= LINUX_FD_CLOEXEC;
            }
            return r;
        }
    }
    if (path_is_tty_device(path) && !console_tty_path_supported(path)) {
        return (uint64_t)-ENXIO;
    }
    if (trace_initd_console_task(process_current_task()) && path_is_tty_device(path)) {
        task_t *t = process_current_task();
        printf("[initd-spawn] pid=%d open path=%s flags=0x%x\n",
               t ? t->pid : -1, path, (uint32_t)flags);
    }

    if (path_is_tty_device(path) && strcmp(path, "/dev/tty") != 0) {
        return open_console_tty_fd(p, path, flags);
    }

    if (strcmp(path, "/dev/tty") == 0) {
        task_t *cur = process_current_task();
        int fd = fd_alloc(p, 0);
        edge_fd_t *e;
        int line_id = -1;
        if (fd < 0) return (uint64_t)-EMFILE;
        e = &p->fds[fd];
        e->file_ref = file_ref_alloc((uint32_t)flags);
        if (!e->file_ref) {
            fd_abort_reserved(p, fd);
            return (uint64_t)-ENFILE;
        }
        e->flags = flags;
        e->fd_flags =
            (request->flags & KERNEL_VFS_OPEN_CLOEXEC) ?
            LINUX_FD_CLOEXEC : 0;
        fd_description_set_offset(e, 0);
        e->pipe_id = -1;
        strncpy(e->path, path, sizeof(e->path) - 1);
        e->path[sizeof(e->path) - 1] = 0;

        if (!cur || cur->ctty_kind == PROCESS_CTTY_NONE) {
            if (gui_diag_task(cur) && g_gui_pty_trace_budget-- > 0) {
                printf("[ptydiag] open-tty pid=%d task=%s res=ENXIO ctty=none flags=0x%x\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?", (unsigned)flags);
            }
            (void)file_ref_put(e->file_ref);
            fd_abort_reserved(p, fd);
            return (uint64_t)-ENXIO;
        }
        if (cur->ctty_kind == PROCESS_CTTY_CONSOLE) {
            line_id = console_line_from_vt(cur->ctty_id);
            if (line_id == 0) {
                int inferred = fd_proc_infer_console_line(p);
                if (inferred >= 0) line_id = inferred;
            }
            if (!console_line_valid(line_id)) {
                if (gui_diag_task(cur) && g_gui_pty_trace_budget-- > 0) {
                    printf("[ptydiag] open-tty pid=%d task=%s res=ENXIO bad-console ctty=%d line=%d flags=0x%x\n",
                           cur ? cur->pid : -1, cur ? cur->name : "?",
                           cur ? cur->ctty_id : -1, line_id, (unsigned)flags);
                }
                (void)file_ref_put(e->file_ref);
                fd_abort_reserved(p, fd);
                return (uint64_t)-ENXIO;
            }
            e->kind = FD_CONSOLE;
            e->pipe_id = line_id;
            if (line_id == 0) {
                strncpy(e->path, "/dev/ttyS0", sizeof(e->path) - 1);
            } else {
                e->path[0] = '/';
                e->path[1] = 'd';
                e->path[2] = 'e';
                e->path[3] = 'v';
                e->path[4] = '/';
                e->path[5] = 't';
                e->path[6] = 't';
                e->path[7] = 'y';
                e->path[8] = (char)('0' + line_id);
                e->path[9] = 0;
            }
            e->path[sizeof(e->path) - 1] = 0;
            if (trace_vt_shell_task(cur)) {
                printf("[ttydbg] pid=%d task=%s open /dev/tty ctty_id=%d line=%d stdio=%d/%d/%d\n",
                       cur->pid, cur->name, cur->ctty_id, line_id,
                       console_line_from_fd_entry(&p->fds[0]),
                       console_line_from_fd_entry(&p->fds[1]),
                       console_line_from_fd_entry(&p->fds[2]));
            }
            if (trace_initd_console_task(cur)) {
                printf("[initd-spawn] pid=%d open /dev/tty -> %s fd=%d\n",
                       cur ? cur->pid : -1, e->path, fd);
            }
            if (fd_publish(p, fd) < 0) {
                (void)file_ref_put(e->file_ref);
                fd_abort_reserved(p, fd);
                return (uint64_t)-EBADF;
            }
            return (uint64_t)fd;
        }
        if (cur->ctty_kind == PROCESS_CTTY_PTY) {
            int pty_id = cur->ctty_id;
            if (pty_id < 0 || pty_id >= EDGE_MAX_PTYS || !g_ptys[pty_id].used) {
                if (gui_diag_task(cur) && g_gui_pty_trace_budget-- > 0) {
                    printf("[ptydiag] open-tty pid=%d task=%s res=ENXIO bad-pty pty=%d flags=0x%x\n",
                           cur ? cur->pid : -1, cur ? cur->name : "?",
                           pty_id, (unsigned)flags);
                }
                (void)file_ref_put(e->file_ref);
                fd_abort_reserved(p, fd);
                return (uint64_t)-ENXIO;
            }
            pty_add_ref(pty_id, 0);
            e->kind = FD_PTY_SLAVE;
            e->pipe_id = pty_id;
            if (gui_diag_task(cur) && g_gui_pty_trace_budget-- > 0) {
                printf("[ptydiag] open-tty pid=%d task=%s fd=%d res=pty-slave pty=%d flags=0x%x\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, pty_id, (unsigned)flags);
            }
            if (trace_initd_console_task(cur)) {
                printf("[initd-spawn] pid=%d open /dev/tty -> pty fd=%d pty=%d\n",
                       cur ? cur->pid : -1, fd, pty_id);
            }
            if (fd_publish(p, fd) < 0) {
                pty_drop_ref(pty_id, 0);
                (void)file_ref_put(e->file_ref);
                fd_abort_reserved(p, fd);
                return (uint64_t)-EBADF;
            }
            return (uint64_t)fd;
        }
        (void)file_ref_put(e->file_ref);
        fd_abort_reserved(p, fd);
        if (gui_diag_task(cur) && g_gui_pty_trace_budget-- > 0) {
            printf("[ptydiag] open-tty pid=%d task=%s res=ENXIO unknown-ctty kind=%d id=%d flags=0x%x\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   cur ? cur->ctty_kind : -1, cur ? cur->ctty_id : -1,
                   (unsigned)flags);
        }
        return (uint64_t)-ENXIO;
    }

    if (strcmp(path, "/dev/ptmx") == 0) {
        int fd = fd_alloc(p, 0);
        int pty_id;
        edge_fd_t *e;
        if (fd < 0) return (uint64_t)-EMFILE;
        pty_id = pty_alloc();
        if (pty_id < 0) {
            fd_abort_reserved(p, fd);
            return (uint64_t)(int64_t)pty_id;
        }
        e = &p->fds[fd];
        e->file_ref = file_ref_alloc((uint32_t)flags);
        if (!e->file_ref) {
            pty_drop_ref(pty_id, 1);
            fd_abort_reserved(p, fd);
            return (uint64_t)-ENFILE;
        }
        e->kind = FD_PTY_MASTER;
        e->flags = flags;
        e->fd_flags =
            (request->flags & KERNEL_VFS_OPEN_CLOEXEC) ?
            LINUX_FD_CLOEXEC : 0;
        e->pipe_id = pty_id;
        fd_description_set_offset(e, 0);
        strncpy(e->path, path, sizeof(e->path) - 1);
        e->path[sizeof(e->path) - 1] = 0;
        if (fd_publish(p, fd) < 0) {
            pty_drop_ref(pty_id, 1);
            (void)file_ref_put(e->file_ref);
            fd_abort_reserved(p, fd);
            return (uint64_t)-EBADF;
        }
        if ((gui_diag_task(process_current_task()) || EDGE_PTY_DIAG_TRACE) &&
            (g_gui_pty_trace_budget-- > 0 || g_pty_open_trace_budget-- > 0)) {
            task_t *cur = process_current_task();
            printf("[ptydiag] open-ptmx pid=%d task=%s fd=%d pty=%d flags=0x%x unlocked=%d refs=%d/%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, pty_id, (unsigned)flags, g_ptys[pty_id].unlocked,
                   g_ptys[pty_id].refs_master, g_ptys[pty_id].refs_slave);
        }
        return (uint64_t)fd;
    }
    if (strncmp(path, "/dev/pts/", 9) == 0) {
        int pty_id = -1;
        int fd;
        edge_fd_t *e;
        if (!path_is_devpts_slave(path, &pty_id)) return (uint64_t)-ENOENT;
        if (pty_id < 0 || pty_id >= EDGE_MAX_PTYS || !g_ptys[pty_id].used || !g_ptys[pty_id].unlocked) {
            if ((gui_diag_task(process_current_task()) || EDGE_PTY_DIAG_TRACE) &&
                (g_gui_pty_trace_budget-- > 0 || g_pty_open_trace_budget-- > 0)) {
                task_t *cur = process_current_task();
                printf("[ptydiag] open-pts pid=%d task=%s path=%s res=ENOENT pty=%d flags=0x%x used=%d unlocked=%d\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       path, pty_id, (unsigned)flags,
                       (pty_id >= 0 && pty_id < EDGE_MAX_PTYS) ? g_ptys[pty_id].used : -1,
                       (pty_id >= 0 && pty_id < EDGE_MAX_PTYS) ? g_ptys[pty_id].unlocked : -1);
            }
            return (uint64_t)-ENOENT;
        }
        fd = fd_alloc(p, 0);
        if (fd < 0) return (uint64_t)-EMFILE;
        e = &p->fds[fd];
        e->file_ref = file_ref_alloc((uint32_t)flags);
        if (!e->file_ref) {
            fd_abort_reserved(p, fd);
            return (uint64_t)-ENFILE;
        }
        pty_add_ref(pty_id, 0);
        if (g_ptys[pty_id].session.foreground_pgid <= 0) {
            int pg = process_getpgid(0);
            if (pg > 0) g_ptys[pty_id].session.foreground_pgid = pg;
        }
        pty_maybe_assign_controlling_tty(pty_id, flags);
        e->kind = FD_PTY_SLAVE;
        e->flags = flags;
        e->fd_flags =
            (request->flags & KERNEL_VFS_OPEN_CLOEXEC) ?
            LINUX_FD_CLOEXEC : 0;
        e->pipe_id = pty_id;
        fd_description_set_offset(e, 0);
        strncpy(e->path, path, sizeof(e->path) - 1);
        e->path[sizeof(e->path) - 1] = 0;
        if (fd_publish(p, fd) < 0) {
            pty_drop_ref(pty_id, 0);
            (void)file_ref_put(e->file_ref);
            fd_abort_reserved(p, fd);
            return (uint64_t)-EBADF;
        }
        if ((gui_diag_task(process_current_task()) || EDGE_PTY_DIAG_TRACE) &&
            (g_gui_pty_trace_budget-- > 0 || g_pty_open_trace_budget-- > 0)) {
            task_t *cur = process_current_task();
            printf("[ptydiag] open-pts pid=%d task=%s fd=%d path=%s pty=%d flags=0x%x ctty=%d/%d refs=%d/%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, path, pty_id, (unsigned)flags,
                   cur ? cur->ctty_kind : -1, cur ? cur->ctty_id : -1,
                   g_ptys[pty_id].refs_master, g_ptys[pty_id].refs_slave);
        }
        return (uint64_t)fd;
    }

    if ((strcmp(path, "/proc") == 0 ||
         strncmp(path, "/proc/", 6) == 0) &&
        !vfs_mount_exists("/proc", "proc", 0)) {
        (void)vfs_mkdir("/proc");
        (void)vfs_mount("proc", "/proc", "proc");
    }
    *handled = 0;
    return 0;
}

int arch_vfs_open_install_regular(
    const kernel_vfs_open_request_t *request, const char *path,
    const vfs_inode_t *inode, vfs_superblock_t *superblock,
    int unlink_after_open) {
    edge_fd_proc_t *process;
    edge_fd_t *entry;
    int descriptor;
    int flags;
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    int bridge_opened = 0;
#endif
    int alsa_opened = 0;

    if (!request || !path || !inode ||
        (!superblock && !(request->flags & KERNEL_VFS_OPEN_PATH)))
        return -EIO;
    flags = (int)request->linux_flags;
    process = fd_proc_for_pid_empty(fd_owner_pid_current(), 1);
    if (!process) return -ENOMEM;
    if ((inode->mode & 0xf000u) == VFS_INODE_FIFO &&
        !(request->flags & KERNEL_VFS_OPEN_PATH))
        return open_fifo_fd(
            process, path, flags, inode, superblock);

    descriptor = fd_alloc(process, 0);
    if (descriptor < 0) {
        if (unlink_after_open) (void)vfs_unlink(path);
        return -EMFILE;
    }

    entry = &process->fds[descriptor];
    entry->file_ref = file_ref_alloc((uint32_t)flags);
    if (!entry->file_ref) {
        fd_abort_reserved(process, descriptor);
        if (unlink_after_open) (void)vfs_unlink(path);
        return -ENFILE;
    }
    entry->kind = FD_VFS;
    entry->flags = flags;
    entry->landlock_access = request->landlock_access;
    entry->fd_flags =
        (request->flags & KERNEL_VFS_OPEN_CLOEXEC) ?
            LINUX_FD_CLOEXEC : 0;
    fd_description_set_offset(entry, 0);
    entry->inode = *inode;
    entry->pipe_id =
        path_is_tty_device(path) ? console_line_from_path(path) : -1;
    strncpy(entry->path, path, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = 0;
    if (vfs_inode_open(superblock, inode) < 0) {
        (void)file_ref_put(entry->file_ref);
        fd_abort_reserved(process, descriptor);
        if (unlink_after_open) (void)vfs_unlink(path);
        return -ENFILE;
    }
    entry->sb = vfs_superblock_stable(superblock);
    entry->mount_id = superblock ? superblock->mount_id : 0;
    fd_mount_monitor_initialize(entry);
    if (!(request->flags & KERNEL_VFS_OPEN_PATH) &&
        alsa_path_kind(entry->path) != EDGE_ALSA_NODE_NONE) {
        alsa_open(entry->path);
        alsa_opened = 1;
    }
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if (!(request->flags & KERNEL_VFS_OPEN_PATH) &&
        (entry->inode.mode & 0xf000u) == VFS_INODE_CHR) {
        uint64_t identity = file_ref_identity(entry->file_ref);
        int bridge_result = bsd_bridge_cdev_open(
            entry->inode.rdev, (uint32_t)flags, identity,
            process_getpid(), process_getpgid(0));

        if (bridge_result != BSD_BRIDGE_CDEV_NOT_HANDLED) {
            if (bridge_result < 0) {
                if (alsa_opened)
                    alsa_close(entry->path);
                vfs_inode_close(entry->sb, &entry->inode);
                (void)file_ref_put(entry->file_ref);
                fd_abort_reserved(process, descriptor);
                if (unlink_after_open) (void)vfs_unlink(path);
                return bridge_result;
            }
            bridge_opened = 1;
        }
    }
#endif
    if (unlink_after_open) {
        static const char deleted_suffix[] = " (deleted)";
        size_t length;

        if (vfs_unlink(path) < 0) {
            if (alsa_opened)
                alsa_close(entry->path);
#ifdef CONFIG_BSD_DRIVER_BRIDGE
            if (bridge_opened)
                (void)bsd_bridge_cdev_close(
                    file_ref_identity(entry->file_ref));
#endif
            vfs_inode_close(entry->sb, inode);
            (void)file_ref_put(entry->file_ref);
            fd_abort_reserved(process, descriptor);
            return -EIO;
        }
        (void)vfs_inode_refresh(entry->sb, &entry->inode);
        length = strlen(entry->path);
        if (length + sizeof(deleted_suffix) <= sizeof(entry->path))
            memcpy(entry->path + length, deleted_suffix,
                   sizeof(deleted_suffix));
    }
    {
        task_t *current = process_current_task();
        if (xfce_boot_trace_task(current) &&
            g_xfce_boot_trace_budget-- > 0) {
            printf("[xfceboot] open-ok pid=%d cmd=%s fd=%d flags=0x%x path=%s\n",
                   current ? current->pid : -1,
                   (current && current->name[0]) ? current->name : "?",
                   descriptor, (uint32_t)flags, entry->path);
        }
    }
    if (path_is_event_input(entry->path)) {
        int initial_tail =
            keyboard_event_cursor_init(
                path_input_event_index(entry->path));
        fd_description_set_input_tail(entry, initial_tail);
    }
    if (path_is_kmsg_device(entry->path))
        fd_description_set_offset(
            entry, bootlog_kmsg_first_offset());
    if (trace_initd_console_task(process_current_task()) &&
        path_is_tty_device(path)) {
        task_t *current = process_current_task();
        printf("[initd-spawn] pid=%d open resolved path=%s fd=%d kind=%d\n",
               current ? current->pid : -1, path, descriptor,
               (int)entry->kind);
    }

    if (strcmp(entry->path, "/dev/fb0") == 0) {
        if (g_fb_console_hold_count++ == 0)
            fb_console_set_present_enabled(0);
    }
    if (fd_publish(process, descriptor) < 0) {
        if (strcmp(entry->path, "/dev/fb0") == 0 &&
            g_fb_console_hold_count > 0) {
            g_fb_console_hold_count--;
            if (g_fb_console_hold_count == 0 &&
                !syscall_console_active_vt_in_graphics())
                fb_console_set_present_enabled(1);
        }
#ifdef CONFIG_BSD_DRIVER_BRIDGE
        if (bridge_opened)
            (void)bsd_bridge_cdev_close(
                file_ref_identity(entry->file_ref));
#endif
        if (alsa_opened)
            alsa_close(entry->path);
        vfs_inode_close(entry->sb, &entry->inode);
        (void)file_ref_put(entry->file_ref);
        fd_abort_reserved(process, descriptor);
        return -EBADF;
    }
    return descriptor;
}

static uint64_t do_sys_close(uint64_t fd_u) {
    int fd = (int)fd_u;
    int refs_left = 0;
    edge_fd_proc_t *p = fd_proc_for_pid(fd_owner_pid_current(), 0);
    edge_fd_t closing;
    edge_fd_t *e = &closing;
    task_t *cur = process_current_task();
    static int pty_close_trace_budget = EDGE_PTY_DIAG_TRACE ? 192 : 0;
    const char *x11_sock_path = 0;
    int x11_sock_id = -1;
    if (!p) return (uint64_t)-EBADF;
    if (fd_remove_open(p, fd, &closing) < 0)
        return (uint64_t)-EBADF;
    if (e->kind == FD_SOCKET) {
        x11_sock_id = e->pipe_id;
        x11_sock_path = e->path[0] ? e->path : unix_binding_path_for_sock(e->pipe_id);
        if (x11_unix_path_is_traced(x11_sock_path)) {
            x11_unix_trace_binding("close-enter", x11_sock_path, fd, e->pipe_id, 0);
        }
    }
    if (fd <= 2 && ssh_trace_task(cur)) {
        printf("[sshdbg] close pid=%d cmd=%s fd=%d kind=%d path=%s ref=%d\n",
               cur ? cur->pid : -1,
               cur ? cur->name : "?",
               fd,
               (int)e->kind,
               e->path[0] ? e->path : "-",
               e->file_ref);
    }
    if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
        pty_close_trace_budget-- > 0) {
        int pty_id = e->pipe_id;
        int used = (pty_id >= 0 && pty_id < EDGE_MAX_PTYS) ? g_ptys[pty_id].used : -1;
        int unlocked = (pty_id >= 0 && pty_id < EDGE_MAX_PTYS) ? g_ptys[pty_id].unlocked : -1;
        int refs_master = (pty_id >= 0 && pty_id < EDGE_MAX_PTYS) ? g_ptys[pty_id].refs_master : -1;
        int refs_slave = (pty_id >= 0 && pty_id < EDGE_MAX_PTYS) ? g_ptys[pty_id].refs_slave : -1;
        printf("[ptydiag] close pid=%d task=%s fd=%d kind=%s pty=%d flags=0x%x fdflags=0x%x used=%d unlocked=%d refs=%d/%d\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               fd, fd_kind_name(e->kind), pty_id, (unsigned)e->flags,
               (unsigned)e->fd_flags, used, unlocked, refs_master, refs_slave);
    }
    fd_log_lifecycle("close", process_getpid(), fd, e, 0);
    refs_left = fd_release_entry(e, cur, 1, 1);
    if (refs_left == -EBADF)
        return (uint64_t)-EBADF;
    if (x11_unix_path_is_traced(x11_sock_path)) {
        x11_unix_trace_binding("close-after-fileref", x11_sock_path, fd, x11_sock_id, refs_left);
    }

    if (g_pipe_lifecycle_trace_budget > 0 && pipe_lifecycle_trace_task(cur) &&
        (e->kind == FD_PIPE_R || e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW)) {
        int pipe_id = e->pipe_id;
        int readers = (pipe_id >= 0 && pipe_id < EDGE_MAX_PIPES) ?
            (int)g_pipes[pipe_id].readers : -1;
        int writers = (pipe_id >= 0 && pipe_id < EDGE_MAX_PIPES) ?
            (int)g_pipes[pipe_id].writers : -1;
        uint32_t count = (pipe_id >= 0 && pipe_id < EDGE_MAX_PIPES) ? g_pipes[pipe_id].count : 0;
        printf("[pipefd] close pid=%d cmd=%s fd=%d kind=%s pipe=%d r=%d w=%d count=%u refs_left=%d budget=%d\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               fd, fd_kind_name(e->kind), pipe_id, readers, writers, count,
               refs_left, g_pipe_lifecycle_trace_budget - 1);
        g_pipe_lifecycle_trace_budget--;
    }
    return refs_left < 0 ? (uint64_t)refs_left : 0;
}

typedef struct fd_u64_user_copy_context {
    uint64_t user_address;
} fd_u64_user_copy_context_t;

static int fd_copy_u64_to_user(void *opaque, uint64_t value) {
    fd_u64_user_copy_context_t *context =
        (fd_u64_user_copy_context_t *)opaque;
    if (!context || !context->user_address) return -1;
    return copy_to_user(context->user_address, &value, sizeof(value)) < 0 ?
           -1 : 0;
}

static int fd_load_u64_from_user(void *opaque, uint64_t *value) {
    fd_u64_user_copy_context_t *context =
        (fd_u64_user_copy_context_t *)opaque;
    if (!context || !context->user_address || !value) return -1;
    return copy_from_user(value, context->user_address,
                          sizeof(*value)) < 0 ? -1 : 0;
}

static int x86_tun_copy_from_user(
    void *context, void *destination, uint64_t source, uint32_t length) {
    (void)context;
    return copy_from_user(destination, source, length);
}

static int x86_tun_copy_to_user(
    void *context, uint64_t destination, const void *source,
    uint32_t length) {
    (void)context;
    return copy_to_user(destination, source, length);
}

static uint64_t do_sys_fd_read_entry(int fd, edge_fd_t *e,
                                     uint64_t buf_u, uint64_t len_u) {
    uint64_t len = len_u;
    char chunk[EDGE_SYSCALL_IO_CHUNK];
    task_t *cur = process_current_task();

    if (!e) return (uint64_t)-EBADF;
    if (e->kind != FD_EVENTFD &&
        e->kind != FD_TIMERFD &&
        e->kind != FD_SIGNALFD) {
        if (len == 0) return 0;
        if (!buf_u) return (uint64_t)-EFAULT;
    }
    if (e->kind == FD_TUN) {
        int64_t result;
        uint64_t identity = file_ref_identity(e->file_ref);

        do {
            result = edge_linux_tun_read(
                identity, buf_u,
                len > UINT32_MAX ? UINT32_MAX : (uint32_t)len,
                x86_tun_copy_to_user, 0);
            if (result != -EAGAIN ||
                (e->flags & LINUX_O_NONBLOCK) != 0)
                return (uint64_t)result;
            if (signal_pending_interrupt())
                return tty_interrupt_current_ret();
            wait_blocking_step();
        } while (1);
    }
    if (e->kind == FD_CONSOLE) {
        uint64_t r;
        if ((e->flags & LINUX_O_NONBLOCK) != 0 &&
            !console_line_pollin_ready(console_line_from_fd_entry(e))) {
            return (uint64_t)-EAGAIN;
        }
        if (ssh_trace_task(cur)) {
            edge_console_line_t *line = console_line_state(console_line_from_fd_entry(e));
            printf("[sshdbg] read-enter pid=%d cmd=%s fd=%d kind=console line=%d len=%u fl=0x%x lflag=0x%x iflag=0x%x fg=%d pg=%d ll=%u lp=%u reply=%u/%u\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, console_line_from_fd_entry(e), (unsigned)len,
                   (unsigned)e->flags,
                   line ? (unsigned)line->termios.c_lflag : 0,
                   line ? (unsigned)line->termios.c_iflag : 0,
                   line ? line->session.foreground_pgid : -1,
                   cur ? cur->pgid : -1,
                   line ? (unsigned)line->line_len : 0,
                   line ? (unsigned)line->line_pos : 0,
                   line ? (unsigned)line->reply_pos : 0,
                   line ? (unsigned)line->reply_len : 0);
        }
        r = do_sys_read_console_line(console_line_from_fd_entry(e), buf_u, len_u);
        if (ssh_trace_task(cur)) {
            printf("[sshdbg] read-exit pid=%d cmd=%s fd=%d ret=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?", fd, (int)(int64_t)r);
        }
        return r;
    }
    if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) {
        edge_pty_t *pty;
        uint8_t *src_buf;
        uint32_t *src_rpos;
        uint32_t *src_count;
        int peer_refs;
        uint64_t n = 0;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS) return (uint64_t)-EBADF;
        pty = &g_ptys[e->pipe_id];
        if (!pty->used) return (uint64_t)-EBADF;
        if (e->kind == FD_PTY_MASTER) {
            src_buf = pty->s2m_buf;
            src_rpos = &pty->s2m_rpos;
            src_count = &pty->s2m_count;
            peer_refs = pty->refs_slave;
        } else {
            src_buf = pty->m2s_buf;
            src_rpos = &pty->m2s_rpos;
            src_count = &pty->m2s_count;
            peer_refs = pty->refs_master;
        }
        while (*src_count == 0 ||
               (e->kind == FD_PTY_SLAVE &&
                (pty->termios.c_lflag & LINUX_ICANON) != 0 &&
                !pty_slave_input_have_canonical_line(pty))) {
            if (peer_refs <= 0) return 0;
            if ((e->flags & LINUX_O_NONBLOCK) != 0) return (uint64_t)-EAGAIN;
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            wait_blocking_step();
            peer_refs = (e->kind == FD_PTY_MASTER) ? pty->refs_slave : pty->refs_master;
        }
        if (e->kind == FD_PTY_MASTER && pty->packet_mode) {
            uint8_t status = 0;
            /*
             * TIOCPKT packet mode prefixes normal PTY master reads with a
             * status byte.  EdgeOS does not yet synthesize control packets for
             * flow-control transitions, so normal data is tagged with zero.
             * If userspace supplied a one-byte buffer, return only the status
             * byte and leave the payload queued for the next read, matching the
             * "packet framing first" contract without dropping data.
             */
            if (copy_to_user(buf_u, &status, 1) < 0) return (uint64_t)-EFAULT;
            if (len <= 1) return 1;
            n = len - 1;
            if (n > *src_count) n = *src_count;
            for (uint64_t i = 0; i < n; ++i) {
                chunk[i % sizeof(chunk)] = (char)src_buf[*src_rpos];
                *src_rpos = (*src_rpos + 1) % EDGE_PTY_BUF_SIZE;
                (*src_count)--;
                if ((i % sizeof(chunk)) == sizeof(chunk) - 1 || i + 1 == n) {
                    uint64_t start = i - (i % sizeof(chunk));
                    uint64_t sz = (i % sizeof(chunk)) + 1;
                    if (copy_to_user(buf_u + 1 + start, chunk, sz) < 0) return (uint64_t)-EFAULT;
                }
            }
            return n + 1;
        }
        if (e->kind == FD_PTY_SLAVE) n = pty_slave_read_limit(pty, len, *src_count);
        else {
            n = len;
            if (n > *src_count) n = *src_count;
        }
        for (uint64_t i = 0; i < n; ++i) {
            chunk[i % sizeof(chunk)] = (char)src_buf[*src_rpos];
            *src_rpos = (*src_rpos + 1) % EDGE_PTY_BUF_SIZE;
            (*src_count)--;
            if ((i % sizeof(chunk)) == sizeof(chunk) - 1 || i + 1 == n) {
                uint64_t start = i - (i % sizeof(chunk));
                uint64_t sz = (i % sizeof(chunk)) + 1;
                if (copy_to_user(buf_u + start, chunk, sz) < 0) return (uint64_t)-EFAULT;
            }
        }
        return n;
    }
    if (e->kind == FD_SOCKET) {
        uint64_t r = x86_socket_recvfrom_entry_raw(
            fd, e, buf_u, len_u, 0, 0, 0);
        if (ssh_trace_task(cur)) {
            printf("[sshdbg] read pid=%d cmd=%s fd=%d kind=socket len=%u ret=%d fl=0x%x sid=%d\n",
                   cur->pid, cur->name, fd, (unsigned)len, (int)(int64_t)r, (unsigned)e->flags, e->pipe_id);
        }
        return r;
    }
    if (e->kind == FD_EVENTFD) {
        fd_u64_user_copy_context_t copy_context;
        kernel_eventfd_state_t state;
        uint64_t value = 0;
        int nonblocking = (e->flags & LINUX_O_NONBLOCK) != 0;
        int64_t status;
        copy_context.user_address = buf_u;
        for (;;) {
            status = kernel_eventfd_read_io(
                e->pipe_id, len, nonblocking, fd_copy_u64_to_user,
                &copy_context, &value);
            if (status != KERNEL_EVENTFD_IO_WAIT) break;
            if (signal_pending_interrupt()) {
                if (cur) waiter_remove_pid(cur->pid);
                return tty_interrupt_current_ret();
            }
            eventfd_read_waiter_add(e->pipe_id, cur ? cur->pid : 0);
            /*
             * Linux wait queues use the prepare-to-wait pattern: install the
             * waiter, then test the condition again before actually blocking.
             * Without this second test, a writer can increment the eventfd in
             * the tiny window after our first counter check but before
             * scheduler_task_set_blocked(), leaving GLib/DBus style wakeups
             * asleep forever even though the counter is non-zero.
             */
            status = kernel_eventfd_read_io(
                e->pipe_id, len, 0, fd_copy_u64_to_user,
                &copy_context, &value);
            if (status != KERNEL_EVENTFD_IO_WAIT) {
                if (cur) waiter_remove_pid(cur->pid);
                break;
            }
            socket_blocking_wait_step(0);
        }
        if (status == KERNEL_EVENTFD_IO_BYTES)
            fd_wake_eventfd_write_waiters(e->pipe_id);
        if (status < 0) return (uint64_t)(int64_t)status;
        if (g_gui_eventfd_trace_budget > 0 && gui_diag_task(cur)) {
            printf("[gui-eventfd] read pid=%d cmd=%s fd=%d id=%d val=%llu counter_after=%llu fl=0x%x budget=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, e->pipe_id, (unsigned long long)value,
                   (unsigned long long)
                       (eventfd_snapshot(e->pipe_id, &state) ?
                            state.counter : 0),
                   (unsigned)e->flags,
                   g_gui_eventfd_trace_budget - 1);
            g_gui_eventfd_trace_budget--;
        }
        return (uint64_t)status;
    }
    if (e->kind == FD_TIMERFD) {
        fd_u64_user_copy_context_t copy_context;
        uint64_t expirations = 0;
        int status;
        if (len < 8) return (uint64_t)-EINVAL;
        copy_context.user_address = buf_u;
        for (;;) {
            status = kernel_timerfd_read(e->pipe_id, fd_copy_u64_to_user,
                                         &copy_context, &expirations);
            if (status != -EDGE_LINUX_EAGAIN) break;
            if ((e->flags & LINUX_O_NONBLOCK) != 0) return (uint64_t)-EAGAIN;
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            wait_blocking_step();
        }
        if (status < 0) return (uint64_t)(int64_t)status;
        return 8;
    }
    if (e->kind == FD_SIGNALFD) {
        edge_signalfd_copy_context_t copy_context = { .buffer = buf_u };
        int64_t result;
        for (;;) {
            result = kernel_signalfd_read(
                e->pipe_id, len,
                kernel_signalfd_current_dequeue, 0,
                edge_signalfd_copy_record, &copy_context);
            if (result != -EDGE_LINUX_EAGAIN)
                return (uint64_t)result;
            if ((e->flags & LINUX_O_NONBLOCK) != 0)
                return (uint64_t)-EAGAIN;
            wait_blocking_step();
        }
    }
    if (e->kind == FD_PIDFD) return (uint64_t)-EINVAL;
    if (e->kind == FD_EPOLL) return (uint64_t)-EINVAL;
    if (e->kind == FD_INOTIFY) {
        return edge_inotify_read_obj(e, buf_u, len_u);
    }
    if (e->kind == FD_FANOTIFY) {
        return edge_fanotify_read_obj(e, buf_u, len_u);
    }
    if (e->kind == FD_USERFAULTFD) {
        return edge_userfaultfd_read_obj(e, buf_u, len_u);
    }
    if (e->kind == FD_PERF_EVENT) {
        return edge_perf_event_read_obj(fd, e, buf_u, len_u);
    }
    if (e->kind == FD_MEMFD) {
        edge_memfd_t *mf = memfd_get(e->pipe_id);
        uint64_t done = 0;
        if (!mf) return (uint64_t)-EBADF;
        if (mf->secret) return (uint64_t)-EINVAL;
        while (done < len && fd_description_offset(e) < mf->size) {
            uint64_t position = fd_description_offset(e);
            uint64_t n = len - done;
            int r;
            if (n > sizeof(chunk)) n = sizeof(chunk);
            r = memfd_read_to_kernel(mf, position, chunk, n);
            if (r < 0) return done ? done : (uint64_t)(int64_t)r;
            if (r == 0) break;
            if (copy_to_user(buf_u + done, chunk, (uint64_t)r) < 0) return done ? done : (uint64_t)-EFAULT;
            done += (uint64_t)r;
            fd_description_advance(e, (uint64_t)r);
            if ((uint64_t)r < n) break;
        }
        e->inode.size = mf->size;
        return done;
    }

    if (e->kind == FD_PIPE_R || e->kind == FD_PIPE_RW) {
        static int dbus_pipe_trace_budget = EDGE_GUI_DEEP_TRACE ? 256 : 0;
        int trace_dbus_pipe = 0;
        kernel_pipe_io_decision_t decision;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PIPES) return (uint64_t)-EBADF;
        edge_pipe_t *pp = &g_pipes[e->pipe_id];
        if (!pp->used) return (uint64_t)-EBADF;
        trace_dbus_pipe = cur && dbus_pipe_trace_budget > 0 &&
            (strcmp(cur->name, "dbus-run-sessio") == 0 ||
             strcmp(cur->name, "dbus-run-session") == 0 ||
             strcmp(cur->name, "dbus-daemon") == 0);
        for (;;) {
            decision = kernel_pipe_read_decide(
                pp, (e->flags & LINUX_O_NONBLOCK) != 0);
            if (decision == KERNEL_PIPE_IO_READY) break;
            if (decision == KERNEL_PIPE_IO_INVALID) {
                if (trace_dbus_pipe && dbus_pipe_trace_budget-- > 0) {
                    printf("[dbuspipe] read-eof-unused pid=%d cmd=%s fd=%d pipe=%d len=%u\n",
                           cur->pid, cur->name, fd, e->pipe_id, (unsigned)len);
                }
                return (uint64_t)-EBADF;
            }
            if (decision == KERNEL_PIPE_IO_COMPLETE) {
                if (trace_dbus_pipe && dbus_pipe_trace_budget-- > 0) {
                    printf("[dbuspipe] read-eof-nowriter pid=%d cmd=%s fd=%d pipe=%d len=%u\n",
                           cur->pid, cur->name, fd, e->pipe_id, (unsigned)len);
                }
                return 0;
            }
            if (decision == KERNEL_PIPE_IO_WOULD_BLOCK) {
                if (trace_dbus_pipe && dbus_pipe_trace_budget-- > 0) {
                    printf("[dbuspipe] read-eagain pid=%d cmd=%s fd=%d pipe=%d len=%u r=%d w=%d\n",
                           cur->pid, cur->name, fd, e->pipe_id, (unsigned)len,
                           pp->readers, pp->writers);
                }
                return (uint64_t)-EAGAIN;
            }
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            if (trace_dbus_pipe && dbus_pipe_trace_budget-- > 0) {
                printf("[dbuspipe] read-block pid=%d cmd=%s fd=%d pipe=%d len=%u r=%d w=%d\n",
                       cur->pid, cur->name, fd, e->pipe_id, (unsigned)len,
                       pp->readers, pp->writers);
            }
            pipe_read_waiter_add(e->pipe_id, cur ? cur->pid : 0);
            /*
             * Match Linux pipe read blocking semantics: after adding the
             * waiter, re-check the pipe state before sleeping.  Shell
             * pipelines used by XFCE startup can otherwise miss the writer's
             * wake if the writer runs between the empty-pipe test and the
             * actual block.
             */
            if (kernel_pipe_read_decide(
                    pp, (e->flags & LINUX_O_NONBLOCK) != 0) !=
                KERNEL_PIPE_IO_WAIT) {
                if (cur) waiter_remove_pid(cur->pid);
                continue;
            }
            socket_blocking_wait_step(0);
        }
        int64_t read_result = kernel_pipe_read_user(
            pp, buf_u, len, pipe_x86_copy_to_user, 0);
        uint64_t n;
        if (read_result < 0) return (uint64_t)read_result;
        n = (uint64_t)read_result;
        if (n > 0) fd_wake_pipe_waiters(e->pipe_id);
        if (trace_dbus_pipe && dbus_pipe_trace_budget-- > 0) {
            printf("[dbuspipe] read-ret pid=%d cmd=%s fd=%d pipe=%d len=%u ret=%u count=%u r=%d w=%d fl=0x%x\n",
                   cur->pid, cur->name, fd, e->pipe_id, (unsigned)len, (unsigned)n,
                   pp->count, pp->readers, pp->writers, (unsigned)e->flags);
        }
        if (ssh_trace_task(cur)) {
            printf("[sshdbg] read pid=%d cmd=%s fd=%d kind=pipe len=%u ret=%u fl=0x%x pidx=%d\n",
                   cur->pid, cur->name, fd, (unsigned)len, (unsigned)n, (unsigned)e->flags, e->pipe_id);
        }
        return n;
    }

    if (e->kind == FD_VFS && path_is_tty_device(e->path)) {
        uint64_t r;
        if ((e->flags & LINUX_O_NONBLOCK) != 0 &&
            !console_line_pollin_ready(console_line_from_fd_entry(e))) {
            return (uint64_t)-EAGAIN;
        }
        if (ssh_trace_task(cur)) {
            edge_console_line_t *line = console_line_state(console_line_from_fd_entry(e));
            printf("[sshdbg] read-enter pid=%d cmd=%s fd=%d kind=vfs-tty path=%s line=%d len=%u fl=0x%x lflag=0x%x iflag=0x%x fg=%d pg=%d ll=%u lp=%u reply=%u/%u\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, e->path, console_line_from_fd_entry(e), (unsigned)len,
                   (unsigned)e->flags,
                   line ? (unsigned)line->termios.c_lflag : 0,
                   line ? (unsigned)line->termios.c_iflag : 0,
                   line ? line->session.foreground_pgid : -1,
                   cur ? cur->pgid : -1,
                   line ? (unsigned)line->line_len : 0,
                   line ? (unsigned)line->line_pos : 0,
                   line ? (unsigned)line->reply_pos : 0,
                   line ? (unsigned)line->reply_len : 0);
        }
        r = do_sys_read_console_line(console_line_from_fd_entry(e), buf_u, len_u);
        if (ssh_trace_task(cur)) {
            printf("[sshdbg] read-exit pid=%d cmd=%s fd=%d ret=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?", fd, (int)(int64_t)r);
        }
        return r;
    }
    if (e->kind == FD_VFS && path_is_mouse_input(e->path)) {
        uint64_t done = 0;
        char mchunk[256];
        while (done < len) {
            uint64_t n = len - done;
            int r;
            if (n > sizeof(mchunk)) n = sizeof(mchunk);
            r = keyboard_mouse_read(mchunk, (uint32_t)n, 0);
            if (r > 0) {
                if (copy_to_user(buf_u + done, mchunk, (uint64_t)r) < 0) return (uint64_t)-EFAULT;
                done += (uint64_t)r;
                break;
            }
            if ((e->flags & LINUX_O_NONBLOCK) != 0) return done ? done : (uint64_t)-EAGAIN;
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            wait_blocking_step();
        }
        return done;
    }
    if (e->kind == FD_VFS && path_is_event_input(e->path)) {
        uint64_t done = 0;
        char echunk[256];
        int event_id = path_input_event_index(e->path);
        if (len < EDGE_LINUX_INPUT_EVENT_SIZE) return (uint64_t)-EINVAL;
        while (done < len) {
            uint64_t n = len - done;
            int r;
            if (n > sizeof(echunk)) n = sizeof(echunk);
            n -= n % EDGE_LINUX_INPUT_EVENT_SIZE;
            if (n == 0) break;
            r = fd_description_read_input(
                e, event_id, echunk, (uint32_t)n);
            if (r < 0) return (uint64_t)(int64_t)r;
            r -= r % (int)EDGE_LINUX_INPUT_EVENT_SIZE;
            if (r > 0) {
                if (copy_to_user(buf_u + done, echunk, (uint64_t)r) < 0) return (uint64_t)-EFAULT;
                done += (uint64_t)r;
                break;
            }
            if ((e->flags & LINUX_O_NONBLOCK) != 0) return done ? done : (uint64_t)-EAGAIN;
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            wait_blocking_step();
        }
        return done;
    }
    if (e->kind == FD_VFS && edge_drm_path_is_card(e->path)) {
        uint64_t identity = file_ref_identity(e->file_ref);
        for (;;) {
            uint64_t count = len < sizeof(chunk) ? len : sizeof(chunk);
            int64_t result = edge_drm_read(identity, chunk, count);
            if (result > 0) {
                if (copy_to_user(buf_u, chunk, (uint64_t)result) < 0)
                    return (uint64_t)-EFAULT;
                return (uint64_t)result;
            }
            if (result != -EDGE_LINUX_EAGAIN)
                return (uint64_t)result;
            if ((e->flags & LINUX_O_NONBLOCK) != 0)
                return (uint64_t)-EAGAIN;
            if (signal_pending_interrupt())
                return tty_interrupt_current_ret();
            wait_blocking_step();
        }
    }
    if (e->kind == FD_VFS && path_is_dri_device(e->path))
        return (uint64_t)-EINVAL;
    if (e->kind == FD_VFS && path_is_uinput_device(e->path)) {
        return 0;
    }
    if (e->kind == FD_VFS && path_is_kmsg_device(e->path)) {
        for (;;) {
            uint64_t n = len;
            uint64_t position = fd_description_offset(e);
            int r;
            if (n > sizeof(chunk)) n = sizeof(chunk);
            r = bootlog_kmsg_read_from(&position, chunk, (uint32_t)n);
            fd_description_set_offset(e, position);
            if (r < 0) return (uint64_t)(int64_t)r;
            if (r > 0) {
                if (copy_to_user(buf_u, chunk, (uint64_t)r) < 0)
                    return (uint64_t)-EFAULT;
                return (uint64_t)r;
            }
            if ((e->flags & LINUX_O_NONBLOCK) != 0)
                return (uint64_t)-EAGAIN;
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            wait_blocking_step();
        }
    }
    if (e->kind == FD_VFS && strcmp(e->path, "/dev/fb0") == 0) {
        uint64_t done = 0;
        uint64_t fb_bytes;
        uint64_t position;
        const uint8_t *src;

        if (!fb.addr || fb.pitch == 0 || fb.height == 0) return (uint64_t)-ENODEV;
        fb_bytes = (uint64_t)fb.pitch * (uint64_t)fb.height;
        position = fd_description_offset(e);
        if (position >= fb_bytes) return 0;
        src = fb_user_mmap_active() ? fb.addr : fb_get_draw_buffer();
        if (!src) src = fb.addr;
        while (done < len && position < fb_bytes) {
            uint64_t n = len - done;
            if (n > sizeof(chunk)) n = sizeof(chunk);
            if (n > fb_bytes - position) n = fb_bytes - position;
            memcpy(chunk, src + position, (uint32_t)n);
            if (copy_to_user(buf_u + done, chunk, n) < 0) {
                return done ? done : (uint64_t)-EFAULT;
            }
            done += n;
            position += n;
            fd_description_set_offset(e, position);
        }
        return done;
    }

    if (e->kind != FD_VFS) return (uint64_t)-EBADF;
    if ((e->inode.mode & 0xF000) == VFS_INODE_DIR) return (uint64_t)-EISDIR;

    {
    kernel_io_buffer_t io_buffer;
    char *read_chunk = chunk;
    uint64_t read_capacity = sizeof(chunk);
    uint64_t done = 0;
    uint64_t result;
    int pooled = 0;

    if ((e->inode.mode & 0xF000u) == VFS_INODE_FILE &&
        kernel_io_buffer_acquire(&io_buffer) == 0) {
        read_chunk = (char *)io_buffer.data;
        read_capacity = KERNEL_IO_BUFFER_SIZE;
        pooled = 1;
    }
    while (done < len) {
        uint64_t n = len - done;
        uint64_t position = fd_description_offset(e);
        if (n > read_capacity) n = read_capacity;
        int r = -1;

        if ((e->inode.mode & 0xF000) == VFS_INODE_CHR) {
            r = edge_memdev_read_description(
                e->inode.rdev, file_ref_identity(e->file_ref),
                read_chunk, (uint32_t)n);
            if (r == EDGE_MEMDEV_NOT_HANDLED)
                r = vfs_read_file(e->path, read_chunk, (uint32_t)n);
            else if (r < 0) {
                if (r == -EAGAIN && !done &&
                    (e->flags & LINUX_O_NONBLOCK) == 0) {
                    if (signal_pending_interrupt()) {
                        result = tty_interrupt_current_ret();
                        goto regular_read_out;
                    }
                    wait_blocking_step();
                    continue;
                }
                result = done ? done : (uint64_t)(int64_t)r;
                goto regular_read_out;
            }
        } else if ((e->inode.mode & 0xF000) == VFS_INODE_BLK) {
            block_device_t *device = 0;
            int64_t transferred;
            if (vfs_inode_get_block_device(&e->inode, &device) < 0) {
                result = done ? done : (uint64_t)-ENXIO;
                goto regular_read_out;
            }
            transferred = block_read_bytes(device, position, read_chunk,
                                           (uint32_t)n);
            if (transferred < 0) {
                result = done ? done : (uint64_t)transferred;
                goto regular_read_out;
            }
            r = (int)transferred;
            if (r > 0) fd_description_advance(e, (uint64_t)r);
        } else if (!e->sb) {
            if (position > UINT32_MAX) r = 0;
            else r = vfs_pread(e->path, (uint32_t)position, read_chunk,
                               (uint32_t)n);
            if (r < 0 && position == 0)
                r = vfs_read_file(e->path, read_chunk, (uint32_t)n);
            if (r > 0) fd_description_advance(e, (uint64_t)r);
        } else if (e->sb && e->sb->ops && e->sb->ops->read) {
            if (position > UINT32_MAX) r = 0;
            else r = e->sb->ops->read(e->sb, &e->inode,
                                      (uint32_t)position, read_chunk,
                                      (uint32_t)n);
            if (r > 0) fd_description_advance(e, (uint64_t)r);
        }

        if (r < 0) {
            if (r == -EAGAIN && !done &&
                (e->flags & LINUX_O_NONBLOCK) == 0) {
                if (signal_pending_interrupt()) {
                    result = tty_interrupt_current_ret();
                    goto regular_read_out;
                }
                wait_blocking_step();
                continue;
            }
            result = done ? done : (uint64_t)(int64_t)r;
            goto regular_read_out;
        }
        if (r == 0) break;
        if ((uint64_t)r > n) {
            result = done ? done : (uint64_t)-EIO;
            goto regular_read_out;
        }
        if (e->sb && (e->inode.mode & 0xF000u) == VFS_INODE_FILE)
            edge_mmap_file_cache_overlay_read(
                e->sb, &e->inode, position, read_chunk, (uint32_t)r);
        if (copy_to_user(buf_u + done, read_chunk, (uint64_t)r) < 0) {
            result = done ? done : (uint64_t)-EFAULT;
            goto regular_read_out;
        }
        done += (uint64_t)r;
        if ((uint64_t)r < n) break;
    }
    if (ssh_trace_task(cur)) {
        printf("[sshdbg] read pid=%d cmd=%s fd=%d kind=vfs len=%u ret=%u fl=0x%x\n",
               cur->pid, cur->name, fd, (unsigned)len, (unsigned)done, (unsigned)e->flags);
    }
    result = done;
regular_read_out:
    if (pooled) kernel_io_buffer_release(&io_buffer);
    return result;
    }
}

static int fd_entry_io_access_allowed(
        const edge_fd_t *entry, int writing) {
    if (!entry || !entry->used) return 0;
    if (entry->kind == FD_VFS || entry->kind == FD_MEMFD ||
        entry->kind == FD_TUN) {
        uint32_t access_mode =
            (uint32_t)entry->flags & LINUX_O_ACCMODE;
        if (((uint32_t)entry->flags & LINUX_O_PATH) != 0)
            return 0;
        return writing ? access_mode != LINUX_O_RDONLY :
                         access_mode != LINUX_O_WRONLY;
    }
    if (entry->kind == FD_PIPE_R) return !writing;
    if (entry->kind == FD_PIPE_W) return writing;
    return 1;
}

static uint64_t do_sys_fd_read_with_flags(
        uint64_t fd_u, uint64_t buf_u, uint64_t len_u,
        uint32_t set_flags, uint32_t clear_flags) {
    kernel_fd_operation_lease_t lease = {0};
    edge_fd_t *entry;
    uint64_t result;
    int status;

    status = kernel_fd_operation_acquire((int32_t)fd_u, &lease);
    if (status < 0) return (uint64_t)(int64_t)status;
    entry = (edge_fd_t *)(uintptr_t)kernel_fd_operation_view(&lease);
    if (!entry) {
        (void)kernel_fd_operation_release(&lease);
        return (uint64_t)-EIO;
    }
    if (!fd_entry_io_access_allowed(entry, 0)) {
        (void)kernel_fd_operation_release(&lease);
        return (uint64_t)-EBADF;
    }
    entry->flags = (int)(
        ((uint32_t)entry->flags | set_flags) & ~clear_flags);
    result = do_sys_fd_read_entry((int)fd_u, entry, buf_u, len_u);
    (void)kernel_fd_operation_release(&lease);
    return result;
}

static uint64_t do_sys_fd_read(uint64_t fd_u, uint64_t buf_u,
                               uint64_t len_u) {
    return do_sys_fd_read_with_flags(fd_u, buf_u, len_u, 0, 0);
}

static uint64_t do_sys_fd_write_entry(int fd, edge_fd_t *e,
                                      uint64_t buf_u, uint64_t len_u) {
    uint64_t len = len_u;
    char chunk[EDGE_SYSCALL_IO_CHUNK];
    task_t *cur = process_current_task();

    if (!e) return (uint64_t)-EBADF;
    if (e->kind != FD_EVENTFD &&
        e->kind != FD_TIMERFD &&
        e->kind != FD_SIGNALFD) {
        if (len == 0) return 0;
        if (!buf_u) return (uint64_t)-EFAULT;
    }
    if (e->kind == FD_TUN) {
        int64_t result;
        uint64_t identity = file_ref_identity(e->file_ref);

        do {
            result = edge_linux_tun_write(
                identity, buf_u,
                len > UINT32_MAX ? UINT32_MAX : (uint32_t)len,
                x86_tun_copy_from_user, 0);
            if (result != -EAGAIN ||
                (e->flags & LINUX_O_NONBLOCK) != 0)
                return (uint64_t)result;
            if (signal_pending_interrupt())
                return tty_interrupt_current_ret();
            wait_blocking_step();
        } while (1);
    }

#if EDGE_BB_FD_TRACE
    if (fd == 1 && g_bb_fd_trace_budget > 0) {
        task_t *t = process_current_task();
        if (t && strcmp(t->name, "busybox") == 0) {
            printf("[bbfd] pid=%d fd1 kind=%d flags=0x%x fdflags=0x%x pipe=%d len=%u\n",
                   t->pid, (int)e->kind, (unsigned)e->flags, (unsigned)e->fd_flags, e->pipe_id, (unsigned)len);
            g_bb_fd_trace_budget--;
        }
    }
#endif

    if (e->kind == FD_CONSOLE) return do_sys_write_console_line(console_line_from_fd_entry(e), buf_u, len_u);
    if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) {
        edge_pty_t *pty;
        uint8_t *dst_buf;
        uint32_t *dst_wpos;
        uint32_t *dst_count;
        int peer_refs;
        uint64_t n = 0;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS) return (uint64_t)-EBADF;
        pty = &g_ptys[e->pipe_id];
        if (!pty->used) return (uint64_t)-EBADF;
        if (e->kind == FD_PTY_MASTER) {
            dst_buf = pty->m2s_buf;
            dst_wpos = &pty->m2s_wpos;
            dst_count = &pty->m2s_count;
            peer_refs = pty->refs_slave;
        } else {
            dst_buf = pty->s2m_buf;
            dst_wpos = &pty->s2m_wpos;
            dst_count = &pty->s2m_count;
            peer_refs = pty->refs_master;
        }
        while (*dst_count >= EDGE_PTY_BUF_SIZE) {
            if (peer_refs <= 0) return (uint64_t)-EPIPE;
            if ((e->flags & LINUX_O_NONBLOCK) != 0) return n ? n : (uint64_t)-EAGAIN;
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            wait_blocking_step();
            peer_refs = (e->kind == FD_PTY_MASTER) ? pty->refs_slave : pty->refs_master;
        }
        n = len;
        if (n > (uint64_t)(EDGE_PTY_BUF_SIZE - *dst_count)) n = (uint64_t)(EDGE_PTY_BUF_SIZE - *dst_count);
        for (uint64_t i = 0; i < n; ++i) {
            char c;
            uint32_t need_slots = 1;
            if (copy_from_user(&c, buf_u + i, 1) < 0) return (uint64_t)-EFAULT;
            if (e->kind == FD_PTY_MASTER) {
                if (c == '\r') {
                    if ((pty->termios.c_iflag & LINUX_IGNCR) != 0) continue;
                    if ((pty->termios.c_iflag & LINUX_ICRNL) != 0) c = '\n';
                } else if (c == '\n' && (pty->termios.c_iflag & LINUX_INLCR) != 0) {
                    c = '\r';
                }
            }
            if (e->kind == FD_PTY_SLAVE &&
                c == '\n' &&
                (pty->termios.c_oflag & LINUX_OPOST) != 0 &&
                (pty->termios.c_oflag & LINUX_ONLCR) != 0) {
                need_slots = 2;
            }
            if ((uint32_t)(EDGE_PTY_BUF_SIZE - *dst_count) < need_slots) {
                n = i;
                break;
            }
            if (e->kind == FD_PTY_SLAVE &&
                c == '\n' &&
                (pty->termios.c_oflag & LINUX_OPOST) != 0 &&
                (pty->termios.c_oflag & LINUX_ONLCR) != 0) {
                dst_buf[*dst_wpos] = (uint8_t)'\r';
                *dst_wpos = (*dst_wpos + 1) % EDGE_PTY_BUF_SIZE;
                (*dst_count)++;
            }
            if (e->kind == FD_PTY_MASTER &&
                (pty->termios.c_lflag & LINUX_ISIG) &&
                (unsigned char)c == 3) {
                int fg = pty->session.foreground_pgid;
                if (fg <= 0) fg = process_getpgid(0);
                if (fg > 0) (void)do_sys_kill((uint64_t)(int64_t)(-fg), LINUX_SIGINT);
                if ((pty->termios.c_lflag & LINUX_ECHO) != 0) {
                    const char echo_seq[3] = {'^', 'C', '\n'};
                    for (int ei = 0; ei < 3; ++ei) {
                        if (pty->s2m_count >= EDGE_PTY_BUF_SIZE) break;
                        pty->s2m_buf[pty->s2m_wpos] = (uint8_t)echo_seq[ei];
                        pty->s2m_wpos = (pty->s2m_wpos + 1) % EDGE_PTY_BUF_SIZE;
                        pty->s2m_count++;
                    }
                }
                continue;
            }
            if (e->kind == FD_PTY_MASTER &&
                (pty->termios.c_lflag & LINUX_ICANON) &&
                (unsigned char)c == pty->termios.c_cc[LINUX_VERASE]) {
                if (pty->m2s_count > 0) {
                    uint32_t prev = (pty->m2s_wpos + EDGE_PTY_BUF_SIZE - 1) % EDGE_PTY_BUF_SIZE;
                    if (pty->m2s_buf[prev] != '\n') {
                        pty->m2s_wpos = prev;
                        pty->m2s_count--;
                        if ((pty->termios.c_lflag & LINUX_ECHO) != 0) {
                            pty_echo_seq_to_master(pty, "\b \b", 3);
                        }
                    }
                }
                continue;
            }
            if (e->kind == FD_PTY_MASTER && (pty->termios.c_lflag & LINUX_ECHO) != 0) {
                if (c == '\r' || c == '\n') {
                    if ((pty->termios.c_oflag & LINUX_OPOST) && (pty->termios.c_oflag & LINUX_ONLCR)) {
                        pty_echo_seq_to_master(pty, "\r\n", 2);
                    } else {
                        pty_echo_to_master(pty, (uint8_t)c);
                    }
                } else {
                    pty_echo_to_master(pty, (uint8_t)c);
                }
            }
            dst_buf[*dst_wpos] = (uint8_t)c;
            *dst_wpos = (*dst_wpos + 1) % EDGE_PTY_BUF_SIZE;
            (*dst_count)++;
        }
        return n;
    }
    if (e->kind == FD_SOCKET) {
        uint64_t w = x86_socket_sendto_entry_raw(
            fd, e, buf_u, len_u, 0, 0, 0, 0, 0);
        if (ssh_trace_task(cur)) {
            printf("[sshdbg] write pid=%d cmd=%s fd=%d kind=socket len=%u ret=%d fl=0x%x sid=%d\n",
                   cur->pid, cur->name, fd, (unsigned)len, (int)(int64_t)w, (unsigned)e->flags, e->pipe_id);
        }
        return w;
    }
    if (e->kind == FD_EVENTFD) {
        fd_u64_user_copy_context_t copy_context;
        kernel_eventfd_state_t state;
        uint64_t value = 0;
        int nonblocking = (e->flags & LINUX_O_NONBLOCK) != 0;
        int64_t status;
        copy_context.user_address = buf_u;
        status = kernel_eventfd_write_io(
            e->pipe_id, len, nonblocking, fd_load_u64_from_user,
            &copy_context, &value);
        while (status == KERNEL_EVENTFD_IO_WAIT) {
            if (signal_pending_interrupt()) {
                if (cur) waiter_remove_pid(cur->pid);
                return tty_interrupt_current_ret();
            }
            eventfd_write_waiter_add(e->pipe_id, cur ? cur->pid : 0);
            /*
             * See the eventfd read path above.  A reader can drain the
             * counter after our full-counter check and before we sleep; a
             * Linux-compatible writer must observe that transition here
             * instead of parking until an unrelated future wake.
             */
            status = kernel_eventfd_write_value(e->pipe_id, 0, value);
            if (status != KERNEL_EVENTFD_IO_WAIT) {
                if (cur) waiter_remove_pid(cur->pid);
                break;
            }
            socket_blocking_wait_step(0);
            status = kernel_eventfd_write_value(e->pipe_id, 0, value);
        }
        if (status < 0) return (uint64_t)(int64_t)status;
        if (g_gui_eventfd_trace_budget > 0 && gui_diag_task(cur)) {
            printf("[gui-eventfd] write pid=%d cmd=%s fd=%d id=%d val=%llu counter_after=%llu fl=0x%x budget=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, e->pipe_id, (unsigned long long)value,
                   (unsigned long long)
                       (eventfd_snapshot(e->pipe_id, &state) ?
                            state.counter : 0),
                   (unsigned)e->flags,
                   g_gui_eventfd_trace_budget - 1);
            g_gui_eventfd_trace_budget--;
        }
        if (status == KERNEL_EVENTFD_IO_BYTES)
            fd_wake_eventfd_read_waiters(e->pipe_id);
        return (uint64_t)status;
    }
    if (e->kind == FD_TIMERFD || e->kind == FD_SIGNALFD || e->kind == FD_EPOLL || e->kind == FD_PIDFD) return (uint64_t)-EINVAL;
    if (e->kind == FD_MEMFD) {
        edge_memfd_t *mf = memfd_get(e->pipe_id);
        uint64_t done = 0;
        if (!mf) return (uint64_t)-EBADF;
        if (mf->secret) return (uint64_t)-EINVAL;
        while (done < len) {
            uint64_t position = fd_description_offset(e);
            uint64_t n = len - done;
            int w;
            if (n > sizeof(chunk)) n = sizeof(chunk);
            if (copy_from_user(chunk, buf_u + done, n) < 0) return done ? done : (uint64_t)-EFAULT;
            w = memfd_write_from_kernel(mf, position, chunk, n);
            if (w < 0) return done ? done : (uint64_t)(int64_t)w;
            if (w == 0) break;
            done += (uint64_t)w;
            fd_description_advance(e, (uint64_t)w);
            if ((uint64_t)w < n) break;
        }
        e->inode.size = mf->size;
        return done;
    }

    if (e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW) {
        static int dbus_pipe_trace_budget = EDGE_GUI_DEEP_TRACE ? 256 : 0;
        int trace_dbus_pipe = 0;
        uint64_t done = 0;
        const int nonblocking = (e->flags & LINUX_O_NONBLOCK) != 0;
        const int atomic_write = len <= KERNEL_PIPE_RUNTIME_BUF;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PIPES) return (uint64_t)-EBADF;
        edge_pipe_t *pp = &g_pipes[e->pipe_id];
        trace_dbus_pipe = cur && dbus_pipe_trace_budget > 0 &&
            (strcmp(cur->name, "dbus-run-sessio") == 0 ||
             strcmp(cur->name, "dbus-run-session") == 0 ||
             strcmp(cur->name, "dbus-daemon") == 0 ||
             strcmp(cur->name, "xrdb") == 0 ||
             strcmp(cur->name, "cat") == 0);
        if (!pp->used) return (uint64_t)-EBADF;
        /*
         * Xorg writes generated XKB keymaps through a pipe to xkbcomp.  Those
         * payloads can exceed EDGE_PIPE_SIZE.  Returning a successful short
         * write on a blocking pipe truncates stdin for the reader and xkbcomp
         * reports a bogus keymap syntax failure.  Keep writing until the user
         * buffer is consumed, unless nonblocking mode, signals, or EPIPE force
         * the same short/error behavior Linux callers expect.
        */
        while (done < len) {
            kernel_pipe_io_decision_t decision =
                kernel_pipe_write_decide(
                    pp, len - done, atomic_write, nonblocking);
            if (decision == KERNEL_PIPE_IO_COMPLETE) break;
            if (decision == KERNEL_PIPE_IO_INVALID)
                return done ? done : (uint64_t)-EBADF;
            if (decision == KERNEL_PIPE_IO_BROKEN)
                return done ? done : (uint64_t)-EPIPE;
            if (decision == KERNEL_PIPE_IO_WOULD_BLOCK)
                return done ? done : (uint64_t)-EAGAIN;
            if (decision == KERNEL_PIPE_IO_WAIT) {
                if (signal_pending_interrupt()) return done ? done : tty_interrupt_current_ret();
                /*
                 * If this write already filled the pipe, wake readers before
                 * sleeping.  Linux pipe writers do not wait for the complete
                 * user write before making queued bytes visible; delaying this
                 * wake can deadlock helpers that write records larger than the
                 * current pipe room and then wait for the child to consume it.
                 */
                if (done > 0) fd_wake_pipe_waiters(e->pipe_id);
                pipe_write_waiter_add(e->pipe_id, cur ? cur->pid : 0);
                /*
                 * Do not sleep after registering if the reader already made
                 * room.  This is the write-side half of Linux's pipe
                 * prepare-to-wait ordering and prevents large pipeline writes
                 * from wedging desktop launch helpers.
                 */
                if (kernel_pipe_write_decide(
                        pp, len - done, atomic_write, nonblocking) !=
                    KERNEL_PIPE_IO_WAIT) {
                    if (cur) waiter_remove_pid(cur->pid);
                    continue;
                }
                socket_blocking_wait_step(0);
                continue;
            }
            {
                uint64_t was_empty = (pp->count == 0);
                int64_t result = kernel_pipe_write_user(
                    pp, buf_u + done, len - done,
                    pipe_x86_copy_from_user, 0);
                if (result < 0)
                    return done ? done : (uint64_t)result;
                done += (uint64_t)result;
                if (was_empty || pp->count >= EDGE_PIPE_SIZE || done == len) {
                    fd_wake_pipe_waiters(e->pipe_id);
                }
            }
        }
        if (done > 0) fd_wake_pipe_waiters(e->pipe_id);
        if (trace_dbus_pipe && dbus_pipe_trace_budget-- > 0) {
            printf("[dbuspipe] write-ret pid=%d cmd=%s fd=%d pipe=%d len=%u ret=%u count=%u r=%d w=%d fl=0x%x\n",
                   cur->pid, cur->name, fd, e->pipe_id, (unsigned)len, (unsigned)done,
                   pp->count, pp->readers, pp->writers, (unsigned)e->flags);
        }
        if (ssh_trace_task(cur)) {
            printf("[sshdbg] write pid=%d cmd=%s fd=%d kind=pipe len=%u ret=%u fl=0x%x pidx=%d\n",
                   cur->pid, cur->name, fd, (unsigned)len, (unsigned)done, (unsigned)e->flags, e->pipe_id);
        }
        return done;
    }

    if (e->kind == FD_VFS && path_is_tty_device(e->path)) return do_sys_write_console_line(console_line_from_fd_entry(e), buf_u, len_u);
    if (e->kind == FD_VFS && path_is_dri_device(e->path))
        return (uint64_t)-EINVAL;
    if (e->kind == FD_VFS && (path_is_uinput_device(e->path) ||
                              path_is_mouse_input(e->path) ||
                              path_is_event_input(e->path))) {
        return len_u;
    }
    if (e->kind == FD_VFS && path_is_kmsg_device(e->path)) {
        uint64_t done = 0;
        while (done < len) {
            uint64_t n = len - done;
            char kmsg[256];
            if (n >= sizeof(kmsg)) n = sizeof(kmsg) - 1;
            if (copy_from_user(kmsg, buf_u + done, n) < 0) return done ? done : (uint64_t)-EFAULT;
            kmsg[n] = 0;
            while (n > 0 && (kmsg[n - 1] == '\n' || kmsg[n - 1] == '\r')) {
                kmsg[--n] = 0;
            }
            if (n > 0) bootlog_stage(kmsg);
            done += n;
            /*
             * One log record per write chunk matches the practical contract
             * expected by shell redirects and avoids unbounded kernel stack
             * buffering for large writes.  A trailing newline counts as
             * consumed even when stripped from the stored record.
             */
            while (done < len) {
                char c;
                if (copy_from_user(&c, buf_u + done, 1) < 0) return done ? done : (uint64_t)-EFAULT;
                if (c != '\n' && c != '\r') break;
                done++;
            }
        }
        return done;
    }

    if (e->kind != FD_VFS) return (uint64_t)-EBADF;
    if ((e->inode.mode & 0xF000) == VFS_INODE_DIR) return (uint64_t)-EISDIR;
    if ((e->inode.mode & 0xF000) == VFS_INODE_FILE && e->mount_id) {
        vfs_superblock_t *mount = vfs_superblock_for_mount_id(e->mount_id);
        if (mount && (mount->mount_flags & VFS_MOUNT_READONLY))
            return (uint64_t)-EROFS;
    }

    uint64_t done = 0;

    while (done < len) {
        uint64_t position = fd_description_offset(e);
        uint64_t n = len - done;
        if (n > sizeof(chunk)) n = sizeof(chunk);
        if (copy_from_user(chunk, buf_u + done, n) < 0) {
            if (!done) return (uint64_t)-EFAULT;
            break;
        }

        int w = -1;
        if ((e->inode.mode & 0xF000) == VFS_INODE_CHR) {
            w = edge_memdev_write_description(
                e->inode.rdev, file_ref_identity(e->file_ref),
                chunk, (uint32_t)n);
            if (w == EDGE_MEMDEV_NOT_HANDLED) {
                w = vfs_dev_pwrite(e->path, chunk, (uint32_t)n, position);
                if (w > 0) fd_description_advance(e, (uint64_t)w);
            } else if (w < 0) {
                if (w == -EAGAIN && !done &&
                    (e->flags & LINUX_O_NONBLOCK) == 0) {
                    if (signal_pending_interrupt())
                        return tty_interrupt_current_ret();
                    wait_blocking_step();
                    continue;
                }
                return done ? done : (uint64_t)(int64_t)w;
            }
        } else if ((e->inode.mode & 0xF000) == VFS_INODE_BLK) {
            block_device_t *device = 0;
            int64_t result;
            if (vfs_inode_get_block_device(&e->inode, &device) < 0)
                return done ? done : (uint64_t)-ENXIO;
            result = block_write_bytes(device, position, chunk, (uint32_t)n);
            if (result < 0)
                return done ? done : (uint64_t)result;
            w = (int)result;
            if (w > 0) fd_description_advance(e, (uint64_t)w);
        } else if (e->sb && e->sb->ops && e->sb->ops->write) {
            uint32_t write_offset;
            uint64_t new_position;
            if (position > UINT32_MAX)
                return done ? done : (uint64_t)-EFBIG;
            write_offset = (uint32_t)position;
            if ((e->flags & LINUX_O_APPEND) != 0) {
                w = vfs_append_write(e->path, e->sb, &e->inode, chunk,
                                     (uint32_t)n, &write_offset);
                if (w > 0)
                    fd_description_set_offset(
                        e, (uint64_t)write_offset + (uint64_t)w);
            } else {
                w = e->sb->ops->write(e->sb, &e->inode, write_offset,
                                      chunk, (uint32_t)n);
            }
            if (w > 0) {
                if ((e->flags & LINUX_O_APPEND) == 0)
                    fd_description_advance(e, (uint64_t)w);
                new_position = fd_description_offset(e);
                if (new_position > e->inode.size)
                    e->inode.size = (uint32_t)new_position;
                e->dirty = 1;
                vfs_path_cache_invalidate(e->path);
                edge_mmap_file_cache_apply_write(
                    e->sb, &e->inode, write_offset, chunk, (uint32_t)w);
            }
        }

        if (w < 0) return (uint64_t)-EINVAL;
        done += (uint64_t)w;
        if ((uint64_t)w < n) break;
    }
    if (ssh_trace_task(cur)) {
        printf("[sshdbg] write pid=%d cmd=%s fd=%d kind=vfs len=%u ret=%u fl=0x%x\n",
               cur->pid, cur->name, fd, (unsigned)len, (unsigned)done, (unsigned)e->flags);
    }
    if (done > 0 && e->path[0] && (e->inode.mode & 0xF000u) != VFS_INODE_CHR &&
        (e->inode.mode & 0xF000u) != VFS_INODE_BLK) {
        edge_inotify_notify_path(e->path, EDGE_IN_MODIFY, 0);
    }
    return done;
}

static uint64_t do_sys_fd_write_with_flags(
        uint64_t fd_u, uint64_t buf_u, uint64_t len_u,
        uint32_t set_flags, uint32_t clear_flags) {
    kernel_fd_operation_lease_t lease = {0};
    edge_fd_t *entry;
    uint64_t result;
    int status;

    status = kernel_fd_operation_acquire((int32_t)fd_u, &lease);
    if (status < 0) return (uint64_t)(int64_t)status;
    entry = (edge_fd_t *)(uintptr_t)kernel_fd_operation_view(&lease);
    if (!entry) {
        (void)kernel_fd_operation_release(&lease);
        return (uint64_t)-EIO;
    }
    if (!fd_entry_io_access_allowed(entry, 1)) {
        (void)kernel_fd_operation_release(&lease);
        return (uint64_t)-EBADF;
    }
    entry->flags = (int)(
        ((uint32_t)entry->flags | set_flags) & ~clear_flags);
    result = do_sys_fd_write_entry((int)fd_u, entry, buf_u, len_u);
    (void)kernel_fd_operation_release(&lease);
    return result;
}

static uint64_t do_sys_fd_write(uint64_t fd_u, uint64_t buf_u,
                                uint64_t len_u) {
    return do_sys_fd_write_with_flags(fd_u, buf_u, len_u, 0, 0);
}

static int fd_entry_positional_io_unsupported(
        const edge_fd_t *entry) {
    if (!entry) return 0;
    return fd_is_tty(entry) ||
           entry->kind == FD_CONSOLE ||
           entry->kind == FD_PIPE_R ||
           entry->kind == FD_PIPE_W ||
           entry->kind == FD_PIPE_RW ||
           entry->kind == FD_SOCKET ||
           entry->kind == FD_PTY_MASTER ||
           entry->kind == FD_PTY_SLAVE ||
           entry->kind == FD_EVENTFD ||
           entry->kind == FD_TIMERFD ||
           entry->kind == FD_SIGNALFD ||
           entry->kind == FD_EPOLL ||
           entry->kind == FD_PIDFD ||
           memfd_entry_is_secret(entry);
}

static uint64_t do_sys_pread64_entry(
        edge_fd_t *e, uint64_t buf_u, uint64_t len_u,
        uint64_t off_u) {
    uint64_t len = len_u;
    uint64_t off = off_u;
    char chunk[EDGE_SYSCALL_IO_CHUNK];

    if (!e) return (uint64_t)-EBADF;
    if (len == 0)
        return fd_entry_positional_io_unsupported(e) ?
            (uint64_t)-ESPIPE : 0;
    if (!buf_u) return (uint64_t)-EFAULT;
    if ((int64_t)off < 0) return (uint64_t)-EINVAL;

    if (fd_entry_positional_io_unsupported(e)) {
        return (uint64_t)-ESPIPE;
    }
    if (e->kind == FD_MEMFD) {
        edge_memfd_t *mf = memfd_get(e->pipe_id);
        uint64_t done = 0;
        if (!mf) return (uint64_t)-EBADF;
        while (done < len && off < mf->size) {
            uint64_t n = len - done;
            int r;
            if (n > sizeof(chunk)) n = sizeof(chunk);
            r = memfd_read_to_kernel(mf, off, chunk, n);
            if (r < 0) return done ? done : (uint64_t)(int64_t)r;
            if (r == 0) break;
            if (copy_to_user(buf_u + done, chunk, (uint64_t)r) < 0) return done ? done : (uint64_t)-EFAULT;
            done += (uint64_t)r;
            off += (uint64_t)r;
            if ((uint64_t)r < n) break;
        }
        e->inode.size = mf->size;
        return done;
    }
    if (e->kind != FD_VFS) return (uint64_t)-EBADF;
    if ((e->inode.mode & 0xF000) == VFS_INODE_DIR) return (uint64_t)-EISDIR;
    if (path_is_tty_device(e->path) || path_is_mouse_input(e->path)) return (uint64_t)-ESPIPE;

    {
        kernel_io_buffer_t io_buffer;
        char *read_chunk = chunk;
        uint64_t read_capacity = sizeof(chunk);
        uint64_t done = 0;
        uint64_t result;
        int pooled = 0;

        if ((e->inode.mode & 0xF000u) == VFS_INODE_FILE &&
            kernel_io_buffer_acquire(&io_buffer) == 0) {
            read_chunk = (char *)io_buffer.data;
            read_capacity = KERNEL_IO_BUFFER_SIZE;
            pooled = 1;
        }
        while (done < len) {
            uint64_t n = len - done;
            int r = -1;
            if (n > read_capacity) n = read_capacity;

            if ((e->inode.mode & 0xF000) == VFS_INODE_CHR) {
                result = (uint64_t)-ESPIPE;
                goto pread_out;
            } else if ((e->inode.mode & 0xF000) == VFS_INODE_BLK) {
                block_device_t *device = 0;
                int64_t transferred;
                if (vfs_inode_get_block_device(&e->inode, &device) < 0) {
                    result = done ? done : (uint64_t)-ENXIO;
                    goto pread_out;
                }
                transferred = block_read_bytes(device, off, read_chunk,
                                               (uint32_t)n);
                if (transferred < 0) {
                    result = done ? done : (uint64_t)transferred;
                    goto pread_out;
                }
                r = (int)transferred;
            } else if (e->sb && e->sb->ops && e->sb->ops->read) {
                if (off > UINT32_MAX) r = 0;
                else r = e->sb->ops->read(e->sb, &e->inode,
                                           (uint32_t)off, read_chunk,
                                           (uint32_t)n);
            }

            if (r < 0) {
                result = done ? done : (uint64_t)-EINVAL;
                goto pread_out;
            }
            if (r == 0) break;
            if ((uint64_t)r > n) {
                result = done ? done : (uint64_t)-EIO;
                goto pread_out;
            }
            if (e->sb && (e->inode.mode & 0xF000u) == VFS_INODE_FILE)
                edge_mmap_file_cache_overlay_read(
                    e->sb, &e->inode, off, read_chunk, (uint32_t)r);
            if (copy_to_user(buf_u + done, read_chunk, (uint64_t)r) < 0) {
                result = done ? done : (uint64_t)-EFAULT;
                goto pread_out;
            }
            done += (uint64_t)r;
            off += (uint64_t)r;
            if ((uint64_t)r < n) break;
        }
        result = done;
pread_out:
        if (pooled) kernel_io_buffer_release(&io_buffer);
        return result;
    }
}

static uint64_t do_sys_pwrite64_entry(
        edge_fd_t *e, uint64_t buf_u, uint64_t len_u,
        uint64_t off_u) {
    uint64_t len = len_u;
    uint64_t off = off_u;
    char chunk[EDGE_SYSCALL_IO_CHUNK];

    if (!e) return (uint64_t)-EBADF;
    if (!buf_u && len) return (uint64_t)-EFAULT;
    if (len == 0)
        return fd_entry_positional_io_unsupported(e) ?
            (uint64_t)-ESPIPE : 0;
    if ((int64_t)off < 0) return (uint64_t)-EINVAL;

    if (fd_entry_positional_io_unsupported(e)) {
        return (uint64_t)-ESPIPE;
    }
    if (e->kind == FD_MEMFD) {
        edge_memfd_t *mf = memfd_get(e->pipe_id);
        uint64_t done = 0;
        if (!mf) return (uint64_t)-EBADF;
        while (done < len) {
            uint64_t n = len - done;
            int w;
            if (n > sizeof(chunk)) n = sizeof(chunk);
            if (copy_from_user(chunk, buf_u + done, n) < 0) return done ? done : (uint64_t)-EFAULT;
            w = memfd_write_from_kernel(mf, off, chunk, n);
            if (w < 0) return done ? done : (uint64_t)(int64_t)w;
            if (w == 0) break;
            done += (uint64_t)w;
            off += (uint64_t)w;
            if ((uint64_t)w < n) break;
        }
        e->inode.size = mf->size;
        return done;
    }
    if (e->kind != FD_VFS) return (uint64_t)-EBADF;
    if ((e->inode.mode & 0xF000) == VFS_INODE_DIR) return (uint64_t)-EISDIR;
    if (path_is_tty_device(e->path) || path_is_mouse_input(e->path)) return (uint64_t)-ESPIPE;
    if ((e->inode.mode & 0xF000) == VFS_INODE_FILE && e->mount_id) {
        vfs_superblock_t *mount = vfs_superblock_for_mount_id(e->mount_id);
        if (mount && (mount->mount_flags & VFS_MOUNT_READONLY))
            return (uint64_t)-EROFS;
    }

    {
        uint64_t done = 0;
        while (done < len) {
            uint64_t n = len - done;
            int w = -1;
            if (n > sizeof(chunk)) n = sizeof(chunk);
            if (copy_from_user(chunk, buf_u + done, n) < 0) return done ? done : (uint64_t)-EFAULT;

            if ((e->inode.mode & 0xF000) == VFS_INODE_CHR) {
                w = edge_memdev_write_description(
                    e->inode.rdev, file_ref_identity(e->file_ref),
                    chunk, (uint32_t)n);
                if (w == EDGE_MEMDEV_NOT_HANDLED)
                    w = vfs_dev_pwrite(e->path, chunk, (uint32_t)n, off);
                else if (w < 0)
                    return done ? done : (uint64_t)(int64_t)w;
            } else if ((e->inode.mode & 0xF000) == VFS_INODE_BLK) {
                block_device_t *device = 0;
                int64_t result;
                if (vfs_inode_get_block_device(&e->inode, &device) < 0)
                    return done ? done : (uint64_t)-ENXIO;
                result = block_write_bytes(device, off, chunk, (uint32_t)n);
                if (result < 0)
                    return done ? done : (uint64_t)result;
                w = (int)result;
            } else if (e->sb && e->sb->ops && e->sb->ops->write) {
                w = e->sb->ops->write(e->sb, &e->inode, (uint32_t)off, chunk, (uint32_t)n);
                if (w > 0) {
                    uint64_t end_pos = off + (uint64_t)w;
                    if (end_pos > e->inode.size) e->inode.size = end_pos;
                    e->dirty = 1;
                    vfs_path_cache_invalidate(e->path);
                    edge_mmap_file_cache_apply_write(
                        e->sb, &e->inode, off, chunk, (uint32_t)w);
                }
            }

            if (w < 0) return done ? done : (uint64_t)-EINVAL;
            done += (uint64_t)w;
            off += (uint64_t)w;
            if ((uint64_t)w < n) break;
        }
        return done;
    }
}

static uint64_t do_sys_lseek(uint64_t fd_u, uint64_t off_u, uint64_t whence_u) {
    if (fd_u > INT32_MAX || whence_u > UINT32_MAX)
        return (uint64_t)-EINVAL;
    return (uint64_t)edge_linux_lseek_descriptor(
        (int32_t)fd_u, (int64_t)off_u, (uint32_t)whence_u);
}

static int linux_fd_fill_kstat(edge_fd_t *e, int fd,
                               edge_x86_64_linux_stat_t *st) {
    if (!e || !st) return -EBADF;
    if (e->kind == FD_PIPE_R || e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW) {
        vfs_inode_t fifo_ino;
        if (e->path[0] && vfs_resolve(e->path, &fifo_ino, 0, 0, 0) == 0 &&
            (fifo_ino.mode & 0xF000u) == VFS_INODE_FIFO) {
            fill_kstat(&fifo_ino, st);
        } else {
            fill_kstat_mode_size((uint16_t)(LINUX_S_IFIFO | 0600), 0, st);
        }
    } else if (e->kind == FD_CONSOLE) {
        vfs_inode_t device_inode;
        if (e->path[0] &&
            vfs_resolve(e->path, &device_inode, 0, 0, 0) == 0) {
            /*
             * An opened terminal and its device node must expose identical
             * identity and permissions.  libc verifies this relationship
             * before returning a terminal name.
             */
            fill_kstat(&device_inode, st);
            (void)linux_special_dev_stat_from_path(e->path, st);
        } else {
            fill_kstat_mode_size((uint16_t)(LINUX_S_IFCHR | 0666), 0, st);
            st->st_ino = linux_devnode_ino_from_path(e->path);
            st->st_rdev = linux_tty_rdev_from_path(e->path);
        }
        if (!st->st_rdev) st->st_rdev = linux_tty_rdev_from_line(console_line_from_fd_entry(e));
    } else if (e->kind == FD_PTY_MASTER) {
        fill_kstat_mode_size((uint16_t)(LINUX_S_IFCHR | 0666), 0, st);
        st->st_dev = 1;
        st->st_ino = 0xD0000000u + 12u; /* /dev/ptmx devnode index */
        st->st_rdev = linux_makedev(5, 2);
    } else if (e->kind == FD_PTY_SLAVE) {
        vfs_inode_t inode;
        vfs_superblock_t *superblock = 0;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS ||
            !g_ptys[e->pipe_id].used ||
            devpts_slave_refresh(
                &g_ptys[e->pipe_id].slave_inode,
                &inode, &superblock) < 0)
            return -EIO;
        (void)superblock;
        fill_kstat(&inode, st);
        /*
         * Linux devpts slaves are character devices with major 136 and the PTY
         * index as the minor.  VTE/libutil validate that an opened slave is a
         * tty-like character device; leaving st_rdev zero makes a real PTY look
         * unlike /dev/pts/N and can surface as "Not a tty" in terminal emulators.
        */
        if (!st->st_rdev)
            st->st_rdev = linux_makedev(136, (uint32_t)e->pipe_id);
    } else if (e->kind == FD_NAMESPACE) {
        fill_kstat_mode_size((uint16_t)(LINUX_S_IFREG | 0444), 0, st);
        st->st_ino = edge_namespace_handle_inode(
            (edge_namespace_kind_t)e->namespace_kind, e->namespace_id);
    } else if (e->kind == FD_TUN) {
        fill_kstat_mode_size((uint16_t)(LINUX_S_IFCHR | 0666), 0, st);
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(EDGE_LINUX_TUN_PATH);
        st->st_rdev = linux_makedev(10, 200);
    } else if (e->kind == FD_EVENTFD || e->kind == FD_TIMERFD ||
               e->kind == FD_SIGNALFD || e->kind == FD_EPOLL ||
               e->kind == FD_PIDFD || e->kind == FD_DMA_BUF ||
               e->kind == FD_MOUNT || e->kind == FD_IO_URING ||
               e->kind == FD_BPF || e->kind == FD_SECCOMP) {
        /* Linux anon_inode descriptors have permission bits but no file type. */
        fill_kstat_mode_size(0600, 0, st);
        st->st_ino = 0xE0000000u + (uint64_t)(uint32_t)(e->kind << 16) + (uint64_t)(uint32_t)(e->pipe_id & 0xFFFF);
    } else if (e->kind == FD_MEMFD) {
        edge_memfd_t *mf = memfd_get(e->pipe_id);
        fill_kstat_mode_size(
            (uint16_t)(LINUX_S_IFREG |
                (mf && mf->secret ? 0600 : 0777)),
            mf ? mf->size : 0, st);
        st->st_dev = 1;
        st->st_ino = 0xE1000000u + (uint64_t)(uint32_t)(e->pipe_id & 0xFFFF);
    } else {
        if (e->kind == FD_VFS && e->sb)
            (void)vfs_inode_refresh(e->sb, &e->inode);
        fill_kstat(&e->inode, st);
        if (e->kind == FD_VFS && linux_special_dev_stat_from_path(e->path, st)) {
            if (path_is_tty_device(e->path) && !st->st_rdev) st->st_rdev = linux_tty_rdev_from_line(console_line_from_fd_entry(e));
        }
    }
    if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
        g_pty_stat_trace_budget-- > 0) {
        task_t *cur = process_current_task();
        printf("[ptydiag] fstat pid=%d task=%s fd=%d kind=%s pty=%d mode=0x%x dev=%llu ino=%llu rdev=%llu flags=0x%x\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               fd, fd_kind_name(e->kind), e->pipe_id, (unsigned)st->st_mode,
               (unsigned long long)st->st_dev,
               (unsigned long long)st->st_ino,
               (unsigned long long)st->st_rdev,
               (unsigned)e->flags);
    }
    return 0;
}

int64_t arch_vfs_special_getdents64(
    const kernel_vfs_getdents_request_t *request, int *handled) {
    int fd;
    uint64_t written = 0;

    if (!request || !handled) return -EIO;
    *handled = 0;
    fd = request->descriptor;

    edge_fd_proc_t *p = fd_proc_with_stdio();
    edge_fd_t *e = fd_get(p, fd);
    if (!e) return -EBADF;
    if ((e->inode.mode & 0xF000) != VFS_INODE_DIR) return -ENOTDIR;

    if (strncmp(e->path, "/sys", 4) == 0 && !e->sb) {
        *handled = 1;
        static const char *k_sys[] = { "class", "bus", "block", "devices", "firmware", "fs" };
        static const char *k_fs[] = { "cgroup" };
        static const char *k_empty[] = { 0 };
        static const char *k_class[] = { "block", "drm", "graphics", "input", "power_supply", "rtc", "tty" };
        static const char *k_class_audio[] = { "block", "drm", "graphics", "input", "power_supply", "rtc", "sound", "tty" };
        static const char *k_bus[] = { "pci" };
        static const char *k_pci[] = { "devices" };
        static const char *k_firmware[] = { "acpi" };
        static const char *k_acpi[] = { "tables", "pm_profile" };
        static const char *k_devices[] = { "system" };
        static const char *k_system[] = { "clocksource" };
        static const char *k_clocksource[] = { "clocksource0" };
        static const char *k_clocksource0[] = { "available_clocksource", "current_clocksource" };
        static const char *k_drm[] = { "card0" };
        static const char *k_graphics[] = { "fb0" };
        static const char *k_rtc[] = { "rtc0" };
        static const char *k_sound[] = { "card0", "controlC0", "pcmC0D0p", "timer" };
        static const char *k_sound_capture[] = { "card0", "controlC0", "pcmC0D0p", "pcmC0D0c", "timer" };
        static const char *k_sound_card[] = { "id", "number", "uevent", "subsystem" };
        static const char *k_sound_dev[] = { "dev", "name", "uevent", "subsystem" };
        static const char *k_block_disk_node[] = {
            "queue", "dev", "size", "ro", "removable", "stat", "uevent",
            "range", "alignment_offset", "discard_alignment", "capability",
            "subsystem"
        };
        static const char *k_block_part_node[] = {
            "dev", "size", "start", "partition", "ro", "stat", "uevent",
            "alignment_offset", "discard_alignment", "subsystem"
        };
        static const char *k_block_queue_node[] = {
            "logical_block_size", "physical_block_size", "hw_sector_size",
            "minimum_io_size", "optimal_io_size", "rotational", "read_ahead_kb",
            "max_sectors_kb", "max_hw_sectors_kb", "scheduler", "write_cache"
        };
#ifdef CONFIG_LOOP_DEVICE
        static const char *k_block_loop_node[] = {
            "backing_file", "offset", "sizelimit", "autoclear",
            "partscan", "dio"
        };
#endif
        static const char *k_drm_node[] = { "dev", "uevent", "status", "enabled", "modes" };
        static const char *k_fb_node[] = { "dev", "name", "virtual_size", "bits_per_pixel", "modes", "device", "subsystem" };
        static const char *k_fb_device[] = { "subsystem" };
        static const char *k_input_node[] = { "dev", "name", "uevent" };
        static const char *k_rtc_node[] = {
            "dev", "name", "date", "time", "since_epoch", "hctosys",
            "max_user_freq", "uevent"
        };
        static const char *k_tty_node[] = { "dev", "uevent", "subsystem" };
        static const char *k_tty_mux_node[] = { "dev", "uevent", "active", "subsystem" };
        const char *tty_entries[EDGE_FB_VT_COUNT + 4u];
        char tty_names[EDGE_FB_VT_COUNT + 1u][8];
#ifdef CONFIG_PCI
        static const char *k_pci_device_node[] = {
            "vendor", "device", "subsystem_vendor", "subsystem_device",
            "class", "revision", "irq", "resource", "modalias", "uevent",
            "subsystem"
        };
#endif
#if defined(CONFIG_ACPI) && \
    (defined(CONFIG_ACPI_AC_ADAPTER) || defined(CONFIG_ACPI_BATTERY))
        const char *power_supply_entries[24];
#endif
        const char *const *names = 0;
        uint64_t count_names = 0;
        uint8_t file_entries = 0;

        if (strcmp(e->path, "/sys") == 0) {
            names = k_sys;
            count_names = sizeof(k_sys) / sizeof(k_sys[0]);
        } else if (strcmp(e->path, "/sys/fs") == 0) {
            names = k_fs;
            count_names = sizeof(k_fs) / sizeof(k_fs[0]);
        } else if (strcmp(e->path, "/sys/fs/cgroup") == 0) {
            names = k_empty;
            count_names = 0;
        } else if (strcmp(e->path, "/sys/class") == 0) {
            if (alsa_available()) {
                names = k_class_audio;
                count_names = sizeof(k_class_audio) / sizeof(k_class_audio[0]);
            } else {
                names = k_class;
                count_names = sizeof(k_class) / sizeof(k_class[0]);
            }
        } else if (strcmp(e->path, "/sys/bus") == 0) {
            names = k_bus;
            count_names = sizeof(k_bus) / sizeof(k_bus[0]);
        } else if (strcmp(e->path, "/sys/bus/pci") == 0) {
            names = k_pci;
            count_names = sizeof(k_pci) / sizeof(k_pci[0]);
        } else if (strcmp(e->path, "/sys/firmware") == 0) {
#ifdef CONFIG_ACPI
            if (acpi_available()) {
                names = k_firmware;
                count_names = sizeof(k_firmware) / sizeof(k_firmware[0]);
            }
#endif
        } else if (strcmp(e->path, "/sys/firmware/acpi") == 0) {
            names = k_acpi;
            count_names = sizeof(k_acpi) / sizeof(k_acpi[0]);
            file_entries = 1;
        } else if (strcmp(e->path, "/sys/firmware/acpi/tables/dynamic") == 0) {
            uint64_t idx = fd_description_offset(e);
            while (idx < 2) {
                const char *name = (idx == 0) ? "." : "..";
                int emitted = kernel_vfs_dirent_emit(
                    request, &written, 2, (int64_t)(idx + 1),
                    LINUX_DT_DIR, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
                idx++;
            }
            fd_description_set_offset(e, idx);
            return (int64_t)written;
        } else if (strcmp(e->path, "/sys/firmware/acpi/tables") == 0) {
            uint64_t idx = fd_description_offset(e);
            while (1) {
                const char *name;
                char table_name[16];
                uint8_t dtype = LINUX_DT_REG;
                int emitted;

                if (idx == 0) {
                    name = ".";
                    dtype = LINUX_DT_DIR;
                } else if (idx == 1) {
                    name = "..";
                    dtype = LINUX_DT_DIR;
                } else if (idx == 2) {
                    name = "dynamic";
                    dtype = LINUX_DT_DIR;
                } else {
#ifdef CONFIG_ACPI
                    if (acpi_sysfs_table_name((uint32_t)(idx - 3u), table_name, sizeof(table_name)) < 0) break;
                    name = table_name;
#else
                    break;
#endif
                }
                emitted = kernel_vfs_dirent_emit(
                    request, &written,
                    (idx < 2) ? (uint64_t)2 :
                        (uint64_t)(0x5F800000u + (uint32_t)idx),
                    (int64_t)(idx + 1), dtype, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
                idx++;
            }
            fd_description_set_offset(e, idx);
            return (int64_t)written;
        } else if (strcmp(e->path, "/sys/devices") == 0) {
            names = k_devices;
            count_names = sizeof(k_devices) / sizeof(k_devices[0]);
        } else if (strcmp(e->path, "/sys/devices/system") == 0) {
            names = k_system;
            count_names = sizeof(k_system) / sizeof(k_system[0]);
        } else if (strcmp(e->path, "/sys/devices/system/clocksource") == 0) {
            names = k_clocksource;
            count_names = sizeof(k_clocksource) / sizeof(k_clocksource[0]);
        } else if (strcmp(e->path, "/sys/devices/system/clocksource/clocksource0") == 0) {
            names = k_clocksource0;
            count_names = sizeof(k_clocksource0) / sizeof(k_clocksource0[0]);
            file_entries = 1;
        } else if (strcmp(e->path, "/sys/class/drm") == 0) {
            names = k_drm;
            count_names = sizeof(k_drm) / sizeof(k_drm[0]);
        } else if (strcmp(e->path, "/sys/class/graphics") == 0) {
            names = k_graphics;
            count_names = sizeof(k_graphics) / sizeof(k_graphics[0]);
        } else if (strcmp(e->path, "/sys/class/input") == 0) {
            uint64_t idx = fd_description_offset(e);

            while (1) {
                const char *name;
                char input_name_buffer[32];
                uint8_t dtype = LINUX_DT_LNK;
                uint32_t ordinal;
                uint32_t device = 0;
                int event = 0;
                int found_device = 0;
                int emitted;

                if (idx == 0) {
                    name = ".";
                    dtype = LINUX_DT_DIR;
                } else if (idx == 1) {
                    name = "..";
                    dtype = LINUX_DT_DIR;
                } else {
                    ordinal = (uint32_t)(idx - 2u);
                    event = (ordinal & 1u) != 0;
                    ordinal /= 2u;
                    for (device = 0;
                         device < EDGE_INPUT_DEVICE_MAX; ++device) {
                        if (!input_device_present(device)) continue;
                        if (ordinal-- != 0u) continue;
                        found_device = 1;
                        break;
                    }
                    if (!found_device ||
                        linux_input_index_name(
                            input_name_buffer,
                            sizeof(input_name_buffer),
                            event ? "event" : "input",
                            device) < 0)
                        break;
                    name = input_name_buffer;
                }
                emitted = kernel_vfs_dirent_emit(
                    request, &written,
                    idx < 2u ? 2u :
                        (uint64_t)(0x5F620000u + (uint32_t)idx),
                    (int64_t)(idx + 1u), dtype, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
                ++idx;
            }
            fd_description_set_offset(e, idx);
            return (int64_t)written;
        } else if (strcmp(e->path, "/sys/class/power_supply") == 0) {
            uint64_t idx = fd_description_offset(e);
            while (1) {
                const char *name;
                uint8_t dtype = LINUX_DT_DIR;
                int emitted;

                if (idx == 0) {
                    name = ".";
                } else if (idx == 1) {
                    name = "..";
                } else if (idx == 2) {
#if defined(CONFIG_ACPI) && defined(CONFIG_ACPI_AC_ADAPTER)
                    if (!acpi_available() || !acpi_has_ac_adapter()) {
                        idx++;
                        continue;
                    }
                    name = "AC";
#else
                    idx++;
                    continue;
#endif
                } else if (idx == 3) {
#if defined(CONFIG_ACPI) && defined(CONFIG_ACPI_BATTERY)
                    if (!acpi_available() || !acpi_has_battery()) {
                        idx++;
                        continue;
                    }
                    name = "BAT0";
#else
                    idx++;
                    continue;
#endif
                } else {
                    break;
                }
                emitted = kernel_vfs_dirent_emit(
                    request, &written,
                    (idx < 2) ? (uint64_t)2 :
                        (uint64_t)(0x5F610000u + (uint32_t)idx),
                    (int64_t)(idx + 1), dtype, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
                idx++;
            }
            fd_description_set_offset(e, idx);
            return (int64_t)written;
        } else if (strcmp(e->path, "/sys/class/rtc") == 0) {
            names = k_rtc;
            count_names = sizeof(k_rtc) / sizeof(k_rtc[0]);
        } else if (strcmp(e->path, "/sys/class/sound") == 0 && alsa_available()) {
            if (alsa_capture_available()) {
                names = k_sound_capture;
                count_names = sizeof(k_sound_capture) / sizeof(k_sound_capture[0]);
            } else {
                names = k_sound;
                count_names = sizeof(k_sound) / sizeof(k_sound[0]);
            }
        } else if (strcmp(e->path, "/sys/class/tty") == 0) {
            uint32_t entry = 0u;
            kernel_console_device_t serial;

            tty_entries[entry++] = "console";
            tty_entries[entry++] = "tty";
            for (uint32_t vt = 0u; vt <= EDGE_FB_VT_COUNT; ++vt) {
                uint32_t offset = 3u;

                memcpy(tty_names[vt], "tty", 3u);
                if (vt >= 10u)
                    tty_names[vt][offset++] = (char)('0' + vt / 10u);
                tty_names[vt][offset++] = (char)('0' + vt % 10u);
                tty_names[vt][offset] = 0;
                tty_entries[entry++] = tty_names[vt];
            }
            if (kernel_arch_serial_console_device(&serial) == 0)
                tty_entries[entry++] = serial.name;
            names = tty_entries;
            count_names = entry;
        } else if (strcmp(e->path, "/sys/block") == 0 ||
                   strcmp(e->path, "/sys/class/block") == 0) {
            uint64_t idx = fd_description_offset(e);
            int class_block = (strcmp(e->path, "/sys/class/block") == 0);
            while (1) {
                const char *name;
                char block_name[BLOCK_NAME_MAX];
                uint8_t dtype = class_block ? LINUX_DT_LNK : LINUX_DT_DIR;
                int emitted;

                if (idx == 0) {
                    name = ".";
                    dtype = LINUX_DT_DIR;
                } else if (idx == 1) {
                    name = "..";
                    dtype = LINUX_DT_DIR;
                } else {
                    int rc = class_block ?
                        block_device_name_by_index((uint32_t)(idx - 2u), block_name, sizeof(block_name)) :
                        block_disk_name_by_index((uint32_t)(idx - 2u), block_name, sizeof(block_name));
                    if (rc < 0) break;
                    name = block_name;
                }
                emitted = kernel_vfs_dirent_emit(
                    request, &written,
                    (idx < 2) ? (uint64_t)2 :
                        (uint64_t)(0x5F700000u + (uint32_t)idx),
                    (int64_t)(idx + 1), dtype, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
                idx++;
            }
            fd_description_set_offset(e, idx);
            return (int64_t)written;
        } else if (strncmp(e->path, "/sys/block/", 11) == 0 &&
                   block_sysfs_path_kind(e->path) == BLOCK_SYSFS_PATH_DIR) {
            const char *rest = e->path + 11;
            const char *slash = 0;
            for (const char *p_scan = rest; *p_scan; ++p_scan) {
                if (*p_scan == '/') {
                    slash = p_scan;
                    break;
                }
            }
            if (!slash) {
                uint64_t idx = fd_description_offset(e);
                uint64_t static_count = sizeof(k_block_disk_node) / sizeof(k_block_disk_node[0]);
#ifdef CONFIG_LOOP_DEVICE
                uint32_t major = 0;
                uint32_t minor = 0;
                block_device_t *disk = block_find(rest);
                int loop_disk = disk &&
                    block_linux_major_minor(disk, &major, &minor) == 0 &&
                    major == 7u;
                (void)minor;
#endif
                while (1) {
                    const char *name;
                    char part_name[BLOCK_NAME_MAX];
                    uint8_t dtype = LINUX_DT_REG;
                    int emitted;

                    if (idx == 0) {
                        name = ".";
                        dtype = LINUX_DT_DIR;
                    } else if (idx == 1) {
                        name = "..";
                        dtype = LINUX_DT_DIR;
                    } else if (idx - 2u < static_count) {
                        name = k_block_disk_node[idx - 2u];
                        if (strcmp(name, "queue") == 0) dtype = LINUX_DT_DIR;
                        else if (strcmp(name, "subsystem") == 0) dtype = LINUX_DT_LNK;
#ifdef CONFIG_LOOP_DEVICE
                    } else if (loop_disk && idx - 2u == static_count) {
                        name = "loop";
                        dtype = LINUX_DT_DIR;
#endif
                    } else {
                        uint32_t partition_ordinal =
                            (uint32_t)(idx - 2u - static_count);
#ifdef CONFIG_LOOP_DEVICE
                        if (loop_disk) partition_ordinal--;
#endif
                        if (block_partition_name_by_index(rest, partition_ordinal,
                                                          part_name, sizeof(part_name)) < 0) break;
                        name = part_name;
                        dtype = LINUX_DT_DIR;
                    }
                    emitted = kernel_vfs_dirent_emit(
                        request, &written,
                        (idx < 2) ? (uint64_t)2 :
                            (uint64_t)(0x5F710000u + (uint32_t)idx),
                        (int64_t)(idx + 1), dtype, name);
                    if (emitted < 0) return emitted;
                    if (!emitted) break;
                    idx++;
                }
                fd_description_set_offset(e, idx);
                return (int64_t)written;
            }
            if (strcmp(slash + 1, "queue") == 0) {
                names = k_block_queue_node;
                count_names = sizeof(k_block_queue_node) / sizeof(k_block_queue_node[0]);
                file_entries = 1;
#ifdef CONFIG_LOOP_DEVICE
            } else if (strcmp(slash + 1, "loop") == 0) {
                names = k_block_loop_node;
                count_names = sizeof(k_block_loop_node) /
                              sizeof(k_block_loop_node[0]);
                file_entries = 1;
#endif
            } else {
                const char *second_slash = 0;
                for (const char *p_scan = slash + 1; *p_scan; ++p_scan) {
                    if (*p_scan == '/') {
                        second_slash = p_scan;
                        break;
                    }
                }
                if (!second_slash) {
                    names = k_block_part_node;
                    count_names = sizeof(k_block_part_node) / sizeof(k_block_part_node[0]);
                    file_entries = 1;
                }
            }
        } else if (strcmp(e->path, "/sys/class/drm/card0") == 0) {
            names = k_drm_node;
            count_names = sizeof(k_drm_node) / sizeof(k_drm_node[0]);
            file_entries = 1;
        } else if (strcmp(e->path, "/sys/class/graphics/fb0") == 0) {
            names = k_fb_node;
            count_names = sizeof(k_fb_node) / sizeof(k_fb_node[0]);
            file_entries = 1;
        } else if (strcmp(e->path, "/sys/class/graphics/fb0/device") == 0) {
            names = k_fb_device;
            count_names = sizeof(k_fb_device) / sizeof(k_fb_device[0]);
            file_entries = 1;
        } else if (strncmp(e->path, "/sys/class/input/", 17) == 0) {
            names = k_input_node;
            count_names = sizeof(k_input_node) / sizeof(k_input_node[0]);
            file_entries = 1;
        } else if (strncmp(e->path, "/sys/class/power_supply/", 24) == 0) {
            const char *node = e->path + 24;
            if (strcmp(node, "BAT0") == 0) {
#if defined(CONFIG_ACPI) && defined(CONFIG_ACPI_BATTERY)
                if (acpi_available() && acpi_has_battery()) {
                    struct edge_acpi_battery_info information;
                    uint32_t attributes;

                    power_supply_entries[count_names++] = "type";
                    power_supply_entries[count_names++] = "scope";
                    power_supply_entries[count_names++] = "model_name";
                    power_supply_entries[count_names++] = "manufacturer";
                    power_supply_entries[count_names++] = "uevent";
                    power_supply_entries[count_names++] = "status";
                    power_supply_entries[count_names++] = "present";
                    if (acpi_get_battery_info(0, &information) == 0) {
                        attributes =
                            acpi_battery_attribute_mask(&information);
                        if (attributes & EDGE_ACPI_BATTERY_ATTR_CAPACITY)
                            power_supply_entries[count_names++] = "capacity";
                        if (attributes & EDGE_ACPI_BATTERY_ATTR_TECHNOLOGY)
                            power_supply_entries[count_names++] = "technology";
                        if (attributes & EDGE_ACPI_BATTERY_ATTR_SERIAL)
                            power_supply_entries[count_names++] = "serial_number";
                        if (attributes & EDGE_ACPI_BATTERY_ATTR_CYCLE_COUNT)
                            power_supply_entries[count_names++] = "cycle_count";
                        if (attributes & EDGE_ACPI_BATTERY_ATTR_VOLTAGE_NOW)
                            power_supply_entries[count_names++] = "voltage_now";
                        if (attributes & EDGE_ACPI_BATTERY_ATTR_VOLTAGE_DESIGN)
                            power_supply_entries[count_names++] =
                                "voltage_min_design";
                        if (attributes & EDGE_ACPI_BATTERY_ATTR_STORAGE) {
                            power_supply_entries[count_names++] =
                                information.units == 0 ?
                                "energy_now" : "charge_now";
                            power_supply_entries[count_names++] =
                                information.units == 0 ?
                                "energy_full" : "charge_full";
                            power_supply_entries[count_names++] =
                                information.units == 0 ?
                                "energy_full_design" : "charge_full_design";
                        }
                        if (attributes & EDGE_ACPI_BATTERY_ATTR_RATE)
                            power_supply_entries[count_names++] =
                                information.units == 0 ?
                                "power_now" : "current_now";
                        if (attributes & EDGE_ACPI_BATTERY_ATTR_TIME_TO_EMPTY)
                            power_supply_entries[count_names++] =
                                "time_to_empty_now";
                    }
                    names = power_supply_entries;
                }
#endif
            } else if (strcmp(node, "AC") == 0) {
#if defined(CONFIG_ACPI) && defined(CONFIG_ACPI_AC_ADAPTER)
                if (acpi_available() && acpi_has_ac_adapter()) {
                    power_supply_entries[count_names++] = "type";
                    power_supply_entries[count_names++] = "scope";
                    power_supply_entries[count_names++] = "model_name";
                    power_supply_entries[count_names++] = "manufacturer";
                    power_supply_entries[count_names++] = "uevent";
                    power_supply_entries[count_names++] = "online";
                    names = power_supply_entries;
                }
#endif
            }
            file_entries = 1;
        } else if (strcmp(e->path, "/sys/class/rtc/rtc0") == 0) {
            names = k_rtc_node;
            count_names = sizeof(k_rtc_node) / sizeof(k_rtc_node[0]);
            file_entries = 1;
        } else if (strncmp(e->path, "/sys/class/sound/", 17) == 0) {
            const char *node = e->path + 17;
            if (strcmp(node, "card0") == 0) {
                names = k_sound_card;
                count_names = sizeof(k_sound_card) / sizeof(k_sound_card[0]);
            } else if (strcmp(node, "controlC0") == 0 ||
                       strcmp(node, "pcmC0D0p") == 0 ||
                       (strcmp(node, "pcmC0D0c") == 0 &&
                        alsa_capture_available()) ||
                       strcmp(node, "timer") == 0) {
                names = k_sound_dev;
                count_names = sizeof(k_sound_dev) / sizeof(k_sound_dev[0]);
            }
            file_entries = 1;
        } else if (strncmp(e->path, "/sys/class/tty/", 15) == 0) {
            const char *node = e->path + 15;
            if (strcmp(node, "tty0") == 0 || strcmp(node, "console") == 0) {
                names = k_tty_mux_node;
                count_names = sizeof(k_tty_mux_node) / sizeof(k_tty_mux_node[0]);
            } else {
                names = k_tty_node;
                count_names = sizeof(k_tty_node) / sizeof(k_tty_node[0]);
            }
            file_entries = 1;
#ifdef CONFIG_PCI
        } else if (strcmp(e->path, "/sys/bus/pci/devices") == 0) {
            uint64_t idx = fd_description_offset(e);
            while (1) {
                const char *name;
                char pci_name[24];
                uint8_t dtype = LINUX_DT_DIR;
                int emitted;

                if (idx == 0) {
                    name = ".";
                } else if (idx == 1) {
                    name = "..";
                } else {
                    if (pci_device_name_by_index((uint32_t)(idx - 2u), pci_name, sizeof(pci_name)) < 0) break;
                    name = pci_name;
                }
                emitted = kernel_vfs_dirent_emit(
                    request, &written,
                    (idx < 2) ? (uint64_t)2 :
                        (uint64_t)(0x5F600000u + (uint32_t)idx),
                    (int64_t)(idx + 1), dtype, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
                idx++;
            }
            fd_description_set_offset(e, idx);
            return (int64_t)written;
        } else if (strncmp(e->path, "/sys/bus/pci/devices/", 21) == 0 &&
                   pci_sysfs_path_kind(e->path) == PCI_SYSFS_PATH_DIR) {
            names = k_pci_device_node;
            count_names = sizeof(k_pci_device_node) / sizeof(k_pci_device_node[0]);
            file_entries = 1;
#endif
        }

        if (names) {
            uint64_t idx = fd_description_offset(e);
            uint64_t total = 2 + count_names;
            while (idx < total) {
                const char *name;
                uint8_t dtype = file_entries ? LINUX_DT_REG : LINUX_DT_DIR;
                if (idx == 0) {
                    name = ".";
                    dtype = LINUX_DT_DIR;
                } else if (idx == 1) {
                    name = "..";
                    dtype = LINUX_DT_DIR;
                } else {
                    name = names[idx - 2];
                }
                if (file_entries && strcmp(name, "tables") == 0) dtype = LINUX_DT_DIR;
                if (file_entries && strcmp(name, "subsystem") == 0) dtype = LINUX_DT_LNK;
                {
                    int emitted = kernel_vfs_dirent_emit(
                        request, &written,
                        (idx < 2) ? (uint64_t)2 :
                            (uint64_t)(0x5F500000u + (uint32_t)idx),
                        (int64_t)(idx + 1), dtype, name);
                    if (emitted < 0) return emitted;
                    if (!emitted) break;
                }
                idx++;
            }
            fd_description_set_offset(e, idx);
            return (int64_t)written;
        }
        return -ENOSYS;
    }

    /*
     * A mounted devtmpfs, tmpfs, or nested device filesystem owns its
     * directory entries.  The synthetic fallback exists only before those
     * mounts are available; using it after mount hides driver-created nodes
     * from getdents64 even though direct lookup succeeds.
     */
    if (kernel_vfs_device_directory_uses_backing_readdir(e->path, e->sb))
        return 0;

    if (strcmp(e->path, "/dev/pts") == 0) {
        *handled = 1;
        uint64_t idx = fd_description_offset(e);
        uint64_t total = 2;
        for (int i = 0; i < EDGE_MAX_PTYS; ++i) {
            if (g_ptys[i].used) total++;
        }
        while (idx < total) {
            const char *name = 0;
            char numbuf[16];
            uint8_t dtype = LINUX_DT_CHR;
            if (idx == 0) {
                name = ".";
                dtype = LINUX_DT_DIR;
            } else if (idx == 1) {
                name = "..";
                dtype = LINUX_DT_DIR;
            } else {
                uint64_t seen = 0;
                int pty_id = -1;
                for (int i = 0; i < EDGE_MAX_PTYS; ++i) {
                    if (!g_ptys[i].used) continue;
                    if (seen == idx - 2) {
                        pty_id = i;
                        break;
                    }
                    seen++;
                }
                if (pty_id < 0) break;
                int n = 0;
                int x = pty_id;
                char tmp[16];
                if (x == 0) {
                    tmp[n++] = '0';
                } else {
                    while (x > 0 && n < (int)sizeof(tmp)) {
                        tmp[n++] = (char)('0' + (x % 10));
                        x /= 10;
                    }
                }
                for (int i = 0; i < n; ++i) numbuf[i] = tmp[n - 1 - i];
                numbuf[n] = 0;
                name = numbuf;
            }

            {
                int emitted = kernel_vfs_dirent_emit(
                    request, &written,
                    (idx < 2) ? (uint64_t)2 :
                        (uint64_t)(0xD0FFF100u + (uint64_t)(idx - 2)),
                    (int64_t)(idx + 1), dtype, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
            }
            idx++;
        }
        fd_description_set_offset(e, idx);
        return (int64_t)written;
    }

    if (strcmp(e->path, "/dev/snd") == 0) {
        *handled = 1;
        static const char *k_snd_chr[] = { "controlC0", "pcmC0D0p", "timer" };
        static const char *k_snd_chr_capture[] = { "controlC0", "pcmC0D0p", "pcmC0D0c", "timer" };
        const char *const *snd_names = alsa_capture_available() ?
            k_snd_chr_capture : k_snd_chr;
        uint64_t snd_count = alsa_capture_available() ?
            (uint64_t)(sizeof(k_snd_chr_capture) / sizeof(k_snd_chr_capture[0])) :
            (uint64_t)(sizeof(k_snd_chr) / sizeof(k_snd_chr[0]));
        uint64_t idx = fd_description_offset(e);
        uint64_t total = 2 + snd_count;
        while (idx < total) {
            const char *name;
            uint8_t dtype = LINUX_DT_CHR;
            if (idx == 0) {
                name = ".";
                dtype = LINUX_DT_DIR;
            } else if (idx == 1) {
                name = "..";
                dtype = LINUX_DT_DIR;
            } else {
                name = snd_names[idx - 2];
            }
            {
                uint64_t inode;
                int emitted;
                if (idx < 2) {
                    inode = (idx == 0) ?
                        alsa_inode_from_kind(EDGE_ALSA_NODE_SND_DIR) : 2;
                } else {
                    char full[64];
                    strcpy(full, "/dev/snd/");
                    strcat(full, name);
                    inode = linux_devnode_ino_from_path(full);
                }
                emitted = kernel_vfs_dirent_emit(
                    request, &written, inode, (int64_t)(idx + 1),
                    dtype, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
            }
            idx++;
        }
        fd_description_set_offset(e, idx);
        return (int64_t)written;
    }

    if (strcmp(e->path, "/dev/input") == 0) {
        uint64_t idx = fd_description_offset(e);
        int pointer_present = 0;

        *handled = 1;
        for (uint32_t device = 0;
             device < EDGE_INPUT_DEVICE_MAX; ++device) {
            if (input_device_role(device) == EDGE_INPUT_ROLE_POINTER) {
                pointer_present = 1;
                break;
            }
        }
        while (1) {
            const char *name;
            char event_name[32];
            char full_path[48];
            uint8_t dtype = LINUX_DT_CHR;
            uint64_t data_ordinal;
            uint32_t device = 0;
            int found_device = 0;
            int emitted;

            if (idx == 0) {
                name = ".";
                dtype = LINUX_DT_DIR;
            } else if (idx == 1) {
                name = "..";
                dtype = LINUX_DT_DIR;
            } else {
                data_ordinal = idx - 2u;
                if (pointer_present && data_ordinal < 2u) {
                    name = data_ordinal == 0u ? "mice" : "mouse0";
                } else {
                    if (pointer_present) data_ordinal -= 2u;
                    for (device = 0;
                         device < EDGE_INPUT_DEVICE_MAX; ++device) {
                        if (!input_device_present(device)) continue;
                        if (data_ordinal-- != 0u) continue;
                        found_device = 1;
                        break;
                    }
                    if (!found_device ||
                        linux_input_index_name(
                            event_name, sizeof(event_name),
                            "event", device) < 0)
                        break;
                    name = event_name;
                }
            }
            if (idx < 2u) {
                full_path[0] = 0;
            } else {
                strcpy(full_path, "/dev/input/");
                strcat(full_path, name);
            }
            emitted = kernel_vfs_dirent_emit(
                request, &written,
                idx < 2u ? 2u :
                    linux_devnode_ino_from_path(full_path),
                (int64_t)(idx + 1u), dtype, name);
            if (emitted < 0) return emitted;
            if (!emitted) break;
            ++idx;
        }
        fd_description_set_offset(e, idx);
        return (int64_t)written;
    }

    if (strcmp(e->path, "/dev/dri") == 0) {
        *handled = 1;
        static const char *k_dri_chr[] = { "card0", "renderD128" };
        const char *const *names = k_dri_chr;
        uint64_t count_names =
            edge_drm_path_is_render(EDGE_VIRTGPU_RENDER_PATH) ? 2u : 1u;
        uint64_t idx = fd_description_offset(e);
        uint64_t total = 2 + count_names;
        while (idx < total) {
            const char *name;
            uint8_t dtype = LINUX_DT_CHR;
            if (idx == 0) {
                name = ".";
                dtype = LINUX_DT_DIR;
            } else if (idx == 1) {
                name = "..";
                dtype = LINUX_DT_DIR;
            } else {
                name = names[idx - 2];
            }
            {
                uint64_t inode = (idx < 2) ?
                    (uint64_t)2 : linux_devnode_ino_from_path(name);
                int emitted;
                if (idx >= 2) {
                    char full[64];
                    if (strcmp(e->path, "/dev/input") == 0) strcpy(full, "/dev/input/");
                    else strcpy(full, "/dev/dri/");
                    strcat(full, name);
                    inode = linux_devnode_ino_from_path(full);
                }
                emitted = kernel_vfs_dirent_emit(
                    request, &written, inode, (int64_t)(idx + 1),
                    dtype, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
            }
            idx++;
        }
        fd_description_set_offset(e, idx);
        return (int64_t)written;
    }

    {
        int is_dev_dir = 0;
        if (strcmp(e->path, "/dev") == 0) {
            is_dev_dir = 1;
        } else {
            vfs_inode_t dev_ino;
            vfs_superblock_t *dev_sb = 0;
            if (vfs_resolve("/dev", &dev_ino, &dev_sb, 0, 0) == 0 &&
                vfs_superblock_same_filesystem(dev_sb, e->sb) &&
                dev_ino.ino == e->inode.ino &&
                (dev_ino.mode & 0xF000) == VFS_INODE_DIR) {
                is_dev_dir = 1;
            }
        }
        if (!is_dev_dir) {
            /* fall through to filesystem-backed readdir */
        } else {
            *handled = 1;
            static const char *k_chr_suffix[] = {
                "null", "zero", "fb0", "random", "urandom", "ptmx",
                "pts", "input", "dri", "snd", "uinput", "video0"
            };
            const char *k_chr[EDGE_FB_VT_COUNT + 16u];
            char tty_names[EDGE_FB_VT_COUNT + 1u][8];
            kernel_console_device_t serial;
            uint32_t character_count = 0u;

            k_chr[character_count++] = "console";
            k_chr[character_count++] = "tty";
            for (uint32_t vt = 0u; vt <= EDGE_FB_VT_COUNT; ++vt) {
                uint32_t offset = 3u;

                memcpy(tty_names[vt], "tty", 3u);
                if (vt >= 10u)
                    tty_names[vt][offset++] = (char)('0' + vt / 10u);
                tty_names[vt][offset++] = (char)('0' + vt % 10u);
                tty_names[vt][offset] = 0;
                k_chr[character_count++] = tty_names[vt];
            }
            if (kernel_arch_serial_console_device(&serial) == 0)
                k_chr[character_count++] = serial.name;
            for (uint32_t suffix = 0u;
                 suffix < sizeof(k_chr_suffix) / sizeof(k_chr_suffix[0]);
                 ++suffix)
                k_chr[character_count++] = k_chr_suffix[suffix];
            uint64_t idx = fd_description_offset(e);
            uint64_t total =
                2 + (uint64_t)block_count() +
                (uint64_t)character_count;
            while (idx < total) {
                const char *name;
                uint8_t dtype;
                if (idx == 0) {
                    name = ".";
                    dtype = LINUX_DT_DIR;
                } else if (idx == 1) {
                    name = "..";
                    dtype = LINUX_DT_DIR;
                } else if (idx < (uint64_t)(2 + block_count())) {
                    int bi = (int)(idx - 2);
                    block_device_t *b = block_get(bi);
                    if (!b || !b->present) {
                        idx++;
                        continue;
                    }
                    name = b->name;
                    dtype = LINUX_DT_BLK;
                } else {
                    uint64_t ci = idx - (uint64_t)(2 + block_count());
                    if (ci >= (uint64_t)character_count)
                        break;
                    name = k_chr[ci];
                    if (strcmp(name, "video0") == 0 &&
                        !uvc_available()) {
                        idx++;
                        continue;
                    }
                    dtype =
                        (strcmp(name, "pts") == 0 ||
                         strcmp(name, "input") == 0 ||
                         strcmp(name, "dri") == 0 ||
                         strcmp(name, "snd") == 0) ?
                            LINUX_DT_DIR : LINUX_DT_CHR;
                }

                uint64_t inode;
                int emitted;
                if (idx < 2) {
                    inode = 2;
                } else if (idx < (uint64_t)(2 + block_count())) {
                    inode = 0xD0000000u + (uint64_t)(idx - 2);
                } else {
                    inode = 0xD0000000u + (uint64_t)block_count() +
                        (idx - (uint64_t)(2 + block_count()));
                }
                emitted = kernel_vfs_dirent_emit(
                    request, &written, inode, (int64_t)(idx + 1),
                    dtype, name);
                if (emitted < 0) return emitted;
                if (!emitted) break;
                idx++;
            }
            fd_description_set_offset(e, idx);
            return (int64_t)written;
        }
    }

    return 0;
}

int arch_vfs_directory_open(int32_t descriptor,
                            kernel_vfs_directory_cursor_t *cursor) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry;

    if (!cursor) return -EIO;
    entry = fd_get(process, descriptor);
    if (!entry) return -EBADF;
    if ((entry->inode.mode & 0xf000u) != VFS_INODE_DIR)
        return -ENOTDIR;
    if (!entry->sb || !entry->sb->ops || !entry->sb->ops->readdir)
        return -ENOSYS;
    cursor->opaque = entry;
    cursor->offset = fd_description_offset(entry);
    return 0;
}

int arch_vfs_directory_next(kernel_vfs_directory_cursor_t *cursor,
                            kernel_vfs_directory_entry_t *entry) {
    edge_fd_t *descriptor;
    uint32_t offset;

    if (!cursor || !entry || !cursor->opaque) return -EIO;
    descriptor = (edge_fd_t *)cursor->opaque;
    offset = (uint32_t)cursor->offset;
    memset(entry, 0, sizeof(*entry));
    if (vfs_readdir_dirent(
            descriptor->sb, &descriptor->inode, offset,
            entry->name, &entry->inode) < 0)
        return 0;
    entry->next_offset = (uint64_t)offset + 1u;
    return 1;
}

void arch_vfs_directory_commit(
    kernel_vfs_directory_cursor_t *cursor,
    const kernel_vfs_directory_entry_t *entry) {
    edge_fd_t *descriptor;
    char child_path[256];

    if (!cursor || !entry || !cursor->opaque) return;
    descriptor = (edge_fd_t *)cursor->opaque;
    if (strcmp(entry->name, ".") != 0 &&
        strcmp(entry->name, "..") != 0 &&
        edge_child_path(
            child_path, (int)sizeof(child_path), descriptor->path,
            entry->name) == 0)
        vfs_path_cache_seed(
            child_path, &entry->inode, descriptor->sb);
    cursor->offset = entry->next_offset;
}

void arch_vfs_directory_finish(kernel_vfs_directory_cursor_t *cursor) {
    edge_fd_t *descriptor;
    if (!cursor || !cursor->opaque) return;
    descriptor = (edge_fd_t *)cursor->opaque;
    fd_description_set_offset(descriptor, cursor->offset);
}

static edge_socket_t *socket_from_fd_entry(const edge_fd_t *e) {
    if (!e) return 0;
    if (e->kind != FD_SOCKET) return 0;
    if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS) return 0;
    if (!g_sockets[e->pipe_id].used) return 0;
    return &g_sockets[e->pipe_id];
}

static edge_socket_t *socket_from_fd(int fd) {
    edge_fd_proc_t *p = fd_proc_with_stdio();
    return socket_from_fd_entry(fd_get(p, fd));
}

static int ifreq_get_name(char *name_out, uint64_t arg_u, struct edge_linux_ifreq *ifr) {
    if (!arg_u || !name_out || !ifr) return -1;
    if (copy_from_user(ifr, arg_u, sizeof(*ifr)) < 0) return -1;
    memcpy(name_out, ifr->ifr_name, 16);
    name_out[15] = 0;
    return 0;
}

static int net_ioctl_copy_from_user(void *context,
                                    void *kernel_destination,
                                    uint64_t user_source, uint64_t size) {
    (void)context;
    return copy_from_user(kernel_destination, user_source, size);
}

static int net_ioctl_copy_to_user(void *context, uint64_t user_destination,
                                  const void *kernel_source, uint64_t size) {
    (void)context;
    return copy_to_user(user_destination, kernel_source, size);
}

static void net_ioctl_trace_missing_if(uint32_t cmd, const char *ifname,
                                       const struct edge_linux_ifreq *ifr) {
    static int budget = 32;
    task_t *cur;
    if (budget-- <= 0) return;
    cur = process_current_task();
    printf("[net-ifioctl] pid=%d task=%s cmd=0x%x missing-if name='%s' "
           "lo='%s' eth0='%s' raw=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
           cur ? cur->pid : -1,
           cur && cur->name[0] ? cur->name : "?",
           cmd, ifname ? ifname : "?",
           g_if_lo.name, g_if_eth0.name,
           (unsigned char)ifr->ifr_name[0], (unsigned char)ifr->ifr_name[1],
           (unsigned char)ifr->ifr_name[2], (unsigned char)ifr->ifr_name[3],
           (unsigned char)ifr->ifr_name[4], (unsigned char)ifr->ifr_name[5],
           (unsigned char)ifr->ifr_name[6], (unsigned char)ifr->ifr_name[7],
           (unsigned char)ifr->ifr_name[8], (unsigned char)ifr->ifr_name[9],
           (unsigned char)ifr->ifr_name[10], (unsigned char)ifr->ifr_name[11],
           (unsigned char)ifr->ifr_name[12], (unsigned char)ifr->ifr_name[13],
           (unsigned char)ifr->ifr_name[14], (unsigned char)ifr->ifr_name[15]);
}

static uint32_t net_ioctl_prefix_to_mask(uint8_t prefix_length) {
    uint8_t bytes[4] = {0};

    for (uint32_t bit = 0; bit < prefix_length && bit < 32u; ++bit)
        bytes[bit / 8u] |= (uint8_t)(1u << (7u - (bit % 8u)));
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8u) |
           ((uint32_t)bytes[2] << 16u) |
           ((uint32_t)bytes[3] << 24u);
}

static int net_ioctl_mask_to_prefix(uint32_t mask, uint8_t *prefix_length) {
    const uint8_t *bytes = (const uint8_t *)&mask;
    uint8_t prefix = 0u;
    int saw_zero = 0;

    if (!prefix_length) return -EINVAL;
    for (uint32_t bit = 0; bit < 32u; ++bit) {
        int set = (bytes[bit / 8u] &
                   (uint8_t)(1u << (7u - (bit % 8u)))) != 0;

        if (set && saw_zero) return -EINVAL;
        if (set) ++prefix;
        else saw_zero = 1;
    }
    *prefix_length = prefix;
    return 0;
}

static uint64_t net_ioctl_socket(uint32_t cmd, uint64_t arg_u) {
    struct edge_linux_ifreq ifr;
    char ifname[16];
    edge_netif_t *nif = 0;
    edge_linux_network_interface_snapshot_t dynamic_interface;
    uint32_t network_namespace = process_current_task() ?
        process_current_task()->namespaces.net : 0u;
    int dynamic = 0;

    if (cmd == LINUX_SIOCADDRT || cmd == LINUX_SIOCDELRT) {
        struct edge_linux_rtentry rt;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&rt, arg_u, sizeof(rt)) < 0) return (uint64_t)-EFAULT;
        if (cmd == LINUX_SIOCDELRT) {
            g_if_eth0.ipv4_dst_be = 0;
            netif_apply_ipv4_to_lwip(&g_if_eth0);
            return 0;
        }
        if (rt.rt_gateway.sa_family == LINUX_AF_INET) {
            memcpy(&g_if_eth0.ipv4_dst_be, &rt.rt_gateway.sa_data[2], sizeof(uint32_t));
            netif_apply_ipv4_to_lwip(&g_if_eth0);
        }
        return 0;
    }

    if (cmd == LINUX_SIOCGIFCONF) {
        struct edge_linux_ifconf ifc;
        struct edge_linux_ifreq entry;
        uint32_t interface_count = 0u;
        uint32_t want = 0u;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&ifc, arg_u, sizeof(ifc)) < 0) return (uint64_t)-EFAULT;
        while (interface_count < 66u) {
            edge_linux_network_interface_snapshot_t snapshot;
            uint32_t ipv4_address;
            const char *name;

            if (interface_count == 0u) {
                name = g_if_lo.name;
                ipv4_address = g_if_lo.ipv4_addr_be;
            } else if (interface_count == 1u) {
                name = g_if_eth0.name;
                ipv4_address = g_if_eth0.ipv4_addr_be;
            } else {
                if (edge_linux_network_interface_at(
                        network_namespace, interface_count - 2u,
                        &snapshot) < 0)
                    break;
                name = snapshot.name;
                ipv4_address = snapshot.ipv4_address;
            }
            memset(&entry, 0, sizeof(entry));
            strncpy(entry.ifr_name, name, sizeof(entry.ifr_name) - 1u);
            entry.ifr_ifru.ifru_addr.sa_family = LINUX_AF_INET;
            memcpy(&entry.ifr_ifru.ifru_addr.sa_data[2],
                   &ipv4_address, sizeof(uint32_t));
            if (ifc.ifc_buf && ifc.ifc_len >= 0 &&
                want + sizeof(entry) <= (uint32_t)ifc.ifc_len &&
                copy_to_user(ifc.ifc_buf + want,
                             &entry, sizeof(entry)) < 0)
                return (uint64_t)-EFAULT;
            want += (uint32_t)sizeof(entry);
            ++interface_count;
        }
        ifc.ifc_len = (int32_t)want;
        if (copy_to_user(arg_u, &ifc, sizeof(ifc)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }

    if (cmd == LINUX_SIOCGIFNAME) {
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&ifr, arg_u, sizeof(ifr)) < 0)
            return (uint64_t)-EFAULT;
        nif = netif_by_index(ifr.ifr_ifru.ifru_ifindex);
        if (!nif) {
            if (edge_linux_network_interface_by_index(
                    network_namespace, ifr.ifr_ifru.ifru_ifindex,
                    &dynamic_interface) < 0)
                return (uint64_t)-ENODEV;
            memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
            memcpy(ifr.ifr_name, dynamic_interface.name,
                   sizeof(ifr.ifr_name));
            if (copy_to_user(arg_u, &ifr, sizeof(ifr)) < 0)
                return (uint64_t)-EFAULT;
            return 0;
        }
        memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
        strncpy(ifr.ifr_name, nif->name, sizeof(ifr.ifr_name) - 1u);
        if (copy_to_user(arg_u, &ifr, sizeof(ifr)) < 0)
            return (uint64_t)-EFAULT;
        return 0;
    }

    if (ifreq_get_name(ifname, arg_u, &ifr) < 0) return (uint64_t)-EFAULT;
    nif = netif_by_name(ifname);
    if (!nif) {
        if (edge_linux_network_interface_by_name(
                network_namespace, ifname, &dynamic_interface) < 0) {
            net_ioctl_trace_missing_if(cmd, ifname, &ifr);
            return (uint64_t)-ENODEV;
        }
        dynamic = 1;
    }

    if (dynamic) {
        int result = 0;

        if (cmd == EDGE_LINUX_SIOCETHTOOL) {
            struct edge_linux_netdev_info device;

            memset(&device, 0, sizeof(device));
            device.driver = "edgeos_virtual";
            device.driver_version = "EdgeOS 0.1";
            device.bus_info = "virtual";
            device.link_up = dynamic_interface.carrier;
            device.speed_mbps = EDGE_LINUX_SPEED_UNKNOWN;
            device.duplex = EDGE_LINUX_DUPLEX_UNKNOWN;
            device.port = EDGE_LINUX_PORT_OTHER;
            device.phy_address = 0xffu;
            result = edge_linux_ethtool_ioctl(
                ifr.ifr_ifru.ifru_data, &device,
                net_ioctl_copy_from_user, net_ioctl_copy_to_user, 0);
            return (uint64_t)(int64_t)result;
        }

        switch (cmd) {
            case LINUX_SIOCGIFINDEX:
                ifr.ifr_ifru.ifru_ifindex = dynamic_interface.ifindex;
                break;
            case LINUX_SIOCGIFFLAGS:
                ifr.ifr_ifru.ifru_flags =
                    (int16_t)dynamic_interface.flags;
                break;
            case LINUX_SIOCSIFFLAGS:
                result = edge_linux_network_interface_configure(
                    network_namespace, dynamic_interface.ifindex,
                    (uint16_t)ifr.ifr_ifru.ifru_flags, 0xffffu,
                    0u, 0, 0u, 0);
                break;
            case LINUX_SIOCGIFMTU:
                ifr.ifr_ifru.ifru_mtu = (int32_t)dynamic_interface.mtu;
                break;
            case LINUX_SIOCSIFMTU:
                if (ifr.ifr_ifru.ifru_mtu < 0) return (uint64_t)-EINVAL;
                result = edge_linux_network_interface_configure(
                    network_namespace, dynamic_interface.ifindex,
                    0u, 0u, (uint32_t)ifr.ifr_ifru.ifru_mtu, 1,
                    0u, 0);
                break;
            case LINUX_SIOCGIFMETRIC:
                ifr.ifr_ifru.ifru_ivalue = 0;
                break;
            case LINUX_SIOCGIFTXQLEN:
                ifr.ifr_ifru.ifru_qlen =
                    (int32_t)dynamic_interface.tx_queue_length;
                break;
            case LINUX_SIOCSIFTXQLEN:
                if (ifr.ifr_ifru.ifru_qlen < 0) return (uint64_t)-EINVAL;
                result = edge_linux_network_interface_configure(
                    network_namespace, dynamic_interface.ifindex,
                    0u, 0u, 0u, 0,
                    (uint32_t)ifr.ifr_ifru.ifru_qlen, 1);
                break;
            case LINUX_SIOCGIFHWADDR:
                memset(&ifr.ifr_ifru.ifru_hwaddr, 0,
                       sizeof(ifr.ifr_ifru.ifru_hwaddr));
                ifr.ifr_ifru.ifru_hwaddr.sa_family =
                    dynamic_interface.hardware_type;
                memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data,
                       dynamic_interface.hardware_address, 6u);
                break;
            case LINUX_SIOCGIFADDR:
            case LINUX_SIOCGIFNETMASK:
            case LINUX_SIOCGIFBRDADDR:
            case LINUX_SIOCGIFDSTADDR: {
                uint32_t value = dynamic_interface.ipv4_address;
                struct edge_sockaddr *address = &ifr.ifr_ifru.ifru_addr;

                if (cmd == LINUX_SIOCGIFNETMASK)
                    value = net_ioctl_prefix_to_mask(
                        dynamic_interface.ipv4_prefix_length);
                else if (cmd == LINUX_SIOCGIFBRDADDR)
                    value |= ~net_ioctl_prefix_to_mask(
                        dynamic_interface.ipv4_prefix_length);
                else if (cmd == LINUX_SIOCGIFDSTADDR)
                    value = dynamic_interface.ipv4_gateway;
                memset(address, 0, sizeof(*address));
                address->sa_family = LINUX_AF_INET;
                memcpy(&address->sa_data[2], &value, sizeof(value));
                break;
            }
            case LINUX_SIOCSIFADDR:
            case LINUX_SIOCSIFNETMASK:
            case LINUX_SIOCSIFDSTADDR: {
                uint32_t address = dynamic_interface.ipv4_address;
                uint32_t gateway = dynamic_interface.ipv4_gateway;
                uint8_t prefix = dynamic_interface.ipv4_prefix_length;
                uint32_t value;

                memcpy(&value, &ifr.ifr_ifru.ifru_addr.sa_data[2],
                       sizeof(value));
                if (cmd == LINUX_SIOCSIFADDR) address = value;
                else if (cmd == LINUX_SIOCSIFDSTADDR) gateway = value;
                else if (net_ioctl_mask_to_prefix(value, &prefix) < 0)
                    return (uint64_t)-EINVAL;
                result = edge_linux_network_interface_configure_ipv4(
                    network_namespace, dynamic_interface.ifindex,
                    address, prefix, gateway);
                break;
            }
            case LINUX_SIOCSIFBRDADDR:
                break;
            default:
                return (uint64_t)-ENOTTY;
        }
        if (result < 0) return (uint64_t)(int64_t)result;
        if (cmd == LINUX_SIOCSIFFLAGS || cmd == LINUX_SIOCSIFMTU ||
            cmd == LINUX_SIOCSIFTXQLEN || cmd == LINUX_SIOCSIFADDR ||
            cmd == LINUX_SIOCSIFNETMASK || cmd == LINUX_SIOCSIFDSTADDR ||
            cmd == LINUX_SIOCSIFBRDADDR)
            return 0;
        if (copy_to_user(arg_u, &ifr, sizeof(ifr)) < 0)
            return (uint64_t)-EFAULT;
        return 0;
    }

    if (cmd == EDGE_LINUX_SIOCETHTOOL) {
        struct edge_linux_netdev_info device;
        int loopback = strcmp(nif->name, "lo") == 0;
        int result;

        memset(&device, 0, sizeof(device));
        device.driver = loopback ? "loopback" : "edgeos_net";
        device.driver_version = "EdgeOS 0.1";
        device.bus_info = loopback ? "virtual" : "platform";
        device.link_up = loopback ? 1u : (nif->up ? 1u : 0u);
        device.speed_mbps = EDGE_LINUX_SPEED_UNKNOWN;
        device.duplex = EDGE_LINUX_DUPLEX_UNKNOWN;
        device.port = EDGE_LINUX_PORT_OTHER;
        device.phy_address = 0xffu;
        result = edge_linux_ethtool_ioctl(
            ifr.ifr_ifru.ifru_data, &device,
            net_ioctl_copy_from_user, net_ioctl_copy_to_user, 0);
        return (uint64_t)(int64_t)result;
    }

    switch (cmd) {
        case LINUX_SIOCGIFINDEX:
            ifr.ifr_ifru.ifru_ifindex = nif->ifindex;
            break;
        case LINUX_SIOCGIFFLAGS:
            ifr.ifr_ifru.ifru_flags = (int32_t)nif->flags;
            break;
        case LINUX_SIOCSIFFLAGS:
            nif->flags = (uint32_t)ifr.ifr_ifru.ifru_flags;
            nif->up = (nif->flags & LINUX_IFF_UP) != 0;
            break;
        case LINUX_SIOCGIFMTU:
            ifr.ifr_ifru.ifru_mtu = (int32_t)nif->mtu;
            break;
        case LINUX_SIOCSIFMTU:
            if (ifr.ifr_ifru.ifru_mtu > 0) nif->mtu = (uint32_t)ifr.ifr_ifru.ifru_mtu;
            break;
        case LINUX_SIOCGIFMETRIC:
            ifr.ifr_ifru.ifru_ivalue = 0;
            break;
        case LINUX_SIOCGIFTXQLEN:
            ifr.ifr_ifru.ifru_qlen = 1000;
            break;
        case LINUX_SIOCSIFTXQLEN:
            break;
        case LINUX_SIOCGIFHWADDR:
            memset(&ifr.ifr_ifru.ifru_hwaddr, 0, sizeof(ifr.ifr_ifru.ifru_hwaddr));
            ifr.ifr_ifru.ifru_hwaddr.sa_family = (strcmp(nif->name, "lo") == 0)
                ? LINUX_ARPHRD_LOOPBACK : LINUX_ARPHRD_ETHER;
            memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data, nif->mac, 6);
            break;
        case LINUX_SIOCGIFADDR:
            memset(&ifr.ifr_ifru.ifru_addr, 0, sizeof(ifr.ifr_ifru.ifru_addr));
            ifr.ifr_ifru.ifru_addr.sa_family = LINUX_AF_INET;
            memcpy(&ifr.ifr_ifru.ifru_addr.sa_data[2], &nif->ipv4_addr_be, sizeof(uint32_t));
            break;
        case LINUX_SIOCSIFADDR:
            memcpy(&nif->ipv4_addr_be, &ifr.ifr_ifru.ifru_addr.sa_data[2], sizeof(uint32_t));
            netif_apply_ipv4_to_lwip(nif);
            break;
        case LINUX_SIOCGIFNETMASK:
            memset(&ifr.ifr_ifru.ifru_netmask, 0, sizeof(ifr.ifr_ifru.ifru_netmask));
            ifr.ifr_ifru.ifru_netmask.sa_family = LINUX_AF_INET;
            memcpy(&ifr.ifr_ifru.ifru_netmask.sa_data[2], &nif->ipv4_netmask_be, sizeof(uint32_t));
            break;
        case LINUX_SIOCSIFNETMASK:
            memcpy(&nif->ipv4_netmask_be, &ifr.ifr_ifru.ifru_netmask.sa_data[2], sizeof(uint32_t));
            netif_apply_ipv4_to_lwip(nif);
            break;
        case LINUX_SIOCGIFBRDADDR:
            memset(&ifr.ifr_ifru.ifru_broadaddr, 0, sizeof(ifr.ifr_ifru.ifru_broadaddr));
            ifr.ifr_ifru.ifru_broadaddr.sa_family = LINUX_AF_INET;
            memcpy(&ifr.ifr_ifru.ifru_broadaddr.sa_data[2], &nif->ipv4_bcast_be, sizeof(uint32_t));
            break;
        case LINUX_SIOCSIFBRDADDR:
            memcpy(&nif->ipv4_bcast_be, &ifr.ifr_ifru.ifru_broadaddr.sa_data[2], sizeof(uint32_t));
            netif_apply_ipv4_to_lwip(nif);
            break;
        case LINUX_SIOCGIFDSTADDR:
            memset(&ifr.ifr_ifru.ifru_dstaddr, 0, sizeof(ifr.ifr_ifru.ifru_dstaddr));
            ifr.ifr_ifru.ifru_dstaddr.sa_family = LINUX_AF_INET;
            memcpy(&ifr.ifr_ifru.ifru_dstaddr.sa_data[2], &nif->ipv4_dst_be, sizeof(uint32_t));
            break;
        case LINUX_SIOCSIFDSTADDR:
            memcpy(&nif->ipv4_dst_be, &ifr.ifr_ifru.ifru_dstaddr.sa_data[2], sizeof(uint32_t));
            netif_apply_ipv4_to_lwip(nif);
            break;
        default:
            return (uint64_t)-ENOTTY;
    }

    if (copy_to_user(arg_u, &ifr, sizeof(ifr)) < 0) return (uint64_t)-EFAULT;
    return 0;
}
