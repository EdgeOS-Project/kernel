static void x86_file_cache_cachestat(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length,
    kernel_vfs_cache_stats_t *statistics);

int process_clone_arch_validate_cgroup(uint64_t descriptor) {
    edge_fd_t *entry;

    if (descriptor > 0x7fffffffu) return -EBADF;
    entry = fd_get(fd_proc_with_stdio(), (int)descriptor);
    if (!entry || entry->kind != FD_VFS ||
        !cgroupfs_directory_valid(entry->sb, &entry->inode))
        return -EBADF;
    return 0;
}

int process_clone_arch_prepare(const kernel_clone_prepare_t *prepare,
                               kernel_clone_state_t *state) {
    task_t *current = process_current_task();
    task_t *child;
    int child_pid;

    if (!prepare || !prepare->user_registers || !state || !current)
        return -EINVAL;
    if (prepare->is_thread) {
        child_pid = process_clone_thread(
            (const edge_trap_frame_t *)prepare->user_registers);
    } else if (prepare->share_vm && prepare->vfork) {
        child_pid = process_vfork_shared_vm(
            (const edge_trap_frame_t *)prepare->user_registers,
            prepare->namespace_flags);
    } else if (prepare->share_vm) {
        child_pid = process_fork_shared_vm(
            (const edge_trap_frame_t *)prepare->user_registers,
            prepare->namespace_flags);
    } else {
        child_pid = process_fork(
            (const edge_trap_frame_t *)prepare->user_registers,
            prepare->namespace_flags);
    }
    if (child_pid < 0) return -EAGAIN;
    child = task_by_pid_mutable_local(child_pid);
    if (!child) return -EIO;

    state->child_global_pid = child_pid;
    state->parent_address_space = current->cr3;
    state->child_address_space = child->cr3;
    state->architecture_state[0] = prepare->share_vm ? 1u : 0u;
    state->prepared = 1;
    if (edge_pid_namespace_global_to_visible(
            current->namespaces.pid, child_pid,
            &state->parent_visible_pid) < 0 ||
        edge_pid_namespace_global_to_visible(
            child->namespaces.pid, child_pid,
            &state->child_visible_pid) < 0)
        return -EAGAIN;
    return 0;
}

int process_clone_arch_configure(
    const kernel_clone_configuration_t *configuration,
    kernel_clone_state_t *state) {
    task_t *current = process_current_task();
    task_t *child;

    if (!configuration || !state || !current) return -EINVAL;
    child = task_by_pid_mutable_local(state->child_global_pid);
    if (!child) return -ESRCH;

    if (configuration->parent == KERNEL_CLONE_PARENT_INHERIT &&
        process_clone_set_parent(child->pid, current->ppid) < 0)
        return -EFAULT;
    if (configuration->signal_handlers ==
            KERNEL_CLONE_SIGNAL_HANDLERS_SHARE &&
        process_clone_share_signal_handlers(child->pid) < 0)
        return -EFAULT;
    if (configuration->signal_handlers ==
            KERNEL_CLONE_SIGNAL_HANDLERS_CLEAR &&
        process_clone_clear_signal_handlers(child->pid) < 0)
        return -EFAULT;

    child->exit_signal = (uint8_t)configuration->exit_signal;
    if (configuration->share_fs)
        child->fs_context_id = current->fs_context_id;
    if (configuration->disable_altstack) {
        child->sigaltstack_sp = 0;
        child->sigaltstack_size = 0;
        child->sigaltstack_flags = EDGE_LINUX_SS_DISABLE;
    } else {
        child->sigaltstack_sp = current->sigaltstack_sp;
        child->sigaltstack_size = current->sigaltstack_size;
        child->sigaltstack_flags = current->sigaltstack_flags;
    }
    if (configuration->child_stack &&
        process_set_fork_frame_rsp(
            child->pid, configuration->child_stack) < 0)
        return -EFAULT;
    if (configuration->set_tls)
        child->fs_base = configuration->tls;
    child->linux_thread.clear_child_tid =
        configuration->clear_child_tid;

    if (configuration->share_files) {
        if (process_set_fd_owner(
                child->pid, fd_owner_pid_current()) < 0)
            return -EFAULT;
    } else {
        if (fd_clone_after_fork(
                fd_owner_pid_current(), child->pid) < 0)
            return -ENOMEM;
        if (process_set_fd_owner(child->pid, child->pid) < 0)
            return -EFAULT;
    }
    return 0;
}

int process_clone_arch_attach_cgroup(uint64_t descriptor,
                                     kernel_clone_state_t *state) {
    edge_fd_t *entry;
    int status;

    if (!state || descriptor > 0x7fffffffu) return -EBADF;
    entry = fd_get(fd_proc_with_stdio(), (int)descriptor);
    if (!entry || entry->kind != FD_VFS ||
        !cgroupfs_directory_valid(entry->sb, &entry->inode))
        return -EBADF;
    status = cgroupfs_attach_process(
        entry->sb, &entry->inode, state->child_global_pid);
    if (status == 0 &&
        process_cgroup_account_rebuilt(state->child_global_pid) < 0)
        return -ESRCH;
    if (status == 0) state->cgroup_accounted = 1;
    return status;
}

int process_clone_arch_install_pidfd(uint64_t user_destination,
                                     kernel_clone_state_t *state) {
    int pidfd;

    if (!state) return -EINVAL;
    pidfd = alloc_special_fd(
        FD_PIDFD, state->child_global_pid, LINUX_O_CLOEXEC);
    if (pidfd < 0) return pidfd;
    state->pidfd = pidfd;
    if (copy_to_user(user_destination, &pidfd, sizeof(pidfd)) < 0)
        return -EFAULT;
    return 0;
}

int process_clone_arch_write_parent_tid(uint64_t user_destination,
                                        kernel_clone_state_t *state) {
    if (!state) return -EINVAL;
    return copy_to_user(
        user_destination, &state->parent_visible_pid,
        sizeof(state->parent_visible_pid));
}

int process_clone_arch_write_child_tid(uint64_t user_destination,
                                       kernel_clone_state_t *state) {
    if (!state) return -EINVAL;
    if (state->architecture_state[0])
        return copy_to_user(
            user_destination, &state->child_visible_pid,
            sizeof(state->child_visible_pid));
    return process_write_user_memory(
        state->child_global_pid, user_destination,
        &state->child_visible_pid, sizeof(state->child_visible_pid));
}

int process_clone_arch_prepare_vfork(kernel_clone_state_t *state) {
    task_t *current = process_current_task();
    task_t *child;

    if (!state || !current) return -EINVAL;
    child = task_by_pid_mutable_local(state->child_global_pid);
    if (!child) return -ESRCH;
    current->vfork_child_pid = child->pid;
    child->vfork_parent_pid = current->pid;
    return 0;
}

int process_clone_arch_publish(kernel_clone_state_t *state,
                               int ptrace_event) {
    if (!state) return -EINVAL;
    if (process_cgroup_account_publish(state->child_global_pid) < 0)
        return -ESRCH;
    if (!ptrace_event)
        wake_new_child_and_yield(state->child_global_pid);
    return 0;
}

int process_clone_arch_wait_vfork(kernel_clone_state_t *state) {
    task_t *current = process_current_task();

    if (!state || !current) return -EINVAL;
    while (current->vfork_child_pid == state->child_global_pid) {
        /*
         * Publish the blocked state before the final completion check.  The
         * vfork child may exec or exit between the loop condition and the
         * schedule operation.  In that window its wakeup observes the parent
         * as running, so blocking without a recheck would lose the only vfork
         * completion event and leave Go's fork-and-exec path asleep forever.
         */
        scheduler_task_set_blocked(current);
        if (current->vfork_child_pid != state->child_global_pid) {
            scheduler_task_make_runnable(current, scheduler_cpu_id());
            break;
        }
        scheduler_yield();
    }
    return 0;
}

void process_clone_arch_abort(kernel_clone_state_t *state) {
    task_t *current;
    task_t *child;

    if (!state || !state->prepared || state->published) return;
    current = process_current_task();
    child = task_by_pid_mutable_local(state->child_global_pid);
    if (state->pidfd >= 0) {
        (void)do_sys_close((uint64_t)(uint32_t)state->pidfd);
        state->pidfd = -1;
    }
    if (state->vfork_prepared && current && child) {
        if (current->vfork_child_pid == child->pid)
            current->vfork_child_pid = 0;
        if (child->vfork_parent_pid == current->pid)
            child->vfork_parent_pid = 0;
    }
    fd_proc_release(state->child_global_pid);
    (void)process_abort_clone(state->child_global_pid);
    state->prepared = 0;
}

static int x86_rseq_copy_from_user(void *context, void *kernel_destination,
                                   uint64_t user_source, uint64_t size) {
    (void)context;
    return copy_from_user(kernel_destination, user_source, size);
}

static int x86_rseq_copy_to_user(void *context, uint64_t user_destination,
                                 const void *kernel_source, uint64_t size) {
    (void)context;
    return copy_to_user(user_destination, kernel_source, size);
}

int edge_process_runtime_current_rseq_binding(
    kernel_linux_rseq_binding_t *binding) {
    task_t *task = process_current_task();
    if (!task || task->is_idle || !binding) return -EINVAL;
    binding->thread_state = &task->linux_thread;
    binding->copy_from_user = x86_rseq_copy_from_user;
    binding->copy_to_user = x86_rseq_copy_to_user;
    binding->copy_context = task;
    binding->cpu_id = scheduler_cpu_id();
    binding->node_id = 0u;
    binding->mm_cid = 0u;
    return 0;
}

int kernel_arch_current_request_reschedule(void) {
    task_t *task = process_current_task();

    if (!task || task->is_idle) return -EINVAL;
    task->need_resched = 1;
    return 0;
}

int kernel_arch_current_rseq_slice_timer_arm(uint32_t microseconds) {
#ifdef CONFIG_APIC
    return apic_timer_arm_oneshot_us(microseconds);
#else
    (void)microseconds;
    return -ENOTSUP;
#endif
}

void kernel_arch_current_rseq_slice_timer_cancel(void) {
#ifdef CONFIG_APIC
    apic_timer_cancel_oneshot();
#endif
}

void syscall_rseq_prepare_user_return(uint64_t *instruction_pointer) {
    task_t *task = process_current_task();
    int result;
    if (!task || task->is_idle || !instruction_pointer) return;
    result = edge_linux_rseq_prepare_user_return(
        &task->linux_thread.rseq, instruction_pointer,
        scheduler_cpu_id(), 0u, 0u,
        x86_rseq_copy_from_user, x86_rseq_copy_to_user, task);
    if (result < 0) (void)process_send_signal(task->pid, LINUX_SIGSEGV);
}

int arch_vfs_current_context(kernel_vfs_current_context_t *context) {
    task_t *task = process_current_task();

    if (!task || !context) return -EDGE_LINUX_EIO;
    context->root = task->root;
    context->cwd = task->cwd;
    for (uint32_t index = 0; index < 4u; ++index)
        context->paths[index] = task->scratch->path_scratch[index];
    for (uint32_t index = 4u; index < 8u; ++index)
        context->paths[index] = task->scratch->path_scratch[index + 5u];
    context->path_capacity = sizeof(task->scratch->path_scratch[0]);
    context->xattr = task->scratch->xattr_scratch;
    context->xattr_capacity = sizeof(task->scratch->xattr_scratch);
    context->resolve_workspace = task->scratch->path_scratch[5];
    context->resolve_workspace_capacity =
        sizeof(task->scratch->path_scratch[0]) * 4u;
    return 0;
}

int arch_vfs_current_mount_namespace(uint32_t *namespace_id) {
    task_t *task = process_current_task();
    if (!task || !namespace_id) return -EDGE_LINUX_EINVAL;
    *namespace_id = task->namespaces.mount;
    return 0;
}

static void x86_vfs_rebase_mount_namespace_descriptors(
    uint32_t namespace_id, const char *new_root, const char *put_old) {
    char replacement[VFS_PATH_MAX];

    for (uint32_t process_index = 0;
         process_index < EDGE_MAX_FD_PROCS; ++process_index) {
        edge_fd_proc_t *process = g_fd_procs[process_index];
        uint64_t irq_flags;

        if (!process ||
            !process_fd_owner_uses_mount_namespace(
                process->pid, namespace_id))
            continue;
        irq_flags = kernel_fd_table_lock(&process->table_runtime);
        for (uint32_t descriptor = 0;
             descriptor < EDGE_MAX_FD; ++descriptor) {
            edge_fd_t *entry = &process->fds[descriptor];

            if (!kernel_fd_table_is_open_locked(
                    &process->table_runtime, descriptor) ||
                !entry->used || !entry->path[0])
                continue;
            if (kernel_vfs_rebase_pivot_path(
                    new_root, put_old, entry->path,
                    replacement, sizeof(replacement)) < 0)
                continue;
            strncpy(entry->path, replacement, sizeof(entry->path) - 1u);
            entry->path[sizeof(entry->path) - 1u] = 0;
        }
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    }
}

void arch_vfs_rebase_mount_namespace_paths(
    uint32_t namespace_id, const char *new_root, const char *put_old) {
    process_rebase_mount_namespace_paths(namespace_id, new_root, put_old);
    x86_vfs_rebase_mount_namespace_descriptors(
        namespace_id, new_root, put_old);
}

void arch_vfs_rebase_mount_move_paths(
    uint32_t namespace_id, const char *source, const char *target) {
    char replacement[VFS_PATH_MAX];

    process_rebase_mount_move_paths(namespace_id, source, target);
    for (uint32_t process_index = 0;
         process_index < EDGE_MAX_FD_PROCS; ++process_index) {
        edge_fd_proc_t *process = g_fd_procs[process_index];
        uint64_t irq_flags;

        if (!process || !process_fd_owner_uses_mount_namespace(
                process->pid, namespace_id))
            continue;
        irq_flags = kernel_fd_table_lock(&process->table_runtime);
        for (uint32_t descriptor = 0;
             descriptor < EDGE_MAX_FD; ++descriptor) {
            edge_fd_t *entry = &process->fds[descriptor];
            if (!kernel_fd_table_is_open_locked(
                    &process->table_runtime, descriptor) ||
                !entry->used || !entry->path[0])
                continue;
            if (kernel_vfs_rebase_move_path(
                    source, target, entry->path, replacement,
                    sizeof(replacement)) < 0)
                continue;
            strncpy(entry->path, replacement, sizeof(entry->path) - 1u);
            entry->path[sizeof(entry->path) - 1u] = 0;
        }
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    }
}

int arch_vfs_resolve_fd(int32_t descriptor, kernel_vfs_target_t *target) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry;
    if (!process) return -EDGE_LINUX_EBADF;
    entry = fd_get(process, descriptor);
    if (!entry) return -EDGE_LINUX_EBADF;
    if (entry->kind == FD_PTY_SLAVE && entry->pipe_id >= 0 &&
        entry->pipe_id < EDGE_MAX_PTYS && g_ptys[entry->pipe_id].used) {
        if (devpts_slave_refresh(
                &g_ptys[entry->pipe_id].slave_inode,
                &target->inode_storage, &target->superblock) < 0)
            return -EDGE_LINUX_EIO;
        target->inode = &target->inode_storage;
        target->resolved_path =
            g_ptys[entry->pipe_id].slave_inode.path;
        return 0;
    }
    if (entry->kind != FD_VFS || !entry->sb) {
        if (!fd_is_tty(entry) || !entry->path[0] ||
            vfs_resolve(entry->path, &target->inode_storage,
                        &target->superblock, 0, 0) < 0 ||
            !target->superblock)
            return -EDGE_LINUX_EOPNOTSUPP;
        target->inode = &target->inode_storage;
        target->resolved_path = entry->path;
        return 0;
    }
    (void)vfs_inode_refresh(entry->sb, &entry->inode);
    target->superblock = entry->sb;
    target->inode = &entry->inode;
    target->resolved_path = entry->path;
    target->linkable_zero_link_inode =
        entry->linkable_zero_link_inode ||
        (((entry->flags & LINUX_O_TMPFILE) == LINUX_O_TMPFILE) &&
         !(entry->flags & LINUX_O_EXCL));
    target->path_only = (entry->flags & LINUX_O_PATH) != 0;
    return 0;
}

int arch_vfs_install_inode_descriptor(vfs_superblock_t *superblock,
                                      const vfs_inode_t *inode,
                                      uint32_t status_flags,
                                      uint32_t descriptor_flags,
                                      int linkable_zero_link_inode) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry;
    int descriptor;

    if (!process) return -EDGE_LINUX_EINVAL;
    descriptor = fd_alloc(process, 0);
    if (descriptor < 0) return -EDGE_LINUX_EMFILE;
    entry = &process->fds[descriptor];
    entry->file_ref = file_ref_alloc(status_flags);
    if (!entry->file_ref) {
        fd_abort_reserved(process, descriptor);
        return -EDGE_LINUX_ENFILE;
    }
    entry->kind = FD_VFS;
    entry->flags = (int)status_flags;
    entry->fd_flags = (int)descriptor_flags;
    entry->linkable_zero_link_inode = linkable_zero_link_inode != 0;
    entry->inode = *inode;
    entry->pipe_id = -1;
    fd_description_set_offset(entry, 0);
    if (vfs_inode_open(superblock, inode) < 0) {
        (void)file_ref_put(entry->file_ref);
        fd_abort_reserved(process, descriptor);
        return -EDGE_LINUX_ENFILE;
    }
    entry->sb = vfs_superblock_stable(superblock);
    entry->mount_id = superblock->mount_id;
    if (fd_publish(process, descriptor) < 0) {
        vfs_inode_close(entry->sb, &entry->inode);
        (void)file_ref_put(entry->file_ref);
        fd_abort_reserved(process, descriptor);
        return -EDGE_LINUX_EBADF;
    }
    return descriptor;
}

int arch_vfs_reopen_fifo_descriptor(
    int32_t source, const kernel_vfs_open_request_t *request) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry;
    int pipe_id;

    if (!process || !request || source < 0 || source >= EDGE_MAX_FD)
        return -EDGE_LINUX_EBADF;
    entry = fd_get(process, source);
    if (!entry)
        return -EDGE_LINUX_EBADF;
    if (entry->kind == FD_VFS && entry->sb &&
        (entry->inode.mode & 0xf000u) == VFS_INODE_FIFO) {
        pipe_id = named_fifo_pipe_for_inode(
            entry->sb, &entry->inode, 1);
    } else if (entry->pipe_id >= 0 &&
               (entry->kind == FD_PIPE_R || entry->kind == FD_PIPE_W ||
                entry->kind == FD_PIPE_RW)) {
        pipe_id = entry->pipe_id;
    } else {
        return -EDGE_LINUX_ENXIO;
    }
    if (pipe_id < 0)
        return -EDGE_LINUX_ENFILE;
    return (int)open_fifo_pipe_fd(
        process, entry->path, (int)request->linux_flags, pipe_id);
}

void arch_vfs_notify_path(const char *path, uint32_t mask) {
    /*
     * unlink(2) removes a directory entry, not the opened file object.  Linux
     * keeps that object's page cache coherent for every descriptor and VMA
     * until their final reference is released.  Chromium relies on this by
     * mapping allocator files and unlinking their names immediately.  Dropping
     * cache entries here left already-faulted PTEs on the old backing page while
     * later faults allocated a second page for the same inode, splitting one
     * MAP_SHARED object into incoherent views.  File slots are inode keyed, so a
     * new file created with the old pathname already receives a distinct slot.
     */
    if (mask & EDGE_IN_DELETE)
        unix_binding_unregister_path(path);
    edge_inotify_notify_path(path, mask, 0);
}

void arch_vfs_notify_move(const char *old_path, const char *new_path) {
    edge_mmap_file_cache_rename_path(old_path, new_path);
    edge_inotify_notify_move(old_path, new_path);
}

int arch_procfd_link_view(int32_t pid, int32_t descriptor,
                          kernel_procfd_link_view_t *view) {
    uint64_t position = 0;
    uint32_t flags = 0;
    uint32_t inode = 0;
    int kind = -1;

    if (!view || !view->path || !view->path_capacity)
        return -EDGE_LINUX_EFAULT;
    view->path[0] = 0;
    if (edge_procfs_fd_debug_snapshot(
            pid, descriptor, &position, &flags, &inode, &kind,
            view->path, view->path_capacity) < 0)
        return -EDGE_LINUX_ENOENT;
    (void)position;
    (void)flags;
    if ((kind == FD_PTY_SLAVE || kind == FD_PTY_MASTER ||
         kind == FD_CONSOLE || kind == FD_VFS) && view->path[0]) {
        view->kind = KERNEL_PROCFD_LINK_PATH;
        view->path_length = (uint32_t)strlen(view->path);
    } else if (kind == FD_PIPE_R || kind == FD_PIPE_W ||
               kind == FD_PIPE_RW) {
        view->kind = KERNEL_PROCFD_LINK_PIPE;
        view->identity = inode;
    } else if (kind == FD_SOCKET) {
        view->kind = KERNEL_PROCFD_LINK_SOCKET;
        view->identity = inode;
    } else if (kind == FD_PIDFD) {
        view->kind = KERNEL_PROCFD_LINK_PIDFD;
    } else {
        view->kind = KERNEL_PROCFD_LINK_ANONYMOUS;
    }
    return 0;
}

int arch_vfs_readlink_path(const char *path, char *target,
                           uint32_t capacity) {
    int length;
    vfs_inode_t inode;

    length = vfs_readlink(path, target, capacity);
    if (length >= 0) return length;
    /*
     * Legacy x86 root filesystems encoded early symlinks as small regular
     * files. Keep that storage compatibility behind the architecture hook;
     * native VFS symlinks above use Linux readlink truncation directly.
     */
    length = edge_read_symlink_target(path, target, (int)capacity);
    if (length >= 0) return length;
    if (vfs_resolve(path, &inode, 0, 0, 0) == 0)
        return -EDGE_LINUX_EINVAL;
    return -EDGE_LINUX_ENOENT;
}

static void linux_stat_to_file_metadata(
    const edge_x86_64_linux_stat_t *source, vfs_superblock_t *superblock,
    kernel_file_metadata_t *metadata) {
    if (!source || !metadata) return;
    kernel_file_metadata_initialize(
        metadata, (uint16_t)source->st_mode,
        source->st_size > 0 ? (uint64_t)source->st_size : 0u);
    metadata->device = superblock ?
        kernel_file_device_encode(
            0u, superblock->mount_id ?
                (uint32_t)superblock->mount_id : 1u) :
        source->st_dev;
    metadata->inode = source->st_ino;
    metadata->rdev = source->st_rdev;
    metadata->blocks = source->st_blocks > 0 ?
                       (uint64_t)source->st_blocks : 0u;
    metadata->links = source->st_nlink > UINT32_MAX ?
                      UINT32_MAX : (uint32_t)source->st_nlink;
    metadata->uid = source->st_uid;
    metadata->gid = source->st_gid;
    metadata->block_size = source->st_blksize > 0 ?
                           (uint32_t)source->st_blksize : 4096u;
    metadata->access_time.seconds = source->st_atim.tv_sec;
    metadata->access_time.nanoseconds = (uint32_t)source->st_atim.tv_nsec;
    metadata->modification_time.seconds = source->st_mtim.tv_sec;
    metadata->modification_time.nanoseconds =
        (uint32_t)source->st_mtim.tv_nsec;
    metadata->change_time.seconds = source->st_ctim.tv_sec;
    metadata->change_time.nanoseconds = (uint32_t)source->st_ctim.tv_nsec;
    if (superblock && superblock->mount_id) {
        metadata->mount_id = superblock->mount_id;
        metadata->result_mask |= KERNEL_FILE_METADATA_MOUNT_ID;
    }
}

int arch_vfs_metadata_path_prepare(const char *path, int nofollow,
                                   char *output, uint32_t capacity) {
    uint32_t length;

    if (!path || !output || !capacity) return -EDGE_LINUX_EFAULT;
    /*
     * The shared VFS resolver owns component and final-link traversal for
     * stat, while vfs_resolve_nofollow owns lstat.  Re-running the legacy x86
     * component walker here duplicated traversal and could recursively enter
     * the serialized VFS workspace while another task was being rescheduled.
     */
    (void)nofollow;
    length = (uint32_t)strlen(path);
    if (length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
    memmove(output, path, length + 1u);
    return 0;
}

int arch_vfs_special_path_metadata(
    const char *path, vfs_superblock_t *superblock,
    const vfs_inode_t *inode, kernel_file_metadata_t *metadata,
    int *handled) {
    edge_x86_64_linux_stat_t result;

    if (!path || !metadata || !handled) return -EDGE_LINUX_EFAULT;
    *handled = 0;
    if (inode) {
        fill_kstat(inode, &result);
        result.st_dev = kernel_file_device_encode(
            0u, superblock && superblock->mount_id ?
                (uint32_t)superblock->mount_id : 1u);
    } else {
        memset(&result, 0, sizeof(result));
        result.st_mode = 0666;
    }
    if (!linux_special_dev_stat_from_path(path, &result)) return 0;
    linux_stat_to_file_metadata(&result, superblock, metadata);
    *handled = 1;
    return 0;
}

int arch_vfs_metadata_fd(int32_t descriptor,
                         kernel_file_metadata_t *metadata) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry;
    kernel_vfs_descriptor_t description;
    edge_x86_64_linux_stat_t result;
    vfs_inode_t path_inode;
    vfs_superblock_t *metadata_superblock;
    int status;
    if (!process) return -EDGE_LINUX_EBADF;
    entry = fd_get(process, descriptor);
    if (!entry) return -EDGE_LINUX_EBADF;
    status = kernel_vfs_describe_descriptor(descriptor, &description);
    if (status < 0) return status;
    status = kernel_file_metadata_from_descriptor(&description, metadata);
    if (status <= 0) return status;
    status = linux_fd_fill_kstat(entry, descriptor, &result);
    if (status < 0) return status;
    metadata_superblock = entry->sb;
    /*
     * Console and PTY descriptors are backed by real devtmpfs/devpts nodes,
     * but their runtime descriptor kind does not retain a VFS superblock.
     * Linux requires stat(path) and fstat(open(path)) to identify the same
     * device; glibc ttyname(3) relies on that identity before returning a
     * pathname.  Recover the pathname's mount identity for these descriptors
     * instead of exposing the synthetic fallback st_dev from fill_kstat().
     */
    if (!metadata_superblock && entry->path[0] == '/' &&
        vfs_resolve(entry->path, &path_inode, &metadata_superblock,
                    0, 0) < 0)
        metadata_superblock = 0;
    linux_stat_to_file_metadata(&result, metadata_superblock, metadata);
    kernel_file_metadata_set_mount_id(
        metadata,
        description.mount_id ? description.mount_id :
        metadata_superblock ? metadata_superblock->mount_id : 0u);
    return 0;
}

int arch_vfs_sync_descriptor(int32_t descriptor,
                             kernel_vfs_sync_operation_t operation) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry = fd_get(process, descriptor);
    if (!entry) return -EDGE_LINUX_EBADF;
    if (operation == KERNEL_VFS_SYNC_FILESYSTEM) {
        if (entry->kind == FD_VFS && entry->sb &&
            edge_mmap_file_cache_sync_superblock(entry->sb) < 0)
            return -EDGE_LINUX_EIO;
        return 0;
    }
    if (entry->kind == FD_MEMFD)
        return memfd_entry_is_secret(entry) ?
            -EDGE_LINUX_EINVAL : 0;
    if (entry->kind != FD_VFS)
        return operation == KERNEL_VFS_SYNC_RANGE ?
            -EDGE_LINUX_ESPIPE : -EDGE_LINUX_EINVAL;
    if (operation == KERNEL_VFS_SYNC_FILE ||
        operation == KERNEL_VFS_SYNC_DATA) {
        if (edge_mmap_file_cache_sync_inode(
                entry->sb, &entry->inode, 0) < 0)
            return -EDGE_LINUX_EIO;
        return fd_sync_inode(
            entry, operation == KERNEL_VFS_SYNC_DATA) < 0 ?
            -EDGE_LINUX_EIO : 0;
    }
    if (operation == KERNEL_VFS_SYNC_RANGE) {
        if (edge_mmap_file_cache_sync_inode(
                entry->sb, &entry->inode, 1) < 0)
            return -EDGE_LINUX_EIO;
        entry->dirty = 0;
        return 0;
    }
    return -EDGE_LINUX_EINVAL;
}

int arch_vfs_describe_descriptor(int32_t descriptor,
                                 kernel_vfs_descriptor_t *description) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    task_t *task = process_current_task();
    edge_fd_t *entry;
    uint16_t inode_kind;

    if (!task || !process) return -EDGE_LINUX_EBADF;
    entry = fd_get(process, descriptor);
    if (!entry) return -EDGE_LINUX_EBADF;

    description->identity = entry->file_ref > 0 ?
        file_ref_identity(entry->file_ref) : 0;
    if (!description->identity)
        description->identity = (uint64_t)(uint32_t)descriptor;
    description->scratch = task->scratch->xattr_scratch;
    description->scratch_capacity = sizeof(task->scratch->xattr_scratch);
    description->path = entry->path[0] ? entry->path : 0;
    description->landlock_access = entry->landlock_access;
    description->readable = 1;
    description->writable = 1;
    description->mount_id = entry->mount_id;

    if (entry->kind == FD_VFS) {
        description->readable = !(entry->flags & LINUX_O_PATH) &&
            (entry->flags & LINUX_O_ACCMODE) != LINUX_O_WRONLY;
        description->writable = !(entry->flags & LINUX_O_PATH) &&
            (entry->flags & LINUX_O_ACCMODE) != LINUX_O_RDONLY;
        description->superblock = entry->sb;
        description->inode = &entry->inode;
        description->size = entry->inode.size;
        description->maximum_size = UINT32_MAX;
        if (path_is_tty_device(entry->path)) {
            description->kind = KERNEL_VFS_DESCRIPTOR_TERMINAL;
            return 0;
        }
        inode_kind = entry->inode.mode & 0xF000u;
        if (inode_kind == VFS_INODE_FILE)
            description->kind = KERNEL_VFS_DESCRIPTOR_REGULAR;
        else if (inode_kind == VFS_INODE_DIR)
            description->kind = KERNEL_VFS_DESCRIPTOR_DIRECTORY;
        else
            description->kind = KERNEL_VFS_DESCRIPTOR_OTHER;
        return 0;
    }
    if (entry->kind == FD_MEMFD) {
        edge_memfd_t *memory = memfd_get(entry->pipe_id);
        if (!memory) return -EDGE_LINUX_EBADF;
        description->kind = KERNEL_VFS_DESCRIPTOR_MEMORY;
        if (memory->secret)
            description->attributes |=
                KERNEL_VFS_DESCRIPTOR_SECRET_MEMORY;
        description->readable = !(entry->flags & LINUX_O_PATH) &&
            (entry->flags & LINUX_O_ACCMODE) != LINUX_O_WRONLY;
        description->writable = !(entry->flags & LINUX_O_PATH) &&
            (entry->flags & LINUX_O_ACCMODE) != LINUX_O_RDONLY;
        description->seals = memory->seals;
        description->size = memory->size;
        description->maximum_size =
            (uint64_t)EDGE_MEMFD_MAX_PAGES * PAGE_SIZE;
        return 0;
    }
    if (entry->kind == FD_PIPE_R || entry->kind == FD_PIPE_W ||
        entry->kind == FD_PIPE_RW) {
        description->kind = KERNEL_VFS_DESCRIPTOR_PIPE;
        description->readable = entry->kind != FD_PIPE_W;
        description->writable = entry->kind != FD_PIPE_R;
        if (!entry->path[0] && entry->pipe_id >= 0 &&
            entry->pipe_id < EDGE_MAX_PIPES &&
            g_pipes[entry->pipe_id].used)
            description->pipe = &g_pipes[entry->pipe_id];
        return 0;
    }
    if (entry->kind == FD_SOCKET) {
        description->kind = KERNEL_VFS_DESCRIPTOR_SOCKET;
        return 0;
    }
    if (entry->kind == FD_CONSOLE) {
        description->kind = KERNEL_VFS_DESCRIPTOR_TERMINAL;
        return 0;
    }
    if (entry->kind == FD_PTY_MASTER || entry->kind == FD_PTY_SLAVE) {
        description->kind = KERNEL_VFS_DESCRIPTOR_PSEUDO_TERMINAL;
        return 0;
    }
    if (entry->kind == FD_NAMESPACE) {
        description->kind = KERNEL_VFS_DESCRIPTOR_NAMESPACE;
        return 0;
    }
    if (entry->kind == FD_EVENTFD || entry->kind == FD_TIMERFD ||
        entry->kind == FD_SIGNALFD || entry->kind == FD_EPOLL ||
        entry->kind == FD_PIDFD || entry->kind == FD_INOTIFY ||
        entry->kind == FD_FANOTIFY || entry->kind == FD_USERFAULTFD ||
        entry->kind == FD_PERF_EVENT ||
        entry->kind == FD_DMA_BUF || entry->kind == FD_MOUNT ||
        entry->kind == FD_IO_URING || entry->kind == FD_LANDLOCK ||
        entry->kind == FD_BPF || entry->kind == FD_SECCOMP) {
        description->kind = KERNEL_VFS_DESCRIPTOR_ANONYMOUS;
        return 0;
    }
    description->kind = KERNEL_VFS_DESCRIPTOR_OTHER;
    return 0;
}

int arch_vfs_cachestat(int32_t descriptor, uint64_t offset,
                       uint64_t length,
                       kernel_vfs_cache_stats_t *statistics) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry;

    if (!statistics || !process) return -EDGE_LINUX_EBADF;
    entry = fd_get(process, descriptor);
    if (!entry) return -EDGE_LINUX_EBADF;
    if (entry->kind == FD_MEMFD) {
        edge_memfd_t *memory = memfd_get(entry->pipe_id);
        uint64_t first_page;
        uint64_t end;
        uint64_t last_page;

        if (!memory) return -EDGE_LINUX_EBADF;
        first_page = offset / PAGE_SIZE;
        end = !length || length > UINT64_MAX - offset ?
              UINT64_MAX : offset + length;
        last_page = end == UINT64_MAX ? UINT64_MAX :
                    (end - (end != 0u)) / PAGE_SIZE;
        if (first_page >= EDGE_MEMFD_MAX_PAGES) return 0;
        if (last_page >= EDGE_MEMFD_MAX_PAGES)
            last_page = EDGE_MEMFD_MAX_PAGES - 1u;
        for (uint64_t page = first_page; page <= last_page; ++page) {
            if (memory->page_idx[page] >= 0) {
                ++statistics->cached_pages;
            } else if (memory->swap_entries &&
                       memory->swap_entries[page]) {
                ++statistics->evicted_pages;
            }
        }
        return 0;
    }
    if (entry->kind == FD_VFS && entry->sb) {
        uint64_t resident = 0;
        uint64_t swapped = 0;

        if (tmpfs_cachestat(entry->sb, &entry->inode, offset, length,
                            &resident, &swapped) == 0) {
            statistics->cached_pages = resident;
            statistics->evicted_pages = swapped;
            return 0;
        }
        x86_file_cache_cachestat(
            entry->sb, &entry->inode, offset, length, statistics);
    }
    return 0;
}

edge_linux_seek_result_t arch_vfs_seek_descriptor(
    int32_t descriptor, int64_t displacement, uint32_t whence,
    uint64_t *result) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry;
    edge_linux_seek_state_t state;
    edge_linux_seek_result_t status;
    int exchange_status;
    uint64_t expected;
    uint64_t position;
    int reference;

    if (!process) return EDGE_LINUX_SEEK_BAD_DESCRIPTOR;
    entry = fd_get(process, descriptor);
    if (!entry) return EDGE_LINUX_SEEK_BAD_DESCRIPTOR;
    if ((entry->flags & LINUX_O_PATH) != 0)
        return EDGE_LINUX_SEEK_PATH_DESCRIPTOR;

    memset(&state, 0, sizeof(state));
    if (entry->kind == FD_VFS) {
        uint16_t inode_kind;
        if (entry->sb) (void)vfs_inode_refresh(entry->sb, &entry->inode);
        inode_kind = entry->inode.mode & 0xf000u;
        if (inode_kind == VFS_INODE_FILE) {
            state.end = entry->inode.size;
            state.maximum = (uint64_t)INT64_MAX - 1u;
            state.capabilities = EDGE_LINUX_SEEK_POSITIONAL |
                                 EDGE_LINUX_SEEK_DATA_HOLE;
            status = edge_linux_seek_resolve_data_hole(
                entry->sb, &entry->inode, displacement, whence,
                &state);
            if (status != EDGE_LINUX_SEEK_OK) return status;
        } else if (inode_kind == VFS_INODE_BLK) {
            block_device_t *device = 0;
            if (vfs_inode_get_block_device(&entry->inode, &device) < 0)
                return EDGE_LINUX_SEEK_ILLEGAL;
            state.end = block_device_size_bytes(device);
            state.maximum = state.end;
            state.capabilities = EDGE_LINUX_SEEK_POSITIONAL;
        } else if (inode_kind == VFS_INODE_DIR) {
            state.end = INT64_MAX;
            state.maximum = INT64_MAX;
            state.capabilities = EDGE_LINUX_SEEK_POSITIONAL |
                                 EDGE_LINUX_SEEK_DATA_HOLE;
        } else if (strcmp(entry->path, "/dev/null") == 0 ||
                   strcmp(entry->path, "/dev/zero") == 0 ||
                   strcmp(entry->path, "/dev/random") == 0 ||
                   strcmp(entry->path, "/dev/urandom") == 0) {
            state.capabilities = EDGE_LINUX_SEEK_NOOP;
        } else if (strcmp(entry->path, "/dev/fb0") == 0) {
            state.end = (uint64_t)fb.pitch * fb.height;
            state.maximum = (uint64_t)INT64_MAX - 1u;
            state.capabilities = EDGE_LINUX_SEEK_POSITIONAL;
        } else {
            return whence > EDGE_LINUX_SEEK_HOLE ?
                   EDGE_LINUX_SEEK_INVALID : EDGE_LINUX_SEEK_ILLEGAL;
        }
    } else if (entry->kind == FD_MEMFD) {
        edge_memfd_t *memory = memfd_get(entry->pipe_id);
        if (!memory) return EDGE_LINUX_SEEK_BAD_DESCRIPTOR;
        if (memory->secret) return EDGE_LINUX_SEEK_ILLEGAL;
        entry->inode.size = memory->size;
        state.end = memory->size;
        state.maximum = (uint64_t)INT64_MAX - 1u;
        state.capabilities = EDGE_LINUX_SEEK_POSITIONAL |
                             EDGE_LINUX_SEEK_DATA_HOLE;
    } else if (entry->kind == FD_EVENTFD || entry->kind == FD_TIMERFD ||
               entry->kind == FD_SIGNALFD) {
        state.capabilities = EDGE_LINUX_SEEK_NOOP;
    } else {
        return whence > EDGE_LINUX_SEEK_HOLE ?
               EDGE_LINUX_SEEK_INVALID : EDGE_LINUX_SEEK_ILLEGAL;
    }

    reference = entry->file_ref;
    for (;;) {
        expected = fd_description_offset(entry);
        state.offset = expected;
        status = edge_linux_seek_calculate(&state, displacement, whence,
                                           &position);
        if (status != EDGE_LINUX_SEEK_OK) return status;
        if (state.capabilities & EDGE_LINUX_SEEK_NOOP) {
            *result = 0;
            return EDGE_LINUX_SEEK_OK;
        }
        if (reference <= 0) {
            fd_description_set_offset(entry, position);
            *result = position;
            return EDGE_LINUX_SEEK_OK;
        }
        exchange_status =
            kernel_file_description_offset_compare_exchange(
                file_ref_locator(reference), &expected, position);
        if (exchange_status < 0) {
            fd_description_set_offset(entry, position);
            *result = position;
            return EDGE_LINUX_SEEK_OK;
        }
        if (exchange_status > 0) {
            entry->pos = position;
            *result = position;
            return EDGE_LINUX_SEEK_OK;
        }
    }
}

kernel_task_scratch_t *arch_task_scratch_current(void) {
    task_t *task = process_current_task();
    return task ? task->scratch : 0;
}

int arch_io_descriptor_ready(int32_t descriptor,
                             kernel_io_operation_t operation) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry = process ? fd_get(process, descriptor) : 0;
    int16_t events;
    if (!entry) return 0;
    events = (operation == KERNEL_IO_WRITE_CURRENT ||
              operation == KERNEL_IO_WRITE_POSITIONAL) ?
                 LINUX_POLLOUT : LINUX_POLLIN;
    return (poll_fd_revents(entry, events) &
            (events | LINUX_POLLERR | LINUX_POLLHUP)) != 0;
}

static int x86_io_positioned_write_offset(
        edge_fd_t *entry, uint32_t flags, uint64_t *offset) {
    if (!entry || !offset) return -EINVAL;
    if ((flags & KERNEL_IO_TRANSFER_NOAPPEND) != 0 ||
        ((flags & KERNEL_IO_TRANSFER_APPEND) == 0 &&
         ((uint32_t)entry->flags & LINUX_O_APPEND) == 0))
        return 0;
    if (entry->kind == FD_MEMFD) {
        edge_memfd_t *memory = memfd_get(entry->pipe_id);
        if (!memory) return -EBADF;
        *offset = memory->size;
    } else if (entry->kind == FD_VFS) {
        if (entry->sb)
            (void)vfs_inode_refresh(entry->sb, &entry->inode);
        *offset = entry->inode.size;
    }
    return 0;
}

int64_t arch_io_user_transfer(int32_t descriptor, uint64_t user_buffer,
                              uint64_t length, uint64_t offset,
                              kernel_io_operation_t operation,
                              uint32_t flags, void *user_registers) {
    kernel_fd_operation_lease_t lease = {0};
    edge_fd_t *entry;
    uint32_t clear_flags = 0;
    uint32_t set_flags = 0;
    int64_t result;
    int status;
    (void)user_registers;

    if (flags & KERNEL_IO_TRANSFER_NONBLOCK)
        set_flags |= LINUX_O_NONBLOCK;
    if (operation == KERNEL_IO_WRITE_CURRENT) {
        if (flags & KERNEL_IO_TRANSFER_APPEND)
            set_flags |= LINUX_O_APPEND;
        if (flags & KERNEL_IO_TRANSFER_NOAPPEND)
            clear_flags |= LINUX_O_APPEND;
        if (!set_flags && !clear_flags)
            return (int64_t)do_sys_fd_write(
                (uint64_t)descriptor, user_buffer, length);
        return (int64_t)do_sys_fd_write_with_flags(
            (uint64_t)descriptor, user_buffer, length,
            set_flags, clear_flags);
    }
    if (operation == KERNEL_IO_READ_CURRENT) {
        if (!set_flags && !clear_flags)
            return (int64_t)do_sys_fd_read(
                (uint64_t)descriptor, user_buffer, length);
        return (int64_t)do_sys_fd_read_with_flags(
            (uint64_t)descriptor, user_buffer, length,
            set_flags, clear_flags);
    }

    status = kernel_fd_operation_acquire(descriptor, &lease);
    if (status < 0) return status;
    entry = (edge_fd_t *)(uintptr_t)kernel_fd_operation_view(&lease);
    if (!entry) {
        result = -EIO;
        goto positional_out;
    }
    if (!fd_entry_io_access_allowed(
            entry, operation == KERNEL_IO_WRITE_POSITIONAL)) {
        result = -EBADF;
        goto positional_out;
    }
    if (operation == KERNEL_IO_READ_POSITIONAL) {
        result = (int64_t)do_sys_pread64_entry(
            entry, user_buffer, length, offset);
        goto positional_out;
    }
    if (operation != KERNEL_IO_WRITE_POSITIONAL) {
        result = -EINVAL;
        goto positional_out;
    }

    status = x86_io_positioned_write_offset(
        entry, flags, &offset);
    if (status < 0) {
        result = status;
        goto positional_out;
    }
    result = (int64_t)do_sys_pwrite64_entry(
        entry, user_buffer, length, offset);

positional_out:
    (void)kernel_fd_operation_release(&lease);
    return result;
}

static int x86_io_vector_access_allowed(
        const edge_fd_t *entry, kernel_io_operation_t operation) {
    int writing = operation == KERNEL_IO_WRITE_CURRENT ||
                  operation == KERNEL_IO_WRITE_POSITIONAL;
    return fd_entry_io_access_allowed(entry, writing);
}

static int x86_io_vector_entry_ready(
        edge_fd_t *entry, kernel_io_operation_t operation) {
    int16_t events =
        (operation == KERNEL_IO_WRITE_CURRENT ||
         operation == KERNEL_IO_WRITE_POSITIONAL) ?
            LINUX_POLLOUT : LINUX_POLLIN;

    if (!entry) return 0;
    return (poll_fd_revents(entry, events) &
            (events | LINUX_POLLERR | LINUX_POLLHUP)) != 0;
}

static int x86_io_vector_sync_entry(
        edge_fd_t *entry, uint32_t flags) {
    int data_only =
        (flags & KERNEL_IO_TRANSFER_SYNC_FILE) == 0;

    if (!entry) return -EIO;
    if (entry->kind == FD_MEMFD) return 0;
    if (entry->kind != FD_VFS) return -EINVAL;
    if (edge_mmap_file_cache_sync_inode(
            entry->sb, &entry->inode, 0) < 0)
        return -EIO;
    return fd_sync_inode(entry, data_only) < 0 ? -EIO : 0;
}

static edge_socket_t *x86_io_record_socket_entry(
        edge_fd_t *entry) {
    edge_socket_t *socket;

    if (!entry || entry->kind != FD_SOCKET) return 0;
    socket = socket_from_fd_entry(entry);
    if (!socket || socket->domain != LINUX_AF_UNIX ||
        !socket_type_is_record(socket->type))
        return 0;
    return socket;
}

static int64_t x86_io_record_recv_iov_entry(
        int32_t descriptor, edge_socket_t *socket,
        edge_fd_t *entry,
        const kernel_socket_iovec_source_t *source,
        uint32_t vector_count) {
    task_t *current = process_current_task();
    uint64_t deadline_us = 0;
    uint32_t shutdown_generation;

    if (!socket || !source) return -EINVAL;
    shutdown_generation = socket->shutdown_read_generation;
    if (socket->recv_timeout_us) {
        uint64_t now_us = boottime_monotonic_us();
        deadline_us = now_us + socket->recv_timeout_us;
        if (deadline_us < now_us) deadline_us = UINT64_MAX;
    }

record_wait:
    while (!socket->packet_count) {
        if (kernel_socket_type_has_peer_eof((uint32_t)socket->type) &&
            (socket->shutdown_read || socket->rx_closed ||
             socket->closed))
            return 0;
        if ((entry && (entry->flags & LINUX_O_NONBLOCK)) ||
            socket->nonblock)
            return -EAGAIN;
        if (socket->type == LINUX_SOCK_DGRAM &&
            socket->shutdown_read_generation !=
                shutdown_generation)
            return 0;
        if (signal_pending_interrupt())
            return (int64_t)tty_interrupt_current_ret();
        if (entry && current)
            socket_waiter_add(
                entry->pipe_id, current->pid,
                LINUX_POLLIN | LINUX_POLLPRI);
        if (socket->packet_count ||
            (kernel_socket_type_has_peer_eof((uint32_t)socket->type) &&
             (socket->shutdown_read || socket->rx_closed ||
              socket->closed))) {
            if (current) waiter_remove_pid(current->pid);
            continue;
        }
        if (socket->type == LINUX_SOCK_DGRAM &&
            socket->shutdown_read_generation !=
                shutdown_generation) {
            if (current) waiter_remove_pid(current->pid);
            return 0;
        }
        if (deadline_us &&
            boottime_monotonic_us() >= deadline_us) {
            if (current) waiter_remove_pid(current->pid);
            return -EAGAIN;
        }
        socket_blocking_wait_step(deadline_us);
    }

    if (socket_iovec_user_access_prepare(
            source, vector_count, EDGE_SOCKET_RX_BUF_SIZE, 1) < 0)
        return -EFAULT;

    {
        uint64_t irq_flags =
            spin_lock_irqsave(&socket->io_lock);
        uint32_t packet_length;
        uint32_t copied = 0;
        int copy_error = 0;

        if (!socket->packet_count) {
            spin_unlock_irqrestore(
                &socket->io_lock, irq_flags);
            goto record_wait;
        }
        packet_length =
            socket_packet_front_length(socket);
        if (packet_length > socket->rx_len) {
            printf("[unix-record] corrupt vector receive fd=%d packet=%u bytes=%u count=%u\n",
                   descriptor, packet_length, socket->rx_len,
                   (uint32_t)socket->packet_count);
            spin_unlock_irqrestore(
                &socket->io_lock, irq_flags);
            return -EIO;
        }

        socket->received_timestamp_us =
            socket->packet_timestamps_us[socket->packet_head];
        socket->received_cred_pid =
            socket->packet_sender_pids[socket->packet_head];
        socket->received_cred_uid =
            socket->packet_sender_uids[socket->packet_head];
        socket->received_cred_gid =
            socket->packet_sender_gids[socket->packet_head];
        socket->rx_peer_len =
            socket->packet_source_lengths[socket->packet_head];
        if (socket->rx_peer_len)
            memcpy(
                socket->rx_peer,
                socket->packet_source_addresses[
                    socket->packet_head],
                socket->rx_peer_len);

        for (uint32_t index = 0;
             index < vector_count &&
             copied < packet_length; ++index) {
            struct edge_linux_iovec vector;
            uint32_t count = packet_length - copied;
            int status = kernel_socket_iovec_source_read(
                source, index, &vector);

            if (status < 0) {
                copy_error = status;
                break;
            }
            if (vector.iov_len < count)
                count = (uint32_t)vector.iov_len;
            if (count && copy_to_user(
                    vector.iov_base,
                    socket->rx_buf + copied, count) < 0) {
                copy_error = -EFAULT;
                break;
            }
            copied += count;
        }

        /*
         * Linux dequeues an AF_UNIX record even when a later iovec copy
         * faults. Earlier iovecs may already contain payload bytes, but the
         * same record must never be delivered a second time.
         */
        if (packet_length < socket->rx_len)
            memmove(
                socket->rx_buf,
                socket->rx_buf + packet_length,
                socket->rx_len - packet_length);
        socket->rx_len -= packet_length;
        socket_packet_pop(socket);
        for (;;) {
            kernel_socket_rights_record_info_t rights_info;

            if (socket_rights_peek_at(
                    socket, 0, &rights_info) < 0 ||
                rights_info.association_kind !=
                    KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET ||
                rights_info.association_sequence >
                    socket->unix_packet_head_sequence)
                break;
            socket_rights_drop_front(socket);
        }
        socket_rights_note_packet_read(socket);
        spin_unlock_irqrestore(
            &socket->io_lock, irq_flags);

        if (socket->unix_peer_id >= 0 &&
            socket->unix_peer_id < EDGE_MAX_SOCKETS)
            fd_wake_socket_waiters_events(
                socket->unix_peer_id,
                LINUX_POLLOUT | LINUX_POLLWRNORM);
        return copy_error ? copy_error : (int64_t)copied;
    }
}

static int64_t x86_io_record_vector_transfer_entry(
        int32_t descriptor, edge_fd_t *entry,
        const struct edge_linux_iovec *vectors,
        uint32_t vector_count, kernel_io_operation_t operation) {
    edge_socket_t *socket =
        x86_io_record_socket_entry(entry);
    kernel_socket_iovec_source_t source;

    if (!socket)
        return KERNEL_IO_VECTOR_SCALAR_FALLBACK;
    if (kernel_socket_iovec_source_from_array(
            &source, vectors, vector_count) < 0)
        return -EINVAL;

    if (operation == KERNEL_IO_WRITE_CURRENT) {
        return (int64_t)unix_record_send_iov_to(
            descriptor, socket, entry, &source, vector_count, 0,
            socket->unix_peer_id, 0);
    }
    if (operation == KERNEL_IO_READ_CURRENT) {
        return x86_io_record_recv_iov_entry(
            descriptor, socket, entry, &source, vector_count);
    }
    return KERNEL_IO_VECTOR_SCALAR_FALLBACK;
}

static int64_t x86_io_atomic_pipe_vector_write_entry(
        edge_fd_t *entry,
        const kernel_io_vector_request_t *request) {
    task_t *current;
    edge_pipe_t *pipe;
    uint8_t *scratch;
    uint64_t described = 0;
    uint32_t copied = 0;
    int nonblocking;

    if (!entry || !request ||
        request->operation != KERNEL_IO_WRITE_CURRENT ||
        (entry->kind != FD_PIPE_W &&
         entry->kind != FD_PIPE_RW) ||
        request->requested_length >
            KERNEL_PIPE_RUNTIME_BUF)
        return KERNEL_IO_VECTOR_SCALAR_FALLBACK;
    if (!request->requested_length) return 0;
    if (entry->pipe_id < 0 ||
        entry->pipe_id >= EDGE_MAX_PIPES)
        return -EBADF;

    for (uint32_t index = 0;
         index < request->vector_count &&
         described < request->requested_length; ++index) {
        uint64_t count = request->vectors[index].iov_len;
        if (count >
            request->requested_length - described)
            count = request->requested_length - described;
        described += count;
    }
    if (described != request->requested_length)
        return -EINVAL;

    pipe = &g_pipes[entry->pipe_id];
    if (kernel_pipe_notification_mode(pipe))
        return -EXDEV;
    nonblocking =
        (entry->flags & LINUX_O_NONBLOCK) != 0;
    for (;;) {
        kernel_pipe_io_decision_t decision =
            kernel_pipe_write_decide(
                pipe, request->requested_length, 1,
                nonblocking);

        if (decision == KERNEL_PIPE_IO_READY) break;
        if (decision == KERNEL_PIPE_IO_COMPLETE)
            return 0;
        if (decision == KERNEL_PIPE_IO_INVALID)
            return -EBADF;
        if (decision == KERNEL_PIPE_IO_BROKEN)
            return -EPIPE;
        if (decision == KERNEL_PIPE_IO_WOULD_BLOCK)
            return -EAGAIN;
        if (signal_pending_interrupt())
            return (int64_t)tty_interrupt_current_ret();
        current = process_current_task();
        pipe_write_waiter_add(
            entry->pipe_id, current ? current->pid : 0);
        if (kernel_pipe_write_decide(
                pipe, request->requested_length, 1,
                nonblocking) != KERNEL_PIPE_IO_WAIT) {
            if (current) waiter_remove_pid(current->pid);
            continue;
        }
        socket_blocking_wait_step(0);
    }

    current = process_current_task();
    if (!current || !current->scratch) return -ENOMEM;
    scratch = (uint8_t *)(void *)
        current->scratch->path_scratch[4];
    /*
     * Admission above guarantees room for the entire PIPE_BUF-sized write.
     * Stage every user byte before changing the pipe so a fault cannot expose
     * a prefix and separate iovecs cannot interleave with another writer.
     */
    for (uint32_t index = 0;
         index < request->vector_count &&
         copied < request->requested_length; ++index) {
        uint64_t count = request->vectors[index].iov_len;

        if (count >
            request->requested_length - copied)
            count = request->requested_length - copied;
        if (!count) continue;
        if (copy_from_user(
                scratch + copied,
                request->vectors[index].iov_base,
                count) < 0)
            return -EFAULT;
        copied += (uint32_t)count;
    }
    if (copied != request->requested_length)
        return -EIO;

    {
        uint32_t saved_write_position =
            pipe->write_position;
        uint32_t saved_count = pipe->count;
        uint64_t saved_read_ready_sequence =
            pipe->read_ready_sequence;
        uint32_t written = kernel_pipe_write_kernel(
            pipe, scratch, copied);

        if (written != copied) {
            pipe->write_position = saved_write_position;
            pipe->count = saved_count;
            pipe->read_ready_sequence =
                saved_read_ready_sequence;
            return -EIO;
        }
    }
    fd_wake_pipe_waiters(entry->pipe_id);
    return (int64_t)copied;
}

static void x86_io_vector_signal_broken_pipe(void) {
    task_t *current = process_current_task();

    if (current)
        (void)process_send_signal(
            current->pid, EDGE_LINUX_SIGPIPE);
}

static int64_t x86_io_scalar_zero_transfer_entry(
        edge_fd_t *entry,
        const kernel_io_vector_request_t *request) {
    uint64_t offset;

    if (!entry || !request || !request->vectors ||
        request->vector_count != 1)
        return -EINVAL;
    if (request->operation == KERNEL_IO_READ_CURRENT)
        return (int64_t)do_sys_fd_read_entry(
            request->descriptor, entry,
            request->vectors[0].iov_base, 0);
    if (request->operation == KERNEL_IO_WRITE_CURRENT)
        return (int64_t)do_sys_fd_write_entry(
            request->descriptor, entry,
            request->vectors[0].iov_base, 0);
    if (request->operation == KERNEL_IO_READ_POSITIONAL)
        return (int64_t)do_sys_pread64_entry(
            entry, request->vectors[0].iov_base, 0,
            request->offset);
    if (request->operation != KERNEL_IO_WRITE_POSITIONAL)
        return -EINVAL;
    offset = request->offset;
    {
        int status = x86_io_positioned_write_offset(
            entry, request->flags, &offset);
        if (status < 0) return status;
    }
    return (int64_t)do_sys_pwrite64_entry(
        entry, request->vectors[0].iov_base, 0, offset);
}

static int64_t x86_io_vector_transfer_entry(
        edge_fd_t *entry,
        const kernel_io_vector_request_t *request) {
    uint64_t total = 0;
    int scalar_zero;
    int writing;
    int64_t result;

    if (!entry || !request ||
        (request->vector_count && !request->vectors))
        return -EINVAL;
    writing = request->operation == KERNEL_IO_WRITE_CURRENT ||
              request->operation == KERNEL_IO_WRITE_POSITIONAL;
    if (request->flags & KERNEL_IO_TRANSFER_NONBLOCK)
        entry->flags |= LINUX_O_NONBLOCK;
    if (request->operation == KERNEL_IO_WRITE_CURRENT &&
        (request->flags & KERNEL_IO_TRANSFER_APPEND))
        entry->flags |= LINUX_O_APPEND;
    if (request->operation == KERNEL_IO_WRITE_CURRENT &&
        (request->flags & KERNEL_IO_TRANSFER_NOAPPEND))
        entry->flags &= ~LINUX_O_APPEND;

    if (request->operation != KERNEL_IO_READ_CURRENT &&
        request->operation != KERNEL_IO_WRITE_CURRENT &&
        request->operation != KERNEL_IO_READ_POSITIONAL &&
        request->operation != KERNEL_IO_WRITE_POSITIONAL)
        return -EINVAL;

    scalar_zero =
        !request->requested_length &&
        (request->flags &
         KERNEL_IO_TRANSFER_SCALAR_SYSCALL);
    if (!request->requested_length && !scalar_zero) {
        result = 0;
        goto vector_complete;
    }
    if (scalar_zero &&
        (!request->vectors || request->vector_count != 1)) {
        result = -EINVAL;
        goto vector_complete;
    }

    if (!(scalar_zero &&
          request->operation == KERNEL_IO_READ_CURRENT &&
          x86_io_record_socket_entry(entry))) {
        result = x86_io_record_vector_transfer_entry(
            request->descriptor, entry, request->vectors,
            request->vector_count, request->operation);
        if (result != KERNEL_IO_VECTOR_SCALAR_FALLBACK) {
            total = result > 0 ? (uint64_t)result : 0;
            goto vector_complete;
        }
    }
    if (scalar_zero) {
        result = x86_io_scalar_zero_transfer_entry(
            entry, request);
        goto vector_complete;
    }

    result = x86_io_atomic_pipe_vector_write_entry(
        entry, request);
    if (result != KERNEL_IO_VECTOR_SCALAR_FALLBACK) {
        total = result > 0 ? (uint64_t)result : 0;
        goto vector_complete;
    }

    for (uint32_t index = 0;
         index < request->vector_count &&
         total < request->requested_length; ++index) {
        uint64_t length = request->vectors[index].iov_len;
        uint64_t transfer_offset = 0;
        int64_t transferred;

        if (length > request->requested_length - total)
            length = request->requested_length - total;
        if (!length) continue;
        if (total &&
            !x86_io_vector_entry_ready(entry, request->operation))
            break;
        if ((request->operation == KERNEL_IO_READ_POSITIONAL ||
             request->operation == KERNEL_IO_WRITE_POSITIONAL) &&
            request->offset > INT64_MAX - total) {
            result = total ? (int64_t)total : -EINVAL;
            goto vector_complete;
        }

        if (request->operation == KERNEL_IO_READ_CURRENT) {
            transferred = (int64_t)do_sys_fd_read_entry(
                request->descriptor, entry,
                request->vectors[index].iov_base, length);
        } else if (request->operation == KERNEL_IO_WRITE_CURRENT) {
            transferred = (int64_t)do_sys_fd_write_entry(
                request->descriptor, entry,
                request->vectors[index].iov_base, length);
        } else {
            transfer_offset = request->offset + total;
            if (request->operation == KERNEL_IO_WRITE_POSITIONAL) {
                int offset_status =
                    x86_io_positioned_write_offset(
                        entry, request->flags, &transfer_offset);
                if (offset_status < 0) {
                    result = total ? (int64_t)total : offset_status;
                    goto vector_complete;
                }
            }
            transferred =
                request->operation == KERNEL_IO_READ_POSITIONAL ?
                    (int64_t)do_sys_pread64_entry(
                        entry, request->vectors[index].iov_base,
                        length, transfer_offset) :
                    (int64_t)do_sys_pwrite64_entry(
                        entry, request->vectors[index].iov_base,
                        length, transfer_offset);
        }
        if (transferred < 0) {
            result = total ? (int64_t)total : transferred;
            goto vector_complete;
        }
        total += (uint64_t)transferred;
        if ((uint64_t)transferred != length) break;
    }
    result = (int64_t)total;

vector_complete:
    if (writing && result == -EPIPE)
        x86_io_vector_signal_broken_pipe();
    if (writing && result > 0 &&
        (request->flags & (KERNEL_IO_TRANSFER_SYNC_DATA |
                           KERNEL_IO_TRANSFER_SYNC_FILE))) {
        int sync_result =
            x86_io_vector_sync_entry(entry, request->flags);
        if (sync_result < 0) result = sync_result;
    }
    return result;
}

static int64_t x86_fd_operation_vector_io(
        void *context, void *storage,
        const struct kernel_io_vector_request *request) {
    edge_fd_t *entry = (edge_fd_t *)storage;

    (void)context;
    if (!request) return -EINVAL;
    if ((request->operation == KERNEL_IO_READ_POSITIONAL ||
         request->operation == KERNEL_IO_WRITE_POSITIONAL) &&
        fd_entry_positional_io_unsupported(entry))
        return -ESPIPE;
    if (!x86_io_vector_access_allowed(entry, request->operation))
        return -EBADF;
    if (request->validate_only) return 0;
    return x86_io_vector_transfer_entry(entry, request);
}

int64_t arch_io_user_vector_transfer(
    int32_t descriptor, const struct edge_linux_iovec *vectors,
    uint32_t vector_count, kernel_io_operation_t operation,
    uint32_t flags, void *user_registers) {
    kernel_fd_operation_lease_t lease = {0};
    edge_fd_t *entry;
    int64_t result;
    int status;

    (void)user_registers;
    status = kernel_fd_operation_acquire(descriptor, &lease);
    if (status < 0) return status;
    entry = (edge_fd_t *)(uintptr_t)kernel_fd_operation_view(&lease);
    if (!entry) {
        (void)kernel_fd_operation_release(&lease);
        return -EIO;
    }
    if (flags & KERNEL_IO_TRANSFER_NONBLOCK)
        entry->flags |= LINUX_O_NONBLOCK;
    result = x86_io_record_vector_transfer_entry(
        descriptor, entry, vectors, vector_count, operation);
    (void)kernel_fd_operation_release(&lease);
    return result;
}

static int64_t x86_fd_operation_file_range(
        void *context, void *storage,
        const kernel_io_file_range_request_t *request) {
    edge_fd_t *entry = (edge_fd_t *)storage;
    kernel_io_file_range_info_t *information;
    uint32_t length;
    uint32_t access_mode;
    uint64_t offset;
    uint16_t inode_kind;
    int written;

    (void)context;
    if (!entry || !request) return -EINVAL;
    offset = request->offset;
    length = request->length;
    switch (request->operation) {
        case KERNEL_IO_FILE_RANGE_QUERY:
            information = request->information;
            if (!information) return -EBADF;
            memset(information, 0, sizeof(*information));
            access_mode = (uint32_t)entry->flags & LINUX_O_ACCMODE;
            information->readable = access_mode != LINUX_O_WRONLY;
            information->writable = access_mode != LINUX_O_RDONLY;
            information->append =
                ((uint32_t)entry->flags & LINUX_O_APPEND) != 0;
            information->offset = fd_description_offset(entry);
            if (entry->kind == FD_PIPE_R ||
                entry->kind == FD_PIPE_W ||
                entry->kind == FD_PIPE_RW) {
                information->kind = KERNEL_IO_FILE_PIPE;
                return 0;
            }
            if (entry->kind == FD_MEMFD) {
                edge_memfd_t *memory = memfd_get(entry->pipe_id);
                if (!memory) return -EBADF;
                information->filesystem =
                    (uint64_t)(uintptr_t)&g_memfds[0];
                information->file =
                    (uint64_t)(uint32_t)entry->pipe_id;
                information->kind = KERNEL_IO_FILE_REGULAR;
                return 0;
            }
            if (entry->kind != FD_VFS) return 0;
            if (entry->sb)
                (void)vfs_inode_refresh(entry->sb, &entry->inode);
            information->filesystem =
                (uint64_t)(uintptr_t)entry->sb;
            information->file = entry->inode.ino;
            information->metadata_flags = entry->inode.metadata_flags;
            inode_kind = entry->inode.mode & 0xf000u;
            if (inode_kind == VFS_INODE_FILE)
                information->kind = KERNEL_IO_FILE_REGULAR;
            else if (inode_kind == VFS_INODE_DIR)
                information->kind = KERNEL_IO_FILE_DIRECTORY;
            return 0;
        case KERNEL_IO_FILE_RANGE_READ:
            if (!request->buffer && length) return -EFAULT;
            if (entry->kind == FD_PIPE_R || entry->kind == FD_PIPE_RW) {
                edge_pipe_t *pipe;
                kernel_pipe_io_decision_t decision;
                uint32_t read;

                if (entry->pipe_id < 0 ||
                    entry->pipe_id >= EDGE_MAX_PIPES)
                    return -EBADF;
                pipe = &g_pipes[entry->pipe_id];
                if (!pipe->used) return -EBADF;
                decision = kernel_pipe_read_decide(pipe, 1);
                if (decision == KERNEL_PIPE_IO_COMPLETE) return 0;
                if (decision == KERNEL_PIPE_IO_WOULD_BLOCK ||
                    decision == KERNEL_PIPE_IO_WAIT)
                    return -EAGAIN;
                if (decision != KERNEL_PIPE_IO_READY) return -EBADF;
                read = kernel_pipe_read_kernel(
                    pipe, request->buffer, length);
                if (read) fd_wake_pipe_waiters(entry->pipe_id);
                return (int64_t)read;
            }
            if (entry->kind == FD_MEMFD) {
                edge_memfd_t *memory = memfd_get(entry->pipe_id);
                if (!memory) return -EBADF;
                if (memory->secret) return -EINVAL;
                return memfd_read_to_kernel(
                    memory, offset, request->buffer, length);
            }
            if (entry->kind != FD_VFS || !entry->sb ||
                !entry->sb->ops || !entry->sb->ops->read)
                return -EINVAL;
            if (offset >= UINT32_MAX) return 0;
            if (length > UINT32_MAX - (uint32_t)offset)
                length = UINT32_MAX - (uint32_t)offset;
            return entry->sb->ops->read(
                entry->sb, &entry->inode, (uint32_t)offset,
                request->buffer, length);
        case KERNEL_IO_FILE_RANGE_WRITE:
            if (!request->buffer && length) return -EFAULT;
            if (entry->kind == FD_MEMFD) {
                edge_memfd_t *memory = memfd_get(entry->pipe_id);
                if (!memory) return -EBADF;
                if (memory->secret) return -EINVAL;
                written = memfd_write_from_kernel(
                    memory, offset, request->buffer, length);
                if (written > 0) entry->inode.size = memory->size;
                return written;
            }
            if (entry->kind != FD_VFS || !entry->sb ||
                !entry->sb->ops || !entry->sb->ops->write)
                return -EINVAL;
            if (offset >= UINT32_MAX) return -EFBIG;
            if (length > UINT32_MAX - (uint32_t)offset)
                length = UINT32_MAX - (uint32_t)offset;
            if (!length) return -EFBIG;
            written = entry->sb->ops->write(
                entry->sb, &entry->inode, (uint32_t)offset,
                request->buffer, length);
            if (written > 0) {
                uint64_t end = offset + (uint32_t)written;
                if (end > entry->inode.size)
                    entry->inode.size = (uint32_t)end;
                entry->dirty = 1;
                vfs_path_cache_invalidate(entry->path);
                edge_mmap_file_cache_apply_write(
                    entry->sb, &entry->inode, offset,
                    request->buffer, (uint32_t)written);
            }
            return written;
        case KERNEL_IO_FILE_RANGE_COMMIT_OFFSET:
            fd_description_set_offset(entry, offset);
            return 0;
        case KERNEL_IO_FILE_RANGE_COMPLETE_WRITE:
            if (entry->path[0] && entry->kind == FD_VFS)
                edge_inotify_notify_path(
                    entry->path, EDGE_IN_MODIFY, 0);
            return 0;
        default:
            return -EINVAL;
    }
}

static uint32_t x86_fd_table_limit(void *context) {
    (void)context;
    return EDGE_MAX_FD;
}

static uint32_t x86_fd_allocation_limit(void *context) {
    (void)context;
    return fd_current_allocation_limit();
}

static void kernel_fd_discard_cloned_table(edge_fd_proc_t *table) {
    fd_clone_table_abort(table);
}

static int kernel_fd_clone_table(int source_owner, int destination_owner) {
    edge_fd_proc_t *source = fd_proc_for_pid(source_owner, 0);
    edge_fd_proc_t *destination;
    if (!source || source_owner <= 0 || destination_owner <= 0 ||
        fd_proc_for_pid(destination_owner, 0))
        return -ENOMEM;
    destination = fd_proc_for_pid_empty(destination_owner, 1);
    if (!destination) return -ENOMEM;
    if (fd_clone_table_contents(source, destination) < 0) {
        kernel_fd_discard_cloned_table(destination);
        return -ENOMEM;
    }
    return 0;
}

static int x86_fd_table_unshare(void *context) {
    task_t *current = process_current_task();
    edge_fd_proc_t *old_table;
    int old_owner;
    int peer_owner = 0;
    int rekeyed = 0;
    int result;
    (void)context;
    if (!current) return -EINVAL;
    old_owner = fd_owner_pid_current();
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        const task_t *peer = process_task_by_index(index);
        int owner;
        if (!peer || peer == current || peer->state == TASK_UNUSED ||
            peer->state == TASK_ZOMBIE)
            continue;
        owner = peer->fd_owner_pid > 0 ? peer->fd_owner_pid : peer->pid;
        if (owner == old_owner) {
            peer_owner = peer->pid;
            break;
        }
    }
    if (!peer_owner) return 0;

    old_table = fd_proc_for_pid(old_owner, 0);
    if (!old_table) return -EBADF;
    if (old_owner == current->pid) {
        if (fd_proc_for_pid(peer_owner, 0)) return -ENOMEM;
        old_table->pid = peer_owner;
        for (int index = 0; index < PROC_MAX_TASKS; ++index) {
            const task_t *peer = process_task_by_index(index);
            int owner;
            if (!peer || peer == current || peer->state == TASK_UNUSED ||
                peer->state == TASK_ZOMBIE)
                continue;
            owner = peer->fd_owner_pid > 0 ?
                    peer->fd_owner_pid : peer->pid;
            if (owner == old_owner)
                (void)process_set_fd_owner(peer->pid, peer_owner);
        }
        old_owner = peer_owner;
        rekeyed = 1;
    }

    result = kernel_fd_clone_table(old_owner, current->pid);
    if (result < 0 ||
        process_set_fd_owner(current->pid, current->pid) < 0) {
        edge_fd_proc_t *clone = fd_proc_for_pid(current->pid, 0);
        if (clone) kernel_fd_discard_cloned_table(clone);
        if (rekeyed) {
            old_table->pid = current->pid;
            for (int index = 0; index < PROC_MAX_TASKS; ++index) {
                const task_t *peer = process_task_by_index(index);
                if (!peer || peer == current || peer->state == TASK_UNUSED ||
                    peer->state == TASK_ZOMBIE)
                    continue;
                if ((peer->fd_owner_pid > 0 ? peer->fd_owner_pid : peer->pid) ==
                    peer_owner)
                    (void)process_set_fd_owner(peer->pid, current->pid);
            }
        }
        return result < 0 ? result : -ENOMEM;
    }
    return 0;
}

static int x86_fd_is_open(void *context, int32_t descriptor) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    (void)context;
    return process && fd_get(process, descriptor) != 0;
}

_Static_assert(
    sizeof(edge_fd_t) <=
        KERNEL_FD_OPERATION_LEASE_STORAGE_SIZE,
    "x86_64 descriptor snapshot exceeds operation lease storage");
_Static_assert(
    _Alignof(edge_fd_t) <=
        _Alignof(kernel_fd_operation_lease_storage_t),
    "x86_64 descriptor snapshot exceeds operation lease alignment");

static edge_fd_proc_t *x86_fd_process_for_owner(
        const void *opaque_owner) {
    const task_t *owner = (const task_t *)opaque_owner;
    int owner_pid;

    if (!owner || owner->state == TASK_UNUSED)
        return 0;
    owner_pid =
        owner->fd_owner_pid > 0 ?
            owner->fd_owner_pid : owner->pid;
    return fd_proc_for_pid(owner_pid, 0);
}

static int x86_fd_operation_acquire(
        void *context, int32_t descriptor, void *storage) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    (void)context;
    if (!storage) return -EINVAL;
    return fd_snapshot_retain(
        process, descriptor, (edge_fd_t *)storage);
}

static int x86_fd_operation_acquire_for_owner(
        void *context, const void *owner,
        int32_t descriptor, void *storage) {
    edge_fd_proc_t *process =
        x86_fd_process_for_owner(owner);
    (void)context;
    if (!storage || !process) return -EBADF;
    return fd_snapshot_retain(
        process, descriptor, (edge_fd_t *)storage);
}

static int x86_fd_operation_acquire_for_pid(
        void *context, int32_t pid,
        int32_t descriptor, void *storage) {
    const task_t *task = process_get_task(pid);

    if (!task) return -ESRCH;
    return x86_fd_operation_acquire_for_owner(
        context, task, descriptor, storage);
}

static int x86_fd_operation_description_id(
        void *context, const void *storage,
        uint64_t *description_id) {
    const edge_fd_t *entry = (const edge_fd_t *)storage;

    (void)context;
    if (!entry || !description_id || entry->file_ref <= 0)
        return -EBADF;
    *description_id = file_ref_identity(entry->file_ref);
    return *description_id ? 0 : -EBADF;
}

static int x86_fd_operation_ready(
        void *context, void *storage, uint32_t operation) {
    edge_fd_t *entry = (edge_fd_t *)storage;
    int16_t events;

    (void)context;
    if (!entry || !entry->used) return -EBADF;
    events = (operation == KERNEL_IO_WRITE_CURRENT ||
              operation == KERNEL_IO_WRITE_POSITIONAL) ?
                 LINUX_POLLOUT : LINUX_POLLIN;
    return (poll_fd_revents(entry, events) &
            (events | LINUX_POLLERR | LINUX_POLLHUP)) != 0;
}

static int x86_fd_operation_release(
        void *context, void *storage) {
    int result;
    (void)context;
    if (!storage) return -EINVAL;
    result = fd_release_entry(
        (edge_fd_t *)storage, 0, 0, 1);
    return result < 0 ? result : 0;
}

static int x86_fd_operation_transfer(
        void *context, void *destination_storage,
        void *source_storage) {
    edge_fd_t *destination = (edge_fd_t *)destination_storage;
    edge_fd_t *source = (edge_fd_t *)source_storage;

    (void)context;
    if (!destination || !source || destination == source)
        return -EINVAL;
    *destination = *source;
    memset(source, 0, sizeof(*source));
    return 0;
}

static int x86_fd_operation_clone(
        void *context, void *destination_storage,
        const void *source_storage) {
    edge_fd_t *destination = (edge_fd_t *)destination_storage;
    const edge_fd_t *source = (const edge_fd_t *)source_storage;
    edge_fd_t clone;
    uint32_t status_flags;

    (void)context;
    if (!destination || !source || destination == source)
        return -EINVAL;
    clone = *source;
    if (!clone.used || clone.file_ref <= 0)
        return -EBADF;
    if (clone.kind == FD_VFS && clone.sb) {
        if (vfs_inode_refresh(clone.sb, &clone.inode) < 0)
            return -EBADF;
    } else if (clone.kind == FD_MEMFD) {
        edge_memfd_t *memory = memfd_get(clone.pipe_id);

        if (!memory) return -EBADF;
        clone.inode.size = memory->size;
    }
    if (file_ref_get(clone.file_ref) < 0)
        return -ENOMEM;
    if (fd_add_backing_object(&clone) < 0) {
        (void)file_ref_put(clone.file_ref);
        return -ENOMEM;
    }
    if (kernel_file_description_status_load(
            file_ref_locator(clone.file_ref), &status_flags) < 0) {
        (void)fd_release_entry(&clone, 0, 0, 0);
        return -EBADF;
    }
    kernel_fd_apply_status_flags(&clone, UINT32_MAX, status_flags);
    *destination = clone;
    return 0;
}

typedef struct x86_fd_transfer_target_storage {
    edge_fd_proc_t *table;
    uint32_t allocation_limit;
    int32_t last_prepared_descriptor;
    uint32_t last_prepare_pending;
} x86_fd_transfer_target_storage_t;

_Static_assert(
    sizeof(x86_fd_transfer_target_storage_t) <=
        KERNEL_FD_TRANSFER_TARGET_STORAGE_SIZE,
    "x86_64 FD transfer target exceeds backend storage");
_Static_assert(
    _Alignof(x86_fd_transfer_target_storage_t) <=
        _Alignof(kernel_fd_transfer_target_storage_t),
    "x86_64 FD transfer target exceeds backend alignment");

static int x86_fd_transfer_target_capture(
        void *context, void *target_storage) {
    x86_fd_transfer_target_storage_t *target =
        (x86_fd_transfer_target_storage_t *)target_storage;
    edge_fd_proc_t *process = fd_proc_with_stdio();
    int result;

    (void)context;
    if (!target || !process) return -EBADF;
    result = fd_proc_table_retain(process);
    if (result < 0) return result;
    memset(target, 0, sizeof(*target));
    target->table = process;
    target->allocation_limit = fd_current_allocation_limit();
    if (target->allocation_limit > EDGE_MAX_FD)
        target->allocation_limit = EDGE_MAX_FD;
    return 0;
}

static int x86_fd_transfer_target_capture_for_owner(
        void *context, const void *owner,
        void *target_storage) {
    x86_fd_transfer_target_storage_t *target =
        (x86_fd_transfer_target_storage_t *)target_storage;
    const task_t *task = (const task_t *)owner;
    edge_fd_proc_t *process =
        x86_fd_process_for_owner(owner);
    uint64_t soft_limit;
    int result;

    (void)context;
    if (!target || !task || !process)
        return -EBADF;
    result = fd_proc_table_retain(process);
    if (result < 0) return result;
    memset(target, 0, sizeof(*target));
    target->table = process;
    soft_limit = __atomic_load_n(
        &task->rlimits[EDGE_LINUX_RLIMIT_NOFILE][0],
        __ATOMIC_ACQUIRE);
    target->allocation_limit =
        soft_limit < EDGE_MAX_FD ?
            (uint32_t)soft_limit : EDGE_MAX_FD;
    return 0;
}

static int x86_fd_transfer_target_capture_for_pid(
        void *context, int32_t pid, void *target_storage) {
    const task_t *task = process_get_task(pid);
    if (!task) return -ESRCH;
    return x86_fd_transfer_target_capture_for_owner(
        context, task, target_storage);
}

static int x86_fd_transfer_target_release(
        void *context, void *target_storage) {
    x86_fd_transfer_target_storage_t *target =
        (x86_fd_transfer_target_storage_t *)target_storage;
    edge_fd_proc_t *table;

    (void)context;
    if (!target || !target->table) return -EINVAL;
    table = target->table;
    memset(target, 0, sizeof(*target));
    fd_proc_table_release(table);
    return 0;
}

static int x86_fd_transfer_target_prepare_internal(
        void *context, void *target_storage,
        const void *source_storage, uint32_t descriptor_flags,
        int32_t requested_descriptor, int exact,
        int32_t *descriptor) {
    x86_fd_transfer_target_storage_t *target =
        (x86_fd_transfer_target_storage_t *)target_storage;
    const edge_fd_t *source = (const edge_fd_t *)source_storage;
    edge_fd_t clone;
    uint32_t number = 0;
    uint32_t status_flags;
    uint64_t irq_flags;
    int result;

    (void)context;
    if (!target || !target->table || !source || !descriptor)
        return -EINVAL;
    *descriptor = -1;
    target->last_prepared_descriptor = -1;
    target->last_prepare_pending = 0;
    if (descriptor_flags & ~KERNEL_FD_CLOEXEC)
        return -EINVAL;
    if (__atomic_load_n(
            &target->table->detached, __ATOMIC_ACQUIRE))
        return -EBADF;

    clone = *source;
    if (!clone.used || clone.file_ref <= 0)
        return -EBADF;
    if (clone.kind == FD_VFS && clone.sb) {
        if (vfs_inode_refresh(
                clone.sb, &clone.inode) < 0)
            return -EBADF;
    } else if (clone.kind == FD_MEMFD) {
        edge_memfd_t *memory = memfd_get(clone.pipe_id);

        if (!memory) return -EBADF;
        clone.inode.size = memory->size;
    }
    if (file_ref_get(clone.file_ref) < 0)
        return -ENOMEM;
    if (fd_add_backing_object(&clone) < 0) {
        (void)file_ref_put(clone.file_ref);
        return -ENOMEM;
    }
    if (kernel_file_description_status_load(
            file_ref_locator(clone.file_ref), &status_flags) < 0) {
        (void)fd_release_entry(&clone, 0, 0, 0);
        return -EBADF;
    }
    kernel_fd_apply_status_flags(
        &clone, UINT32_MAX, status_flags);
    clone.fd_flags =
        (int)(descriptor_flags & KERNEL_FD_CLOEXEC);
    clone.used = 0;

    irq_flags = kernel_fd_table_lock(
        &target->table->table_runtime);
    if (__atomic_load_n(
            &target->table->detached, __ATOMIC_ACQUIRE)) {
        result = -EBADF;
    } else {
        if (exact) {
            if (requested_descriptor < 0 ||
                (uint32_t)requested_descriptor >=
                    target->allocation_limit)
                result = -EBADF;
            else {
                number = (uint32_t)requested_descriptor;
                result = kernel_fd_table_reserve_exact_locked(
                    &target->table->table_runtime, number);
            }
        } else {
            result = kernel_fd_table_reserve_next_below_locked(
                &target->table->table_runtime, 0,
                target->allocation_limit, &number);
        }
        if (result == 0)
            target->table->fds[number] = clone;
    }
    kernel_fd_table_unlock(
        &target->table->table_runtime, irq_flags);
    if (result < 0) {
        clone.used = 1;
        (void)fd_release_entry(&clone, 0, 0, 0);
        return result;
    }
    target->last_prepared_descriptor = (int32_t)number;
    target->last_prepare_pending = 1;
    *descriptor = (int32_t)number;
    return 0;
}

static int x86_fd_transfer_target_prepare(
        void *context, void *target_storage,
        const void *source_storage, uint32_t descriptor_flags,
        int32_t *descriptor) {
    return x86_fd_transfer_target_prepare_internal(
        context, target_storage, source_storage, descriptor_flags,
        -1, 0, descriptor);
}

static int x86_fd_transfer_target_prepare_exact(
        void *context, void *target_storage,
        const void *source_storage, uint32_t descriptor_flags,
        int32_t requested_descriptor, int32_t *descriptor) {
    return x86_fd_transfer_target_prepare_internal(
        context, target_storage, source_storage, descriptor_flags,
        requested_descriptor, 1, descriptor);
}

static int x86_fd_transfer_target_publish_many(
        void *context, void *target_storage,
        const int32_t *descriptors, uint32_t count) {
    x86_fd_transfer_target_storage_t *target =
        (x86_fd_transfer_target_storage_t *)target_storage;
    uint32_t numbers[KERNEL_FD_TRANSFER_MAX];
    uint64_t irq_flags;
    int result;

    (void)context;
    if (!target || !target->table || !descriptors ||
        !count || count > KERNEL_FD_TRANSFER_MAX)
        return -EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        if (descriptors[index] < 0 ||
            descriptors[index] >= EDGE_MAX_FD)
            return -EBADF;
        numbers[index] = (uint32_t)descriptors[index];
    }

    irq_flags = kernel_fd_table_lock(
        &target->table->table_runtime);
    if (__atomic_load_n(
            &target->table->detached, __ATOMIC_ACQUIRE)) {
        kernel_fd_table_unlock(
            &target->table->table_runtime, irq_flags);
        return -EBADF;
    }
    for (uint32_t index = 0; index < count; ++index) {
        edge_fd_t *entry =
            &target->table->fds[numbers[index]];
        if (kernel_fd_table_state_locked(
                &target->table->table_runtime,
                numbers[index]) != KERNEL_FD_SLOT_RESERVED ||
            entry->file_ref <= 0 ||
            __atomic_load_n(&entry->used, __ATOMIC_ACQUIRE)) {
            kernel_fd_table_unlock(
                &target->table->table_runtime, irq_flags);
            return -EBADF;
        }
    }
    result = kernel_fd_table_publish_batch_locked(
        &target->table->table_runtime, numbers, count);
    if (result == 0) {
        for (uint32_t index = 0; index < count; ++index) {
            edge_fd_t *entry =
                &target->table->fds[numbers[index]];
            __atomic_store_n(
                &entry->used, 1, __ATOMIC_RELEASE);
            fd_async_input_watch_update(entry);
        }
    }
    kernel_fd_table_unlock(
        &target->table->table_runtime, irq_flags);
    return result;
}

static int x86_fd_transfer_target_abort_many(
        void *context, void *target_storage,
        const int32_t *descriptors, uint32_t count) {
    x86_fd_transfer_target_storage_t *target =
        (x86_fd_transfer_target_storage_t *)target_storage;
    uint32_t numbers[KERNEL_FD_TRANSFER_MAX];
    uint64_t irq_flags;
    int result;

    (void)context;
    if (!target || !target->table || !descriptors ||
        !count || count > KERNEL_FD_TRANSFER_MAX)
        return -EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        if (descriptors[index] < 0 ||
            descriptors[index] >= EDGE_MAX_FD)
            return -EBADF;
        numbers[index] = (uint32_t)descriptors[index];
    }

    irq_flags = kernel_fd_table_lock(
        &target->table->table_runtime);
    for (uint32_t index = 0; index < count; ++index) {
        edge_fd_t *entry =
            &target->table->fds[numbers[index]];
        if (kernel_fd_table_state_locked(
                &target->table->table_runtime,
                numbers[index]) != KERNEL_FD_SLOT_RESERVED ||
            entry->file_ref <= 0 ||
            __atomic_load_n(&entry->used, __ATOMIC_ACQUIRE)) {
            kernel_fd_table_unlock(
                &target->table->table_runtime, irq_flags);
            return -EBADF;
        }
    }
    result = kernel_fd_table_begin_cancel_batch_locked(
        &target->table->table_runtime, numbers, count);
    kernel_fd_table_unlock(
        &target->table->table_runtime, irq_flags);
    if (result < 0) return result;

    for (uint32_t index = 0; index < count; ++index) {
        edge_fd_t clone;

        memset(&clone, 0, sizeof(clone));
        irq_flags = kernel_fd_table_lock(
            &target->table->table_runtime);
        clone = target->table->fds[numbers[index]];
        memset(&target->table->fds[numbers[index]], 0,
               sizeof(target->table->fds[numbers[index]]));
        kernel_fd_table_unlock(
            &target->table->table_runtime, irq_flags);

        clone.used = 1;
        (void)fd_release_entry(&clone, 0, 0, 0);

        irq_flags = kernel_fd_table_lock(
            &target->table->table_runtime);
        (void)kernel_fd_table_complete_close_locked(
            &target->table->table_runtime, numbers[index]);
        kernel_fd_table_unlock(
            &target->table->table_runtime, irq_flags);
    }
    return 0;
}

static void x86_fd_transfer_target_discard_prepared(
        void *context, void *target_storage) {
    x86_fd_transfer_target_storage_t *target =
        (x86_fd_transfer_target_storage_t *)target_storage;
    int32_t descriptor;

    if (!target || !target->last_prepare_pending)
        __builtin_trap();
    descriptor = target->last_prepared_descriptor;
    target->last_prepared_descriptor = -1;
    target->last_prepare_pending = 0;
    if (x86_fd_transfer_target_abort_many(
            context, target_storage, &descriptor, 1) < 0)
        __builtin_trap();
}

static int x86_fd_close(void *context, int32_t descriptor) {
    (void)context;
    return (int64_t)do_sys_close((uint64_t)(uint32_t)descriptor);
}

static int x86_fd_duplicate_exact(void *context, int32_t source,
                                  int32_t destination,
                                  uint32_t descriptor_flags) {
    uint64_t duplicate;
    (void)context;
    duplicate = descriptor_flags ?
        do_sys_dup_exact(
            (uint64_t)(uint32_t)source,
            (uint64_t)(uint32_t)destination,
            descriptor_flags) :
        do_sys_dup2(
            (uint64_t)(uint32_t)source,
            (uint64_t)(uint32_t)destination);
    if ((int64_t)duplicate < 0) return (int64_t)duplicate;
    return 0;
}

static int x86_fd_duplicate_minimum(void *context, int32_t source,
                                    int32_t minimum,
                                    uint32_t exclusive_limit,
                                    uint32_t descriptor_flags,
                                    int32_t *destination) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t duplicate;
    edge_fd_t installation;
    uint32_t descriptor = 0;
    uint32_t status_flags;
    uint64_t irq_flags;
    int cancel_status;
    int status;

    (void)context;
    if (!destination) return -EINVAL;
    *destination = -1;
    if (!process || source < 0 || source >= EDGE_MAX_FD)
        return -EBADF;
    if (minimum < 0 || minimum >= EDGE_MAX_FD)
        return -EINVAL;
    if (exclusive_limit > EDGE_MAX_FD)
        exclusive_limit = EDGE_MAX_FD;

    memset(&duplicate, 0, sizeof(duplicate));
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &process->table_runtime, (uint32_t)source) ||
        !__atomic_load_n(
            &process->fds[source].used, __ATOMIC_ACQUIRE)) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }

    duplicate = process->fds[source];
    if (duplicate.file_ref <= 0) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }
    if (file_ref_get(duplicate.file_ref) < 0) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -ENOMEM;
    }
    if (fd_add_backing_object(&duplicate) < 0) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        (void)file_ref_put(duplicate.file_ref);
        return -ENOMEM;
    }
    if (kernel_file_description_status_load(
            file_ref_locator(duplicate.file_ref), &status_flags) < 0) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        (void)fd_release_entry(&duplicate, 0, 0, 0);
        return -EBADF;
    }
    kernel_fd_apply_status_flags(
        &duplicate, UINT32_MAX, status_flags);
    duplicate.fd_flags =
        (int)(descriptor_flags & KERNEL_FD_CLOEXEC);

    status = kernel_fd_table_reserve_next_below_locked(
        &process->table_runtime, (uint32_t)minimum,
        exclusive_limit, &descriptor);
    if (status < 0) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        (void)fd_release_entry(&duplicate, 0, 0, 0);
        return status;
    }

    installation = duplicate;
    /* Lockless observers must never see a used entry before OPEN publication. */
    installation.used = 0;
    process->fds[descriptor] = installation;
    status = kernel_fd_table_publish_locked(
        &process->table_runtime, descriptor);
    if (status < 0) {
        cancel_status = kernel_fd_table_cancel_reservation_locked(
            &process->table_runtime, descriptor);
        if (cancel_status == 0)
            memset(&process->fds[descriptor], 0,
                   sizeof(process->fds[descriptor]));
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        (void)fd_release_entry(&duplicate, 0, 0, 0);
        return cancel_status < 0 ? -EIO : status;
    }

    __atomic_store_n(
        &process->fds[descriptor].used, 1, __ATOMIC_RELEASE);
    fd_async_input_watch_update(&process->fds[descriptor]);
    *destination = (int32_t)descriptor;
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);

    fd_log_lifecycle(
        "dup", process_getpid(), source, &duplicate, (int)descriptor);
    fd_log_lifecycle(
        "dup-new", process_getpid(), (int)descriptor, &duplicate, source);
    return 0;
}

static int x86_fd_get_descriptor_flags(void *context, int32_t descriptor,
                                       uint32_t *flags) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    uint64_t irq_flags;
    (void)context;
    if (!process || !flags || descriptor < 0 ||
        descriptor >= EDGE_MAX_FD)
        return -EBADF;
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &process->table_runtime, (uint32_t)descriptor) ||
        !process->fds[descriptor].used) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }
    *flags = (uint32_t)process->fds[descriptor].fd_flags &
             KERNEL_FD_CLOEXEC;
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    return 0;
}

static int x86_fd_set_descriptor_flags(void *context, int32_t descriptor,
                                       uint32_t flags) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    uint64_t irq_flags;
    (void)context;
    if (!process || descriptor < 0 || descriptor >= EDGE_MAX_FD)
        return -EBADF;
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &process->table_runtime, (uint32_t)descriptor) ||
        !process->fds[descriptor].used) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }
    process->fds[descriptor].fd_flags =
        (int)(flags & KERNEL_FD_CLOEXEC);
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    return 0;
}

static int x86_fd_get_status_flags(void *context, int32_t descriptor,
                                   uint32_t *flags) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry;
    uint64_t irq_flags;
    int status;
    (void)context;
    if (!process || !flags || descriptor < 0 ||
        descriptor >= EDGE_MAX_FD)
        return -EBADF;
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &process->table_runtime, (uint32_t)descriptor) ||
        !process->fds[descriptor].used) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }
    entry = &process->fds[descriptor];
    status = fd_description_refresh_status(entry);
    if (status < 0) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }
    *flags = (uint32_t)entry->flags;
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    return 0;
}

static int x86_fd_set_status_flags(void *context, int32_t descriptor,
                                   uint32_t flags) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t source;
    uint64_t irq_flags;
    int reference;
    int status;
    (void)context;
    status = fd_snapshot_retain(process, descriptor, &source);
    if (status < 0)
        return status == -ENOMEM ? -ENOMEM : -EBADF;
    reference = source.file_ref;
    if (kernel_file_description_status_update(
            file_ref_locator(reference), UINT32_MAX, flags) < 0) {
        (void)fd_release_entry(&source, 0, 0, 0);
        return -EBADF;
    }
    for (int process_index = 0; process_index < EDGE_MAX_FD_PROCS;
         ++process_index) {
        edge_fd_proc_t *candidate = g_fd_procs[process_index];
        if (!candidate || !candidate->pid) continue;
        irq_flags = kernel_fd_table_lock(&candidate->table_runtime);
        for (int number = 0; number < EDGE_MAX_FD; ++number)
            if (kernel_fd_table_is_open_locked(
                    &candidate->table_runtime, (uint32_t)number) &&
                candidate->fds[number].used &&
                candidate->fds[number].file_ref == reference)
                kernel_fd_apply_status_flags(
                    &candidate->fds[number], UINT32_MAX, flags);
        kernel_fd_table_unlock(&candidate->table_runtime, irq_flags);
    }
    (void)fd_release_entry(&source, 0, 0, 0);
    return 0;
}

static int x86_fd_pipe_capacity(void *context, int32_t descriptor,
                                uint32_t *capacity) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_kind_t kind;
    uint64_t irq_flags;
    (void)context;
    if (!process || !capacity || descriptor < 0 ||
        descriptor >= EDGE_MAX_FD)
        return -EBADF;
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &process->table_runtime, (uint32_t)descriptor) ||
        !process->fds[descriptor].used) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        return -EBADF;
    }
    kind = process->fds[descriptor].kind;
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    if (kind != FD_PIPE_R && kind != FD_PIPE_W &&
        kind != FD_PIPE_RW)
        return -EBADF;
    *capacity = EDGE_PIPE_SIZE;
    return 0;
}

static int64_t x86_fd_fcntl_fallback(void *context, int32_t descriptor,
                                     uint32_t command, uint64_t argument) {
    (void)context;
    return (int64_t)do_sys_fcntl((uint64_t)(uint32_t)descriptor,
                                 command, argument);
}

static int x86_fd_pidfd_install(void *context, int32_t pid,
                                uint32_t flags);
static int x86_fd_pidfd_target(void *context, int32_t descriptor,
                               int32_t *pid, uint32_t *flags);
static int x86_fd_pidfd_lookup(void *context, int32_t pid,
                               int32_t *tgid);

static const kernel_fd_backend_ops_t x86_fd_backend_ops = {
    .table_limit = x86_fd_table_limit,
    .allocation_limit = x86_fd_allocation_limit,
    .table_unshare = x86_fd_table_unshare,
    .is_open = x86_fd_is_open,
    .operation_acquire = x86_fd_operation_acquire,
    .operation_acquire_for_owner =
        x86_fd_operation_acquire_for_owner,
    .operation_acquire_for_pid =
        x86_fd_operation_acquire_for_pid,
    .operation_release = x86_fd_operation_release,
    .operation_transfer = x86_fd_operation_transfer,
    .operation_clone = x86_fd_operation_clone,
    .operation_description_id =
        x86_fd_operation_description_id,
    .operation_ready = x86_fd_operation_ready,
    .operation_vector_io = x86_fd_operation_vector_io,
    .operation_file_range =
        x86_fd_operation_file_range,
    .operation_socket = x86_fd_operation_socket,
    .transfer_target_capture = x86_fd_transfer_target_capture,
    .transfer_target_capture_for_owner =
        x86_fd_transfer_target_capture_for_owner,
    .transfer_target_capture_for_pid =
        x86_fd_transfer_target_capture_for_pid,
    .transfer_target_release = x86_fd_transfer_target_release,
    .transfer_target_prepare = x86_fd_transfer_target_prepare,
    .transfer_target_prepare_exact =
        x86_fd_transfer_target_prepare_exact,
    .transfer_target_discard_prepared =
        x86_fd_transfer_target_discard_prepared,
    .transfer_target_publish_many =
        x86_fd_transfer_target_publish_many,
    .transfer_target_abort_many =
        x86_fd_transfer_target_abort_many,
    .close = x86_fd_close,
    .duplicate_exact = x86_fd_duplicate_exact,
    .duplicate_minimum = x86_fd_duplicate_minimum,
    .get_descriptor_flags = x86_fd_get_descriptor_flags,
    .set_descriptor_flags = x86_fd_set_descriptor_flags,
    .get_status_flags = x86_fd_get_status_flags,
    .set_status_flags = x86_fd_set_status_flags,
    .pipe_capacity = x86_fd_pipe_capacity,
    .pidfd_lookup = x86_fd_pidfd_lookup,
    .pidfd_install = x86_fd_pidfd_install,
    .pidfd_target = x86_fd_pidfd_target,
    .fcntl_fallback = x86_fd_fcntl_fallback,
};

static int x86_fd_pidfd_lookup(void *context, int32_t pid,
                               int32_t *tgid) {
    const task_t *target = process_get_task(pid);
    (void)context;
    if (!target || !tgid) return -ESRCH;
    *tgid = target->tgid > 0 ? target->tgid : target->pid;
    return 0;
}

static int x86_fd_pidfd_install(void *context, int32_t pid,
                                uint32_t flags) {
    int descriptor;
    edge_fd_proc_t *process;
    edge_fd_t *entry;
    (void)context;
    descriptor = alloc_special_fd(
        FD_PIDFD, pid, LINUX_O_CLOEXEC | (int)(flags & LINUX_O_NONBLOCK));
    if (descriptor < 0) return descriptor;
    process = fd_proc_with_stdio();
    entry = process ? fd_get(process, descriptor) : 0;
    if (!entry) {
        (void)do_sys_close((uint64_t)(uint32_t)descriptor);
        return -EBADF;
    }
    entry->pidfd_flags = flags & LINUX_O_EXCL;
    return descriptor;
}

static int x86_fd_pidfd_target(void *context, int32_t descriptor,
                               int32_t *pid, uint32_t *flags) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry = process ? fd_get(process, descriptor) : 0;
    (void)context;
    if (!entry || entry->kind != FD_PIDFD || !pid || !flags)
        return -EBADF;
    *pid = entry->pipe_id;
    *flags = entry->pidfd_flags;
    return 0;
}

int arch_fd_file_lock_info(int32_t descriptor,
                           kernel_file_lock_info_t *information) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry = process ? fd_get(process, descriptor) : 0;
    return fd_file_lock_info_for_entry(entry, process_current_task(),
                                       information);
}

int arch_file_lock_wait_prepare(void *user_registers, int32_t task_id) {
    task_t *task = process_current_task();
    uint64_t flags;
    (void)user_registers;
    if (!task || task->pid != task_id) return -ESRCH;
    flags = spin_lock_irqsave(&task->file_lock_wait_lock);
    if (task->file_lock_wait_active) {
        spin_unlock_irqrestore(&task->file_lock_wait_lock, flags);
        return -EDGE_LINUX_EDEADLK;
    }
    task->file_lock_wait_result = -EINPROGRESS;
    task->file_lock_wait_active = 1;
    spin_unlock_irqrestore(&task->file_lock_wait_lock, flags);
    return 0;
}

int64_t arch_file_lock_wait_park(int32_t task_id) {
    task_t *task = process_current_task();
    if (!task || task->pid != task_id) return -ESRCH;
    for (;;) {
        uint64_t flags;
        int active;
        int64_t result;
        if (signal_pending_interrupt())
            (void)edge_linux_file_lock_cancel_wait(task_id, -EINTR);
        flags = spin_lock_irqsave(&task->file_lock_wait_lock);
        active = task->file_lock_wait_active;
        result = task->file_lock_wait_result;
        if (active) scheduler_task_set_blocked(task);
        spin_unlock_irqrestore(&task->file_lock_wait_lock, flags);
        if (!active) return result;
        scheduler_yield();
    }
}

void arch_file_lock_wake(int32_t task_id, int64_t result) {
    task_t *task = task_by_pid_mutable_local(task_id);
    uint64_t flags;
    if (!task || task->state == TASK_UNUSED || task->state == TASK_ZOMBIE)
        return;
    flags = spin_lock_irqsave(&task->file_lock_wait_lock);
    if (!task->file_lock_wait_active) {
        spin_unlock_irqrestore(&task->file_lock_wait_lock, flags);
        return;
    }
    task->file_lock_wait_result = result;
    task->file_lock_wait_active = 0;
    if (task->state == TASK_BLOCKED)
        scheduler_task_make_runnable(task, scheduler_cpu_id());
    spin_unlock_irqrestore(&task->file_lock_wait_lock, flags);
}

int arch_mm_program_break_snapshot(
    kernel_mm_program_break_state_t *state) {
    task_t *cur = process_current_task();
    task_t *mm;

    if (!cur || !state) return -ESRCH;
    mm = process_vm_task(cur);
    if (!mm) return -ESRCH;
    state->base = mm->user_heap_base;
    state->current = mm->user_brk;
    state->maximum = mm->user_heap_limit;
    return 0;
}

int arch_mm_program_break_resize(uint64_t old_page, uint64_t new_page) {
    task_t *cur = process_current_task();
    task_t *mm = cur ? process_vm_task(cur) : 0;

    if (!mm) return -ESRCH;
    if (new_page > old_page) {
        int live = mm->user_vma_count;
        if ((uint32_t)live > mm->user_vma_capacity)
            live = (int)mm->user_vma_capacity;
        for (int i = 0; i < live; ++i) {
            edge_user_vma_t *v = &mm->user_vmas[i];
            if (v->end <= v->start) continue;
            if (v->end <= old_page || v->start >= new_page) continue;
            return -ENOMEM;
        }
    } else if (new_page < old_page &&
               process_user_heap_unmap(
                   mm, new_page, old_page - new_page) < 0) {
        return -ENOMEM;
    }
    return 0;
}

void arch_mm_program_break_commit(uint64_t address) {
    task_t *cur = process_current_task();
    task_t *mm = cur ? process_vm_task(cur) : 0;

    if (!mm) return;
    mm->user_brk = address;
    cur->user_brk = address;
}

static void user_vma_recount(task_t *t);

static int user_vma_find_free_slot(task_t *t) {
    if (!t) return -1;
    if (t->user_vma_count > t->user_vma_capacity)
        user_vma_recount(t);
    if (t->user_vma_count < t->user_vma_capacity) {
        uint32_t slot = t->user_vma_count;
        if (t->user_vmas[slot].end <= t->user_vmas[slot].start)
            return (int)slot;
    }
    user_vma_recount(t);
    if (t->user_vma_count >= PROCESS_USER_VMA_MAX ||
        process_user_vma_reserve(t, t->user_vma_count + 1u) < 0)
        return -1;
    return (int)t->user_vma_count;
}

static void user_vma_commit_slot(task_t *t, int slot) {
    if (!t || slot < 0 || (uint32_t)slot >= t->user_vma_capacity ||
        (uint32_t)slot >= PROCESS_USER_VMA_MAX)
        return;
    if (slot >= (int)t->user_vma_count) {
        t->user_vma_count = (uint32_t)slot + 1u;
    }
}

static int user_vma_free_slot_count(task_t *t) {
    if (!t) return 0;
    user_vma_recount(t);
    if (t->user_vma_count >= t->user_vma_capacity) return 0;
    return (int)(t->user_vma_capacity - t->user_vma_count);
}

static int user_vma_live_limit(task_t *t) {
    if (!t) return 0;
    if (t->user_vma_count > t->user_vma_capacity) {
        user_vma_recount(t);
    }
    return (int)t->user_vma_count;
}

static void user_vma_compact(task_t *t) {
    int write = 0;
    int live;
    if (!t) return;
    /*
     * Keep live VMA descriptors in a dense prefix. Linux's VMA tree gives
     * mm operations lookup over live areas; EdgeOS uses a dynamically grown
     * compact store, so desktop workloads become pathological if munmap/mprotect
     * leaves sparse live entries near the end of the table.  Fast paths that
     * stop after user_vma_count depend on this invariant.
     */
    live = t->user_vma_count;
    if ((uint32_t)live > t->user_vma_capacity)
        live = (int)t->user_vma_capacity;
    for (int read = 0; read < live; ++read) {
        edge_user_vma_t *v = &t->user_vmas[read];
        if (v->end <= v->start) continue;
        if (write != read) {
            t->user_vmas[write] = *v;
            memset(v, 0, sizeof(*v));
        }
        ++write;
    }
    t->user_vma_count = (uint32_t)write;
}

static void user_vma_recount(task_t *t) {
    if (!t) return;
    user_vma_compact(t);
}

static void user_vma_refresh_mmap_hint(task_t *t) {
    uint64_t hint;
    int live;
    if (!t) return;
    hint = USER_MMAP_LIMIT_ADDR;
    live = user_vma_live_limit(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        if (v->end <= v->start) continue;
        if (v->start < USER_MMAP_BASE_ADDR || v->start >= USER_MMAP_LIMIT_ADDR) continue;
        if (v->start < hint) hint = v->start;
    }
    t->user_mmap_next = hint;
}

static void user_vma_note_mmap_range(task_t *t, uint64_t start) {
    if (!t) return;
    if (start < USER_MMAP_BASE_ADDR || start >= USER_MMAP_LIMIT_ADDR) return;
    if (t->user_mmap_next < USER_MMAP_BASE_ADDR ||
        t->user_mmap_next > USER_MMAP_LIMIT_ADDR ||
        start < t->user_mmap_next) {
        t->user_mmap_next = start;
    }
}

static int user_vma_can_merge(const edge_user_vma_t *a, const edge_user_vma_t *b) {
    if (!a || !b) return 0;
    if (a->end <= a->start || b->end <= b->start) return 0;
    if (a->prot != b->prot || a->flags != b->flags ||
        a->fork_policy != b->fork_policy)
        return 0;
    if (a->file_backed || b->file_backed) {
        uint64_t a_len;
        uint64_t b_len;
        /*
         * Linux keeps adjacent compatible file VMAs mergeable after mprotect()
         * splits.  Dynamic loaders and plugin scanners repeatedly protect
         * single pages in shared libraries; if those file VMAs never coalesce,
         * later ABI operations scan thousands of fragments and XFCE startup
         * looks hung even though syscalls are succeeding.  Merge only when the
         * mapping is the same backing file and the file offsets are contiguous.
         */
        if (!a->file_backed || !b->file_backed) return 0;
        if (a->file_slot != b->file_slot) return 0;
        a_len = a->end - a->start;
        b_len = b->end - b->start;
        if (a->end == b->start && a->file_off + a_len == b->file_off) return 1;
        if (b->end == a->start && b->file_off + b_len == a->file_off) return 1;
        return 0;
    }
    return !(a->end < b->start || b->end < a->start);
}

static void user_vma_coalesce_slot(task_t *t, int slot) {
    edge_user_vma_t *a;
    if (!t || slot < 0 || (uint32_t)slot >= t->user_vma_capacity) return;
    a = &t->user_vmas[slot];
    if (a->end <= a->start) {
        user_vma_recount(t);
        user_vma_refresh_mmap_hint(t);
        return;
    }
    for (;;) {
        int merged = 0;
        int live = user_vma_live_limit(t);
        for (int i = 0; i < live; ++i) {
            edge_user_vma_t *b;
            if (i == slot) continue;
            b = &t->user_vmas[i];
            if (!user_vma_can_merge(a, b)) continue;
            if (a->file_backed) {
                uint64_t a_file_end = a->file_off + a->file_len;
                uint64_t b_file_end = b->file_off + b->file_len;
                uint64_t new_start = a->start < b->start ? a->start : b->start;
                uint64_t new_end = a->end > b->end ? a->end : b->end;
                uint64_t new_file_off;
                uint64_t new_file_end;
                /*
                 * Linux VMAs describe both a virtual range and the exact file
                 * byte range still backed by that mapping.  mprotect/munmap can
                 * split file VMAs at page granularity, and coalescing must not
                 * rebuild file_len from virtual length: the last page of a file
                 * mapping may be only partially file-backed, with the remainder
                 * zero-filled.  Losing that boundary lets later lazy faults read
                 * bytes from the wrong part of a shared object, which corrupts
                 * dynamic-loader state in desktop processes.
                 */
                new_file_off = (a->start <= b->start) ? a->file_off : b->file_off;
                new_file_end = a_file_end > b_file_end ? a_file_end : b_file_end;
                if (new_file_end < new_file_off) new_file_end = new_file_off;
                if (new_file_end - new_file_off > new_end - new_start) {
                    new_file_end = new_file_off + (new_end - new_start);
                }
                a->start = new_start;
                a->end = new_end;
                a->file_off = new_file_off;
                a->file_len = new_file_end - new_file_off;
            } else {
                if (b->start < a->start) a->start = b->start;
                if (b->end > a->end) a->end = b->end;
            }
            process_user_vma_release_backing(b);
            memset(b, 0, sizeof(*b));
            merged = 1;
        }
        if (!merged) break;
    }
    user_vma_recount(t);
}

static void user_vma_merge_compatible(task_t *t) {
    int live;
    int write;

    if (!t) return;
    /*
     * Full desktop stacks can carry more than a thousand VMAs and repeatedly
     * split them with mprotect().  Calling user_vma_coalesce_slot() for every
     * live slot makes one protection change quadratic in the VMA count because
     * each slot scans the complete array.  Sort the dense descriptor prefix by
     * virtual address, then coalesce adjacent compatible ranges in one pass.
     * Non-overlapping VMAs that can merge are necessarily neighbors after the
     * sort, so this preserves the existing merge policy without the all-pairs
     * scan.
     *
     * Red flag: keep file offsets and partial final-page lengths exact while
     * merging.  Reconstructing file_len from the virtual span can make a later
     * lazy fault read beyond the mapped part of a shared object.
     */
    user_vma_recount(t);
    live = user_vma_live_limit(t);
    for (int gap = live / 2; gap > 0; gap /= 2) {
        for (int index = gap; index < live; ++index) {
            edge_user_vma_t value = t->user_vmas[index];
            int position = index;

            while (position >= gap &&
                   t->user_vmas[position - gap].start > value.start) {
                t->user_vmas[position] =
                    t->user_vmas[position - gap];
                position -= gap;
            }
            t->user_vmas[position] = value;
        }
    }

    write = 0;
    for (int read = 0; read < live; ++read) {
        edge_user_vma_t *current = &t->user_vmas[read];
        edge_user_vma_t *previous;

        if (current->end <= current->start) continue;
        previous = write > 0 ? &t->user_vmas[write - 1] : 0;
        if (previous && user_vma_can_merge(previous, current)) {
            if (previous->file_backed) {
                uint64_t previous_file_end =
                    previous->file_off + previous->file_len;
                uint64_t current_file_end =
                    current->file_off + current->file_len;
                uint64_t new_start =
                    previous->start < current->start ?
                    previous->start : current->start;
                uint64_t new_end =
                    previous->end > current->end ?
                    previous->end : current->end;
                uint64_t new_file_off =
                    previous->start <= current->start ?
                    previous->file_off : current->file_off;
                uint64_t new_file_end =
                    previous_file_end > current_file_end ?
                    previous_file_end : current_file_end;

                if (new_file_end < new_file_off)
                    new_file_end = new_file_off;
                if (new_file_end - new_file_off > new_end - new_start)
                    new_file_end = new_file_off + (new_end - new_start);
                previous->start = new_start;
                previous->end = new_end;
                previous->file_off = new_file_off;
                previous->file_len = new_file_end - new_file_off;
            } else {
                if (current->start < previous->start)
                    previous->start = current->start;
                if (current->end > previous->end)
                    previous->end = current->end;
            }
            process_user_vma_release_backing(current);
            memset(current, 0, sizeof(*current));
            continue;
        }
        if (write != read) {
            t->user_vmas[write] = *current;
            memset(current, 0, sizeof(*current));
        }
        ++write;
    }
    t->user_vma_count = (uint32_t)write;
    user_vma_refresh_mmap_hint(t);
}

/*
 * File-backed MAP_SHARED VMAs must survive fd close, fork, and later msync or
 * munmap. Store backing paths in a small kernel-global intern table instead of
 * embedding a full path in every VMA or every task; task_t is already large and
 * growing it can push the multiboot BSS beyond what GRUB can load.
 */
/*
 * Linux has no small global cap on the number of distinct pathnames that may
 * be mapped by processes over the lifetime of the system.  EdgeOS keeps compact
 * file-slot metadata so sparse mmap faults can resolve pages after the original
 * fd is closed, and so read-only executable/shared-library pages can be cached.
 * A full XFCE login through Alpine's unmodified rootfs can easily touch more
 * than 512 unique .so/font/plugin paths: tumblerd and GStreamer scan plugin
 * directories, then Thunar/xfdesktop/panel pull in their own GLib/GTK stacks.
 * Returning ENOMEM when this table fills makes dlopen(3) report "Out of
 * memory" even while the VM has real RAM available.
 *
 * Red flag: do not replace this with an Alpine/XFCE path denylist.  This is a
 * Linux mmap ABI resource.  If this table becomes pressure again, implement a
 * real unused-slot reclaim pass keyed on live VMAs and file-page-cache refs.
 */
#define USER_MMAP_FILE_SLOT_MAX 4096
typedef struct user_mmap_file_slot {
    uint8_t used;
    uint8_t have_inode;
    uint8_t orphaned;
    uint8_t orphan_ref;
    uint32_t cache_generation;
    uint32_t mapping_refs;
    int32_t orphan_next;
    uint8_t orphan_pending;
    uint8_t reclaiming;
    uint8_t _pad[2];
    uint64_t last_used_sequence;
    vfs_inode_t inode;
    vfs_superblock_t *sb;
    char path[TASK_CWD_MAX];
} user_mmap_file_slot_t;

static user_mmap_file_slot_t g_user_mmap_file_slots[USER_MMAP_FILE_SLOT_MAX];
static volatile int g_user_mmap_file_slot_lock;
static int32_t g_user_mmap_orphan_head = -1;
static int32_t g_user_mmap_orphan_tail = -1;
static uint64_t g_user_mmap_file_use_sequence;
static uint32_t g_user_mmap_file_slot_high;

#define USER_MMAP_FILE_RECLAIM_BATCH 256u
static volatile int g_user_mmap_file_reclaim_lock;
static kernel_mm_reclaim_candidate_t
    g_user_mmap_file_reclaim_selection[USER_MMAP_FILE_RECLAIM_BATCH];
static int16_t
    g_user_mmap_file_reclaim_index[USER_MMAP_FILE_SLOT_MAX];
static uint8_t
    g_user_mmap_file_reclaim_failed[USER_MMAP_FILE_RECLAIM_BATCH];
static uint64_t g_user_mmap_file_live_slots[
    (USER_MMAP_FILE_SLOT_MAX + 63u) / 64u];
static vfs_superblock_t *
    g_user_mmap_file_reclaim_superblocks[USER_MMAP_FILE_RECLAIM_BATCH];

/*
 * Cache read-only file mmap pages globally.  Desktop stacks map the same shared
 * libraries in many processes; without this cache, every client gets private
 * copies and the sparse backing pool is exhausted.  Keep the cache comfortably
 * above the old 384 MiB cap so plugin scanners do not fail before the 2 GiB
 * sparse backing pool is actually pressured.
 */
#define USER_MMAP_FILE_PAGE_CACHE_MAX 262144
#define USER_MMAP_FILE_READAHEAD_PAGES EDGE_FILE_MAPPING_FAULT_BATCH_PAGES
#define USER_MMAP_FILE_PAGE_CACHE_HASH_MAX 524288
typedef struct user_mmap_file_page_cache {
    uint8_t used;
    uint8_t writable_seen;
    uint8_t write_notify_armed;
    uint8_t _pad[5];
    uint16_t file_slot;
    uint16_t _pad2;
    uint32_t slot_generation;
    uint64_t file_page_off;
    int backing_idx;
    uint32_t backing_generation;
    kernel_mm_cache_state_t reclaim;
} user_mmap_file_page_cache_t;

static user_mmap_file_page_cache_t g_user_mmap_file_page_cache[USER_MMAP_FILE_PAGE_CACHE_MAX];
static int g_user_mmap_file_page_cache_hash[USER_MMAP_FILE_PAGE_CACHE_HASH_MAX];
static int g_user_mmap_file_page_cache_high;
static int g_user_mmap_file_page_cache_free_hint;
static volatile int g_user_mmap_file_page_cache_lock;
static uint64_t g_user_mmap_file_page_cache_sequence;

static int g_user_mmap_debug_budget = 0;
static int g_user_mmap_large_file_log_budget = 0;
static int g_apk_mmap_trace_budget = 0;
static int g_apk_libcrypto_vma_dump_budget = 0;
static int g_user_mmap_exec_fault_log_budget = 0;
static int g_user_vma_overlap_log_budget = 32;
static int g_user_mmap_cache_fail_log_budget = 48;
static int g_user_mmap_fail_log_budget = 96;
static int g_user_mmap_resource_fail_log_budget = 16;
static int g_user_mmap_dso_diag_budget = 0;
static int g_apk_libcrypto_phdr_budget = 0;
static int g_apk_libcrypto_ro_write_budget = 0;
static int g_apk_libcrypto_inode_budget = 0;

static const char *user_mmap_file_path(uint16_t slot);
static int x86_mmap_orphan_drain(uint32_t maximum_slots);
static void user_mmap_file_cache_lock(void);
static void user_mmap_file_cache_unlock(void);
static int edge_mmap_file_cache_writeback_page(
    user_mmap_file_page_cache_t *page);

static int x86_page_writeback_backend(uint64_t token,
                                      uint32_t dirty_generation,
                                      void *context) {
    uint32_t page_slot = (uint32_t)token;
    uint32_t slot_generation = (uint32_t)(token >> 32u);
    user_mmap_file_page_cache_t *page;
    int rearm_write_notify;
    int result;
    (void)dirty_generation;
    (void)context;
    if (!page_slot--) return VFS_PAGE_WRITEBACK_DISCARD;
    user_mmap_file_cache_lock();
    if (page_slot >= (uint32_t)g_user_mmap_file_page_cache_high ||
        !g_user_mmap_file_page_cache[page_slot].used ||
        g_user_mmap_file_page_cache[page_slot].slot_generation !=
            slot_generation) {
        user_mmap_file_cache_unlock();
        return VFS_PAGE_WRITEBACK_DISCARD;
    }
    page = &g_user_mmap_file_page_cache[page_slot];
    rearm_write_notify = !page->write_notify_armed;
    if (rearm_write_notify) {
        for (int index = 0;
             index < g_user_mmap_file_page_cache_high; ++index) {
            if (g_user_mmap_file_page_cache[index].used)
                g_user_mmap_file_page_cache[index].write_notify_armed = 1u;
        }
    }
    user_mmap_file_cache_unlock();
    if (rearm_write_notify)
        process_user_mmap_writeprotect_all_file_cache();
    result = edge_mmap_file_cache_writeback_page(page);
    return result < 0 ? VFS_PAGE_WRITEBACK_ERR_IO :
                        VFS_PAGE_WRITEBACK_COMPLETE;
}

static void x86_page_writeback_forget_cache(
    const user_mmap_file_page_cache_t *page, uint32_t page_slot) {
    uint64_t token;
    if (!page || !page->used) return;
    token = ((uint64_t)page->slot_generation << 32u) |
            (uint64_t)(page_slot + 1u);
    vfs_page_writeback_forget_token(
        x86_page_writeback_backend, 0, token);
}

static void user_mmap_file_slot_lock(void) {
    uint32_t spins = 0;

    while (__sync_lock_test_and_set(&g_user_mmap_file_slot_lock, 1)) {
        task_t *cur = process_current_task();

        __asm__ __volatile__("pause");
        ++spins;
        if (cur && !cur->is_idle && cur->pid > 0 &&
            cur->state == TASK_RUNNING &&
            (spins & 0x3fffu) == 0u)
            scheduler_yield();
    }
}

static void user_mmap_file_slot_unlock(void) {
    __sync_lock_release(&g_user_mmap_file_slot_lock);
}

static uint32_t user_mmap_file_slot_limit(void) {
    return __atomic_load_n(
        &g_user_mmap_file_slot_high, __ATOMIC_ACQUIRE);
}

/* g_user_mmap_file_slot_lock is held and the new slot is fully initialized. */
static void user_mmap_file_slot_publish_high_locked(
    uint32_t exclusive_limit) {
    uint32_t current = __atomic_load_n(
        &g_user_mmap_file_slot_high, __ATOMIC_RELAXED);
    if (exclusive_limit > current)
        __atomic_store_n(
            &g_user_mmap_file_slot_high, exclusive_limit,
            __ATOMIC_RELEASE);
}

/* g_user_mmap_file_slot_lock is held. */
static void user_mmap_file_slot_touch_locked(
    user_mmap_file_slot_t *slot) {
    if (!slot) return;
    ++g_user_mmap_file_use_sequence;
    if (!g_user_mmap_file_use_sequence)
        ++g_user_mmap_file_use_sequence;
    slot->last_used_sequence = g_user_mmap_file_use_sequence;
}

/* g_user_mmap_file_slot_lock is held. */
static void user_mmap_file_slot_refresh_identity_locked(
    user_mmap_file_slot_t *slot, const vfs_inode_t *inode) {
    if (!slot || !inode) return;
    slot->inode = *inode;
    /*
     * A process may unlink a temporary file before mmap(2).  The descriptor
     * still supplies a valid inode, but the unlink notification necessarily
     * preceded creation of this cache identity.  Record that state here so
     * the final VMA release preserves and then retires the inode consistently
     * with the AArch64 file-page cache.
     */
    if (vfs_inode_link_count(inode) == 0) slot->orphaned = 1;
}

static void user_mmap_file_reclaim_lock(void) {
    uint32_t spins = 0;

    while (__sync_lock_test_and_set(
               &g_user_mmap_file_reclaim_lock, 1)) {
        task_t *cur = process_current_task();

        __asm__ __volatile__("pause");
        ++spins;
        if (cur && !cur->is_idle && cur->pid > 0 &&
            cur->state == TASK_RUNNING &&
            (spins & 0x3fffu) == 0u)
            scheduler_yield();
    }
}

static void user_mmap_file_reclaim_unlock(void) {
    __sync_lock_release(&g_user_mmap_file_reclaim_lock);
}

/* g_user_mmap_file_slot_lock is held. */
static void user_mmap_orphan_enqueue_locked(uint16_t file_slot) {
    user_mmap_file_slot_t *slot;
    if (file_slot >= USER_MMAP_FILE_SLOT_MAX) return;
    slot = &g_user_mmap_file_slots[file_slot];
    if (!slot->used || !slot->orphaned || !slot->orphan_ref ||
        slot->orphan_pending)
        return;
    slot->orphan_pending = 1;
    slot->orphan_next = -1;
    if (g_user_mmap_orphan_tail >= 0)
        g_user_mmap_file_slots[g_user_mmap_orphan_tail].orphan_next =
            (int32_t)file_slot;
    else
        g_user_mmap_orphan_head = (int32_t)file_slot;
    g_user_mmap_orphan_tail = (int32_t)file_slot;
}

/* g_user_mmap_file_slot_lock is held. */
static int32_t user_mmap_orphan_pop_locked(void) {
    int32_t file_slot = g_user_mmap_orphan_head;
    user_mmap_file_slot_t *slot;
    if (file_slot < 0 || file_slot >= USER_MMAP_FILE_SLOT_MAX) return -1;
    slot = &g_user_mmap_file_slots[file_slot];
    g_user_mmap_orphan_head = slot->orphan_next;
    if (g_user_mmap_orphan_head < 0) g_user_mmap_orphan_tail = -1;
    slot->orphan_next = -1;
    slot->orphan_pending = 0;
    return file_slot;
}

static int user_mmap_file_slot_mapping_retain(uint16_t file_slot) {
    user_mmap_file_slot_t *slot;
    int result = -1;
    if (file_slot >= USER_MMAP_FILE_SLOT_MAX) return -1;
    user_mmap_file_slot_lock();
    slot = &g_user_mmap_file_slots[file_slot];
    if (slot->used && !slot->reclaiming && slot->have_inode &&
        slot->mapping_refs != UINT32_MAX) {
        ++slot->mapping_refs;
        user_mmap_file_slot_touch_locked(slot);
        result = 0;
    }
    user_mmap_file_slot_unlock();
    return result;
}

static void user_mmap_file_slot_mapping_release(uint16_t file_slot) {
    user_mmap_file_slot_t *slot;
    if (file_slot >= USER_MMAP_FILE_SLOT_MAX) return;
    user_mmap_file_slot_lock();
    slot = &g_user_mmap_file_slots[file_slot];
    if (slot->used && slot->mapping_refs) --slot->mapping_refs;
    if (slot->used && slot->orphaned && slot->orphan_ref)
        user_mmap_orphan_enqueue_locked(file_slot);
    user_mmap_file_slot_unlock();
}

static int user_mmap_file_slot_is_orphaned(uint16_t file_slot) {
    int result = 0;
    if (file_slot >= USER_MMAP_FILE_SLOT_MAX) return 0;
    user_mmap_file_slot_lock();
    if (g_user_mmap_file_slots[file_slot].used)
        result = g_user_mmap_file_slots[file_slot].orphaned != 0;
    user_mmap_file_slot_unlock();
    return result;
}

static void user_mmap_file_cache_lock(void) {
    uint32_t spins = 0;

    while (__sync_lock_test_and_set(&g_user_mmap_file_page_cache_lock, 1)) {
        task_t *cur = process_current_task();

        __asm__ __volatile__("pause");
        ++spins;
        if (cur && !cur->is_idle && cur->pid > 0 &&
            cur->state == TASK_RUNNING &&
            (spins & 0x3fffu) == 0u)
            scheduler_yield();
    }
}

static void user_mmap_file_cache_unlock(void) {
    __sync_lock_release(&g_user_mmap_file_page_cache_lock);
}

static void x86_file_cache_cachestat(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length,
    kernel_vfs_cache_stats_t *statistics) {
    uint64_t end;
    uint32_t generation = 0;
    int file_slot = -1;

    if (!superblock || !inode || !statistics) return;
    end = !length || length > UINT64_MAX - offset ?
          UINT64_MAX : offset + length;
    user_mmap_file_slot_lock();
    for (uint32_t slot = 0; slot < user_mmap_file_slot_limit(); ++slot) {
        const user_mmap_file_slot_t *candidate =
            &g_user_mmap_file_slots[slot];
        if (!candidate->used || candidate->reclaiming ||
            !candidate->have_inode ||
            !vfs_inode_same_object(
                candidate->sb, &candidate->inode,
                superblock, inode))
            continue;
        file_slot = (int)slot;
        generation = candidate->cache_generation;
        break;
    }
    user_mmap_file_slot_unlock();
    if (file_slot < 0) return;

    user_mmap_file_cache_lock();
    for (int slot = 0; slot < g_user_mmap_file_page_cache_high; ++slot) {
        const user_mmap_file_page_cache_t *page =
            &g_user_mmap_file_page_cache[slot];
        if (!page->used || page->file_slot != (uint16_t)file_slot ||
            page->slot_generation != generation ||
            page->file_page_off < offset || page->file_page_off >= end ||
            !process_user_mmap_backing_page_active(page->backing_idx) ||
            process_user_mmap_backing_page_generation(page->backing_idx) !=
                page->backing_generation)
            continue;
        ++statistics->cached_pages;
    }
    user_mmap_file_cache_unlock();
}

static int user_mmap_is_apk_libcrypto(task_t *t, const char *path) {
    const char *n = (t && t->name[0]) ? t->name : "";
    return strcmp(n, "apk") == 0 && path && strstr(path, "/usr/lib/libcrypto.so.3") != 0;
}

static void user_mmap_dump_apk_libcrypto_vmas(task_t *t, const char *tag,
                                              uint64_t base, uint64_t len,
                                              uint64_t prot, uint64_t flags,
                                              uint64_t off) {
    int live;
    uint64_t end;
    if (g_apk_libcrypto_vma_dump_budget <= 0) return;
    if (!t) return;
    end = base + len;
    if (end < base) end = ~0ULL;
    g_apk_libcrypto_vma_dump_budget--;
    live = user_vma_live_limit(t);
    printf("[apk-libcrypto-vmas] %s pid=%d base=0x%x len=0x%x prot=0x%x flags=0x%x off=0x%x live=%d budget=%d\n",
           tag ? tag : "?",
           t->pid,
           (uint32_t)base, (uint32_t)len,
           (uint32_t)prot, (uint32_t)flags, (uint32_t)off,
           live, g_apk_libcrypto_vma_dump_budget);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        const char *path;
        if (v->end <= v->start) continue;
        path = v->file_backed ? user_mmap_file_path(v->file_slot) : "-";
        if (v->file_backed && (!path || strstr(path, "/usr/lib/libcrypto.so.3") == 0)) continue;
        if (!v->file_backed && (v->end <= base || v->start >= end)) continue;
        printf("[apk-libcrypto-vma] slot=%d 0x%x-0x%x prot=0x%x flags=0x%x file_off=0x%x file_len=0x%x path=%s\n",
               i,
               (uint32_t)v->start, (uint32_t)v->end,
               v->prot, v->flags,
               (uint32_t)v->file_off, (uint32_t)v->file_len,
               path && path[0] ? path : "-");
    }
}

static void user_mmap_log_apk_libcrypto_inode(task_t *t, const char *tag,
                                              const char *path, int file_slot,
                                              const vfs_inode_t *ino,
                                              vfs_superblock_t *sb) {
    if (g_apk_libcrypto_inode_budget <= 0) return;
    if (!user_mmap_is_apk_libcrypto(t, path)) return;
    g_apk_libcrypto_inode_budget--;
    printf("[apk-libcrypto-inode] %s pid=%d slot=%d ino=%u size=%u mode=0x%x sb=%s:%s path=%s budget=%d\n",
           tag ? tag : "?",
           t ? t->pid : -1,
           file_slot,
           ino ? ino->ino : 0,
           ino ? ino->size : 0,
           ino ? ino->mode : 0,
           sb ? sb->fs_name : "-",
           sb ? sb->dev_name : "-",
           path ? path : "-",
           g_apk_libcrypto_inode_budget);
}

static int user_mmap_trace_process(const task_t *t) {
    const char *n;
    if (!t || !t->name[0]) return 0;
    n = t->name;
    if (g_apk_mmap_trace_budget > 0 && strcmp(n, "apk") == 0) {
        g_apk_mmap_trace_budget--;
        return 1;
    }
    /*
     * Xorg, GTK and the session daemons call mmap/mprotect heavily during
     * normal startup.  Serial logging materially changes desktop
     * responsiveness, so VM operation traces are opt-in only.
     */
    if (EDGE_GUI_DEEP_TRACE) {
        if (strcmp(n, "tumblerd") == 0) return 1;
        return strcmp(n, "exo-open") == 0 ||
               strcmp(n, "gst-plugin-scan") == 0 ||
               strcmp(n, "gst-plugin-scanner") == 0 ||
               strcmp(n, "xfce4-session") == 0 ||
               strcmp(n, "xfwm4") == 0 ||
               strcmp(n, "xfdesktop") == 0 ||
               strcmp(n, "xfsettingsd") == 0 ||
               strcmp(n, "xfce4-panel") == 0 ||
               strcmp(n, "Thunar") == 0 ||
               strcmp(n, "Xorg") == 0;
    }
    return 0;
}

static void user_mmap_trace_op(task_t *cur, const char *op, uint64_t addr, uint64_t len,
                               uint64_t a3, uint64_t a4, uint64_t ret,
                               const char *path) {
    static int budget = 256;
    if (budget <= 0 || !user_mmap_trace_process(cur)) return;
    budget--;
    printf("[vmop] pid=%d cmd=%s op=%s addr=0x%x len=0x%x a3=0x%x a4=0x%x ret=0x%x vmas=%u backing=%u/%u pt=%u/%u path=%s budget=%d\n",
           cur ? cur->pid : -1,
           cur && cur->name[0] ? cur->name : "?",
           op ? op : "?",
           (uint32_t)addr, (uint32_t)len,
           (uint32_t)a3, (uint32_t)a4, (uint32_t)ret,
           cur ? cur->user_vma_count : 0,
           process_user_mmap_backing_used_pages(),
           process_user_mmap_backing_total_pages(),
           process_user_mmap_pt_used_pages(),
           process_user_mmap_pt_total_pages(),
           path ? path : "-", budget);
}

static uint64_t user_mmap_fail(task_t *cur, const char *why, uint64_t ret,
                               uint64_t addr, uint64_t len, uint64_t prot,
                               uint64_t flags, int fd, uint64_t off,
                               const char *path) {
    task_t *mm = process_vm_task(cur);
    int traced = user_mmap_trace_process(cur);
    int resource_failure = (int64_t)ret == -ENOMEM &&
                           g_user_mmap_resource_fail_log_budget > 0;

    if (g_user_mmap_fail_log_budget > 0 && (traced || resource_failure)) {
        if (resource_failure) g_user_mmap_resource_fail_log_budget--;
        g_user_mmap_fail_log_budget--;
        printf("[mmap-fail] pid=%d mm=%d cmd=%s why=%s ret=%d addr=0x%x len=0x%x prot=0x%x flags=0x%x fd=%d off=0x%x hint=0x%x vmas=%u/%u backing=%u/%u pt=%u/%u path=%s budget=%d\n",
               cur ? cur->pid : -1, mm ? mm->pid : -1,
               cur && cur->name[0] ? cur->name : "?",
               why ? why : "?", (int)(int64_t)ret,
               (uint32_t)addr, (uint32_t)len, (uint32_t)prot,
               (uint32_t)flags, fd, (uint32_t)off,
               mm ? (uint32_t)mm->user_mmap_next : 0,
               mm ? mm->user_vma_count : 0, (uint32_t)PROCESS_USER_VMA_MAX,
               process_user_mmap_backing_used_pages(),
               process_user_mmap_backing_total_pages(),
               process_user_mmap_pt_used_pages(),
               process_user_mmap_pt_total_pages(),
               path ? path : "-", g_user_mmap_fail_log_budget);
    }
    return ret;
}

static void xorg_hash_change_check(const char *where, const char *path, uint64_t base, uint64_t len) {
    static int reported;
    task_t *cur;
    const volatile uint32_t *h;

    if (!EDGE_X11_TRACE) return;
    if (reported) return;
    cur = process_current_task();
    if (!cur || strcmp(cur->name, "Xorg") != 0) return;
    h = (const volatile uint32_t *)(uintptr_t)0x0000000000400388ULL;
    if (h[0] == 0x3f9u && h[1] == 0x193u && h[2] == 0x100u && h[3] == 0x0eu) return;
    reported = 1;
    printf("[xorg-hash-change] where=%s path=%s ret=0x%x len=0x%x hash=%x %x %x %x %x %x %x %x\n",
           where ? where : "?",
           path ? path : "-",
           (uint32_t)base, (uint32_t)len,
           h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
}

static void user_mmap_debug(task_t *cur, const char *why, uint64_t addr, uint64_t len,
                            uint64_t prot, uint64_t flags, int fd, uint64_t off,
                            const char *path) {
    if (g_user_mmap_debug_budget <= 0) return;
    g_user_mmap_debug_budget--;
    printf("[mmap-debug] pid=%d cmd=%s why=%s addr=0x%x len=0x%x prot=0x%x flags=0x%x fd=%d off=0x%x vmas=%u backing=%u/%u pt=%u/%u path=%s budget=%d\n",
           cur ? cur->pid : -1, cur && cur->name[0] ? cur->name : "?",
           why ? why : "?", (uint32_t)addr, (uint32_t)len, (uint32_t)prot,
           (uint32_t)flags, fd, (uint32_t)off, cur ? cur->user_vma_count : 0,
           process_user_mmap_backing_used_pages(), process_user_mmap_backing_total_pages(),
           process_user_mmap_pt_used_pages(), process_user_mmap_pt_total_pages(),
           path ? path : "-", g_user_mmap_debug_budget);
}

static void user_mmap_large_file_trace(task_t *cur, const char *phase, uint64_t base,
                                       uint64_t len, uint64_t prot, uint64_t flags,
                                       uint64_t off, const char *path) {
    if (g_user_mmap_large_file_log_budget <= 0) return;
    if (len < (512ULL * 1024ULL)) return;
    if (!cur) return;
    if (strcmp(cur->name, "xfce4-session") != 0 &&
        strcmp(cur->name, "xfwm4") != 0 &&
        strcmp(cur->name, "xfdesktop") != 0 &&
        strcmp(cur->name, "xfce4-panel") != 0 &&
        strcmp(cur->name, "xfsettingsd") != 0 &&
        strcmp(cur->name, "Xorg") != 0) {
        return;
    }
    g_user_mmap_large_file_log_budget--;
    printf("[mmap-file] pid=%d cmd=%s phase=%s ret=0x%x len=0x%x prot=0x%x flags=0x%x off=0x%x backing=%u/%u path=%s budget=%d\n",
           cur->pid, cur->name[0] ? cur->name : "?",
           phase ? phase : "?", (uint32_t)base, (uint32_t)len,
           (uint32_t)prot, (uint32_t)flags, (uint32_t)off,
           process_user_mmap_backing_used_pages(), process_user_mmap_backing_total_pages(),
           path ? path : "-", g_user_mmap_large_file_log_budget);
}

static const char *user_mmap_file_path(uint16_t slot) {
    if (slot >= USER_MMAP_FILE_SLOT_MAX) return 0;
    if (!g_user_mmap_file_slots[slot].used ||
        g_user_mmap_file_slots[slot].reclaiming)
        return 0;
    return g_user_mmap_file_slots[slot].path;
}

const char *process_user_mmap_file_path_for_slot(uint16_t slot) {
    return user_mmap_file_path(slot);
}

static int user_vma_get_file_inode(const edge_user_vma_t *v,
                                   vfs_inode_t *ino_out,
                                   vfs_superblock_t **sb_out);

static int file_vma_retain(const edge_user_vma_t *vma) {
    const char *path;
    edge_memfd_t *mf;
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;
    int id;
    if (!vma || !vma->file_backed || vma->end <= vma->start) return 0;
    path = user_mmap_file_path(vma->file_slot);
    id = memfd_id_from_path(path);
    if (id > 0) {
        mf = memfd_get(id);
        if (!mf || mf->mapping_refs == UINT32_MAX) return -1;
        mf->mapping_refs++;
        return 0;
    }
    if (user_vma_get_file_inode(vma, &inode, &superblock) < 0)
        return 0;
    if (vfs_inode_open(superblock, &inode) < 0) return -1;
    if (user_mmap_file_slot_mapping_retain(vma->file_slot) < 0) {
        vfs_inode_close(superblock, &inode);
        return -1;
    }
    return 0;
}

static void file_vma_release(const edge_user_vma_t *vma) {
    const char *path;
    edge_memfd_t *mf;
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;
    int id;
    if (!vma || !vma->file_backed || vma->end <= vma->start) return;
    path = user_mmap_file_path(vma->file_slot);
    id = memfd_id_from_path(path);
    if (id > 0) {
        mf = memfd_get(id);
        if (!mf) return;
        if (mf->mapping_refs > 0) mf->mapping_refs--;
        memfd_destroy_if_unreferenced(mf);
        return;
    }
    if (user_vma_get_file_inode(vma, &inode, &superblock) == 0) {
        if (user_mmap_file_slot_is_orphaned(vma->file_slot))
            vfs_inode_lifetime_prepare_alias_release(
                superblock, &inode);
        user_mmap_file_slot_mapping_release(vma->file_slot);
        vfs_inode_close(superblock, &inode);
    }
}

static int user_vma_path_is(const edge_user_vma_t *v, const char *path) {
    const char *vpath;
    if (!v || !path || !v->file_backed || v->end <= v->start) return 0;
    vpath = user_mmap_file_path(v->file_slot);
    return vpath && strcmp(vpath, path) == 0;
}

static int user_vma_task_has_path(const task_t *t, const char *path) {
    int live;
    if (!t || !path) return 0;
    live = t->user_vma_count;
    if ((uint32_t)live > t->user_vma_capacity)
        live = (int)t->user_vma_capacity;
    for (int i = 0; i < live; ++i) {
        if (user_vma_path_is(&t->user_vmas[i], path)) return 1;
    }
    return 0;
}

static int user_vma_any_live_task_has_path(const char *path) {
    if (!path) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *t = process_task_by_index(i);
        if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) continue;
        if (user_vma_task_has_path(t, path)) return 1;
    }
    return 0;
}

static int fbdev_user_mapping_or_fd_live(void) {
    /*
     * Linux fbdev scanout remains usable as long as userspace owns either the
     * mmap or the device object that can create/re-create it.  EdgeOS has to
     * emulate scanout through explicit virtio-gpu flushes; dropping that pump
     * while Xorg still has /dev/fb0 open leaves a black/stale desktop.  Keep
     * this generic to the fbdev device path and do not special-case Xorg/XFCE
     * process names or Alpine rootfs layout.
     */
    return user_vma_any_live_task_has_path("/dev/fb0") ||
           fd_any_live_task_has_path("/dev/fb0");
}

static int user_mmap_read_file_page(uint16_t file_slot, uint64_t file_off, void *dst) {
    const char *path;
    vfs_inode_t ino;
    vfs_superblock_t *sb = 0;
    uint32_t count;
    int memfd_id;

    if (!dst) return -1;
    path = user_mmap_file_path(file_slot);
    if (!path) return -1;

    memset(dst, 0, PAGE_SIZE);
    memfd_id = memfd_id_from_path(path);
    if (memfd_id > 0) {
        edge_memfd_t *mf = memfd_get(memfd_id);
        int r;
        if (!mf) return -1;
        r = memfd_read_to_kernel(mf, file_off, dst, PAGE_SIZE);
        return r < 0 ? -1 : 0;
    }
    if (file_slot < USER_MMAP_FILE_SLOT_MAX && g_user_mmap_file_slots[file_slot].have_inode) {
        ino = g_user_mmap_file_slots[file_slot].inode;
        sb = g_user_mmap_file_slots[file_slot].sb;
    } else if (vfs_resolve(path, &ino, &sb, 0, 0) < 0) {
        return -1;
    }
    if (!sb || !sb->ops || !sb->ops->read) return -1;
    if (file_off >= ino.size) return 0;
    count = (uint32_t)((uint64_t)ino.size - file_off);
    if (count > PAGE_SIZE) count = PAGE_SIZE;
    return vfs_read_inode_exact(sb, &ino, file_off, dst, count);
}

static uint32_t user_mmap_file_cache_hash_key(uint16_t file_slot, uint64_t file_page_off) {
    uint64_t page_no = file_page_off >> 12;
    uint64_t h = page_no ^ ((uint64_t)file_slot * 0x9e3779b185ebca87ULL);
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return (uint32_t)h & (USER_MMAP_FILE_PAGE_CACHE_HASH_MAX - 1u);
}

static int user_mmap_file_cache_entry_matches(int idx, uint16_t file_slot, uint64_t file_page_off) {
    user_mmap_file_page_cache_t *c;
    if (idx < 0 || idx >= USER_MMAP_FILE_PAGE_CACHE_MAX) return 0;
    c = &g_user_mmap_file_page_cache[idx];
    return c->used && c->file_slot == file_slot && c->file_page_off == file_page_off;
}

static uint32_t user_mmap_file_slot_generation(uint16_t file_slot) {
    if (file_slot >= USER_MMAP_FILE_SLOT_MAX) return 0;
    if (!g_user_mmap_file_slots[file_slot].used ||
        g_user_mmap_file_slots[file_slot].reclaiming)
        return 0;
    return g_user_mmap_file_slots[file_slot].cache_generation;
}

static void user_mmap_file_cache_note_shadow(
        const user_mmap_file_page_cache_t *page, int refault) {
    user_mmap_file_slot_t *file;
    uint64_t mapping_identity;

    if (!page || page->file_slot >= USER_MMAP_FILE_SLOT_MAX) return;
    file = &g_user_mmap_file_slots[page->file_slot];
    if (!file->used || !file->have_inode || !file->sb ||
        page->slot_generation != file->cache_generation)
        return;
    mapping_identity =
        (uint64_t)(uintptr_t)vfs_superblock_identity(file->sb);
    if (refault)
        kernel_mm_file_cache_note_refault(
            mapping_identity, file->inode.ino,
            file->inode.generation, page->file_page_off);
    else
        kernel_mm_file_cache_note_eviction(
            mapping_identity, file->inode.ino,
            file->inode.generation, page->file_page_off);
}

static int user_mmap_file_cache_hash_lookup(uint16_t file_slot, uint64_t file_page_off) {
    uint32_t start = user_mmap_file_cache_hash_key(file_slot, file_page_off);
    for (uint32_t probe = 0; probe < USER_MMAP_FILE_PAGE_CACHE_HASH_MAX; ++probe) {
        uint32_t h = (start + probe) & (USER_MMAP_FILE_PAGE_CACHE_HASH_MAX - 1u);
        int ent = g_user_mmap_file_page_cache_hash[h];
        if (ent == 0) return -1;
        if (ent < 0) continue;
        if (user_mmap_file_cache_entry_matches(ent - 1, file_slot, file_page_off)) return ent - 1;
    }
    return -1;
}

static void user_mmap_file_cache_hash_remove_slot(int idx) {
    user_mmap_file_page_cache_t *c;
    uint32_t start;
    if (idx < 0 || idx >= USER_MMAP_FILE_PAGE_CACHE_MAX) return;
    c = &g_user_mmap_file_page_cache[idx];
    if (!c->used) return;
    start = user_mmap_file_cache_hash_key(c->file_slot, c->file_page_off);
    for (uint32_t probe = 0; probe < USER_MMAP_FILE_PAGE_CACHE_HASH_MAX; ++probe) {
        uint32_t h = (start + probe) & (USER_MMAP_FILE_PAGE_CACHE_HASH_MAX - 1u);
        if (g_user_mmap_file_page_cache_hash[h] == 0) return;
        if (g_user_mmap_file_page_cache_hash[h] == idx + 1) {
            g_user_mmap_file_page_cache_hash[h] = -1;
            return;
        }
    }
}

static int user_mmap_file_cache_hash_insert(int idx) {
    user_mmap_file_page_cache_t *c;
    uint32_t start;
    int tombstone = -1;
    if (idx < 0 || idx >= USER_MMAP_FILE_PAGE_CACHE_MAX) return -1;
    c = &g_user_mmap_file_page_cache[idx];
    if (!c->used) return -1;
    start = user_mmap_file_cache_hash_key(c->file_slot, c->file_page_off);
    for (uint32_t probe = 0; probe < USER_MMAP_FILE_PAGE_CACHE_HASH_MAX; ++probe) {
        uint32_t h = (start + probe) & (USER_MMAP_FILE_PAGE_CACHE_HASH_MAX - 1u);
        int ent = g_user_mmap_file_page_cache_hash[h];
        if (ent == idx + 1) return 0;
        if (ent < 0) {
            if (tombstone < 0) tombstone = (int)h;
            continue;
        }
        if (ent == 0) {
            g_user_mmap_file_page_cache_hash[tombstone >= 0 ? tombstone : (int)h] = idx + 1;
            return 0;
        }
    }
    if (tombstone >= 0) {
        g_user_mmap_file_page_cache_hash[tombstone] = idx + 1;
        return 0;
    }
    return -1;
}

static uint32_t user_mmap_file_cache_reclaim_locked(
        uint32_t target_pages, int *first_slot_out,
        uint64_t *scanned_pages_out) {
    kernel_mm_reclaim_candidate_t selection[64] = {{0}};
    uint32_t selected = 0;
    uint32_t reclaimed = 0;
    uint64_t scanned_pages = 0;

    if (first_slot_out) *first_slot_out = -1;
    if (scanned_pages_out) *scanned_pages_out = 0;
    if (!target_pages) return 0;
    if (target_pages > 64u) target_pages = 64u;
    for (int index = 0;
         index < g_user_mmap_file_page_cache_high; ++index) {
        user_mmap_file_page_cache_t *page =
            &g_user_mmap_file_page_cache[index];
        kernel_mm_reclaim_candidate_t candidate = {0};
        uint16_t references;

        if (!page->used) continue;
        ++scanned_pages;
        references = process_user_mmap_backing_page_refcount(
            page->backing_idx);
        candidate.slot = (uint32_t)index;
        candidate.used = references != 0u;
        candidate.references = references == 1u ? 0u : references;
        candidate.pinned =
            process_user_mmap_backing_page_generation(
                page->backing_idx) != page->backing_generation;
        candidate.active = page->reclaim.active;
        candidate.last_used_sequence =
            page->reclaim.last_used_sequence;
        kernel_mm_cache_state_age(&page->reclaim);
        selected = kernel_mm_reclaim_candidate_offer(
            selection, selected, target_pages, &candidate);
    }
    for (uint32_t candidate_index = 0;
         candidate_index < selected; ++candidate_index) {
        int index = (int)selection[candidate_index].slot;
        user_mmap_file_page_cache_t *page =
            &g_user_mmap_file_page_cache[index];

        if (page->used &&
            process_user_mmap_backing_page_refcount(
                page->backing_idx) == 1u &&
            process_user_mmap_backing_page_generation(
                page->backing_idx) == page->backing_generation &&
            edge_mmap_file_cache_writeback_page(page) == 0) {
            user_mmap_file_cache_note_shadow(page, 0);
            user_mmap_file_cache_hash_remove_slot(index);
            process_user_mmap_release_backing_page(page->backing_idx);
            x86_page_writeback_forget_cache(page, (uint32_t)index);
            memset(page, 0, sizeof(*page));
            if (index < g_user_mmap_file_page_cache_free_hint)
                g_user_mmap_file_page_cache_free_hint = index;
            if (first_slot_out && *first_slot_out < 0)
                *first_slot_out = index;
            ++reclaimed;
        }
    }
    if (scanned_pages_out) *scanned_pages_out = scanned_pages;
    edge_mm_statistics_note_reclaim(scanned_pages, reclaimed);
    return reclaimed;
}

static int user_mmap_file_cache_reclaim_one_locked(void) {
    int first_slot = -1;

    (void)user_mmap_file_cache_reclaim_locked(1u, &first_slot, 0);
    return first_slot;
}

uint32_t arch_mm_reclaim_pages(uint32_t cgroup_id, uint32_t target_pages,
                               uint64_t *scanned_pages_out) {
    uint64_t scanned_pages = 0;
    uint64_t scanned_batch = 0;
    uint32_t reclaimed = 0;

    if (scanned_pages_out) *scanned_pages_out = 0;
    if (!target_pages) return 0;
    if (!cgroup_id) {
        user_mmap_file_cache_lock();
        reclaimed = user_mmap_file_cache_reclaim_locked(
            target_pages, 0, &scanned_batch);
        user_mmap_file_cache_unlock();
        scanned_pages += scanned_batch;
    }
#ifdef CONFIG_FS_SWAP
    if (reclaimed < target_pages) {
        reclaimed += process_user_mmap_swap_reclaim(
            cgroup_id, target_pages - reclaimed, &scanned_batch);
        scanned_pages += scanned_batch;
    }
    if (reclaimed < target_pages) {
        reclaimed += memfd_pressure_reclaim(
            cgroup_id, target_pages - reclaimed, &scanned_batch);
        scanned_pages += scanned_batch;
    }
#endif
    if (scanned_pages_out) *scanned_pages_out = scanned_pages;
    return reclaimed;
}

static int user_mmap_file_cache_next_free_without_reclaim(void) {
    int high = g_user_mmap_file_page_cache_high;
    if (high < 0 || high > USER_MMAP_FILE_PAGE_CACHE_MAX) high = USER_MMAP_FILE_PAGE_CACHE_MAX;
    if (g_user_mmap_file_page_cache_free_hint < 0 ||
        g_user_mmap_file_page_cache_free_hint > high) {
        g_user_mmap_file_page_cache_free_hint = high;
    }
    if (g_user_mmap_file_page_cache_free_hint < high) {
        for (int i = g_user_mmap_file_page_cache_free_hint; i < high; ++i) {
            if (!g_user_mmap_file_page_cache[i].used) {
                g_user_mmap_file_page_cache_free_hint = i;
                return i;
            }
        }
        g_user_mmap_file_page_cache_free_hint = high;
    }
    if (high < USER_MMAP_FILE_PAGE_CACHE_MAX) return high;
    for (int i = 0; i < high; ++i) {
        if (!g_user_mmap_file_page_cache[i].used) {
            g_user_mmap_file_page_cache_free_hint = i;
            return i;
        }
    }
    return -1;
}

static int user_mmap_file_cache_next_free(void) {
    int slot = user_mmap_file_cache_next_free_without_reclaim();
    return slot >= 0 ? slot : user_mmap_file_cache_reclaim_one_locked();
}

static int user_mmap_file_cache_find_locked(uint16_t file_slot,
                                            uint64_t file_page_off,
                                            int *free_slot_out) {
    int free_slot = -1;
    int idx = user_mmap_file_cache_hash_lookup(file_slot, file_page_off);
    if (idx >= 0) {
        user_mmap_file_page_cache_t *c = &g_user_mmap_file_page_cache[idx];
        if (c->slot_generation == user_mmap_file_slot_generation(file_slot) &&
            process_user_mmap_backing_page_active(c->backing_idx) &&
            process_user_mmap_backing_page_generation(c->backing_idx) == c->backing_generation) {
            kernel_mm_cache_state_access(
                &c->reclaim,
                __atomic_add_fetch(
                    &g_user_mmap_file_page_cache_sequence, 1u,
                    __ATOMIC_RELAXED));
            if (free_slot_out)
                *free_slot_out =
                    user_mmap_file_cache_next_free_without_reclaim();
            return c->backing_idx;
        }
        user_mmap_file_cache_hash_remove_slot(idx);
        /*
         * A slot-generation change invalidates the cache owner's reference but
         * does not invalidate PTE references held by existing mappings.  Drop
         * exactly the cache reference when the backing identity still matches;
         * a generation mismatch means the index has already been recycled and
         * must never release the unrelated current page.
         */
        if (process_user_mmap_backing_page_active(c->backing_idx) &&
            process_user_mmap_backing_page_generation(c->backing_idx) ==
                c->backing_generation) {
            process_user_mmap_release_backing_page(c->backing_idx);
        }
        x86_page_writeback_forget_cache(c, (uint32_t)idx);
        memset(c, 0, sizeof(*c));
        if (idx < g_user_mmap_file_page_cache_free_hint) g_user_mmap_file_page_cache_free_hint = idx;
        free_slot = idx;
    }
    if (free_slot < 0) free_slot = user_mmap_file_cache_next_free();
    if (free_slot_out) *free_slot_out = free_slot;
    return -1;
}

static int user_mmap_file_cache_find(uint16_t file_slot,
                                     uint64_t file_page_off,
                                     int *free_slot_out) {
    int result;
    user_mmap_file_cache_lock();
    result = user_mmap_file_cache_find_locked(
        file_slot, file_page_off, free_slot_out);
    user_mmap_file_cache_unlock();
    return result;
}

static int user_mmap_file_cache_acquire(uint16_t file_slot,
                                        uint64_t file_page_off,
                                        int *free_slot_out) {
    int result;
    user_mmap_file_cache_lock();
    result = user_mmap_file_cache_find_locked(
        file_slot, file_page_off, free_slot_out);
    if (result >= 0)
        process_user_mmap_retain_backing_page(result);
    user_mmap_file_cache_unlock();
    return result;
}

static int user_mmap_file_cache_store_locked(
    uint16_t file_slot, uint64_t file_page_off, int backing_idx,
    int free_slot_hint, int *release_incoming) {
    int free_slot = free_slot_hint;
    int existing;
    int result = 0;
    if (release_incoming) *release_incoming = 0;
    if (backing_idx < 0) return -1;
    existing = user_mmap_file_cache_find_locked(
        file_slot, file_page_off, &free_slot);
    if (existing >= 0) {
        if (existing != backing_idx && release_incoming)
            *release_incoming = 1;
        return 0;
    }
    /*
     * A free-slot hint is observational, not a reservation.  Another cache
     * insertion, including an earlier page from the same readahead batch, may
     * consume it before this call acquires the lock.  Never overwrite a live
     * entry: doing so leaves its hash key pointing at unrelated backing and
     * leaks the cache's page reference.
     */
    if (free_slot < 0 || free_slot >= USER_MMAP_FILE_PAGE_CACHE_MAX ||
        g_user_mmap_file_page_cache[free_slot].used) {
        free_slot = user_mmap_file_cache_next_free();
    }
    if (free_slot < 0 || free_slot >= USER_MMAP_FILE_PAGE_CACHE_MAX) {
        return -1;
    }
    g_user_mmap_file_page_cache[free_slot].used = 1;
    g_user_mmap_file_page_cache[free_slot].file_slot = file_slot;
    g_user_mmap_file_page_cache[free_slot].slot_generation =
        user_mmap_file_slot_generation(file_slot);
    g_user_mmap_file_page_cache[free_slot].file_page_off = file_page_off;
    g_user_mmap_file_page_cache[free_slot].backing_idx = backing_idx;
    g_user_mmap_file_page_cache[free_slot].backing_generation =
        process_user_mmap_backing_page_generation(backing_idx);
    kernel_mm_cache_state_insert(
        &g_user_mmap_file_page_cache[free_slot].reclaim,
        __atomic_add_fetch(
            &g_user_mmap_file_page_cache_sequence, 1u,
            __ATOMIC_RELAXED));
    if (user_mmap_file_cache_hash_insert(free_slot) < 0) {
        memset(&g_user_mmap_file_page_cache[free_slot], 0,
               sizeof(g_user_mmap_file_page_cache[free_slot]));
        if (free_slot < g_user_mmap_file_page_cache_free_hint) {
            g_user_mmap_file_page_cache_free_hint = free_slot;
        }
        result = -1;
        goto out;
    }
    user_mmap_file_cache_note_shadow(
        &g_user_mmap_file_page_cache[free_slot], 1);
    if (free_slot >= g_user_mmap_file_page_cache_high) {
        g_user_mmap_file_page_cache_high = free_slot + 1;
        g_user_mmap_file_page_cache_free_hint = g_user_mmap_file_page_cache_high;
    }
out:
    return result;
}

static int user_mmap_file_cache_store(uint16_t file_slot,
                                      uint64_t file_page_off,
                                      int backing_idx,
                                      int free_slot_hint) {
    int release_incoming = 0;
    int result;

    user_mmap_file_cache_lock();
    result = user_mmap_file_cache_store_locked(
        file_slot, file_page_off, backing_idx, free_slot_hint,
        &release_incoming);
    user_mmap_file_cache_unlock();
    if (release_incoming)
        process_user_mmap_release_backing_page(backing_idx);
    return result;
}

static void user_mmap_file_cache_store_batch(
    uint16_t file_slot, uint64_t file_page_off, int *backing,
    uint32_t pages) {
    int release_backing[USER_MMAP_FILE_READAHEAD_PAGES];
    uint32_t release_count = 0;

    if (!backing || pages == 0 ||
        pages > USER_MMAP_FILE_READAHEAD_PAGES)
        return;
    user_mmap_file_cache_lock();
    for (uint32_t index = 0; index < pages; ++index) {
        int release_incoming = 0;
        int result;

        if (backing[index] < 0) continue;
        result = user_mmap_file_cache_store_locked(
            file_slot,
            file_page_off + (uint64_t)index * PAGE_SIZE,
            backing[index], -1, &release_incoming);
        if (result < 0 || release_incoming) {
            release_backing[release_count++] = backing[index];
            backing[index] = -1;
        }
    }
    user_mmap_file_cache_unlock();

    /* Never nest the backing allocator lock under the file-cache lock. */
    for (uint32_t index = 0; index < release_count; ++index)
        process_user_mmap_release_backing_page(release_backing[index]);
}

static int user_mmap_prefetch_file_cache(uint16_t file_slot, uint64_t file_page_off, uint32_t pages) {
    enum { USER_MMAP_PREFETCH_SLOTS = 4 };
    static volatile uint32_t prefetch_locks[USER_MMAP_PREFETCH_SLOTS];
    static uint8_t
        prefetch_buffers[USER_MMAP_PREFETCH_SLOTS]
                        [USER_MMAP_FILE_READAHEAD_PAGES * PAGE_SIZE]
            __attribute__((aligned(PAGE_SIZE)));
    uint8_t *prefetch_buf = 0;
    const char *path;
    vfs_inode_t ino;
    vfs_superblock_t *sb = 0;
    uint32_t bytes;
    uint32_t count;
    int memfd_id;
    int backing[USER_MMAP_FILE_READAHEAD_PAGES];
    int prefetch_slot = -1;

    if (pages == 0) return -1;
    if (pages > USER_MMAP_FILE_READAHEAD_PAGES) pages = USER_MMAP_FILE_READAHEAD_PAGES;
    if ((file_page_off & (PAGE_SIZE - 1ULL)) != 0) return -1;
    path = user_mmap_file_path(file_slot);
    if (!path) return -1;
    memfd_id = memfd_id_from_path(path);
    if (memfd_id > 0) return -1;
    if (file_slot < USER_MMAP_FILE_SLOT_MAX && g_user_mmap_file_slots[file_slot].have_inode) {
        ino = g_user_mmap_file_slots[file_slot].inode;
        sb = g_user_mmap_file_slots[file_slot].sb;
    } else if (vfs_resolve(path, &ino, &sb, 0, 0) < 0) {
        return -1;
    }
    if (!sb || !sb->ops || !sb->ops->read) return -1;
    if (file_page_off >= ino.size) return -1;
    {
        uint64_t remaining = (uint64_t)ino.size - file_page_off;
        uint64_t file_pages =
            remaining / PAGE_SIZE +
            ((remaining % PAGE_SIZE) != 0 ? 1u : 0u);
        if (file_pages < pages) pages = (uint32_t)file_pages;
    }
    if (pages == 0) return -1;

    /*
     * A file read may yield while storage completes.  Serializing every mmap
     * fault behind one global readahead buffer made browser workers repeatedly
     * yield behind an unrelated library read.  Claim one bounded buffer per
     * concurrent reader; if all slots are busy, let the caller perform its
     * normal single-page read instead of spinning or accumulating stale work.
     */
    {
        uint32_t first = scheduler_cpu_id() % USER_MMAP_PREFETCH_SLOTS;
        for (uint32_t probe = 0; probe < USER_MMAP_PREFETCH_SLOTS; ++probe) {
            uint32_t slot = (first + probe) % USER_MMAP_PREFETCH_SLOTS;
            uint32_t expected = 0u;
            if (__atomic_compare_exchange_n(
                    &prefetch_locks[slot], &expected, 1u, 0,
                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                prefetch_slot = (int)slot;
                prefetch_buf = prefetch_buffers[slot];
                break;
            }
        }
    }
    if (prefetch_slot < 0) return -1;

    for (uint32_t i = 0; i < pages; ++i) {
        uint64_t off = file_page_off + (uint64_t)i * PAGE_SIZE;
        backing[i] = -1;
        if (user_mmap_file_cache_find(file_slot, off, 0) >= 0) continue;
        backing[i] = process_user_mmap_alloc_file_backing_page();
        if (backing[i] < 0) {
            for (uint32_t j = 0; j < i; ++j) {
                if (backing[j] >= 0) process_user_mmap_release_backing_page(backing[j]);
            }
            __atomic_store_n(
                &prefetch_locks[prefetch_slot], 0u, __ATOMIC_RELEASE);
            return -1;
        }
    }

    prefetch_buf = prefetch_buffers[prefetch_slot];
    memset(prefetch_buf, 0, pages * PAGE_SIZE);
    bytes = pages * PAGE_SIZE;
    count = (uint32_t)((uint64_t)ino.size - file_page_off);
    if (count > bytes) count = bytes;
    if (vfs_read_inode_exact(
            sb, &ino, file_page_off, prefetch_buf, count) < 0) {
        __atomic_store_n(
            &prefetch_locks[prefetch_slot], 0u, __ATOMIC_RELEASE);
        for (uint32_t i = 0; i < pages; ++i) {
            if (backing[i] >= 0)
                process_user_mmap_release_backing_page(backing[i]);
        }
        return -1;
    }
    for (uint32_t i = 0; i < pages; ++i) {
        uint8_t *page;
        if (backing[i] < 0) continue;
        page = process_user_mmap_backing_page_ptr(backing[i]);
        if (!page) continue;
        memcpy(page, prefetch_buf + i * PAGE_SIZE, PAGE_SIZE);
    }
    __atomic_store_n(
        &prefetch_locks[prefetch_slot], 0u, __ATOMIC_RELEASE);

    user_mmap_file_cache_store_batch(
        file_slot, file_page_off, backing, pages);
    return user_mmap_file_cache_find(file_slot, file_page_off, 0);
}

static int user_mmap_cached_file_backing(uint16_t file_slot, uint64_t file_page_off) {
    const char *slot_path = user_mmap_file_path(file_slot);
    int memfd_id = memfd_id_from_path(slot_path);
    int free_slot = -1;
    uint32_t readahead_pages = 1u;
    if (memfd_id > 0) {
        edge_memfd_t *mf = memfd_get(memfd_id);
        uint64_t page_no = file_page_off / PAGE_SIZE;
        int backing_idx;
        if (!mf) return -1;
        backing_idx = memfd_storage_page(mf, page_no, 1);
        if (backing_idx >= 0)
            process_user_mmap_retain_backing_page(backing_idx);
        return backing_idx;
    }
    {
        int hit = user_mmap_file_cache_acquire(
            file_slot, file_page_off, &free_slot);
        if (hit >= 0) return hit;
    }
    {
        if (file_slot < USER_MMAP_FILE_SLOT_MAX) {
            user_mmap_file_slot_t *slot =
                &g_user_mmap_file_slots[file_slot];
            if (slot->used && slot->have_inode && slot->sb)
                readahead_pages = vfs_readahead_plan(
                    slot->sb, &slot->inode, file_page_off,
                    USER_MMAP_FILE_READAHEAD_PAGES);
        }
        int hit = user_mmap_prefetch_file_cache(
            file_slot, file_page_off, readahead_pages);
        if (hit >= 0) {
            hit = user_mmap_file_cache_acquire(
                file_slot, file_page_off, 0);
            if (hit >= 0) return hit;
        }
    }
    if (free_slot < 0) {
        if (g_user_mmap_cache_fail_log_budget > 0) {
            const char *path = user_mmap_file_path(file_slot);
            printf("[mmap-file-cache] full slot=%u off=0x%x entries=%u backing=%u/%u path=%s budget=%d\n",
                   (uint32_t)file_slot, (uint32_t)file_page_off,
                   (uint32_t)USER_MMAP_FILE_PAGE_CACHE_MAX,
                   process_user_mmap_backing_used_pages(),
                   process_user_mmap_backing_total_pages(),
                   path ? path : "-", g_user_mmap_cache_fail_log_budget - 1);
            g_user_mmap_cache_fail_log_budget--;
        }
        return -1;
    }

    int backing_idx = process_user_mmap_alloc_file_backing_page();
    void *page = process_user_mmap_backing_page_ptr(backing_idx);
    if (backing_idx < 0 || !page) {
        if (g_user_mmap_cache_fail_log_budget > 0) {
            const char *path = user_mmap_file_path(file_slot);
            printf("[mmap-file-cache] backing-fail slot=%u off=0x%x backing=%u/%u pt=%u/%u path=%s budget=%d\n",
                   (uint32_t)file_slot, (uint32_t)file_page_off,
                   process_user_mmap_backing_used_pages(),
                   process_user_mmap_backing_total_pages(),
                   process_user_mmap_pt_used_pages(),
                   process_user_mmap_pt_total_pages(),
                   path ? path : "-", g_user_mmap_cache_fail_log_budget - 1);
            g_user_mmap_cache_fail_log_budget--;
        }
        return -1;
    }
    if (user_mmap_read_file_page(file_slot, file_page_off, page) < 0) {
        process_user_mmap_release_backing_page(backing_idx);
        return -1;
    }
    if (user_mmap_file_cache_store(file_slot, file_page_off, backing_idx, free_slot) < 0) {
        process_user_mmap_release_backing_page(backing_idx);
        return -1;
    }
    return user_mmap_file_cache_acquire(file_slot, file_page_off, 0);
}

void process_user_mmap_file_page_write_notify(
        uint16_t file_slot, uint64_t file_page_off) {
    int cache_slot;
    vfs_superblock_t *superblock = 0;
    vfs_inode_t inode;
    uint64_t token = 0;
    user_mmap_file_cache_lock();
    cache_slot = user_mmap_file_cache_hash_lookup(
        file_slot, file_page_off);
    if (cache_slot >= 0) {
        user_mmap_file_page_cache_t *page =
            &g_user_mmap_file_page_cache[cache_slot];
        g_user_mmap_file_page_cache[cache_slot].writable_seen = 1;
        g_user_mmap_file_page_cache[cache_slot].write_notify_armed = 0;
        if (file_slot < USER_MMAP_FILE_SLOT_MAX &&
            g_user_mmap_file_slots[file_slot].used &&
            g_user_mmap_file_slots[file_slot].have_inode &&
            g_user_mmap_file_slots[file_slot].sb) {
            superblock = g_user_mmap_file_slots[file_slot].sb;
            inode = g_user_mmap_file_slots[file_slot].inode;
            token = ((uint64_t)page->slot_generation << 32u) |
                    (uint32_t)(cache_slot + 1);
        }
    }
    user_mmap_file_cache_unlock();
    if (superblock)
        (void)vfs_page_writeback_mark_dirty(
            superblock, &inode, file_page_off, token,
            x86_page_writeback_backend, 0);
}

static int user_mmap_file_slot_for_inode(vfs_superblock_t *superblock,
                                         const vfs_inode_t *inode) {
    uint32_t slot_limit = user_mmap_file_slot_limit();
    if (!superblock || !inode) return -1;
    for (uint32_t slot = 0; slot < slot_limit; ++slot) {
        user_mmap_file_slot_t *candidate = &g_user_mmap_file_slots[slot];
        if (candidate->used && !candidate->reclaiming &&
            candidate->have_inode &&
            vfs_inode_same_object(candidate->sb, &candidate->inode,
                                  superblock, inode))
            return (int)slot;
    }
    return -1;
}

static user_mmap_file_page_cache_t *user_mmap_file_cache_page(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t file_page_offset) {
    int file_slot = user_mmap_file_slot_for_inode(superblock, inode);
    int cache_slot;
    user_mmap_file_page_cache_t *page;
    if (file_slot < 0) return 0;
    cache_slot = user_mmap_file_cache_hash_lookup(
        (uint16_t)file_slot, file_page_offset);
    if (cache_slot < 0) return 0;
    page = &g_user_mmap_file_page_cache[cache_slot];
    if (!page->used ||
        page->slot_generation != user_mmap_file_slot_generation(
            page->file_slot) ||
        !process_user_mmap_backing_page_active(page->backing_idx) ||
        process_user_mmap_backing_page_generation(page->backing_idx) !=
            page->backing_generation)
        return 0;
    return page;
}

void edge_mmap_file_cache_overlay_read(vfs_superblock_t *superblock,
                                       const vfs_inode_t *inode,
                                       uint64_t offset, void *buffer,
                                       uint32_t length) {
    uint64_t end;
    uint64_t page_offset;
    if (!superblock || !inode || !buffer || !length ||
        offset > UINT64_MAX - length)
        return;
    end = offset + length;
    page_offset = offset & ~(uint64_t)(PAGE_SIZE - 1u);
    user_mmap_file_cache_lock();
    while (page_offset < end) {
        user_mmap_file_page_cache_t *page = user_mmap_file_cache_page(
            superblock, inode, page_offset);
        if (page) {
            uint64_t copy_start = offset > page_offset ? offset : page_offset;
            uint64_t page_end = page_offset + PAGE_SIZE;
            uint64_t copy_end = end < page_end ? end : page_end;
            void *backing = process_user_mmap_backing_page_ptr(
                page->backing_idx);
            if (backing)
                memcpy((uint8_t *)buffer + copy_start - offset,
                       (const uint8_t *)backing + copy_start - page_offset,
                       (uint32_t)(copy_end - copy_start));
        }
        page_offset += PAGE_SIZE;
    }
    user_mmap_file_cache_unlock();
}

void edge_mmap_file_cache_apply_write(vfs_superblock_t *superblock,
                                      const vfs_inode_t *inode,
                                      uint64_t offset, const void *buffer,
                                      uint32_t length) {
    uint64_t end;
    uint64_t page_offset;
    if (!superblock || !inode || !buffer || !length ||
        offset > UINT64_MAX - length)
        return;
    end = offset + length;
    page_offset = offset & ~(uint64_t)(PAGE_SIZE - 1u);
    user_mmap_file_cache_lock();
    while (page_offset < end) {
        user_mmap_file_page_cache_t *page = user_mmap_file_cache_page(
            superblock, inode, page_offset);
        if (page) {
            uint64_t copy_start = offset > page_offset ? offset : page_offset;
            uint64_t page_end = page_offset + PAGE_SIZE;
            uint64_t copy_end = end < page_end ? end : page_end;
            void *backing = process_user_mmap_backing_page_ptr(
                page->backing_idx);
            if (backing) {
                memcpy((uint8_t *)backing + copy_start - page_offset,
                       (const uint8_t *)buffer + copy_start - offset,
                       (uint32_t)(copy_end - copy_start));
            }
        }
        page_offset += PAGE_SIZE;
    }
    user_mmap_file_cache_unlock();
}

static void edge_mmap_file_cache_publish_inode(
    vfs_superblock_t *superblock, const vfs_inode_t *inode) {
    uint32_t slot_limit = user_mmap_file_slot_limit();
    if (!superblock || !inode) return;
    for (uint32_t slot = 0; slot < slot_limit; ++slot) {
        user_mmap_file_slot_t *file = &g_user_mmap_file_slots[slot];
        if (!file->used || file->reclaiming ||
            !file->have_inode ||
            !vfs_inode_same_object(file->sb, &file->inode,
                                   superblock, inode))
            continue;
        file->inode = *inode;
    }
}

static int user_vma_file_slot_matches_inode(const edge_user_vma_t *vma,
                                            vfs_superblock_t *superblock,
                                            const vfs_inode_t *inode) {
    user_mmap_file_slot_t *slot;
    if (!vma || !vma->file_backed ||
        vma->file_slot >= USER_MMAP_FILE_SLOT_MAX ||
        !superblock || !inode)
        return 0;
    slot = &g_user_mmap_file_slots[vma->file_slot];
    return slot->used && !slot->reclaiming &&
           slot->have_inode &&
           vfs_inode_same_object(slot->sb, &slot->inode,
                                 superblock, inode);
}

static void edge_mmap_unmap_truncated_inode_pages(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t length) {
    uint64_t cutoff = page_align_up(length);

    for (int task_index = 0; task_index < PROC_MAX_TASKS; ++task_index) {
        task_t *memory = (task_t *)process_task_by_index(task_index);
        int live;
        if (!memory || memory->state == TASK_UNUSED ||
            process_vm_task(memory) != memory)
            continue;
        live = user_vma_live_limit(memory);
        for (int vma_index = 0; vma_index < live; ++vma_index) {
            edge_user_vma_t *vma = &memory->user_vmas[vma_index];
            uint64_t mapping_length;
            uint64_t mapping_file_end;
            uint64_t invalid_file_start;
            uint64_t invalid_address;
            uint64_t invalid_length;

            if (vma->end <= vma->start ||
                !user_vma_file_slot_matches_inode(
                    vma, superblock, inode))
                continue;
            vma->file_size = length > UINT32_MAX ? UINT32_MAX :
                             (uint32_t)length;
            mapping_length = vma->end - vma->start;
            mapping_file_end = vma->file_off + mapping_length;
            if (mapping_file_end < vma->file_off ||
                cutoff >= mapping_file_end)
                continue;
            invalid_file_start = cutoff > vma->file_off ?
                                 cutoff : vma->file_off;
            invalid_address = vma->start +
                              invalid_file_start - vma->file_off;
            invalid_length = vma->end - invalid_address;
            if (invalid_length)
                process_user_mmap_unmap_fast(
                    memory, invalid_address, invalid_length);
        }
    }
}

void edge_mmap_file_cache_resize(vfs_superblock_t *superblock,
                                 const vfs_inode_t *inode,
                                 uint64_t length) {
    uint64_t tail_page = length & ~(uint64_t)(PAGE_SIZE - 1u);
    uint32_t tail_offset = (uint32_t)(length - tail_page);

    if (!superblock || !inode) return;
    edge_mmap_file_cache_publish_inode(superblock, inode);
    edge_mmap_unmap_truncated_inode_pages(superblock, inode, length);
    user_mmap_file_cache_lock();
    for (int index = 0; index < g_user_mmap_file_page_cache_high; ++index) {
        user_mmap_file_page_cache_t *page =
            &g_user_mmap_file_page_cache[index];
        user_mmap_file_slot_t *file;
        void *backing;
        if (!page->used || page->file_slot >= USER_MMAP_FILE_SLOT_MAX)
            continue;
        file = &g_user_mmap_file_slots[page->file_slot];
        if (!file->used || !file->have_inode ||
            !vfs_inode_same_object(file->sb, &file->inode,
                                   superblock, inode))
            continue;
        if (page->file_page_off > tail_page ||
            (page->file_page_off == tail_page && tail_offset == 0)) {
            user_mmap_file_cache_hash_remove_slot(index);
            process_user_mmap_release_backing_page(page->backing_idx);
            x86_page_writeback_forget_cache(page, (uint32_t)index);
            memset(page, 0, sizeof(*page));
            if (index < g_user_mmap_file_page_cache_free_hint)
                g_user_mmap_file_page_cache_free_hint = index;
            continue;
        }
        if (page->file_page_off != tail_page || tail_offset == 0)
            continue;
        backing = process_user_mmap_backing_page_ptr(page->backing_idx);
        if (backing)
            memset((uint8_t *)backing + tail_offset, 0,
                   PAGE_SIZE - tail_offset);
    }
    user_mmap_file_cache_unlock();
}

void edge_mmap_file_cache_zero_range(vfs_superblock_t *superblock,
                                     const vfs_inode_t *inode,
                                     uint64_t offset, uint64_t length) {
    uint64_t end;
    uint64_t page_offset;
    if (!superblock || !inode || !length || offset > UINT64_MAX - length)
        return;
    end = offset + length;
    page_offset = offset & ~(uint64_t)(PAGE_SIZE - 1u);
    edge_mmap_file_cache_publish_inode(superblock, inode);
    user_mmap_file_cache_lock();
    while (page_offset < end) {
        user_mmap_file_page_cache_t *page = user_mmap_file_cache_page(
            superblock, inode, page_offset);
        if (page) {
            uint64_t zero_start = offset > page_offset ? offset : page_offset;
            uint64_t page_end = page_offset + PAGE_SIZE;
            uint64_t zero_end = end < page_end ? end : page_end;
            void *backing = process_user_mmap_backing_page_ptr(
                page->backing_idx);
            if (backing)
                memset((uint8_t *)backing + zero_start - page_offset, 0,
                       (uint32_t)(zero_end - zero_start));
        }
        page_offset += PAGE_SIZE;
    }
    user_mmap_file_cache_unlock();
}

static void edge_mmap_unmap_inode_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length) {
    uint64_t file_start;
    uint64_t file_end;

    if (!superblock || !inode || !length) return;
    file_start = offset & ~(uint64_t)(PAGE_SIZE - 1u);
    if (length > UINT64_MAX - offset)
        file_end = UINT64_MAX;
    else
        file_end = page_align_up(offset + length);
    if (file_end < file_start) file_end = UINT64_MAX;

    for (int task_index = 0; task_index < PROC_MAX_TASKS; ++task_index) {
        task_t *memory = (task_t *)process_task_by_index(task_index);
        int live;
        if (!memory || memory->state == TASK_UNUSED ||
            process_vm_task(memory) != memory)
            continue;
        live = user_vma_live_limit(memory);
        for (int vma_index = 0; vma_index < live; ++vma_index) {
            edge_user_vma_t *vma = &memory->user_vmas[vma_index];
            uint64_t mapping_length;
            uint64_t mapping_file_end;
            uint64_t overlap_start;
            uint64_t overlap_end;
            uint64_t address;

            if (vma->end <= vma->start ||
                !user_vma_file_slot_matches_inode(
                    vma, superblock, inode))
                continue;
            mapping_length = vma->end - vma->start;
            mapping_file_end = vma->file_off + mapping_length;
            if (mapping_file_end < vma->file_off)
                mapping_file_end = UINT64_MAX;
            overlap_start = file_start > vma->file_off ?
                            file_start : vma->file_off;
            overlap_end = file_end < mapping_file_end ?
                          file_end : mapping_file_end;
            if (overlap_end <= overlap_start) continue;
            address = vma->start + overlap_start - vma->file_off;
            process_user_mmap_unmap_fast(
                memory, address, overlap_end - overlap_start);
        }
    }
}

void edge_mmap_file_cache_invalidate_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length) {
    uint64_t end;

    if (!superblock || !inode || !length) return;
    end = length > UINT64_MAX - offset ? UINT64_MAX : offset + length;
    edge_mmap_file_cache_publish_inode(superblock, inode);
    edge_mmap_unmap_inode_range(superblock, inode, offset, length);

    user_mmap_file_cache_lock();
    for (int index = 0;
         index < g_user_mmap_file_page_cache_high; ++index) {
        user_mmap_file_page_cache_t *page =
            &g_user_mmap_file_page_cache[index];
        user_mmap_file_slot_t *file;
        uint64_t page_end;
        if (!page->used || page->file_slot >= USER_MMAP_FILE_SLOT_MAX)
            continue;
        file = &g_user_mmap_file_slots[page->file_slot];
        if (!file->used || !file->have_inode ||
            !vfs_inode_same_object(file->sb, &file->inode,
                                   superblock, inode))
            continue;
        page_end = page->file_page_off + PAGE_SIZE;
        if (page_end <= offset || page->file_page_off >= end)
            continue;
        user_mmap_file_cache_hash_remove_slot(index);
        if (process_user_mmap_backing_page_active(page->backing_idx) &&
            process_user_mmap_backing_page_generation(page->backing_idx) ==
                page->backing_generation)
            process_user_mmap_release_backing_page(page->backing_idx);
        x86_page_writeback_forget_cache(page, (uint32_t)index);
        memset(page, 0, sizeof(*page));
        if (index < g_user_mmap_file_page_cache_free_hint)
            g_user_mmap_file_page_cache_free_hint = index;
    }
    while (g_user_mmap_file_page_cache_high > 0 &&
           !g_user_mmap_file_page_cache[
                g_user_mmap_file_page_cache_high - 1].used)
        --g_user_mmap_file_page_cache_high;
    if (g_user_mmap_file_page_cache_free_hint >
        g_user_mmap_file_page_cache_high)
        g_user_mmap_file_page_cache_free_hint =
            g_user_mmap_file_page_cache_high;
    user_mmap_file_cache_unlock();
}

static int edge_mmap_file_cache_writeback_page(
    user_mmap_file_page_cache_t *page) {
    user_mmap_file_slot_t *file;
    vfs_inode_t inode;
    void *backing;
    uint32_t count;
    int written;
    if (!page || !page->used || !page->writable_seen) return 0;
    if (page->file_slot >= USER_MMAP_FILE_SLOT_MAX) return -EIO;
    file = &g_user_mmap_file_slots[page->file_slot];
    if (!file->used || !file->have_inode || !file->sb ||
        page->slot_generation != file->cache_generation ||
        !file->sb->ops || !file->sb->ops->write)
        return -EIO;
    backing = process_user_mmap_backing_page_ptr(page->backing_idx);
    if (!backing ||
        process_user_mmap_backing_page_generation(page->backing_idx) !=
            page->backing_generation)
        return -EIO;
    inode = file->inode;
    if (vfs_inode_refresh(file->sb, &inode) < 0) return -EIO;
    if (!vfs_inode_same_object(file->sb, &file->inode,
                               file->sb, &inode))
        return -EIO;
    file->inode = inode;
    if (page->file_page_off >= inode.size) return 0;
    count = inode.size - (uint32_t)page->file_page_off;
    if (count > PAGE_SIZE) count = PAGE_SIZE;
    written = file->sb->ops->write(
        file->sb, &file->inode, (uint32_t)page->file_page_off,
        backing, count);
    return written == (int)count ? 0 : -EIO;
}

static int edge_mmap_file_cache_sync_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length, int sync_filesystem) {
    int result = 0;
    if (!superblock || !inode) return -EIO;
    if (vfs_page_writeback_sync_range(
            superblock, inode, offset, length) < 0)
        result = -EIO;
    if (sync_filesystem &&
        vfs_sync_inode(superblock, inode, 0) < 0)
        result = -EIO;
    return result;
}

int edge_mmap_file_cache_sync_inode(vfs_superblock_t *superblock,
                                    const vfs_inode_t *inode,
                                    int sync_filesystem) {
    return edge_mmap_file_cache_sync_range(
        superblock, inode, 0, UINT64_MAX, sync_filesystem);
}

int edge_mmap_file_cache_sync_superblock(vfs_superblock_t *superblock) {
    int result = 0;
    if (!superblock) return -EIO;
    if (vfs_page_writeback_sync_superblock(superblock) < 0)
        result = -EIO;
    if (superblock->ops && superblock->ops->sync &&
        superblock->ops->sync(superblock) < 0)
        result = -EIO;
    return result;
}

void edge_mmap_file_cache_invalidate_path(const char *path) {
    char abs[TASK_CWD_MAX];

    if (!path || !path[0]) return;
    if (build_at_path(LINUX_AT_FDCWD, path, abs, (int)sizeof(abs)) < 0) return;
    user_mmap_file_cache_lock();
    for (int i = 0; i < USER_MMAP_FILE_PAGE_CACHE_MAX; ++i) {
        user_mmap_file_page_cache_t *c = &g_user_mmap_file_page_cache[i];
        const char *slot_path;
        if (!c->used) continue;
        slot_path = user_mmap_file_path(c->file_slot);
        if (!slot_path || strcmp(slot_path, abs) != 0) continue;
        user_mmap_file_cache_hash_remove_slot(i);
        process_user_mmap_release_backing_page(c->backing_idx);
        x86_page_writeback_forget_cache(c, (uint32_t)i);
        memset(c, 0, sizeof(*c));
        if (i < g_user_mmap_file_page_cache_free_hint) g_user_mmap_file_page_cache_free_hint = i;
    }
    user_mmap_file_cache_unlock();
}

void edge_mmap_file_cache_rename_path(const char *old_path, const char *new_path) {
    /*
     * Linux rename(2) changes directory entries without detaching mappings from
     * the source inode.  In particular, GDBM deliberately renames a temporary
     * database while its writable MAP_SHARED mapping is still live and calls
     * msync(2) afterwards.  Dropping the source cache here loses those dirty
     * pages and turns a successful msync into silent data loss.
     *
     * File slots and cache entries carry an inode, superblock, and inode
     * generation, so retaining an entry cannot make a later mapping of a
     * replacement pathname reuse the wrong object.  Keep both the renamed
     * source and any replaced destination inode alive for existing VMAs; only
     * update the printable/fault-resolution pathname of the source slot.
     */
    user_mmap_file_rename_path(old_path, new_path);
}

static int x86_mmap_orphan_find_slot(vfs_superblock_t *superblock,
                                     const vfs_inode_t *inode,
                                     int orphan_only) {
    int result = -1;
    uint32_t slot_limit;
    if (!superblock || !inode) return -1;
    user_mmap_file_slot_lock();
    slot_limit = user_mmap_file_slot_limit();
    for (uint32_t file_slot = 0; file_slot < slot_limit;
         ++file_slot) {
        user_mmap_file_slot_t *slot =
            &g_user_mmap_file_slots[file_slot];
        if (!slot->used || slot->reclaiming ||
            !slot->have_inode ||
            (orphan_only && !slot->orphaned) ||
            !vfs_inode_same_object(slot->sb, &slot->inode,
                                   superblock, inode))
            continue;
        result = (int)file_slot;
        break;
    }
    user_mmap_file_slot_unlock();
    return result;
}

/*
 * Hold one inode reference for an orphaned x86 file-cache identity.  The VFS
 * keeps a temporary reference across unlink/rename replacement, so this can
 * safely acquire the cache's independent reference after nlink reaches zero.
 */
static int x86_mmap_orphan_pin_slot(uint16_t file_slot,
                                    vfs_superblock_t *superblock,
                                    const vfs_inode_t *inode,
                                    int mark_orphan) {
    user_mmap_file_slot_t *slot;
    vfs_superblock_t *pin_superblock = 0;
    vfs_inode_t pin_inode;
    int available = 0;
    int retained = 0;

    if (file_slot >= USER_MMAP_FILE_SLOT_MAX ||
        !superblock || !inode)
        return -1;

    user_mmap_file_slot_lock();
    slot = &g_user_mmap_file_slots[file_slot];
    if (!slot->used || slot->reclaiming ||
        !slot->have_inode ||
        !vfs_inode_same_object(slot->sb, &slot->inode,
                               superblock, inode)) {
        user_mmap_file_slot_unlock();
        return -1;
    }
    if (mark_orphan) {
        slot->orphaned = 1;
        slot->inode = *inode;
    }
    if (!slot->orphaned) {
        user_mmap_file_slot_unlock();
        return -1;
    }
    if (slot->orphan_ref) {
        user_mmap_orphan_enqueue_locked(file_slot);
        user_mmap_file_slot_unlock();
        return 0;
    }
    pin_superblock = slot->sb;
    pin_inode = slot->inode;
    user_mmap_file_slot_unlock();

    if (vfs_inode_open(pin_superblock, &pin_inode) < 0) return -1;

    user_mmap_file_slot_lock();
    slot = &g_user_mmap_file_slots[file_slot];
    if (slot->used && !slot->reclaiming &&
        slot->have_inode && slot->orphaned &&
        vfs_inode_same_object(slot->sb, &slot->inode,
                              pin_superblock, &pin_inode)) {
        if (!slot->orphan_ref) {
            slot->orphan_ref = 1;
            retained = 1;
        }
        available = slot->orphan_ref != 0;
        user_mmap_orphan_enqueue_locked(file_slot);
    }
    user_mmap_file_slot_unlock();
    if (!retained) vfs_inode_close(pin_superblock, &pin_inode);
    return available ? 0 : -1;
}

static void x86_mmap_orphan_requeue(uint16_t file_slot) {
    user_mmap_file_slot_lock();
    user_mmap_orphan_enqueue_locked(file_slot);
    user_mmap_file_slot_unlock();
}

static int x86_mmap_orphan_drain(uint32_t maximum_slots) {
    int result = 0;

    while (maximum_slots--) {
        user_mmap_file_slot_t *slot;
        vfs_superblock_t *superblock = 0;
        vfs_inode_t inode;
        uint32_t cache_generation;
        int32_t file_slot;
        int release_reference = 0;
        int slot_result = 0;

        user_mmap_file_slot_lock();
        file_slot = user_mmap_orphan_pop_locked();
        if (file_slot < 0) {
            user_mmap_file_slot_unlock();
            break;
        }
        slot = &g_user_mmap_file_slots[file_slot];
        if (!slot->used || !slot->orphaned || !slot->orphan_ref) {
            user_mmap_file_slot_unlock();
            continue;
        }
        if (slot->mapping_refs) {
            user_mmap_orphan_enqueue_locked((uint16_t)file_slot);
            user_mmap_file_slot_unlock();
            continue;
        }
        superblock = slot->sb;
        inode = slot->inode;
        cache_generation = slot->cache_generation;
        user_mmap_file_slot_unlock();

        /*
         * Write every page first.  A single failure keeps the complete cache
         * and its inode reference intact, so retrying cannot observe a partly
         * reclaimed zero-link file.
         */
        for (int page_slot = 0;
             page_slot < g_user_mmap_file_page_cache_high; ++page_slot) {
            user_mmap_file_page_cache_t *page =
                &g_user_mmap_file_page_cache[page_slot];
            if (!page->used || page->file_slot != (uint16_t)file_slot ||
                page->slot_generation != cache_generation)
                continue;
            if (edge_mmap_file_cache_writeback_page(page) < 0)
                slot_result = -EIO;
        }
        if (slot_result < 0) {
            result = -EIO;
            x86_mmap_orphan_requeue((uint16_t)file_slot);
            continue;
        }

        user_mmap_file_slot_lock();
        if (g_user_mmap_file_slots[file_slot].mapping_refs) {
            user_mmap_orphan_enqueue_locked((uint16_t)file_slot);
            user_mmap_file_slot_unlock();
            continue;
        }
        user_mmap_file_slot_unlock();

        user_mmap_file_cache_lock();
        for (int page_slot = 0;
             page_slot < g_user_mmap_file_page_cache_high; ++page_slot) {
            user_mmap_file_page_cache_t *page =
                &g_user_mmap_file_page_cache[page_slot];
            if (!page->used || page->file_slot != (uint16_t)file_slot ||
                page->slot_generation != cache_generation)
                continue;
            user_mmap_file_cache_hash_remove_slot(page_slot);
            if (process_user_mmap_backing_page_active(
                    page->backing_idx) &&
                process_user_mmap_backing_page_generation(
                    page->backing_idx) == page->backing_generation)
                process_user_mmap_release_backing_page(
                    page->backing_idx);
            x86_page_writeback_forget_cache(
                page, (uint32_t)page_slot);
            memset(page, 0, sizeof(*page));
            if (page_slot < g_user_mmap_file_page_cache_free_hint)
                g_user_mmap_file_page_cache_free_hint = page_slot;
        }
        user_mmap_file_cache_unlock();

        user_mmap_file_slot_lock();
        slot = &g_user_mmap_file_slots[file_slot];
        if (slot->used && slot->orphaned && slot->orphan_ref &&
            slot->cache_generation == cache_generation &&
            vfs_inode_same_object(slot->sb, &slot->inode,
                                  superblock, &inode)) {
            if (slot->mapping_refs) {
                user_mmap_orphan_enqueue_locked((uint16_t)file_slot);
            } else {
                memset(slot, 0, sizeof(*slot));
                release_reference = 1;
            }
        }
        user_mmap_file_slot_unlock();
        if (release_reference) {
            vfs_inode_close(superblock, &inode);
            vfs_superblock_release(superblock);
        }
    }
    return result;
}

static void x86_mmap_lifetime_orphan_inode(
    void *context, vfs_superblock_t *superblock,
    const vfs_inode_t *inode) {
    int file_slot;
    (void)context;
    file_slot = x86_mmap_orphan_find_slot(superblock, inode, 0);
    if (file_slot < 0) return;
    if (x86_mmap_orphan_pin_slot(
            (uint16_t)file_slot, superblock, inode, 1) == 0)
        (void)x86_mmap_orphan_drain(1u);
}

static void x86_mmap_lifetime_prepare_alias_release(
    void *context, vfs_superblock_t *superblock,
    const vfs_inode_t *inode) {
    int file_slot;
    (void)context;
    file_slot = x86_mmap_orphan_find_slot(superblock, inode, 1);
    if (file_slot < 0) return;
    (void)x86_mmap_orphan_pin_slot(
        (uint16_t)file_slot, superblock, inode, 0);
}

static void x86_mmap_lifetime_finish_alias_release(void *context) {
    (void)context;
    (void)x86_mmap_orphan_drain(1u);
}

static int x86_mmap_lifetime_shutdown(void *context) {
    int result = 0;
    (void)context;

    /*
     * Terminal shutdown is a strict two-phase operation.  Do not release an
     * orphan reference here: the shared VFS first verifies that every cached
     * page was written, then performs ordinary filesystem sync, and only then
     * invokes the filesystem's terminal callback once per stable instance.
     */
    for (int page_slot = 0;
         page_slot < g_user_mmap_file_page_cache_high; ++page_slot) {
        user_mmap_file_page_cache_t *page =
            &g_user_mmap_file_page_cache[page_slot];
        if (page->used &&
            edge_mmap_file_cache_writeback_page(page) < 0)
            result = -EIO;
    }
    return result;
}

static const vfs_inode_lifetime_backend_ops_t
    x86_mmap_lifetime_backend_ops = {
        .orphan_inode = x86_mmap_lifetime_orphan_inode,
        .prepare_alias_release =
            x86_mmap_lifetime_prepare_alias_release,
        .finish_alias_release =
            x86_mmap_lifetime_finish_alias_release,
        .shutdown = x86_mmap_lifetime_shutdown,
    };

static int memfd_has_writable_shared_mapping(int memfd_id) {
    char prefix[32];
    if (memfd_id <= 0) return 0;
    memfd_build_path(prefix, sizeof(prefix), memfd_id, "");
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *t = process_task_by_index(i);
        if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) continue;
        /*
         * CLONE_VM threads all operate on their leader's VMA table.  Their
         * task-local arrays are only creation-time snapshots and must not be
         * interpreted as additional live mappings.  Doing so leaves phantom
         * writable mappings after the mm owner unmaps a memfd and makes
         * F_ADD_SEALS fail with EBUSY in Glycin and other threaded runtimes.
         */
        if (process_vm_task((task_t *)t) != t) continue;
        for (uint32_t v = 0; v < t->user_vma_count &&
                                  v < t->user_vma_capacity; ++v) {
            const edge_user_vma_t *m = &t->user_vmas[v];
            const char *path;
            if (m->end <= m->start || !m->file_backed) continue;
            if (!(m->flags & LINUX_MAP_SHARED) || !(m->prot & LINUX_PROT_WRITE)) continue;
            path = user_mmap_file_path(m->file_slot);
            if (path && strncmp(path, prefix, strlen(prefix)) == 0) return 1;
        }
    }
    return 0;
}

static void memfd_unmap_truncated_pages(int memfd_id, uint64_t length) {
    uint64_t cutoff = page_align_up(length);
    if (memfd_id <= 0) return;

    for (int task_index = 0; task_index < PROC_MAX_TASKS; ++task_index) {
        task_t *memory = (task_t *)process_task_by_index(task_index);
        int live;
        if (!memory || memory->state == TASK_UNUSED ||
            process_vm_task(memory) != memory)
            continue;
        live = user_vma_live_limit(memory);
        for (int vma_index = 0; vma_index < live; ++vma_index) {
            edge_user_vma_t *vma = &memory->user_vmas[vma_index];
            const char *path;
            uint64_t mapping_length;
            uint64_t mapping_file_end;
            uint64_t invalid_file_start;
            uint64_t invalid_address;
            uint64_t invalid_length;

            if (vma->end <= vma->start || !vma->file_backed)
                continue;
            path = user_mmap_file_path(vma->file_slot);
            if (memfd_id_from_path(path) != memfd_id) continue;
            mapping_length = vma->end - vma->start;
            mapping_file_end = vma->file_off + mapping_length;
            if (mapping_file_end < vma->file_off ||
                cutoff >= mapping_file_end)
                continue;
            invalid_file_start = cutoff > vma->file_off ?
                                 cutoff : vma->file_off;
            invalid_address = vma->start +
                              invalid_file_start - vma->file_off;
            invalid_length = vma->end - invalid_address;
            if (invalid_length)
                process_user_mmap_unmap_fast(
                    memory, invalid_address, invalid_length);
        }
    }
}

static int memfd_unmap_resident_object_page(int memfd_id,
                                             uint64_t object_page,
                                             int backing_index) {
    uint64_t object_offset = object_page * PAGE_SIZE;
    int unmapped_pages = 0;

    if (memfd_id <= 0 || backing_index < 0) return -1;
    for (int task_index = 0; task_index < PROC_MAX_TASKS; ++task_index) {
        task_t *memory = (task_t *)process_task_by_index(task_index);
        int live;

        if (!memory || memory->state == TASK_UNUSED ||
            process_vm_task(memory) != memory)
            continue;
        live = user_vma_live_limit(memory);
        for (int vma_index = 0; vma_index < live; ++vma_index) {
            edge_user_vma_t *vma = &memory->user_vmas[vma_index];
            const char *path;
            uint64_t mapping_length;
            uint64_t mapping_file_end;
            uint64_t address;

            if (vma->end <= vma->start || !vma->file_backed)
                continue;
            path = user_mmap_file_path(vma->file_slot);
            if (memfd_id_from_path(path) != memfd_id) continue;
            mapping_length = vma->end - vma->start;
            mapping_file_end = vma->file_off + mapping_length;
            if (mapping_file_end < vma->file_off ||
                object_offset < vma->file_off ||
                object_offset >= mapping_file_end)
                continue;
            address = vma->start + object_offset - vma->file_off;
            if (kernel_mm_lock_space_contains(memory->cr3, address))
                return -1;
            {
                int unmapped = process_user_mmap_unmap_page_if_backing(
                    memory, address, backing_index);
                if (unmapped < 0) return -1;
                unmapped_pages += unmapped;
            }
        }
    }
    return unmapped_pages;
}

static int memfd_pageout_object_page(edge_memfd_t *mf, int memfd_id,
                                     uint64_t page_no,
                                     uint32_t cgroup_id) {
#ifdef CONFIG_FS_SWAP
    uint64_t swap_entry;
    uint32_t owner;
    int backing_index;
    void *page;

    if (!mf || mf->secret || memfd_id <= 0 ||
        page_no >= EDGE_MEMFD_MAX_PAGES ||
        !swap_total_bytes())
        return 0;
    backing_index = mf->page_idx[page_no];
    if (backing_index < 0 || memfd_ensure_swap_metadata(mf) < 0)
        return 0;
    if (process_user_mmap_backing_page_cgroup(
            backing_index, &owner) < 0 || owner != cgroup_id)
        return 0;
    page = process_user_mmap_backing_page_ptr(backing_index);
    if (!page || memfd_unmap_resident_object_page(
            memfd_id, page_no, backing_index) <= 0)
        return 0;
    if (process_user_mmap_backing_page_cgroup(
            backing_index, &owner) == 0)
        return 0;
    if (process_user_mmap_backing_page_refcount(backing_index) != 1u)
        return 0;
    if (swap_store_page(cgroup_id, page, &swap_entry) < 0)
        return -1;
    if (process_user_mmap_backing_page_refcount(backing_index) != 1u ||
        mf->page_idx[page_no] != backing_index) {
        swap_release_entry(swap_entry);
        return 0;
    }
    mf->swap_entries[page_no] = swap_entry;
    mf->page_idx[page_no] = -1;
    process_user_mmap_release_backing_page(backing_index);
    return 1;
#else
    (void)mf;
    (void)memfd_id;
    (void)page_no;
    (void)cgroup_id;
    return 0;
#endif
}

static uint32_t memfd_pageout_range(task_t *memory, uint64_t start,
                                    uint64_t end,
                                    uint64_t *scanned_pages_out) {
#ifdef CONFIG_FS_SWAP
    uint64_t scanned = 0;
    uint32_t reclaimed = 0;
    int live;

    if (scanned_pages_out) *scanned_pages_out = 0;
    if (!memory || end <= start || !swap_total_bytes()) return 0;
    live = user_vma_live_limit(memory);
    for (int vma_index = 0; vma_index < live; ++vma_index) {
        edge_user_vma_t *vma = &memory->user_vmas[vma_index];
        const char *path;
        edge_memfd_t *mf;
        uint64_t overlap_start;
        uint64_t overlap_end;
        int memfd_id;

        if (vma->end <= vma->start || !vma->file_backed ||
            end <= vma->start || start >= vma->end)
            continue;
        path = user_mmap_file_path(vma->file_slot);
        memfd_id = memfd_id_from_path(path);
        if (memfd_id <= 0 || !(mf = memfd_get(memfd_id))) continue;
        overlap_start = start > vma->start ? start : vma->start;
        overlap_end = end < vma->end ? end : vma->end;
        for (uint64_t address = overlap_start; address < overlap_end;
             address += PAGE_SIZE) {
            uint64_t file_offset = vma->file_off + address - vma->start;
            uint64_t page_no = file_offset / PAGE_SIZE;
            int result;

            ++scanned;
            if (page_no >= EDGE_MEMFD_MAX_PAGES ||
                kernel_mm_lock_space_contains(memory->cr3, address))
                continue;
            result = memfd_pageout_object_page(
                mf, memfd_id, page_no, memory->cgroup_id);
            if (result < 0) break;
            reclaimed += (uint32_t)result;
        }
    }
    if (scanned_pages_out) *scanned_pages_out = scanned;
    edge_mm_statistics_note_reclaim(scanned, reclaimed);
    return reclaimed;
#else
    (void)memory;
    (void)start;
    (void)end;
    if (scanned_pages_out) *scanned_pages_out = 0;
    return 0;
#endif
}

static uint32_t memfd_pressure_reclaim(uint32_t cgroup_id,
                                       uint32_t target_pages,
                                       uint64_t *scanned_pages_out) {
#ifdef CONFIG_FS_SWAP
    static uint32_t object_cursor = 1u;
    static uint32_t page_cursor;
    uint32_t reclaimed = 0;
    uint32_t scanned = 0;
    uint32_t scan_budget;
    uint32_t idle_objects = 0;

    if (scanned_pages_out) *scanned_pages_out = 0;
    if (!target_pages || !swap_total_bytes()) return 0;
    scan_budget = target_pages > 64u ? 4096u : target_pages * 64u;
    if (scan_budget < 128u) scan_budget = 128u;
    while (reclaimed < target_pages && scanned < scan_budget) {
        edge_memfd_t *mf;
        uint64_t object_pages;
        uint32_t owner;
        int backing_index;
        int result;

        if (object_cursor == 0 || object_cursor >= EDGE_MEMFD_MAX) {
            object_cursor = 1u;
            page_cursor = 0;
        }
        mf = memfd_get((int)object_cursor);
        if (!mf || mf->secret || !mf->size) {
            ++object_cursor;
            page_cursor = 0;
            if (++idle_objects >= EDGE_MEMFD_MAX - 1u) break;
            continue;
        }
        object_pages = page_align_up(mf->size) / PAGE_SIZE;
        if (object_pages > EDGE_MEMFD_MAX_PAGES)
            object_pages = EDGE_MEMFD_MAX_PAGES;
        if (page_cursor >= object_pages) {
            ++object_cursor;
            page_cursor = 0;
            if (++idle_objects >= EDGE_MEMFD_MAX - 1u) break;
            continue;
        }
        idle_objects = 0;
        backing_index = mf->page_idx[page_cursor++];
        ++scanned;
        if (backing_index < 0 ||
            process_user_mmap_backing_page_cgroup(
                backing_index, &owner) < 0 ||
            owner != cgroup_id)
            continue;
        result = memfd_pageout_object_page(
            mf, (int)object_cursor, page_cursor - 1u, cgroup_id);
        if (result < 0) break;
        reclaimed += (uint32_t)result;
    }
    if (scanned_pages_out) *scanned_pages_out = scanned;
    edge_mm_statistics_note_reclaim(scanned, reclaimed);
    return reclaimed;
#else
    (void)cgroup_id;
    (void)target_pages;
    if (scanned_pages_out) *scanned_pages_out = 0;
    return 0;
#endif
}

static int user_mmap_exec_fault_should_log(task_t *t, const char *path, uint32_t prot) {
    if (g_user_mmap_exec_fault_log_budget <= 0) return 0;
    if ((prot & LINUX_PROT_EXEC) == 0) return 0;
    if (!t || !path) return 0;
    if (strcmp(t->name, "Xorg") == 0 ||
        strcmp(t->name, "xfce4-session") == 0 ||
        strcmp(t->name, "xfwm4") == 0 ||
        strcmp(t->name, "xfdesktop") == 0 ||
        strcmp(t->name, "xfce4-panel") == 0 ||
        strcmp(t->name, "xfsettingsd") == 0 ||
        strcmp(t->name, "gdbus") == 0 ||
        strcmp(t->name, "Thunar") == 0 ||
        strcmp(t->name, "gst-plugin-scanner") == 0) {
        return 1;
    }
    return strstr(path, "/usr/lib/libglib-") != 0 ||
           strstr(path, "/usr/lib/libgio-") != 0 ||
           strstr(path, "/usr/lib/libgdk-") != 0 ||
           strstr(path, "/usr/lib/libgtk-") != 0 ||
           strstr(path, "/usr/lib/libX11.") != 0 ||
           strstr(path, "/usr/lib/libcairo.") != 0;
}

static void user_mmap_log_exec_fault_page(task_t *t, const edge_user_vma_t *v,
                                          uint64_t page, uint64_t file_page_off,
                                          int shared_file_page, int backing_idx) {
    const char *path;
    uint8_t *p;
    uint32_t cksum = 0;
    if (!v || !v->file_backed) return;
    path = user_mmap_file_path(v->file_slot);
    if (!user_mmap_exec_fault_should_log(t, path, v->prot)) return;
    p = process_user_mmap_backing_page_ptr(backing_idx);
    if (!p) return;
    for (uint32_t i = 0; i < PAGE_SIZE; ++i) cksum = (cksum * 131u) + p[i];
    g_user_mmap_exec_fault_log_budget--;
    printf("[mmap-exec-fault] pid=%d cmd=%s va=0x%x vma=0x%x-0x%x prot=0x%x flags=0x%x file_off=0x%x file_len=0x%x page_off=0x%x shared=%d backing=%d cksum=0x%x path=%s bytes=%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x budget=%d\n",
           t ? t->pid : -1,
           (t && t->name[0]) ? t->name : "?",
           (uint32_t)page,
           (uint32_t)v->start, (uint32_t)v->end,
           v->prot, v->flags,
           (uint32_t)v->file_off, (uint32_t)v->file_len, (uint32_t)file_page_off,
           shared_file_page, backing_idx, cksum,
           path && path[0] ? path : "-",
           (uint32_t)p[0], (uint32_t)p[1], (uint32_t)p[2], (uint32_t)p[3],
           (uint32_t)p[4], (uint32_t)p[5], (uint32_t)p[6], (uint32_t)p[7],
           (uint32_t)p[8], (uint32_t)p[9], (uint32_t)p[10], (uint32_t)p[11],
           (uint32_t)p[12], (uint32_t)p[13], (uint32_t)p[14], (uint32_t)p[15],
           g_user_mmap_exec_fault_log_budget);
}

static uint16_t user_mmap_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t user_mmap_le32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t user_mmap_le64(const uint8_t *p) {
    return (uint64_t)user_mmap_le32(p) |
           ((uint64_t)user_mmap_le32(p + 4) << 32);
}

static void user_mmap_diag_elf64_phdrs(task_t *t, const char *path, const uint8_t *p) {
    uint64_t phoff;
    uint16_t phentsz;
    uint16_t phnum;
    uint16_t max_phnum;
    if (g_apk_libcrypto_phdr_budget <= 0) return;
    if (!p || !user_mmap_is_apk_libcrypto(t, path)) return;
    if (p[0] != 0x7f || p[1] != 'E' || p[2] != 'L' || p[3] != 'F' ||
        p[4] != 2 || p[5] != 1) {
        printf("[apk-libcrypto-elf] pid=%d invalid magic=%x %x %x %x class=%x data=%x path=%s budget=%d\n",
               t ? t->pid : -1,
               (uint32_t)p[0], (uint32_t)p[1], (uint32_t)p[2], (uint32_t)p[3],
               (uint32_t)p[4], (uint32_t)p[5],
               path ? path : "-", g_apk_libcrypto_phdr_budget - 1);
        g_apk_libcrypto_phdr_budget--;
        return;
    }
    phoff = user_mmap_le64(p + 32);
    phentsz = user_mmap_le16(p + 54);
    phnum = user_mmap_le16(p + 56);
    printf("[apk-libcrypto-elf] pid=%d cmd=%s phoff=0x%x phentsz=%u phnum=%u entry=0x%x type=%u machine=%u path=%s budget=%d\n",
           t ? t->pid : -1,
           (t && t->name[0]) ? t->name : "?",
           (uint32_t)phoff, (uint32_t)phentsz, (uint32_t)phnum,
           (uint32_t)user_mmap_le64(p + 24),
           (uint32_t)user_mmap_le16(p + 16),
           (uint32_t)user_mmap_le16(p + 18),
           path ? path : "-", g_apk_libcrypto_phdr_budget - 1);
    max_phnum = phnum;
    if (max_phnum > 16) max_phnum = 16;
    if (phentsz < 56 || phoff > PAGE_SIZE || phoff + (uint64_t)max_phnum * phentsz > PAGE_SIZE) {
        g_apk_libcrypto_phdr_budget--;
        return;
    }
    for (uint16_t i = 0; i < max_phnum; ++i) {
        const uint8_t *q = p + phoff + (uint64_t)i * phentsz;
        uint32_t type = user_mmap_le32(q + 0);
        uint32_t flags = user_mmap_le32(q + 4);
        uint64_t off = user_mmap_le64(q + 8);
        uint64_t vaddr = user_mmap_le64(q + 16);
        uint64_t filesz = user_mmap_le64(q + 32);
        uint64_t memsz = user_mmap_le64(q + 40);
        uint64_t align = user_mmap_le64(q + 48);
        printf("[apk-libcrypto-phdr] pid=%d i=%u type=0x%x flags=0x%x off=0x%x vaddr=0x%x filesz=0x%x memsz=0x%x align=0x%x\n",
               t ? t->pid : -1,
               (uint32_t)i, type, flags,
               (uint32_t)off, (uint32_t)vaddr,
               (uint32_t)filesz, (uint32_t)memsz,
               (uint32_t)align);
    }
    g_apk_libcrypto_phdr_budget--;
}

static void user_mmap_diag_dso_page(task_t *t, const edge_user_vma_t *v,
                                    uint64_t page, uint64_t file_page_off,
                                    int backing_idx, int shared_file_page) {
    const char *path;
    uint8_t *p;
    uint32_t cksum = 0;
    uint32_t probe = 0;
    if (g_user_mmap_dso_diag_budget <= 0) return;
    if (!v || !v->file_backed) return;
    path = user_mmap_file_path(v->file_slot);
    if (!path || (strstr(path, "tumbler-xdg-cache.so") == 0 &&
                  !user_mmap_is_apk_libcrypto(t, path))) return;
    if (file_page_off != 0 && file_page_off != 0x6000 && file_page_off != 0x446000) return;
    p = process_user_mmap_backing_page_ptr(backing_idx);
    if (!p) return;
    for (uint32_t i = 0; i < PAGE_SIZE; ++i) cksum = (cksum * 131u) + p[i];
    if (file_page_off == 0) {
        probe = 0x300;
        user_mmap_diag_elf64_phdrs(t, path, p);
    } else {
        probe = 0xa40;
    }
    g_user_mmap_dso_diag_budget--;
    printf("[mmap-dso] pid=%d cmd=%s va=0x%x page_off=0x%x vma=0x%x-0x%x file_off=0x%x len=0x%x shared=%d backing=%d cksum=0x%x probe=0x%x bytes=%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x path=%s budget=%d\n",
           t ? t->pid : -1,
           (t && t->name[0]) ? t->name : "?",
           (uint32_t)page, (uint32_t)file_page_off,
           (uint32_t)v->start, (uint32_t)v->end,
           (uint32_t)v->file_off, (uint32_t)v->file_len,
           shared_file_page, backing_idx, cksum, probe,
           (uint32_t)p[probe + 0], (uint32_t)p[probe + 1],
           (uint32_t)p[probe + 2], (uint32_t)p[probe + 3],
           (uint32_t)p[probe + 4], (uint32_t)p[probe + 5],
           (uint32_t)p[probe + 6], (uint32_t)p[probe + 7],
           (uint32_t)p[probe + 8], (uint32_t)p[probe + 9],
           (uint32_t)p[probe + 10], (uint32_t)p[probe + 11],
           (uint32_t)p[probe + 12], (uint32_t)p[probe + 13],
           (uint32_t)p[probe + 14], (uint32_t)p[probe + 15],
           path, g_user_mmap_dso_diag_budget);
}

static uint64_t user_mmap_file_fault_end(const edge_user_vma_t *v) {
    uint64_t vma_length;
    uint64_t coverage;
    uint64_t file_size = 0;
    int have_file_size = 0;

    if (!v || !v->file_backed || v->end <= v->start) return 0;
    vma_length = v->end - v->start;
    coverage = v->file_len < vma_length ? v->file_len : vma_length;
    if (v->file_have_inode) {
        file_size = v->file_size;
        have_file_size = 1;
    } else if (v->file_slot < USER_MMAP_FILE_SLOT_MAX &&
               g_user_mmap_file_slots[v->file_slot].used &&
               g_user_mmap_file_slots[v->file_slot].have_inode) {
        file_size = g_user_mmap_file_slots[v->file_slot].inode.size;
        have_file_size = 1;
    }
    if (have_file_size) {
        uint64_t bytes;
        if (v->file_off >= file_size) return v->start;
        bytes = file_size - v->file_off;
        if (coverage > bytes) coverage = bytes;
    }
    coverage = page_align_up(coverage);
    if (coverage > vma_length) coverage = vma_length;
    return v->start + coverage;
}

static int user_mmap_map_cached_fault_window(
    task_t *t, const edge_user_vma_t *v, uint64_t fault_page,
    int required_backing, int writable, int shared_file_page,
    int private_cow) {
    int backing[USER_MMAP_FILE_READAHEAD_PAGES];
    uint64_t file_end;
    uint64_t start;
    uint64_t available_pages;
    uint32_t page_count;
    uint32_t required_index;
    uint32_t acquired = 0;
    int result;

    if (!t || !v || required_backing < 0) {
        if (required_backing >= 0)
            process_user_mmap_release_backing_page(required_backing);
        return -1;
    }
    if (fault_page < v->start || fault_page >= v->end) {
        process_user_mmap_release_backing_page(required_backing);
        return -1;
    }
    if (shared_file_page && writable) {
        uint64_t offset_in_vma = fault_page - v->start;
        if (offset_in_vma <= UINT64_MAX - v->file_off) {
            process_user_mmap_file_page_write_notify(
                v->file_slot, v->file_off + offset_in_vma);
        }
    }
    file_end = user_mmap_file_fault_end(v);
    if (fault_page < v->start || fault_page >= file_end ||
        (v->prot & (LINUX_PROT_READ | LINUX_PROT_WRITE |
                    LINUX_PROT_EXEC)) == 0) {
        result = process_user_mmap_map_file_cache_page(
            t, fault_page, required_backing,
            shared_file_page && writable, private_cow);
        process_user_mmap_release_backing_page(required_backing);
        return result;
    }

    /*
     * Match the cache's forward readahead direction.  The required page is the
     * first entry and the rest are speculative cache hits, never extra I/O.
     */
    start = fault_page;
    available_pages = (file_end - start) / PAGE_SIZE;
    if (available_pages > USER_MMAP_FILE_READAHEAD_PAGES)
        available_pages = USER_MMAP_FILE_READAHEAD_PAGES;
    page_count = (uint32_t)available_pages;
    required_index = (uint32_t)((fault_page - start) / PAGE_SIZE);
    if (page_count == 0 || required_index >= page_count) {
        result = process_user_mmap_map_file_cache_page(
            t, fault_page, required_backing,
            shared_file_page && writable, private_cow);
        process_user_mmap_release_backing_page(required_backing);
        return result;
    }

    for (uint32_t index = 0; index < page_count; ++index) {
        uint64_t va = start + (uint64_t)index * PAGE_SIZE;
        uint64_t offset_in_vma = va - v->start;
        uint64_t file_page_off;

        backing[index] = -1;
        if (index == required_index) {
            backing[index] = required_backing;
        } else {
            if (offset_in_vma > UINT64_MAX - v->file_off) continue;
            file_page_off = v->file_off + offset_in_vma;
            backing[index] = user_mmap_file_cache_acquire(
                v->file_slot, file_page_off, 0);
        }
        if (backing[index] < 0) continue;
        acquired++;
        if (index != required_index && shared_file_page && writable) {
            file_page_off = v->file_off + offset_in_vma;
            process_user_mmap_file_page_write_notify(
                v->file_slot, file_page_off);
        }
    }

    if (acquired > 1) {
        result = process_user_mmap_map_file_cache_pages(
            t, start, backing, page_count, required_index,
            shared_file_page && writable, private_cow);
    } else {
        result = process_user_mmap_map_file_cache_page(
            t, fault_page, required_backing,
            shared_file_page && writable, private_cow);
    }
    for (uint32_t index = 0; index < page_count; ++index) {
        if (backing[index] >= 0)
            process_user_mmap_release_backing_page(backing[index]);
    }
    return result;
}

int user_mmap_populate_file_page(task_t *t, const edge_user_vma_t *v, uint64_t page, int write) {
    uint64_t offset_in_vma;
    uint64_t file_page_off;
    int writable;
    int shared_file_page;
    int private_cow;
    int backing_idx;

    if (!t || !v || !v->file_backed) return -1;
    if (page < v->start || page >= v->end) return -1;
    if (write && (v->prot & LINUX_PROT_WRITE) == 0) {
        const char *path = user_mmap_file_path(v->file_slot);
        if (g_apk_libcrypto_ro_write_budget > 0 && user_mmap_is_apk_libcrypto(t, path)) {
            uint64_t off_in_vma = page - v->start;
            printf("[apk-libcrypto-ro-write] pid=%d cmd=%s addr_page=0x%x vma=0x%x-0x%x prot=0x%x flags=0x%x file_off=0x%x file_page_off=0x%x file_len=0x%x path=%s budget=%d\n",
                   t ? t->pid : -1,
                   (t && t->name[0]) ? t->name : "?",
                   (uint32_t)page,
                   (uint32_t)v->start, (uint32_t)v->end,
                   v->prot, v->flags,
                   (uint32_t)v->file_off,
                   (uint32_t)(v->file_off + off_in_vma),
                   (uint32_t)v->file_len,
                   path ? path : "-",
                   g_apk_libcrypto_ro_write_budget - 1);
            user_mmap_dump_apk_libcrypto_vmas(t, "ro-write", v->start, v->end - v->start,
                                              v->prot, v->flags, v->file_off);
            g_apk_libcrypto_ro_write_budget--;
        }
        return -1;
    }

    offset_in_vma = page - v->start;
    if (offset_in_vma >= v->file_len) {
        /*
         * Past-EOF MAP_PRIVATE/MAP_SHARED tail pages are zero-filled.  This
         * covers BSS-like mapping tails without forcing mmap(2) to allocate
         * every page up front.  Keep protection aligned with the VMA after the
         * anonymous zero page is installed.
         */
        if (process_user_mmap_commit(t, page, PAGE_SIZE) < 0) return -1;
        if (process_user_mmap_protect(t, page, PAGE_SIZE, v->prot) < 0) return -1;
        return 0;
    }

    file_page_off = v->file_off + offset_in_vma;
    writable = ((v->prot & LINUX_PROT_WRITE) != 0);
    /*
     * Linux MAP_PRIVATE mappings read from the same immutable page-cache page
     * as MAP_SHARED until the process writes.  A writable private VMA must never
     * receive a writable alias to that cache page: install it read-only with
     * PAGE_COW and let the architecture fault path allocate private backing on
     * the first write.  Read-only text stays shared across every ELF consumer.
     * PAGE_FILE_CACHE ownership and backing generations prevent a stale cache
     * entry from being confused with a recycled anonymous or device page.
     */
    shared_file_page = ((v->flags & LINUX_MAP_SHARED) != 0);
    private_cow = !shared_file_page && writable;
    backing_idx = user_mmap_cached_file_backing(v->file_slot, file_page_off);
    if (backing_idx < 0) return -1;
    user_mmap_diag_dso_page(t, v, page, file_page_off, backing_idx, shared_file_page);
    user_mmap_log_exec_fault_page(t, v, page, file_page_off, shared_file_page, backing_idx);
    return user_mmap_map_cached_fault_window(
        t, v, page, backing_idx, writable, shared_file_page,
        private_cow);
}

static int user_mmap_inode_same(const vfs_inode_t *a, vfs_superblock_t *asb,
                                const vfs_inode_t *b, vfs_superblock_t *bsb) {
    return vfs_inode_same_object(asb, a, bsb, b);
}

static void user_vma_set_file_identity(edge_user_vma_t *v,
                                       const vfs_inode_t *inode,
                                       vfs_superblock_t *sb) {
    if (!v) return;
    v->file_have_inode = 0;
    v->file_sb = 0;
    v->file_ino = 0;
    v->file_generation = 0;
    v->file_mode = 0;
    v->file_uid = 0;
    v->file_gid = 0;
    v->file_size = 0;
    memset(v->file_fs_private, 0, sizeof(v->file_fs_private));
    if (!inode || !sb) return;
    v->file_ino = inode->ino;
    v->file_generation = inode->generation;
    v->file_mode = inode->mode;
    v->file_uid = inode->uid;
    v->file_gid = inode->gid;
    v->file_size = inode->size;
    memcpy(v->file_fs_private, inode->fs_private, sizeof(v->file_fs_private));
    v->file_sb = vfs_superblock_stable(sb);
    v->file_have_inode = 1;
}

static int user_mmap_file_slot_inode(uint16_t file_slot, vfs_inode_t *ino_out,
                                     vfs_superblock_t **sb_out) {
    if (file_slot >= USER_MMAP_FILE_SLOT_MAX) return -1;
    if (!g_user_mmap_file_slots[file_slot].used ||
        g_user_mmap_file_slots[file_slot].reclaiming ||
        !g_user_mmap_file_slots[file_slot].have_inode ||
        !g_user_mmap_file_slots[file_slot].sb) return -1;
    if (ino_out) *ino_out = g_user_mmap_file_slots[file_slot].inode;
    if (sb_out) *sb_out = g_user_mmap_file_slots[file_slot].sb;
    return 0;
}

static int user_vma_get_file_inode(const edge_user_vma_t *v,
                                   vfs_inode_t *ino_out,
                                   vfs_superblock_t **sb_out) {
    vfs_inode_t ino;
    if (!v || !v->file_backed || !v->file_have_inode || !v->file_sb) return -1;
    memset(&ino, 0, sizeof(ino));
    ino.ino = v->file_ino;
    ino.generation = v->file_generation;
    ino.mode = v->file_mode;
    ino.uid = v->file_uid;
    ino.gid = v->file_gid;
    ino.size = v->file_size;
    memcpy(ino.fs_private, v->file_fs_private, sizeof(ino.fs_private));
    if (ino_out) *ino_out = ino;
    if (sb_out) *sb_out = (vfs_superblock_t *)v->file_sb;
    return 0;
}

static int user_mmap_read_file_page_for_vma(const edge_user_vma_t *v,
                                            uint64_t file_off,
                                            void *dst) {
    vfs_inode_t ino;
    vfs_superblock_t *sb = 0;
    uint32_t count;
    const char *path;
    int memfd_id;

    if (!dst || !v || !v->file_backed) return -1;
    path = user_mmap_file_path(v->file_slot);
    memset(dst, 0, PAGE_SIZE);

    memfd_id = memfd_id_from_path(path);
    if (memfd_id > 0) {
        edge_memfd_t *mf = memfd_get(memfd_id);
        int r;
        if (!mf) return -1;
        r = memfd_read_to_kernel(mf, file_off, dst, PAGE_SIZE);
        return r < 0 ? -1 : 0;
    }

    /*
     * Linux file VMAs fault from the file object captured at mmap(2) time.
     * Prefer the VMA-local inode snapshot so a closed fd, renamed file, or
     * diagnostic path-slot churn cannot make later executable faults read
     * the wrong file or fail with a missing pathname.
     */
    if (user_vma_get_file_inode(v, &ino, &sb) < 0 &&
        user_mmap_file_slot_inode(v->file_slot, &ino, &sb) < 0) {
        if (!path || vfs_resolve(path, &ino, &sb, 0, 0) < 0) return -1;
    }
    if (!sb || !sb->ops || !sb->ops->read) return -1;
    if (file_off >= ino.size) return 0;
    count = (uint32_t)((uint64_t)ino.size - file_off);
    if (count > PAGE_SIZE) count = PAGE_SIZE;
    return vfs_read_inode_exact(sb, &ino, file_off, dst, count);
}

static void user_mmap_build_inode_slot_path(char *buf, uint32_t max, const vfs_inode_t *inode) {
    char ino_buf[24];
    if (!buf || max == 0) return;
    buf[0] = 0;
    if (!inode) return;
    strcpy(buf, "/.edgeos-inode/");
    itoa(ino_buf, 10, (int)inode->ino);
    if ((uint32_t)(strlen(buf) + strlen(ino_buf) + 1) < max) {
        strcat(buf, ino_buf);
    }
}

static void user_mmap_file_slot_snapshot_live_vmas(void) {
    memset(g_user_mmap_file_live_slots, 0,
           sizeof(g_user_mmap_file_live_slots));
    for (int task_slot = 0; task_slot < PROC_MAX_TASKS; ++task_slot) {
        const task_t *task = process_task_by_index(task_slot);
        task_t *mm;
        int live;

        if (!task || task->state == TASK_UNUSED) continue;
        mm = process_vm_task((task_t *)task);
        if (!mm) continue;
        live = mm->user_vma_count;
        if ((uint32_t)live > mm->user_vma_capacity)
            live = (int)mm->user_vma_capacity;
        for (int vma_slot = 0; vma_slot < live; ++vma_slot) {
            const edge_user_vma_t *vma = &mm->user_vmas[vma_slot];
            if (vma->file_backed && vma->end > vma->start &&
                vma->file_slot < USER_MMAP_FILE_SLOT_MAX)
                g_user_mmap_file_live_slots[vma->file_slot / 64u] |=
                    1ull << (vma->file_slot % 64u);
        }
    }
}

static int user_mmap_file_slot_live_in_snapshot(uint16_t file_slot) {
    if (file_slot >= USER_MMAP_FILE_SLOT_MAX) return 0;
    return (g_user_mmap_file_live_slots[file_slot / 64u] &
            (1ull << (file_slot % 64u))) != 0;
}

/*
 * The path/inode table is an identity cache, not a lifetime limit.  Repeated
 * desktop application launches create short-lived shared-memory and temporary
 * file identities, so retain active entries and retire the least recently used
 * inactive batch when the bounded table reaches pressure.  Writable cached
 * pages are committed before their identity is released.
 */
static uint32_t user_mmap_file_slot_reclaim_unused(void) {
    uint32_t selected = 0;
    uint32_t marked = 0;
    uint32_t freed = 0;
    uint32_t slot_limit;

    user_mmap_file_reclaim_lock();
    memset(g_user_mmap_file_reclaim_index, 0xff,
           sizeof(g_user_mmap_file_reclaim_index));
    memset(g_user_mmap_file_reclaim_failed, 0,
           sizeof(g_user_mmap_file_reclaim_failed));
    memset(g_user_mmap_file_reclaim_superblocks, 0,
           sizeof(g_user_mmap_file_reclaim_superblocks));
    user_mmap_file_slot_snapshot_live_vmas();
    slot_limit = user_mmap_file_slot_limit();

    for (uint32_t file_slot = 0;
         file_slot < slot_limit; ++file_slot) {
        kernel_mm_reclaim_candidate_t candidate;
        user_mmap_file_slot_t *slot;

        memset(&candidate, 0, sizeof(candidate));
        user_mmap_file_slot_lock();
        slot = &g_user_mmap_file_slots[file_slot];
        candidate.slot = (uint16_t)file_slot;
        candidate.used = slot->used;
        candidate.busy = slot->reclaiming;
        candidate.pinned =
            slot->orphaned || slot->orphan_ref ||
            slot->orphan_pending;
        candidate.references = slot->mapping_refs;
        candidate.last_used_sequence = slot->last_used_sequence;
        user_mmap_file_slot_unlock();
        if (!candidate.used || candidate.busy ||
            candidate.pinned || candidate.references)
            continue;
        if (user_mmap_file_slot_live_in_snapshot(
                (uint16_t)file_slot))
            candidate.pinned = 1;
        selected = kernel_mm_reclaim_candidate_offer(
            g_user_mmap_file_reclaim_selection, selected,
            USER_MMAP_FILE_RECLAIM_BATCH, &candidate);
    }

    user_mmap_file_slot_snapshot_live_vmas();
    for (uint32_t candidate_index = 0;
         candidate_index < selected; ++candidate_index) {
        const kernel_mm_reclaim_candidate_t *candidate =
            &g_user_mmap_file_reclaim_selection[candidate_index];
        user_mmap_file_slot_t *slot;
        uint16_t file_slot = candidate->slot;

        if (user_mmap_file_slot_live_in_snapshot(file_slot)) {
            g_user_mmap_file_reclaim_failed[candidate_index] = 1;
            continue;
        }
        user_mmap_file_slot_lock();
        slot = &g_user_mmap_file_slots[file_slot];
        if (!slot->used || slot->reclaiming ||
            slot->mapping_refs || slot->orphaned ||
            slot->orphan_ref || slot->orphan_pending ||
            slot->last_used_sequence !=
                candidate->last_used_sequence) {
            g_user_mmap_file_reclaim_failed[candidate_index] = 1;
            user_mmap_file_slot_unlock();
            continue;
        }
        slot->reclaiming = 1;
        g_user_mmap_file_reclaim_index[file_slot] =
            (int16_t)candidate_index;
        ++marked;
        user_mmap_file_slot_unlock();
    }

    if (!marked) {
        user_mmap_file_reclaim_unlock();
        return 0;
    }

    user_mmap_file_cache_lock();
    for (int page_slot = 0;
         page_slot < g_user_mmap_file_page_cache_high; ++page_slot) {
        user_mmap_file_page_cache_t *page =
            &g_user_mmap_file_page_cache[page_slot];
        int16_t candidate_index;

        if (!page->used ||
            page->file_slot >= USER_MMAP_FILE_SLOT_MAX)
            continue;
        candidate_index =
            g_user_mmap_file_reclaim_index[page->file_slot];
        if (candidate_index < 0 ||
            g_user_mmap_file_reclaim_failed[candidate_index])
            continue;
        if (edge_mmap_file_cache_writeback_page(page) < 0)
            g_user_mmap_file_reclaim_failed[candidate_index] = 1;
    }
    for (int page_slot = 0;
         page_slot < g_user_mmap_file_page_cache_high; ++page_slot) {
        user_mmap_file_page_cache_t *page =
            &g_user_mmap_file_page_cache[page_slot];
        int16_t candidate_index;

        if (!page->used ||
            page->file_slot >= USER_MMAP_FILE_SLOT_MAX)
            continue;
        candidate_index =
            g_user_mmap_file_reclaim_index[page->file_slot];
        if (candidate_index < 0 ||
            g_user_mmap_file_reclaim_failed[candidate_index])
            continue;
        user_mmap_file_cache_hash_remove_slot(page_slot);
        if (process_user_mmap_backing_page_active(
                page->backing_idx) &&
            process_user_mmap_backing_page_generation(
                page->backing_idx) == page->backing_generation)
            process_user_mmap_release_backing_page(
                page->backing_idx);
        x86_page_writeback_forget_cache(
            page, (uint32_t)page_slot);
        memset(page, 0, sizeof(*page));
        if (page_slot < g_user_mmap_file_page_cache_free_hint)
            g_user_mmap_file_page_cache_free_hint = page_slot;
    }
    while (g_user_mmap_file_page_cache_high > 0 &&
           !g_user_mmap_file_page_cache[
                g_user_mmap_file_page_cache_high - 1].used)
        --g_user_mmap_file_page_cache_high;
    if (g_user_mmap_file_page_cache_free_hint >
        g_user_mmap_file_page_cache_high)
        g_user_mmap_file_page_cache_free_hint =
            g_user_mmap_file_page_cache_high;
    user_mmap_file_cache_unlock();

    user_mmap_file_slot_snapshot_live_vmas();
    for (uint32_t candidate_index = 0;
         candidate_index < selected; ++candidate_index) {
        const kernel_mm_reclaim_candidate_t *candidate =
            &g_user_mmap_file_reclaim_selection[candidate_index];
        user_mmap_file_slot_t *slot;
        vfs_superblock_t *superblock = 0;
        uint16_t file_slot = candidate->slot;

        if (!g_user_mmap_file_reclaim_failed[candidate_index] &&
            user_mmap_file_slot_live_in_snapshot(file_slot))
            g_user_mmap_file_reclaim_failed[candidate_index] = 1;
        user_mmap_file_slot_lock();
        slot = &g_user_mmap_file_slots[file_slot];
        if (!g_user_mmap_file_reclaim_failed[candidate_index] &&
            slot->used && slot->reclaiming &&
            !slot->mapping_refs && !slot->orphaned &&
            !slot->orphan_ref && !slot->orphan_pending &&
            slot->last_used_sequence ==
                candidate->last_used_sequence) {
            if (slot->have_inode) superblock = slot->sb;
            memset(slot, 0, sizeof(*slot));
            g_user_mmap_file_reclaim_superblocks[candidate_index] =
                superblock;
            ++freed;
        } else if (slot->used && slot->reclaiming) {
            slot->reclaiming = 0;
        }
        user_mmap_file_slot_unlock();
    }

    for (uint32_t candidate_index = 0;
         candidate_index < selected; ++candidate_index) {
        if (g_user_mmap_file_reclaim_superblocks[candidate_index])
            vfs_superblock_release(
                g_user_mmap_file_reclaim_superblocks[candidate_index]);
    }
    user_mmap_file_reclaim_unlock();
    return freed;
}

static int user_mmap_file_slot_ex(const char *path, const vfs_inode_t *inode, vfs_superblock_t *sb) {
    int free_slot = -1;
    int reclaim_attempted = 0;
    uint32_t slot_limit;
    if (!path || !path[0]) return -1;
retry:
    free_slot = -1;
    user_mmap_file_slot_lock();
    slot_limit = user_mmap_file_slot_limit();
    if (inode && sb) {
        for (uint32_t i = 0; i < slot_limit; ++i) {
            if (!g_user_mmap_file_slots[i].used) {
                if (free_slot < 0) free_slot = (int)i;
                continue;
            }
            if (g_user_mmap_file_slots[i].reclaiming) continue;
            if (g_user_mmap_file_slots[i].have_inode &&
                user_mmap_inode_same(&g_user_mmap_file_slots[i].inode,
                                     g_user_mmap_file_slots[i].sb,
                                     inode, sb)) {
                /*
                 * Linux VMAs are backed by the opened file object, not by a
                 * later pathname lookup.  Keep one slot per inode/superblock
                 * and merely refresh the printable path when the same inode is
                 * observed through a new name.
                 */
                strncpy(g_user_mmap_file_slots[i].path, path,
                        sizeof(g_user_mmap_file_slots[i].path) - 1);
                g_user_mmap_file_slots[i].path[sizeof(g_user_mmap_file_slots[i].path) - 1] = 0;
                user_mmap_file_slot_refresh_identity_locked(
                    &g_user_mmap_file_slots[i], inode);
                user_mmap_log_apk_libcrypto_inode(process_current_task(), "slot-reuse-inode",
                                                  path, (int)i, inode, sb);
                user_mmap_file_slot_touch_locked(
                    &g_user_mmap_file_slots[i]);
                user_mmap_file_slot_unlock();
                return (int)i;
            }
        }
    }
    for (uint32_t i = 0; i < slot_limit; ++i) {
        if (g_user_mmap_file_slots[i].used) {
            if (g_user_mmap_file_slots[i].reclaiming) continue;
            if (strcmp(g_user_mmap_file_slots[i].path, (char *)path) == 0) {
                if (inode && sb) {
                    if (g_user_mmap_file_slots[i].have_inode &&
                        !user_mmap_inode_same(&g_user_mmap_file_slots[i].inode,
                                             g_user_mmap_file_slots[i].sb,
                                             inode, sb)) {
                        /*
                         * Atomic package updates commonly reuse a pathname for
                         * a different inode.  Reusing the old slot would make a
                         * new mmap read the previous file's bytes while the VMA
                         * claims the new pathname.  Allocate a fresh slot below.
                         */
                        continue;
                    }
                    if (!g_user_mmap_file_slots[i].have_inode) {
                        vfs_superblock_t *stable =
                            vfs_superblock_acquire(sb);
                        if (!stable) {
                            user_mmap_file_slot_unlock();
                            return -1;
                        }
                        g_user_mmap_file_slots[i].cache_generation++;
                        if (g_user_mmap_file_slots[i].cache_generation == 0) {
                            g_user_mmap_file_slots[i].cache_generation = 1;
                        }
                        g_user_mmap_file_slots[i].sb = stable;
                    }
                    user_mmap_file_slot_refresh_identity_locked(
                        &g_user_mmap_file_slots[i], inode);
                    g_user_mmap_file_slots[i].have_inode = 1;
                }
                user_mmap_log_apk_libcrypto_inode(process_current_task(), "slot-reuse-path",
                                                  path, (int)i,
                                                  g_user_mmap_file_slots[i].have_inode ?
                                                      &g_user_mmap_file_slots[i].inode : inode,
                                                  g_user_mmap_file_slots[i].have_inode ?
                                                      g_user_mmap_file_slots[i].sb : sb);
                user_mmap_file_slot_touch_locked(
                    &g_user_mmap_file_slots[i]);
                user_mmap_file_slot_unlock();
                return (int)i;
            }
            continue;
        }
        if (free_slot < 0) free_slot = (int)i;
    }
    if (free_slot < 0 && slot_limit < USER_MMAP_FILE_SLOT_MAX)
        free_slot = (int)slot_limit;
    if (free_slot < 0) {
        user_mmap_file_slot_unlock();
        if (!reclaim_attempted) {
            reclaim_attempted = 1;
            if (user_mmap_file_slot_reclaim_unused() > 0)
                goto retry;
        }
        if (g_user_mmap_cache_fail_log_budget > 0) {
            printf("[mmap-file-slot] full max=%u path=%s backing=%u/%u pt=%u/%u budget=%d\n",
                   (uint32_t)USER_MMAP_FILE_SLOT_MAX, path,
                   process_user_mmap_backing_used_pages(),
                   process_user_mmap_backing_total_pages(),
                   process_user_mmap_pt_used_pages(),
                   process_user_mmap_pt_total_pages(),
                   g_user_mmap_cache_fail_log_budget - 1);
            g_user_mmap_cache_fail_log_budget--;
        }
        return -1;
    }
    memset(&g_user_mmap_file_slots[free_slot], 0, sizeof(g_user_mmap_file_slots[free_slot]));
    g_user_mmap_file_slots[free_slot].used = 1;
    g_user_mmap_file_slots[free_slot].cache_generation = 1;
    g_user_mmap_file_slots[free_slot].orphan_next = -1;
    if (inode && sb) {
        vfs_superblock_t *stable = vfs_superblock_acquire(sb);
        if (!stable) {
            memset(&g_user_mmap_file_slots[free_slot], 0,
                   sizeof(g_user_mmap_file_slots[free_slot]));
            user_mmap_file_slot_unlock();
            return -1;
        }
        user_mmap_file_slot_refresh_identity_locked(
            &g_user_mmap_file_slots[free_slot], inode);
        g_user_mmap_file_slots[free_slot].sb = stable;
        g_user_mmap_file_slots[free_slot].have_inode = 1;
    }
    strncpy(g_user_mmap_file_slots[free_slot].path, path,
            sizeof(g_user_mmap_file_slots[free_slot].path) - 1);
    g_user_mmap_file_slots[free_slot].path[sizeof(g_user_mmap_file_slots[free_slot].path) - 1] = 0;
    user_mmap_file_slot_touch_locked(
        &g_user_mmap_file_slots[free_slot]);
    user_mmap_file_slot_publish_high_locked(
        (uint32_t)free_slot + 1u);
    user_mmap_log_apk_libcrypto_inode(process_current_task(), "slot-new",
                                      path, free_slot, inode, sb);
    user_mmap_file_slot_unlock();
    return free_slot;
}

static int user_mmap_file_slot(const char *path) {
    return user_mmap_file_slot_ex(path, 0, 0);
}

static void user_mmap_file_rename_path(const char *old_path, const char *new_path) {
    uint32_t old_length;
    uint32_t new_length;
    uint32_t slot_limit = user_mmap_file_slot_limit();
    if (!old_path || !old_path[0] || !new_path || !new_path[0]) return;
    old_length = (uint32_t)strlen(old_path);
    new_length = (uint32_t)strlen(new_path);
    for (uint32_t i = 0; i < slot_limit; ++i) {
        const char *suffix;
        uint32_t suffix_length;
        if (!g_user_mmap_file_slots[i].used ||
            g_user_mmap_file_slots[i].reclaiming)
            continue;
        if (strcmp(g_user_mmap_file_slots[i].path, (char *)old_path) == 0) {
            suffix = "";
        } else if (strncmp(g_user_mmap_file_slots[i].path, old_path,
                           old_length) == 0 &&
                   g_user_mmap_file_slots[i].path[old_length] == '/') {
            suffix = g_user_mmap_file_slots[i].path + old_length;
        } else {
            continue;
        }
        suffix_length = (uint32_t)strlen(suffix);
        if (new_length + suffix_length >=
            sizeof(g_user_mmap_file_slots[i].path))
            continue;
        /*
         * Linux VMAs are inode-backed, not pathname-backed.  A rename moves the
         * directory name, but the file object already referenced by an mmap is
         * still the same inode.  Directory renames also move every descendant
         * pathname, so preserve the suffix for any mapped file below the source
         * directory.  Do not change the saved inode or backing-page identity.
         */
        memmove(g_user_mmap_file_slots[i].path + new_length, suffix,
                suffix_length + 1u);
        memcpy(g_user_mmap_file_slots[i].path, new_path, new_length);
    }
}

static int user_vma_record_ex_slot(task_t *t, uint64_t start, uint64_t end,
                                   uint32_t prot, uint32_t flags,
                                   const char *file_path, uint64_t file_off,
                                   uint64_t file_len, uint8_t fork_policy,
                                   int file_slot_override) {
    int slot;
    int file_backed = file_path && file_path[0];
    int file_slot = -1;
    uint64_t vma_len;
    uint64_t file_coverage = 0;
    if (!t || end <= start) return -1;
    vma_len = end - start;
    if (file_backed) {
        /*
         * Linux file VMAs are page based.  mmap(2)'s byte length is rounded up
         * to the VMA's page range, and faults in the final partial page read
         * the file bytes that exist and zero-fill the rest.  Keeping the raw
         * caller length here breaks later mprotect/munmap/mremap split math:
         * executable library pages can be reclassified as past-EOF anonymous
         * zero pages, or adjacent page VMAs can coalesce with a shortened file
         * extent.  Store page-rounded file coverage capped to the VMA length;
         * user_mmap_read_file_page() already performs Linux-style zero-fill
         * for actual EOF short reads.
         */
        file_coverage = page_align_up(file_len);
        if (file_coverage == 0 || file_coverage > vma_len) file_coverage = vma_len;
        file_slot = file_slot_override >= 0 ? file_slot_override : user_mmap_file_slot(file_path);
        if (file_slot < 0) return -1;
        int live = user_vma_live_limit(t);
        for (int i = 0; i < live; ++i) {
            edge_user_vma_t *v = &t->user_vmas[i];
            const char *old_path = 0;
            if (v->end <= v->start) continue;
            if (end <= v->start || start >= v->end) continue;
            if (g_user_vma_overlap_log_budget > 0) {
                if (v->file_backed) old_path = user_mmap_file_path(v->file_slot);
                g_user_vma_overlap_log_budget--;
                printf("[vma-overlap] pid=%d cmd=%s new=0x%x-0x%x prot=0x%x flags=0x%x off=0x%x path=%s old_slot=%d old=0x%x-0x%x prot=0x%x flags=0x%x off=0x%x path=%s budget=%d\n",
                       t ? t->pid : -1,
                       (t && t->name[0]) ? t->name : "?",
                       (uint32_t)start, (uint32_t)end,
                       prot, flags, (uint32_t)file_off,
                       file_path ? file_path : "-",
                       i,
                       (uint32_t)v->start, (uint32_t)v->end,
                       v->prot, v->flags, (uint32_t)v->file_off,
                       old_path && old_path[0] ? old_path : "-",
                       g_user_vma_overlap_log_budget);
            }
            return -1;
        }
    }
    if (!file_backed) {
        int live = user_vma_live_limit(t);
        for (int i = 0; i < live; ++i) {
            edge_user_vma_t *v = &t->user_vmas[i];
            if (v->end <= v->start) continue;
            if (v->file_backed) continue;
            if (v->prot != prot || v->flags != flags) continue;
            if (end < v->start || start > v->end) continue;
            if (start < v->start) v->start = start;
            if (end > v->end) v->end = end;
            user_vma_coalesce_slot(t, i);
            user_vma_note_mmap_range(t, start);
            return 0;
        }
    }
    slot = user_vma_find_free_slot(t);
    if (slot < 0) return -1;
    t->user_vmas[slot].start = start;
    t->user_vmas[slot].end = end;
    t->user_vmas[slot].file_off = file_backed ? file_off : 0;
    t->user_vmas[slot].file_len = file_backed ? file_coverage : 0;
    t->user_vmas[slot].prot = prot;
    t->user_vmas[slot].flags = flags;
    t->user_vmas[slot].fork_policy = fork_policy;
    t->user_vmas[slot].file_slot = file_backed ? (uint16_t)file_slot : 0;
    t->user_vmas[slot].file_backed = file_backed ? 1 : 0;
    if (file_backed) {
        vfs_inode_t ino;
        vfs_superblock_t *sb = 0;
        if (user_mmap_file_slot_inode((uint16_t)file_slot, &ino, &sb) == 0)
            user_vma_set_file_identity(&t->user_vmas[slot], &ino, sb);
        else
            user_vma_set_file_identity(&t->user_vmas[slot], 0, 0);
    } else {
        user_vma_set_file_identity(&t->user_vmas[slot], 0, 0);
    }
    if (process_user_vma_retain_backing(&t->user_vmas[slot]) < 0) {
        memset(&t->user_vmas[slot], 0, sizeof(t->user_vmas[slot]));
        return -1;
    }
    user_vma_commit_slot(t, slot);
    user_vma_coalesce_slot(t, slot);
    user_vma_note_mmap_range(t, start);
    if (file_backed && file_path && strcmp(file_path, "/dev/fb0") == 0) {
        process_user_fbdev_owner_set(t, 1);
    }
    return 0;
}

static int user_vma_record_ex(task_t *t, uint64_t start, uint64_t end, uint32_t prot, uint32_t flags,
                              const char *file_path, uint64_t file_off, uint64_t file_len) {
    return user_vma_record_ex_slot(t, start, end, prot, flags,
                                   file_path, file_off, file_len, 0, -1);
}

static int user_vma_record(task_t *t, uint64_t start, uint64_t end, uint32_t prot, uint32_t flags) {
    return user_vma_record_ex(t, start, end, prot, flags, 0, 0, 0);
}

int process_user_elf_map_inode_pid(int pid, const char *display_path,
                                   const vfs_inode_t *inode,
                                   vfs_superblock_t *superblock,
                                   uint64_t start, uint64_t len,
                                   uint64_t file_offset,
                                   uint32_t protection) {
    task_t *task;
    task_t *mm;
    int file_slot;

    if (!display_path || !display_path[0] || !inode || !superblock ||
        len == 0 ||
        (start & (PAGE_SIZE - 1ULL)) != 0 ||
        (len & (PAGE_SIZE - 1ULL)) != 0 ||
        (file_offset & (PAGE_SIZE - 1ULL)) != 0 ||
        start + len < start)
        return -1;
    task = process_task_by_pid(pid);
    mm = process_vm_task(task);
    if (!mm) return -1;
    file_slot = user_mmap_file_slot_ex(
        display_path, inode, superblock);
    if (file_slot < 0) return -1;
    return user_vma_record_ex_slot(
        mm, start, start + len, protection, LINUX_MAP_PRIVATE,
        display_path, file_offset, len, 0, file_slot);
}

int process_user_elf_map_file_pid(int pid, const char *path, uint64_t start,
                                  uint64_t len, uint64_t file_offset,
                                  uint32_t protection) {
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;

    if (!path || !path[0] ||
        vfs_resolve(path, &inode, &superblock, 0, 0) < 0 ||
        !superblock)
        return -1;
    return process_user_elf_map_inode_pid(
        pid, path, &inode, superblock, start, len,
        file_offset, protection);
}

static int user_vma_range_overlaps(task_t *t, uint64_t start, uint64_t end) {
    if (!t || end <= start) return 1;
    int live = user_vma_live_limit(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        if (v->end <= v->start) continue;
        if (end <= v->start || start >= v->end) continue;
        return 1;
    }
    return 0;
}

static int user_range_has_present_pages(uint64_t start, uint64_t end) {
    if (end <= start) return 1;
    for (uint64_t va = page_align_down(start); va < end; va += PAGE_SIZE) {
        uint64_t flags = user_pte_flags(va);
        if ((flags & PTE_PRESENT) && (flags & PTE_USER)) return 1;
    }
    return 0;
}

static int user_range_is_fixed_heap(task_t *mm, uint64_t start, uint64_t len) {
    uint64_t end;
    if (!mm || len == 0) return 0;
    end = start + len;
    if (end < start) return 0;
    if (start < USER_HEAP_BASE_ADDR || end > USER_HEAP_ABS_LIMIT_ADDR) return 0;
    return 1;
}

static int user_vma_range_covered(task_t *t, uint64_t start, uint64_t end) {
    uint64_t pos;
    int live;
    if (!t || end <= start) return 0;
    live = user_vma_live_limit(t);
    pos = start;
    while (pos < end) {
        uint64_t next = pos;
        for (int i = 0; i < live; ++i) {
            edge_user_vma_t *v = &t->user_vmas[i];
            if (v->end <= v->start) continue;
            if (pos >= v->start && pos < v->end) {
                next = v->end;
                break;
            }
        }
        if (next <= pos) return 0;
        pos = next;
    }
    return 1;
}

static int user_madvise_noop_range_covered(task_t *t, uint64_t start,
                                           uint64_t end) {
    int live;

    if (user_vma_range_covered(t, start, end)) return 1;

    /*
     * The x86_64 process layout exposes the initial interpreter and main
     * stack through adjacent fixed page-table windows.  The stack is an
     * implicit mapping and therefore is not represented in user_vmas.  A
     * Linux allocator can issue metadata-only advice starting immediately
     * after the final recorded interpreter segment and continuing through the
     * initial stack.  Accept only that fixed-window case; keep unrelated
     * unmapped ranges subject to the normal ENOMEM check.
     */
    if (!t || end <= start || start < USER_TEXT_BASE_ADDR ||
        start >= USER_STACK_BASE_ADDR ||
        end > t->user_stack_top ||
        t->user_stack_top != USER_STACK_BASE_ADDR + USER_STACK_SIZE_ADDR)
        return 0;
    if (user_vma_range_overlaps(t, start, end)) return 1;

    live = user_vma_live_limit(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        if (v->end == start && v->start >= USER_TEXT_BASE_ADDR &&
            v->end <= USER_STACK_BASE_ADDR)
            return 1;
    }
    return 0;
}

static int user_vma_range_has_prot(task_t *t, uint64_t start, uint64_t end, uint32_t prot) {
    uint64_t pos;
    int live;
    if (!t || end <= start) return 0;
    live = user_vma_live_limit(t);
    pos = start;
    while (pos < end) {
        uint64_t next = pos;
        for (int i = 0; i < live; ++i) {
            edge_user_vma_t *v = &t->user_vmas[i];
            if (v->end <= v->start) continue;
            if (pos >= v->start && pos < v->end) {
                if (v->prot != prot) return 0;
                next = v->end;
                break;
            }
        }
        if (next <= pos) return 0;
        pos = next;
    }
    return 1;
}

static int user_vma_protect_range(task_t *t, uint64_t start, uint64_t end, uint32_t prot) {
    int changed = 0;
    int needed_slots = 0;
    int live;
    if (!t || end <= start) return -1;
    if (!user_vma_range_covered(t, start, end)) return -1;
    if (user_vma_range_has_prot(t, start, end, prot)) return 0;
    live = user_vma_live_limit(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        if (v->end <= v->start) continue;
        if (end <= v->start || start >= v->end) continue;
        if (v->start >= start && v->end <= end) continue;
        /*
         * mprotect(2) can split a VMA.  Linux returns ENOMEM if the split would
         * exceed the mapping-count limit; silently dropping either side leaves
         * present PTEs with no VMA metadata, and later fork COW faults cannot be
         * resolved.  Preflight the slot requirement before touching metadata.
         */
        if (start > v->start && end < v->end) needed_slots += 2;
        else needed_slots += 1;
    }
    if (needed_slots > 0 &&
        (t->user_vma_count > PROCESS_USER_VMA_MAX -
                                  (uint32_t)needed_slots ||
         process_user_vma_reserve(
             t, t->user_vma_count + (uint32_t)needed_slots) < 0))
        return -1;
    if (needed_slots > user_vma_free_slot_count(t)) return -1;
    live = user_vma_live_limit(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        uint64_t old_start;
        uint64_t old_end;
        uint32_t old_prot;
        uint32_t old_flags;
        if (v->end <= v->start) continue;
        if (end <= v->start || start >= v->end) continue;
        if (v->start >= start && v->end <= end) {
            v->prot = prot;
            changed = 1;
            continue;
        }
        old_start = v->start;
        old_end = v->end;
        old_prot = v->prot;
        old_flags = v->flags;
        edge_user_vma_t old = *v;
        const char *old_path = old.file_backed ? user_mmap_file_path(old.file_slot) : 0;
        if (start <= old_start) {
            uint64_t delta = end - old_start;
            v->start = end;
            if (v->file_backed) {
                v->file_off += delta;
                v->file_len = v->file_len > delta ? v->file_len - delta : 0;
            }
            if (user_vma_record_ex_slot(t, old_start, end, prot, old_flags, old_path,
                                        old.file_off,
                                        old.file_len < delta ? old.file_len : delta,
                                        old.fork_policy,
                                        old.file_backed ? old.file_slot : -1) < 0) return -1;
        } else if (end >= old_end) {
            uint64_t delta = start - old_start;
            v->end = start;
            if (v->file_backed) {
                if (v->file_len > delta) v->file_len = delta;
            }
            if (user_vma_record_ex_slot(t, start, old_end, prot, old_flags, old_path,
                                        old.file_off + delta,
                                        old.file_len > delta ? old.file_len - delta : 0,
                                        old.fork_policy,
                                        old.file_backed ? old.file_slot : -1) < 0) return -1;
        } else {
            uint64_t left_len = start - old_start;
            uint64_t mid_off = start - old_start;
            uint64_t right_off = end - old_start;
            v->end = start;
            if (v->file_backed) {
                if (v->file_len > left_len) v->file_len = left_len;
            }
            if (user_vma_record_ex_slot(t, end, old_end, old_prot, old_flags, old_path,
                                        old.file_off + right_off,
                                        old.file_len > right_off ? old.file_len - right_off : 0,
                                        old.fork_policy,
                                        old.file_backed ? old.file_slot : -1) < 0) return -1;
            if (user_vma_record_ex_slot(t, start, end, prot, old_flags, old_path,
                                        old.file_off + mid_off,
                                        old.file_len > mid_off ?
                                            (old.file_len - mid_off < end - start ? old.file_len - mid_off : end - start) :
                                            0,
                                        old.fork_policy,
                                        old.file_backed ? old.file_slot : -1) < 0) return -1;
        }
        changed = 1;
    }
    if (changed) {
        user_vma_merge_compatible(t);
    }
    return 0;
}

static int user_vma_private_anonymous_range_covered(
    task_t *t, uint64_t start, uint64_t end) {
    uint64_t position;
    int live;

    if (!t || end <= start) return 0;
    live = user_vma_live_limit(t);
    position = start;
    while (position < end) {
        uint64_t next = position;
        for (int index = 0; index < live; ++index) {
            edge_user_vma_t *vma = &t->user_vmas[index];
            if (vma->end <= vma->start || position < vma->start ||
                position >= vma->end)
                continue;
            if (vma->file_backed ||
                (vma->flags & LINUX_MAP_SHARED) != 0)
                return 0;
            next = vma->end < end ? vma->end : end;
            break;
        }
        if (next <= position) return 0;
        position = next;
    }
    return 1;
}

static int user_vma_set_fork_policy_range(
    task_t *t, uint64_t start, uint64_t end, uint8_t fork_policy) {
    int needed_slots = 0;
    int live;

    if (!user_vma_private_anonymous_range_covered(t, start, end))
        return -1;
    live = user_vma_live_limit(t);
    for (int index = 0; index < live; ++index) {
        edge_user_vma_t *vma = &t->user_vmas[index];
        if (vma->end <= vma->start || end <= vma->start ||
            start >= vma->end)
            continue;
        if (vma->start >= start && vma->end <= end) continue;
        needed_slots += start > vma->start && end < vma->end ? 2 : 1;
    }
    if (needed_slots > 0 &&
        (t->user_vma_count > PROCESS_USER_VMA_MAX -
                                 (uint32_t)needed_slots ||
         process_user_vma_reserve(
             t, t->user_vma_count + (uint32_t)needed_slots) < 0 ||
         needed_slots > user_vma_free_slot_count(t)))
        return -1;

    live = user_vma_live_limit(t);
    for (int index = 0; index < live; ++index) {
        edge_user_vma_t *vma = &t->user_vmas[index];
        edge_user_vma_t old;
        if (vma->end <= vma->start || end <= vma->start ||
            start >= vma->end)
            continue;
        if (vma->start >= start && vma->end <= end) {
            vma->fork_policy = fork_policy;
            continue;
        }
        old = *vma;
        if (start <= old.start) {
            vma->start = end;
            if (user_vma_record_ex_slot(
                    t, old.start, end, old.prot, old.flags, 0, 0, 0,
                    fork_policy, -1) < 0)
                return -1;
        } else if (end >= old.end) {
            vma->end = start;
            if (user_vma_record_ex_slot(
                    t, start, old.end, old.prot, old.flags, 0, 0, 0,
                    fork_policy, -1) < 0)
                return -1;
        } else {
            vma->end = start;
            if (user_vma_record_ex_slot(
                    t, end, old.end, old.prot, old.flags, 0, 0, 0,
                    old.fork_policy, -1) < 0 ||
                user_vma_record_ex_slot(
                    t, start, end, old.prot, old.flags, 0, 0, 0,
                    fork_policy, -1) < 0)
                return -1;
        }
    }
    user_vma_merge_compatible(t);
    return 0;
}

static int user_vma_protect_intersections(task_t *t, uint64_t start,
                                          uint64_t end, uint32_t prot) {
    uint64_t position;

    if (!t || end <= start) return -1;
    position = start;
    while (position < end) {
        edge_user_vma_t *cover = 0;
        uint64_t next = end;
        int live = user_vma_live_limit(t);

        for (int index = 0; index < live; ++index) {
            edge_user_vma_t *vma = &t->user_vmas[index];
            if (vma->end <= vma->start) continue;
            if (position >= vma->start && position < vma->end) {
                cover = vma;
                break;
            }
            if (vma->start > position && vma->start < next)
                next = vma->start;
        }
        if (!cover) {
            position = next;
            continue;
        }
        next = cover->end < end ? cover->end : end;
        if (user_vma_protect_range(t, position, next, prot) < 0)
            return -1;
        position = next;
    }
    return 0;
}

static uint64_t user_vma_find_topdown_gap(task_t *t, uint64_t floor, uint64_t top, uint64_t need, uint64_t align) {
    uint64_t cursor;
    int live;
    int max_iter;
    if (!t || need == 0) return 0;
    if (top <= floor || need > (top - floor)) return 0;
    if (align < PAGE_SIZE || (align & (align - 1ULL)) != 0) align = PAGE_SIZE;
    cursor = top;
    live = user_vma_live_limit(t);
    max_iter = live + 4;
    if (max_iter < 8) max_iter = 8;
    for (int iter = 0; iter < max_iter; ++iter) {
        uint64_t base;
        uint64_t end;
        uint64_t next_cursor = cursor;
        int overlap = 0;
        uint64_t floor_aligned;
        if (cursor <= floor || need > (cursor - floor)) return 0;
        floor_aligned = (floor + align - 1ULL) & ~(align - 1ULL);
        if (floor_aligned < floor) return 0;
        if (cursor <= floor_aligned || need > (cursor - floor_aligned)) return 0;
        base = (cursor - need) & ~(align - 1ULL);
        if (base < floor_aligned) base = floor_aligned;
        end = base + need;
        if (end > top || end < base) return 0;
        for (int i = 0; i < live; ++i) {
            edge_user_vma_t *v = &t->user_vmas[i];
            if (v->end <= v->start) continue;
            if (v->end <= floor || v->start >= top) continue;
            if (end <= v->start || base >= v->end) continue;
            overlap = 1;
            if (v->start < next_cursor) next_cursor = v->start;
        }
        /*
         * Both mmap arenas are exclusively owned by sparse VMAs.  Their page
         * tables are backing state, not an independent address allocator, so
         * Linux-style gap selection is driven by VMA metadata.  Walking every
         * PTE here made Chromium's 4 GiB V8 cage reservation inspect more than
         * one million absent pages before mmap could return.
         */
        if (!overlap) return base;
        if (next_cursor >= cursor) return 0;
        cursor = next_cursor;
    }
    return 0;
}

static uint64_t user_vma_find_bottomup_gap(task_t *t, uint64_t floor,
                                           uint64_t top, uint64_t need,
                                           uint64_t align) {
    uint64_t candidate;
    int live;
    int max_iter;

    if (!t || !need || top <= floor || need > top - floor) return 0;
    if (align < PAGE_SIZE || (align & (align - 1ULL)) != 0)
        align = PAGE_SIZE;
    candidate = (floor + align - 1ULL) & ~(align - 1ULL);
    if (candidate < floor) return 0;
    live = user_vma_live_limit(t);
    max_iter = live + 4;
    if (max_iter < 8) max_iter = 8;

    for (int iteration = 0; iteration < max_iter; ++iteration) {
        uint64_t end;
        uint64_t next = candidate;
        int overlap = 0;

        if (candidate > top || need > top - candidate) return 0;
        end = candidate + need;
        for (int i = 0; i < live; ++i) {
            const edge_user_vma_t *vma = &t->user_vmas[i];
            if (vma->end <= vma->start || vma->end <= floor ||
                vma->start >= top)
                continue;
            if (end <= vma->start || candidate >= vma->end) continue;
            overlap = 1;
            if (vma->end > next) next = vma->end;
        }
        if (!overlap) return candidate;
        if (next <= candidate || next > UINT64_MAX - (align - 1ULL))
            return 0;
        candidate = (next + align - 1ULL) & ~(align - 1ULL);
    }
    return 0;
}

static uint64_t user_vma_find_hint_gap(task_t *t, uint64_t floor, uint64_t top,
                                       uint64_t need, uint64_t align) {
    uint64_t cursor;
    uint64_t base;
    uint64_t floor_aligned;
    if (!t || need == 0) return 0;
    if (top <= floor || need > (top - floor)) return 0;
    if (align < PAGE_SIZE || (align & (align - 1ULL)) != 0) align = PAGE_SIZE;
    floor_aligned = (floor + align - 1ULL) & ~(align - 1ULL);
    if (floor_aligned < floor) return 0;

    /*
     * Linux's mm keeps tree/rbtree state for fast top-down allocation. EdgeOS
     * uses a compact VMA store, so restarting every mmap(NULL) search from the
     * arena ceiling makes plugin scanners pay an avoidable O(number-of-VMAs)
     * walk for thousands of adjacent 4 KiB anonymous mappings.  Track the
     * current low-water mark and first try the next page below it.  If the hint
     * is stale or fragmented we fall back to the full gap search below.
     */
    cursor = t->user_mmap_next;
    if (cursor == 0 || cursor > top || cursor < floor) cursor = top;
    if (cursor <= floor_aligned || need > (cursor - floor_aligned)) return 0;
    base = (cursor - need) & ~(align - 1ULL);
    if (base < floor_aligned || base + need < base || base + need > top) return 0;
    if (user_vma_range_overlaps(t, base, base + need)) return 0;
    return base;
}

static int user_vma_remove_range(task_t *t, uint64_t start, uint64_t end) {
    int changed = 0;
    int refresh_mmap_hint = 0;
    int touched_fbdev = 0;
    int live;
    if (!t || end <= start) return 0;
    live = user_vma_live_limit(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        if (v->end <= v->start || end <= v->start || start >= v->end)
            continue;
        if (start > v->start && end < v->end) {
            if (t->user_vma_count >= PROCESS_USER_VMA_MAX ||
                process_user_vma_reserve(t, t->user_vma_count + 1u) < 0)
                return -1;
            live = user_vma_live_limit(t);
            break;
        }
    }
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        uint64_t old_start;
        if (v->end <= v->start) continue;
        if (end <= v->start || start >= v->end) continue;
        old_start = v->start;
        if (user_vma_path_is(v, "/dev/fb0")) touched_fbdev = 1;
        changed = 1;
        if (start <= v->start && end >= v->end) {
            if (old_start == t->user_mmap_next) refresh_mmap_hint = 1;
            process_user_vma_release_backing(v);
            memset(v, 0, sizeof(*v));
            continue;
        }
        if (start <= v->start) {
            uint64_t delta = end - v->start;
            v->start = end;
            if (old_start == t->user_mmap_next) refresh_mmap_hint = 1;
            if (v->file_backed) {
                v->file_off += delta;
                v->file_len = v->file_len > delta ? v->file_len - delta : 0;
            }
            continue;
        }
        if (end >= v->end) {
            if (v->file_backed) {
                uint64_t keep = start - v->start;
                if (v->file_len > keep) v->file_len = keep;
            }
            v->end = start;
            continue;
        }
        /*
         * Removing a middle slice needs an extra VMA for the upper half.  Do
         * not trim the lower half and drop the upper metadata when the fixed
         * VMA array is full; that leaves valid user PTEs outside any VMA and
         * breaks later COW write faults after fork.  Match Linux's behavior by
         * failing the operation before mutating the mapping.
         */
        int slot = user_vma_find_free_slot(t);
        if (slot < 0) return -1;
        edge_user_vma_t old = *v;
        if (process_user_vma_retain_backing(&old) < 0) return -1;
        t->user_vmas[slot] = old;
        t->user_vmas[slot].start = end;
        t->user_vmas[slot].end = old.end;
        t->user_vmas[slot].file_off = old.file_off + (end - old.start);
        t->user_vmas[slot].file_len = old.file_len > (end - old.start) ? old.file_len - (end - old.start) : 0;
        user_vma_commit_slot(t, slot);
        if (v->file_backed) {
            uint64_t keep = start - v->start;
            if (v->file_len > keep) v->file_len = keep;
        }
        v->end = start;
    }
    if (changed) {
        /*
         * Removing a range can only delete, trim, or split mappings. It never
         * creates a new adjacent compatible span, so avoid the quadratic merge
         * pass on teardown paths that issue many page-sized munmap calls.
         */
        user_vma_recount(t);
        if (refresh_mmap_hint) user_vma_refresh_mmap_hint(t);
        if (touched_fbdev) process_user_fbdev_owner_refresh(t);
    }
    return changed;
}

static int user_vma_sync_shared_file_range(task_t *t, uint64_t start, uint64_t end) {
    static uint8_t sync_buf[65536];
    int live;
    if (!t || end <= start) return 0;
    live = user_vma_live_limit(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        uint64_t s;
        uint64_t e;
        uint64_t max_end;
        vfs_inode_t ino;
        vfs_superblock_t *sb = 0;
        if (v->end <= v->start) continue;
        if (!v->file_backed || !(v->flags & LINUX_MAP_SHARED)) continue;
        if (!(v->prot & LINUX_PROT_WRITE)) continue;
        if (end <= v->start || start >= v->end) continue;
        max_end = v->start + v->file_len;
        if (max_end < v->start) max_end = v->end;
        s = start > v->start ? start : v->start;
        e = end < v->end ? end : v->end;
        if (e > max_end) e = max_end;
        if (e <= s) continue;
        const char *path = user_mmap_file_path(v->file_slot);
        if (path && strcmp(path, "/dev/fb0") == 0) {
            /*
             * Linux accepts msync(2) on shared device mappings that do not have
             * regular filesystem writeback.  For fbdev, the useful operation is
             * making mmap stores visible to scanout.  Returning EIO/ENOMEM here
             * breaks normal mmap clients such as Python and any Xorg/fbdev path
             * that explicitly syncs damage.  Red flag: keep this generic to the
             * fbdev device mapping; do not special-case Xorg, XFCE, or rootfs
             * paths outside the device ABI.
             */
            fb_flush_rect(0, 0, (int)fb.width, (int)fb.height);
            continue;
        }
        {
            int memfd_id = memfd_id_from_path(path);
            if (memfd_id > 0) {
                edge_memfd_t *mf = memfd_get(memfd_id);
                if (!mf) return -EIO;
                /*
                 * Sparse memfd VMAs map the object's backing pages directly,
                 * so writes are already visible and no filesystem writeback is
                 * required.  Legacy fixed-layout mappings are copy-backed and
                 * must be synchronized explicitly before their VMA is removed.
                 */
                if (process_user_mmap_range_ok(v->start, v->end - v->start))
                    continue;
                while (s < e) {
                    uint64_t n = e - s;
                    int w;
                    if (n > sizeof(sync_buf)) n = sizeof(sync_buf);
                    if (copy_from_user(sync_buf, s, n) < 0) return -EFAULT;
                    w = memfd_write_mapping_from_kernel(
                        mf, v->file_off + (s - v->start), sync_buf, n);
                    if (w < 0 || (uint64_t)w != n) return -EIO;
                    s += n;
                }
                continue;
            }
        }
        if (user_vma_get_file_inode(v, &ino, &sb) < 0 &&
            user_mmap_file_slot_inode(v->file_slot, &ino, &sb) < 0 &&
            (!path || vfs_resolve(path, &ino, &sb, 0, 0) < 0)) {
            return -EIO;
        }
        if (!sb || !sb->ops || !sb->ops->write) return -EIO;
        if (process_user_mmap_range_ok(v->start, v->end - v->start)) {
            if (edge_mmap_file_cache_sync_range(
                    sb, &ino, v->file_off + (s - v->start), e - s, 1) < 0)
                return -EIO;
            continue;
        }
        while (s < e) {
            uint64_t n = e - s;
            int w;
            if (n > sizeof(sync_buf)) n = sizeof(sync_buf);
            if (copy_from_user(sync_buf, s, n) < 0) {
                return -EFAULT;
            }
            w = sb->ops->write(sb, &ino, (uint32_t)(v->file_off + (s - v->start)), sync_buf, (uint32_t)n);
            if (w < 0 || (uint64_t)w != n) {
                return -EIO;
            }
            s += n;
        }
        if (sb->ops->sync) (void)sb->ops->sync(sb);
        edge_mmap_file_cache_invalidate_path(path);
    }
    return 0;
}

static int64_t arch_mm_map_locked(
    const kernel_mm_map_request_t *request) {
    uint64_t addr;
    uint64_t len;
    uint64_t prot;
    uint64_t flags;
    uint64_t fd;
    uint64_t off;
    uint64_t base;
    uint64_t need;
    uint64_t top;
    uint64_t floor;
    uint64_t gap_align;
    static uint8_t mmap_kbuf[131072];
    task_t *cur = process_current_task();
    task_t *mm = 0;
    int sparse_mmap = 0;
    int trace_py = 0;
    int mmap_file_slot = -1;
    const char *tname = "?";
    const char *file_path = 0;
    char inode_slot_path[64];
    if (!request) return -EIO;
    addr = request->address;
    len = request->length;
    prot = request->protection;
    flags = request->flags;
    fd = (uint64_t)(int64_t)request->descriptor;
    off = request->offset;
    if (len == 0) return (uint64_t)-EINVAL;
    if ((int64_t)fd < 0 && (flags & LINUX_MAP_ANON) == 0)
        return (uint64_t)-EBADF;
    if (((flags & LINUX_MAP_ANON) == 0) && ((off & (PAGE_SIZE - 1)) != 0)) return (uint64_t)-EINVAL;

    if (!cur) return (uint64_t)-EINVAL;
    mm = process_vm_task(cur);
    if (!mm) return (uint64_t)-EINVAL;
    tname = cur->name[0] ? cur->name : "?";
    trace_py = 0 && (strcmp(tname, "python3") == 0);
    need = page_align_up(len);
    if (need == 0) return (uint64_t)-EINVAL;

    if ((flags & (LINUX_MAP_FIXED | LINUX_MAP_FIXED_NOREPLACE)) != 0) {
        if ((addr & (PAGE_SIZE - 1)) != 0) return (uint64_t)-EINVAL;
        base = addr;
    } else {
        /* Anonymous userspace allocators such as Go's runtime reserve large
         * sparse regions. Keep mmap in a dedicated arena above the legacy brk
         * window so these reservations do not collide with the fixed low
         * layout used by existing EdgeOS binaries. */
        top = USER_MMAP_LIMIT_ADDR;
        floor = USER_MMAP_BASE_ADDR;
        if (need > top - floor ||
            (addr >= USER_MMAP_HIGH_BASE_ADDR &&
             addr < USER_MMAP_HIGH_LIMIT_ADDR)) {
            floor = USER_MMAP_HIGH_BASE_ADDR;
            top = USER_MMAP_HIGH_LIMIT_ADDR;
        }
        gap_align = PAGE_SIZE;
        if ((flags & LINUX_MAP_ANON) != 0 && need >= (64ULL * 1024ULL * 1024ULL) &&
            (need & (need - 1ULL)) == 0) {
            gap_align = need;
        }
        base = 0;
        if (addr != 0) {
            uint64_t hint = page_align_down(addr);
            if (hint >= floor &&
                hint + need >= hint &&
                hint + need <= top &&
                !user_vma_range_overlaps(mm, hint, hint + need)) {
                base = hint;
            }
        }
        if (base == 0) {
            base = user_vma_find_hint_gap(mm, floor, top, need, gap_align);
        }
        if (base == 0) {
            base = user_vma_find_topdown_gap(mm, floor, top, need, gap_align);
        }
        if (base == 0) {
            base = user_vma_find_bottomup_gap(mm, floor, top, need,
                                              gap_align);
        }
        if (base == 0 && floor == USER_MMAP_BASE_ADDR) {
            floor = USER_MMAP_HIGH_BASE_ADDR;
            top = USER_MMAP_HIGH_LIMIT_ADDR;
            base = user_vma_find_hint_gap(mm, floor, top, need, gap_align);
            if (base == 0) {
                base = user_vma_find_topdown_gap(
                    mm, floor, top, need, gap_align);
            }
            if (base == 0) {
                base = user_vma_find_bottomup_gap(
                    mm, floor, top, need, gap_align);
            }
        }
        if (base == 0) {
            static int gap_trace_budget = 16;
            if (gap_trace_budget > 0) {
                uint64_t hint_gap = user_vma_find_hint_gap(
                    mm, floor, top, need, gap_align);
                uint64_t top_gap = user_vma_find_topdown_gap(
                    mm, floor, top, need, gap_align);
                uint64_t bottom_gap = user_vma_find_bottomup_gap(
                    mm, floor, top, need, gap_align);
                int first_overlap = -1;
                uint64_t probe_end = floor + need;
                int live = user_vma_live_limit(mm);

                if (probe_end >= floor) {
                    for (int index = 0; index < live; ++index) {
                        edge_user_vma_t *vma = &mm->user_vmas[index];
                        if (vma->end <= vma->start ||
                            probe_end <= vma->start ||
                            floor >= vma->end)
                            continue;
                        first_overlap = index;
                        break;
                    }
                }
                printf("[mmap-gap] pid=%d len=0x%x%08x need=0x%x%08x "
                       "floor=0x%x%08x top=0x%x%08x align=0x%x%08x "
                       "hint=0x%x%08x topdown=0x%x%08x bottom=0x%x%08x "
                       "first_overlap=%d live=%d budget=%d\n",
                       cur ? cur->pid : -1,
                       (uint32_t)(len >> 32), (uint32_t)len,
                       (uint32_t)(need >> 32), (uint32_t)need,
                       (uint32_t)(floor >> 32), (uint32_t)floor,
                       (uint32_t)(top >> 32), (uint32_t)top,
                       (uint32_t)(gap_align >> 32), (uint32_t)gap_align,
                       (uint32_t)(hint_gap >> 32), (uint32_t)hint_gap,
                       (uint32_t)(top_gap >> 32), (uint32_t)top_gap,
                       (uint32_t)(bottom_gap >> 32), (uint32_t)bottom_gap,
                       first_overlap, live, gap_trace_budget - 1);
                if (first_overlap >= 0) {
                    edge_user_vma_t *vma = &mm->user_vmas[first_overlap];
                    printf("[mmap-gap-overlap] slot=%d start=0x%x%08x "
                           "end=0x%x%08x prot=0x%x flags=0x%x\n",
                           first_overlap,
                           (uint32_t)(vma->start >> 32),
                           (uint32_t)vma->start,
                           (uint32_t)(vma->end >> 32),
                           (uint32_t)vma->end,
                           vma->prot, vma->flags);
                }
                gap_trace_budget--;
            }
            return user_mmap_fail(cur, "no-gap", (uint64_t)-ENOMEM,
                                  addr, len, prot, flags, (int)fd, off, 0);
        }
    }

    if (base < USER_MIN_ADDR || base + need < base || base + need > USER_MAX_ADDR) {
        return user_mmap_fail(cur, "range", (uint64_t)-ENOMEM,
                              addr, len, prot, flags, (int)fd, off, 0);
    }
    sparse_mmap = process_user_mmap_range_ok(base, need);
    if ((flags & LINUX_MAP_FIXED_NOREPLACE) != 0 && user_vma_range_overlaps(mm, base, base + need)) {
        return (uint64_t)-EEXIST;
    }
    if ((flags & LINUX_MAP_FIXED) != 0) {
        if (user_vma_remove_range(mm, base, base + need) < 0) {
            return user_mmap_fail(cur, "fixed-remove", (uint64_t)-ENOMEM,
                                  addr, len, prot, flags, (int)fd, off, 0);
        }
        if (sparse_mmap) {
            process_user_mmap_unmap(mm, base, need);
        } else if (user_range_is_fixed_heap(mm, base, need)) {
            /*
             * MAP_FIXED replaces whatever occupied the virtual range.  The legacy
             * EdgeOS heap window is backed by separate fixed PTE arrays, so VMA
             * removal alone is not enough; stale present heap pages would keep old
             * writable memory alive under a new PROT_NONE/read-only reservation.
             */
            if (process_user_heap_unmap(mm, base, need) < 0) {
                return user_mmap_fail(cur, "fixed-heap-unmap", (uint64_t)-ENOMEM,
                                      addr, len, prot, flags, (int)fd, off, 0);
            }
        }
    } else if (user_vma_range_overlaps(mm, base, base + need) ||
               (!sparse_mmap &&
                user_range_has_present_pages(base, base + need))) {
        return user_mmap_fail(cur, "overlap", (uint64_t)-ENOMEM,
                              addr, len, prot, flags, (int)fd, off, 0);
    }
    if (!sparse_mmap && !user_range_is_fixed_heap(mm, base, need)) {
        for (uint64_t v = base; v < base + need; v += PAGE_SIZE) {
            uint64_t ptef = user_pte_flags(v);
            if (!(ptef & PTE_PRESENT) || !(ptef & PTE_USER)) {
                return user_mmap_fail(cur, "fixed-page-missing", (uint64_t)-ENOMEM,
                                      addr, len, prot, flags, (int)fd, off, 0);
            }
            if ((prot & LINUX_PROT_WRITE) && !(ptef & PTE_WRITE)) {
                return user_mmap_fail(cur, "fixed-page-ro", (uint64_t)-ENOMEM,
                                      addr, len, prot, flags, (int)fd, off, 0);
            }
        }
    }

    if ((flags & LINUX_MAP_ANON) == 0) {
        edge_fd_proc_t *p = fd_proc_for_pid(fd_owner_pid_current(), 0);
        edge_fd_t *e = fd_get(p, (int)fd);
        uint64_t done = 0;
        if (!e) return (uint64_t)-EBADF;
        if (e->path[0]) file_path = e->path;
        else if (e->kind == FD_VFS && e->sb) {
            user_mmap_build_inode_slot_path(inode_slot_path, sizeof(inode_slot_path), &e->inode);
            if (inode_slot_path[0]) file_path = inode_slot_path;
        }
        if (e->kind == FD_IO_URING) {
            uint32_t page_count = 0;
            int result;
            if (!(flags & LINUX_MAP_SHARED) || !sparse_mmap)
                return (uint64_t)-EINVAL;
            result = kernel_io_uring_mmap_info(
                e->pipe_id, off, len, &page_count);
            if (result < 0) return (uint64_t)(int64_t)result;
            for (uint32_t page_index = 0;
                 page_index < page_count; ++page_index) {
                kernel_io_uring_page_t page = {0};
                result = kernel_io_uring_mmap_page(
                    e->pipe_id, off, page_index, &page);
                if (result == 0) {
                    if (page.cookie <= INT32_MAX)
                        result = process_user_mmap_map_backing_page(
                            mm, base + (uint64_t)page_index * PAGE_SIZE,
                            (int)page.cookie,
                            (prot & LINUX_PROT_WRITE) != 0);
                    else
                        result = -ENOMEM;
                }
                if (page.address && page.cookie <= INT32_MAX)
                    process_user_mmap_release_backing_page(
                        (int)page.cookie);
                if (result < 0) {
                    process_user_mmap_unmap(
                        mm, base, (uint64_t)page_index * PAGE_SIZE);
                    return (uint64_t)(int64_t)(
                        result < 0 ? result : -ENOMEM);
                }
            }
            if (user_vma_record_ex(
                    mm, base, base + need, (uint32_t)prot,
                    (uint32_t)flags, "[io_uring]", off, len) < 0) {
                process_user_mmap_unmap(mm, base, need);
                return (uint64_t)-ENOMEM;
            }
            return base;
        }
        if (e->kind == FD_BPF) {
            uint32_t page_count = 0;
            int result;

            if (!(flags & LINUX_MAP_SHARED) || !sparse_mmap)
                return (uint64_t)-EINVAL;
            result = kernel_bpf_map_mmap_info(
                e->pipe_id, off, len,
                (prot & LINUX_PROT_WRITE) != 0, &page_count);
            if (result < 0) return (uint64_t)(int64_t)result;
            for (uint32_t page_index = 0;
                 page_index < page_count; ++page_index) {
                void *page_address = 0;
                int backing_index;

                result = kernel_bpf_map_mmap_page(
                    e->pipe_id, off, page_index, &page_address);
                backing_index = result == 0 && page_address ?
                    process_user_mmap_backing_page_index(page_address) : -1;
                if (backing_index < 0 ||
                    process_user_mmap_map_backing_page(
                        mm, base + (uint64_t)page_index * PAGE_SIZE,
                        backing_index,
                        (prot & LINUX_PROT_WRITE) != 0) < 0) {
                    process_user_mmap_unmap(
                        mm, base, (uint64_t)page_index * PAGE_SIZE);
                    return (uint64_t)(int64_t)(
                        result < 0 ? result : -ENOMEM);
                }
            }
            if (user_vma_record_ex(
                    mm, base, base + need, (uint32_t)prot,
                    (uint32_t)flags, "[bpf-ringbuf]", off, len) < 0) {
                process_user_mmap_unmap(mm, base, need);
                return (uint64_t)-ENOMEM;
            }
            return base;
        }
        if (e->kind == FD_SOCKET) {
            edge_socket_t *socket;
            uint32_t page_count = 0;
            if (!(flags & LINUX_MAP_SHARED) ||
                !(prot & (LINUX_PROT_READ | LINUX_PROT_WRITE)) ||
                !sparse_mmap || e->pipe_id < 0 ||
                e->pipe_id >= EDGE_MAX_SOCKETS ||
                !g_sockets[e->pipe_id].used)
                return (uint64_t)-EINVAL;
            socket = &g_sockets[e->pipe_id];
            if (socket->domain != LINUX_AF_PACKET ||
                socket->packet_handle < 0)
                return (uint64_t)-ENODEV;
            {
                int result = edge_linux_packet_ring_mmap_info(
                    socket->packet_handle, off, len, &page_count);
                if (result < 0) return (uint64_t)(int64_t)result;
            }
            for (uint32_t page = 0; page < page_count; ++page) {
                void *kernel_address = 0;
                uint64_t mapping_cookie = 0;
                int result = edge_linux_packet_ring_page(
                    socket->packet_handle, page, &kernel_address,
                    &mapping_cookie);
                (void)kernel_address;
                if (result < 0 || mapping_cookie > INT32_MAX ||
                    process_user_mmap_map_backing_page(
                        mm, base + (uint64_t)page * PAGE_SIZE,
                        (int)mapping_cookie, 1) < 0) {
                    process_user_mmap_unmap(mm, base,
                        (uint64_t)page * PAGE_SIZE);
                    return (uint64_t)-ENOMEM;
                }
            }
            if (user_vma_record_ex(mm, base, base + need,
                                   (uint32_t)prot, (uint32_t)flags,
                                   "[packet]", off, len) < 0) {
                process_user_mmap_unmap(mm, base, need);
                return (uint64_t)-ENOMEM;
            }
            user_mmap_trace_op(cur, "mmap-packet", addr, len, prot,
                               flags, base, "[packet]");
            return base;
        }
        if (e->kind == FD_MEMFD) {
            edge_memfd_t *mf = memfd_get(e->pipe_id);
            uint64_t map_end = off + len;
            if (!mf) return (uint64_t)-EBADF;
            if (map_end < off) return (uint64_t)-EOVERFLOW;
            if ((flags & LINUX_MAP_SHARED) && (prot & LINUX_PROT_WRITE) &&
                (mf->seals & (LINUX_F_SEAL_WRITE | LINUX_F_SEAL_FUTURE_WRITE))) {
                return (uint64_t)-EPERM;
            }
            if (sparse_mmap) {
                int file_slot = user_mmap_file_slot(e->path);
                if (file_slot < 0) {
                    return user_mmap_fail(cur, "memfd-slot", (uint64_t)-ENOMEM,
                                          addr, len, prot, flags, (int)fd, off, e->path);
                }
                mmap_file_slot = file_slot;
            } else {
                while (done < len) {
                    uint64_t n = len - done;
                    int r;
                    if (n > sizeof(mmap_kbuf)) n = sizeof(mmap_kbuf);
                    r = memfd_read_to_kernel(mf, off + done, mmap_kbuf, n);
                    if (r < 0) return (uint64_t)(int64_t)r;
                    if (copy_to_user(base + done, mmap_kbuf, n) < 0) return (uint64_t)-EFAULT;
                    done += n;
                }
            }
        } else if (e->kind != FD_VFS) return (uint64_t)-EBADF;
        if (e->kind == FD_MEMFD) {
            goto mmap_record_vma;
        }
        if (0 && strcmp(tname, "Xorg") == 0 &&
            (base < 0x01000000ULL || addr < 0x01000000ULL || (flags & LINUX_MAP_FIXED) != 0)) {
            printf("[mmap-xorg] file path=%s ret=0x%x req=0x%x len=0x%x need=0x%x prot=0x%x flags=0x%x fd=%d off=0x%x sparse=%d\n",
                   e->path[0] ? e->path : "-", (uint32_t)base, (uint32_t)addr,
                   (uint32_t)len, (uint32_t)need, (uint32_t)prot, (uint32_t)flags,
                   (int)fd, (uint32_t)off, sparse_mmap);
        }
        if ((e->inode.mode & 0xF000u) == VFS_INODE_CHR || (e->inode.mode & 0xF000u) == VFS_INODE_BLK) {
            uint64_t maddr = 0;
            uint64_t mlen = 0;
            if ((e->inode.mode & 0xF000u) == VFS_INODE_CHR &&
                edge_drm_path_is_device(e->path)) {
                uint64_t description_identity =
                    file_ref_identity(e->file_ref);
                uint32_t page_count = 0;
                int result;

                if (!(flags & LINUX_MAP_SHARED) || !sparse_mmap ||
                    description_identity == 0)
                    return (uint64_t)-EINVAL;
                result = edge_drm_mmap_prepare(
                    description_identity, off, need, &page_count);
                if (result < 0) return (uint64_t)(int64_t)result;
                for (uint32_t page = 0; page < page_count; ++page) {
                    void *kernel_address = 0;
                    int backing_index;

                    result = edge_drm_mmap_page(
                        description_identity, off, page,
                        &kernel_address);
                    if (result < 0 || !kernel_address) {
                        process_user_mmap_unmap(
                            mm, base, (uint64_t)page * PAGE_SIZE);
                        return (uint64_t)(int64_t)(
                            result < 0 ? result : -ENOMEM);
                    }
                    backing_index =
                        process_user_mmap_backing_page_index(
                            kernel_address);
                    if (backing_index < 0 ||
                        process_user_mmap_map_backing_page(
                            mm, base + (uint64_t)page * PAGE_SIZE,
                            backing_index,
                            (prot & LINUX_PROT_WRITE) != 0) < 0) {
                        process_user_mmap_unmap(
                            mm, base, (uint64_t)page * PAGE_SIZE);
                        return (uint64_t)-ENOMEM;
                    }
                }
                if (user_vma_record_ex(
                        mm, base, base + need, (uint32_t)prot,
                        (uint32_t)flags, e->path, off, len) < 0) {
                    process_user_mmap_unmap(mm, base, need);
                    return (uint64_t)-ENOMEM;
                }
                user_mmap_trace_op(
                    cur, "mmap-drm", addr, len, prot, flags,
                    base, e->path);
                return base;
            }
#ifdef CONFIG_BSD_DRIVER_BRIDGE
            if ((e->inode.mode & 0xF000u) == VFS_INODE_CHR &&
                bsd_bridge_cdev_mmap_supported(e->inode.rdev)) {
                uint64_t description_identity =
                    file_ref_identity(e->file_ref);

                if (!(flags & LINUX_MAP_SHARED) || !sparse_mmap ||
                    description_identity == 0)
                    return (uint64_t)-EINVAL;
                for (done = 0; done < need; done += PAGE_SIZE) {
                    uint64_t physical = 0;
                    int32_t memory_attribute =
                        BSD_BRIDGE_CDEV_MEMORY_DEFAULT;
                    int result;

                    if (off > UINT64_MAX - done) {
                        process_user_mmap_unmap(mm, base, done);
                        return (uint64_t)-EOVERFLOW;
                    }
                    result = bsd_bridge_cdev_mmap_page(
                        e->inode.rdev, description_identity,
                        off + done, (uint32_t)prot,
                        &physical, &memory_attribute);
                    if (result < 0 ||
                        (physical & (PAGE_SIZE - 1u)) != 0 ||
                        process_user_device_install_page(
                            mm, base + done, physical,
                            (uint32_t)prot, memory_attribute) < 0) {
                        process_user_mmap_unmap(mm, base, done);
                        return result < 0 ?
                            (uint64_t)(int64_t)result :
                            (uint64_t)-ENOMEM;
                    }
                }
                if (user_vma_record_ex(
                        mm, base, base + need, (uint32_t)prot,
                        (uint32_t)flags, e->path, off, len) < 0) {
                    process_user_mmap_unmap(mm, base, need);
                    return (uint64_t)-ENOMEM;
                }
                user_mmap_trace_op(
                    cur, "mmap-bsd-cdev", addr, len, prot, flags,
                    base, e->path);
                return base;
            }
#endif
            if (vfs_dev_mmap(e->path, len, off, base, &maddr, &mlen) == 0) {
                uint64_t dev_need = need;
                static int fb_mmap_diag_budget =
                    EDGE_GUI_DEEP_TRACE ? 8 : 0;
                if ((flags & LINUX_MAP_FIXED_NOREPLACE) != 0 &&
                    user_vma_range_overlaps(mm, maddr, maddr + dev_need)) {
                    if (EDGE_X11_TRACE && (strcmp(tname, "Xorg") == 0 || strcmp(e->path, "/dev/fb0") == 0)) {
                        printf("[mmap-dev] pid=%d %s path=%s alias-collide ret=0x%x len=0x%x req=0x%x req_len=0x%x prot=0x%x flags=0x%x fd=%d off=0x%x\n",
                               cur->pid, tname, e->path[0] ? e->path : "-",
                               (uint32_t)maddr, (uint32_t)mlen, (uint32_t)addr, (uint32_t)len,
                               (uint32_t)prot, (uint32_t)flags, (int)fd, (uint32_t)off);
                    }
                    return (uint64_t)-EEXIST;
                }
                /*
                 * Linux fbdev mmap correctness depends on the relationship
                 * between FBIOGET_FSCREENINFO.smem_start, the mmap offset, and
                 * the returned aperture.  Log only the first few /dev/fb0 maps
                 * so serial still stays usable under XFCE startup load.
                 */
                if (fb_mmap_diag_budget > 0 && strcmp(e->path, "/dev/fb0") == 0) {
                    fb_mmap_diag_budget--;
                    printf("[mmap-dev] pid=%d %s path=%s ret=0x%x:%x map_len=0x%x req=0x%x:%x req_len=0x%x prot=0x%x flags=0x%x fd=%d off=0x%x dev_need=0x%x budget=%d\n",
                           cur ? cur->pid : -1, tname, e->path[0] ? e->path : "-",
                           (uint32_t)(maddr >> 32), (uint32_t)maddr,
                           (uint32_t)mlen,
                           (uint32_t)(addr >> 32), (uint32_t)addr,
                           (uint32_t)len, (uint32_t)prot, (uint32_t)flags,
                           (int)fd, (uint32_t)off, (uint32_t)dev_need,
                           fb_mmap_diag_budget);
                }
                if (trace_py || (EDGE_X11_TRACE && (strcmp(tname, "Xorg") == 0 || strcmp(e->path, "/dev/fb0") == 0))) {
                    /*
                     * Keep this visible while bringing up real desktop stacks:
                     * fbdev clients combine mmap's return value with
                     * FBIOGET_FSCREENINFO.smem_start low bits, and bad values
                     * produce user faults in supervisor-only identity PDEs.
                     */
                    printf("[mmap-dev] pid=%d %s path=%s ret=0x%x map_len=0x%x req=0x%x req_len=0x%x prot=0x%x flags=0x%x fd=%d off=0x%x\n",
                           cur->pid, tname, e->path[0] ? e->path : "-",
                           (uint32_t)maddr, (uint32_t)mlen, (uint32_t)addr, (uint32_t)len,
                           (uint32_t)prot, (uint32_t)flags, (int)fd, (uint32_t)off);
                }
                xorg_hash_change_check("dev-mmap", e->path, maddr, mlen ? mlen : len);
                /*
                 * Device mappings are VMAs too.  In particular, fbdev mappings
                 * must survive close(fd) and only stop driving display flushes
                 * after munmap/exit removes the mapping.  Returning before VMA
                 * bookkeeping made Xorg's Linux-compatible close-after-mmap
                 * sequence leave the virtio-gpu scanout stale.
                 */
                if (user_vma_record_ex(mm, maddr, maddr + dev_need,
                                       (uint32_t)prot, (uint32_t)flags,
                                       e->path, off, len) < 0) {
                    user_mmap_debug(cur, "dev-vma-record", addr, len, prot, flags, (int)fd, off, e->path);
                    return user_mmap_fail(cur, "dev-vma-record", (uint64_t)-ENOMEM,
                                          addr, len, prot, flags, (int)fd, off, e->path);
                }
                if (strcmp(e->path, "/dev/fb0") == 0 &&
                    process_user_fbdev_install_vma(mm, maddr, dev_need) < 0) {
                    (void)user_vma_remove_range(mm, maddr, maddr + dev_need);
                    process_user_mmap_unmap(mm, maddr, dev_need);
                    return user_mmap_fail(cur, "dev-fbdev-install", (uint64_t)-ENOMEM,
                                          addr, len, prot, flags, (int)fd, off, e->path);
                }
                user_mmap_trace_op(cur, "mmap-dev", addr, len, prot, flags, maddr, e->path);
                return maddr;
            }
            return (uint64_t)-ENOSYS;
        }
        if (sparse_mmap) {
            int file_slot = user_mmap_file_slot_ex(file_path, &e->inode, e->sb);
            uint64_t file_need = page_align_up(len);
            /*
             * Fault-time VFS/block reads are unsafe today, so file-backed
             * mappings populate file bytes during mmap(2).  Read-only private
             * executable/library mappings may share the global file-page cache:
             * otherwise a real desktop maps hundreds of MiB of duplicate shared
             * objects and spends minutes reading Mesa/GTK/LLVM one process at a
             * time.  Writable private mappings still get process-local pages, and
             * process_user_mmap_protect() performs COW before any later
             * MAP_PRIVATE file page is made writable for relocations/RELRO.
             *
             * Red flag: do not map cached file pages writable for MAP_PRIVATE.
             * If the COW-on-mprotect path is changed, re-test XFCE/GTK because
             * relocation writes into the cache corrupt executable code in other
             * processes.
             */
            if (file_slot < 0) {
                user_mmap_debug(cur, "file-slot", addr, len, prot, flags, (int)fd, off, e->path);
                return user_mmap_fail(cur, "file-slot", (uint64_t)-ENOMEM,
                                      addr, len, prot, flags, (int)fd, off, file_path);
            }
            user_mmap_log_apk_libcrypto_inode(cur, "mmap-fd", file_path, file_slot, &e->inode, e->sb);
            mmap_file_slot = file_slot;
            if (file_need > need) file_need = need;
            /*
             * Linux does not synchronously read every page of a file-backed
             * mmap.  Record the VMA below and populate file pages from
             * process_user_mmap_handle_fault() as userspace touches them.  This
             * is required for large GTK/XFCE sessions: eager population of
             * every shared-object/font mapping pins the VM in mmap(2), makes
             * serial and USB input look frozen, and keeps Xorg's fbdev surface
             * black until the session manager eventually finishes mapping
             * libraries.  The file slot was still created above so the VMA can
             * resolve stable inode-backed pages after the fd is closed.
             */
            user_mmap_large_file_trace(cur, "defer", base, file_need, prot, flags, off, e->path);
        } else {
            memset(mmap_kbuf, 0, sizeof(mmap_kbuf));
            for (uint64_t z = 0; z < need; ) {
                uint64_t zn = need - z;
                if (zn > sizeof(mmap_kbuf)) zn = sizeof(mmap_kbuf);
                if (copy_to_user(base + z, mmap_kbuf, zn) < 0) return (uint64_t)-EFAULT;
                z += zn;
            }
            while (done < len) {
                uint64_t n = len - done;
                int r;
                if (n > sizeof(mmap_kbuf)) n = sizeof(mmap_kbuf);
                if (!e->sb || !e->sb->ops || !e->sb->ops->read) break;
                r = e->sb->ops->read(e->sb, &e->inode, (uint32_t)(off + done), (void *)mmap_kbuf, (uint32_t)n);
                if (r < 0) return (uint64_t)-EIO;
                if (r == 0) break;
                if (copy_to_user(base + done, mmap_kbuf, (uint64_t)r) < 0) return (uint64_t)-EFAULT;
                done += (uint64_t)r;
                if ((uint64_t)r < n) break;
            }
        }
    } else {
        if (0 && strcmp(tname, "Xorg") == 0 &&
            (base < 0x01000000ULL || addr < 0x01000000ULL || (flags & LINUX_MAP_FIXED) != 0)) {
            printf("[mmap-xorg] anon ret=0x%x req=0x%x len=0x%x need=0x%x prot=0x%x flags=0x%x off=0x%x sparse=%d\n",
                   (uint32_t)base, (uint32_t)addr, (uint32_t)len, (uint32_t)need,
                   (uint32_t)prot, (uint32_t)flags, (uint32_t)off, sparse_mmap);
        }
        if (sparse_mmap) {
            /*
             * Linux does not allocate and zero every anonymous mmap page at
             * mmap(2) time.  GTK/XFCE allocators churn through many short-lived
             * anonymous mappings; eagerly committing each one here pins QEMU at
             * 100% CPU and starves the serial shell/input path before the
             * desktop finishes starting.  Record the VMA below and let
             * process_user_mmap_handle_fault() allocate a zero page only when
             * userspace actually touches it.  Keep file-backed mappings eager
             * above until VFS/block I/O is safe from the page-fault path.
             */
            xorg_hash_change_check("anon-vma", "-", base, need);
        } else {
            memset(mmap_kbuf, 0, sizeof(mmap_kbuf));
            for (uint64_t z = 0; z < need; ) {
                uint64_t zn = need - z;
                if (zn > sizeof(mmap_kbuf)) zn = sizeof(mmap_kbuf);
                if (copy_to_user(base + z, mmap_kbuf, zn) < 0) return (uint64_t)-EFAULT;
                z += zn;
            }
        }
    }

    if (sparse_mmap || user_range_is_fixed_heap(mm, base, need)) {
mmap_record_vma:
        if (user_vma_record_ex_slot(mm, base, base + need, (uint32_t)prot, (uint32_t)flags,
                                    file_path, off, len, 0,
                                    mmap_file_slot) < 0) {
            user_mmap_debug(cur, "vma-record", addr, len, prot, flags, (int)fd, off, file_path);
            if (sparse_mmap) process_user_mmap_unmap(mm, base, need);
            return user_mmap_fail(cur, "vma-record", (uint64_t)-ENOMEM,
                                  addr, len, prot, flags, (int)fd, off, file_path);
        }
        if (user_mmap_is_apk_libcrypto(cur, file_path)) {
            user_mmap_dump_apk_libcrypto_vmas(mm, "after-record", base, need, prot, flags, off);
        }
        if (sparse_mmap && (flags & LINUX_MAP_ANON) != 0 &&
            (flags & LINUX_MAP_SHARED) != 0) {
            /*
             * A Linux anonymous MAP_SHARED mapping is one shmem object across
             * fork.  If an untouched page is allocated independently in the
             * parent and child after fork, writes disappear between the two
             * mappings and shared-memory allocators observe corruption.  The
             * x86 address-space implementation does not yet attach a separate
             * shmem object to anonymous VMAs, so materialize the shared pages
             * before the mapping can be cloned.  ARM64 follows the same eager
             * shared-page policy.  Private anonymous mappings remain demand
             * allocated and keep their zero-page/COW behavior.
             */
            if (process_user_mmap_commit(mm, base, need) < 0 ||
                process_user_mmap_protect(mm, base, need,
                                          (uint32_t)prot) < 0) {
                (void)user_vma_remove_range(mm, base, base + need);
                process_user_mmap_unmap(mm, base, need);
                return user_mmap_fail(
                    cur, "shared-anon-populate", (uint64_t)-ENOMEM,
                    addr, len, prot, flags, (int)fd, off, 0);
            }
        }
        if ((flags & (LINUX_MAP_FIXED | LINUX_MAP_FIXED_NOREPLACE)) == 0 &&
            base >= USER_MMAP_BASE_ADDR &&
            base < USER_MMAP_LIMIT_ADDR && base < mm->user_mmap_next) {
            mm->user_mmap_next = base;
        }
    }
    if (trace_py) {
        printf("[mmap] pid=%d %s ret=0x%x addr=0x%x len=0x%x need=0x%x prot=0x%x flags=0x%x fd=%d off=0x%x next=0x%x\n",
               cur->pid, tname, (uint32_t)base, (uint32_t)addr, (uint32_t)len, (uint32_t)need, (uint32_t)prot,
               (uint32_t)flags, (int)fd, (uint32_t)off, (uint32_t)cur->user_mmap_next);
    }
    xorg_hash_change_check("mmap-return", 0, base, need);
    user_mmap_trace_op(cur, "mmap", addr, len, prot, flags, base, file_path);
    return base;
}

int64_t arch_mm_map(const kernel_mm_map_request_t *request) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    int64_t result;

    if (!memory) return -EINVAL;
    process_user_vma_mutation_lock(memory);
    result = arch_mm_map_locked(request);
    process_user_vma_mutation_unlock(memory);
    return result;
}

int arch_mm_file_mapping_info(uint64_t address,
                              kernel_mm_file_mapping_info_t *info) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    int result = -EINVAL;

    if (!memory || !info) return -EINVAL;
    process_user_vma_mutation_lock(memory);
    for (int index = 0; index < user_vma_live_limit(memory); ++index) {
        const edge_user_vma_t *mapping = &memory->user_vmas[index];
        if (!mapping->file_backed || mapping->end <= mapping->start ||
            address < mapping->start || address >= mapping->end)
            continue;
        memset(info, 0, sizeof(*info));
        info->start = mapping->start;
        info->end = mapping->end;
        info->file_offset = mapping->file_off + address - mapping->start;
        info->backing_identity = (uint64_t)mapping->file_slot + 1u;
        info->object_identity =
            ((uint64_t)mapping->file_ino << 32u) |
            mapping->file_generation;
        info->protection = mapping->prot;
        info->attributes = mapping->flags;
        info->shared =
            (mapping->flags & LINUX_MAP_SHARED) != 0 ? 1u : 0u;
        result = 0;
        break;
    }
    process_user_vma_mutation_unlock(memory);
    return result;
}

static int user_vma_clone_file_piece(task_t *task,
                                     const edge_user_vma_t *source,
                                     uint64_t start, uint64_t end,
                                     uint64_t file_offset) {
    int slot;

    if (!task || !source || !source->file_backed || end <= start)
        return -1;
    slot = user_vma_find_free_slot(task);
    if (slot < 0) return -1;
    task->user_vmas[slot] = *source;
    task->user_vmas[slot].start = start;
    task->user_vmas[slot].end = end;
    task->user_vmas[slot].file_off = file_offset;
    task->user_vmas[slot].file_len = end - start;
    if (process_user_vma_retain_backing(&task->user_vmas[slot]) < 0) {
        memset(&task->user_vmas[slot], 0, sizeof(task->user_vmas[slot]));
        return -1;
    }
    user_vma_commit_slot(task, slot);
    return 0;
}

static int user_vma_reoffset_file_range(task_t *task, uint64_t start,
                                        uint64_t end,
                                        uint64_t file_offset) {
    edge_user_vma_t first;
    uint64_t cursor = start;
    int needed_slots = 0;
    int have_first = 0;
    int live;

    if (!task || end <= start) return -1;
    live = user_vma_live_limit(task);
    while (cursor < end) {
        edge_user_vma_t *mapping = 0;
        for (int index = 0; index < live; ++index) {
            edge_user_vma_t *candidate = &task->user_vmas[index];
            if (candidate->end > candidate->start &&
                cursor >= candidate->start && cursor < candidate->end) {
                mapping = candidate;
                break;
            }
        }
        if (!mapping || !mapping->file_backed ||
            !(mapping->flags & LINUX_MAP_SHARED))
            return -1;
        if (!have_first) {
            first = *mapping;
            have_first = 1;
        } else if (mapping->file_slot != first.file_slot ||
                   mapping->prot != first.prot ||
                   mapping->flags != first.flags)
            return -1;
        cursor = mapping->end < end ? mapping->end : end;
    }

    for (int index = 0; index < live; ++index) {
        const edge_user_vma_t *mapping = &task->user_vmas[index];
        if (mapping->end <= mapping->start || end <= mapping->start ||
            start >= mapping->end)
            continue;
        if (start > mapping->start && end < mapping->end)
            needed_slots += 2;
        else if (start > mapping->start || end < mapping->end)
            ++needed_slots;
    }
    if (needed_slots > 0 &&
        (task->user_vma_count > PROCESS_USER_VMA_MAX -
                                     (uint32_t)needed_slots ||
         process_user_vma_reserve(
             task, task->user_vma_count + (uint32_t)needed_slots) < 0 ||
         needed_slots > user_vma_free_slot_count(task)))
        return -1;

    live = user_vma_live_limit(task);
    for (int index = 0; index < live; ++index) {
        edge_user_vma_t *mapping = &task->user_vmas[index];
        edge_user_vma_t old;
        uint64_t overlap_start;
        uint64_t overlap_end;

        if (mapping->end <= mapping->start || end <= mapping->start ||
            start >= mapping->end)
            continue;
        old = *mapping;
        overlap_start = start > old.start ? start : old.start;
        overlap_end = end < old.end ? end : old.end;
        if (overlap_start == old.start && overlap_end == old.end) {
            mapping->file_off = file_offset + old.start - start;
            mapping->file_len = old.end - old.start;
            continue;
        }
        if (overlap_start == old.start) {
            if (user_vma_clone_file_piece(
                    task, &old, overlap_end, old.end,
                    old.file_off + overlap_end - old.start) < 0)
                return -1;
            mapping->end = overlap_end;
            mapping->file_off = file_offset + old.start - start;
            mapping->file_len = overlap_end - old.start;
            continue;
        }

        mapping->end = overlap_start;
        mapping->file_len = overlap_start - old.start;
        if (overlap_end < old.end &&
            user_vma_clone_file_piece(
                task, &old, overlap_end, old.end,
                old.file_off + overlap_end - old.start) < 0)
            return -1;
        if (user_vma_clone_file_piece(
                task, &old, overlap_start, overlap_end,
                file_offset + overlap_start - start) < 0)
            return -1;
    }
    user_vma_merge_compatible(task);
    return 0;
}

int64_t arch_mm_remap_file_pages(uint64_t address, uint64_t length,
                                 uint64_t file_offset, uint32_t flags) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    int64_t result = -EINVAL;
    (void)flags;

    if (!memory || !process_user_mmap_range_ok(address, length))
        return -EINVAL;
    process_user_vma_mutation_lock(memory);
    if (user_vma_sync_shared_file_range(
            memory, address, address + length) < 0)
        result = -EIO;
    else if (user_vma_reoffset_file_range(
                 memory, address, address + length, file_offset) < 0)
        result = -ENOMEM;
    else {
        process_user_mmap_unmap_fast(memory, address, length);
        vfs_inode_lifetime_finish_alias_release();
        result = 0;
    }
    process_user_vma_mutation_unlock(memory);
    if (result == 0 && !(flags & KERNEL_MM_MAP_NONBLOCK)) {
        uint64_t end = address + length;
        for (uint64_t page = address; page < end; page += PAGE_SIZE)
            (void)process_user_mmap_handle_fault(memory, page, 0);
    }
    return result;
}

static int64_t arch_mm_unmap_range_locked(
    uint64_t addr, uint64_t len) {
    task_t *cur = process_current_task();
    task_t *mm = 0;
    uint64_t need;
    int sparse_mmap = 0;
    int touched_fbdev = 0;
    int trace_py = 0;
    const char *tname = "?";
    if (!cur) return (uint64_t)-EINVAL;
    mm = process_vm_task(cur);
    if (!mm) return (uint64_t)-EINVAL;
    tname = cur->name[0] ? cur->name : "?";
    trace_py = 0 && (strcmp(tname, "python3") == 0);
    need = len;
    sparse_mmap = process_user_mmap_range_ok(addr, need);
    if (user_vma_sync_shared_file_range(mm, addr, addr + need) < 0) return (uint64_t)-EIO;
    int live = user_vma_live_limit(mm);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &mm->user_vmas[i];
        if (v->end <= v->start) continue;
        if (addr + need <= v->start || addr >= v->end) continue;
        if (user_vma_path_is(v, "/dev/fb0")) {
            touched_fbdev = 1;
            break;
        }
    }

    if (sparse_mmap) {
        user_mmap_trace_op(cur, "munmap", addr, len, 0, 0, 0, 0);
        if (user_vma_remove_range(mm, addr, addr + need) < 0) return (uint64_t)-ENOMEM;
        process_user_mmap_unmap_fast(mm, addr, need);
        vfs_inode_lifetime_finish_alias_release();
        if (touched_fbdev && !fbdev_user_mapping_or_fd_live()) fb_release_user_mmap();
        if (trace_py) {
            printf("[munmap] pid=%d %s addr=0x%x len=0x%x need=0x%x next=0x%x (sparse)\n",
                   cur->pid, tname, (uint32_t)addr, (uint32_t)len, (uint32_t)need, (uint32_t)cur->user_mmap_next);
        }
        return 0;
    }
    if (addr >= USER_HEAP_BASE_ADDR && addr < mm->user_heap_limit) {
        user_mmap_trace_op(cur, "munmap-fixed", addr, len, 0, 0, 0, 0);
        if (user_vma_remove_range(mm, addr, addr + need) < 0) return (uint64_t)-ENOMEM;
        if (process_user_heap_unmap(mm, addr, need) < 0) return (uint64_t)-ENOMEM;
        vfs_inode_lifetime_finish_alias_release();
        if (touched_fbdev && !fbdev_user_mapping_or_fd_live()) fb_release_user_mmap();
        if (trace_py) {
            printf("[munmap] pid=%d %s addr=0x%x len=0x%x need=0x%x next=0x%x\n",
                   cur->pid, tname, (uint32_t)addr, (uint32_t)len, (uint32_t)need, (uint32_t)cur->user_mmap_next);
        }
        return 0;
    }
    if (touched_fbdev) {
        user_mmap_trace_op(cur, "munmap-fb", addr, len, 0, 0, 0, "/dev/fb0");
        if (user_vma_remove_range(mm, addr, addr + need) < 0) return (uint64_t)-ENOMEM;
        if (!fbdev_user_mapping_or_fd_live()) fb_release_user_mmap();
        return 0;
    }
    if (trace_py) {
        printf("[munmap] pid=%d %s addr=0x%x len=0x%x need=0x%x next=0x%x (noop)\n",
               cur->pid, tname, (uint32_t)addr, (uint32_t)len, (uint32_t)need, (uint32_t)cur->user_mmap_next);
    }
    return 0;
}

int64_t arch_mm_unmap_range(uint64_t addr, uint64_t len) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    int64_t result;

    if (!memory) return -EINVAL;
    process_user_vma_mutation_lock(memory);
    result = arch_mm_unmap_range_locked(addr, len);
    process_user_vma_mutation_unlock(memory);
    return result;
}

static int64_t arch_mm_protect_range_locked(
    uint64_t addr, uint64_t len, uint64_t prot) {
    task_t *cur = process_current_task();
    if (!cur) return (uint64_t)-EINVAL;

    uint64_t end = page_align_up(addr + len);
    if (end < addr) return -ENOMEM;
    if (process_user_mmap_range_ok(addr, end - addr)) {
        task_t *mm = process_vm_task(cur);
        user_mmap_trace_op(cur, "mprotect", addr, len, prot, 0, 0, 0);
        if (!mm || user_vma_protect_range(mm, addr, end, (uint32_t)prot) < 0) {
            return user_mmap_fail(cur, "mprotect-vma", (uint64_t)-ENOMEM,
                                  addr, len, prot, 0, -1, 0, 0);
        }
        /*
         * Linux mprotect(2) changes permissions; it must not populate
         * non-present pages.  In particular, file-backed MAP_PRIVATE text and
         * shared-object VMAs are demand-faulted from their file.  Committing
         * the whole range here installs anonymous zero pages before the first
         * instruction fetch, so later GTK/Pango/XFCE workers execute garbage or
         * try to write through RX mappings instead of faulting in the real file
         * bytes.  Only update existing PTE permissions below; absent pages will
         * use the VMA's new prot when process_user_mmap_handle_fault() loads
         * them.
         *
         * Red flag: do not reintroduce eager commit for mprotect to "avoid"
         * page faults.  Demand faults are the Linux ABI behavior and are
         * required for file-backed executable mappings to stay correct.
         */
        if (process_user_mmap_protect(mm, addr, end - addr, (uint32_t)prot) < 0) {
            return user_mmap_fail(cur, "mprotect-pte", (uint64_t)-ENOMEM,
                                  addr, len, prot, 0, -1, 0, 0);
        }
        return 0;
    }
    {
        task_t *mm = process_vm_task(cur);
        if (mm && user_range_is_fixed_heap(mm, addr, end - addr) &&
            user_vma_range_covered(mm, addr, end)) {
            user_mmap_trace_op(cur, "mprotect-fixed-heap", addr, len, prot, 0, 0, 0);
            if (user_vma_protect_range(mm, addr, end, (uint32_t)prot) < 0) {
                return user_mmap_fail(cur, "mprotect-fixed-heap-vma", (uint64_t)-ENOMEM,
                                      addr, len, prot, 0, -1, 0, 0);
            }
            if (process_user_fixed_mprotect(cur, addr, end - addr, (uint32_t)prot) < 0) {
                return user_mmap_fail(cur, "mprotect-fixed-heap-pte", (uint64_t)-ENOMEM,
                                      addr, len, prot, 0, -1, 0, 0);
            }
            return 0;
        }
    }
    {
        task_t *mm = process_vm_task(cur);
        if (mm && user_vma_protect_intersections(
                      mm, addr, end, (uint32_t)prot) < 0) {
            return user_mmap_fail(cur, "mprotect-fixed-vma",
                                  (uint64_t)-ENOMEM, addr, len, prot,
                                  0, -1, 0, 0);
        }
        int fixed_rc = process_user_fixed_mprotect(cur, addr, end - addr, (uint32_t)prot);
        if (fixed_rc < 0) {
            return user_mmap_fail(cur, "mprotect-fixed", (uint64_t)-ENOMEM,
                                  addr, len, prot, 0, -1, 0, 0);
        }
        if (fixed_rc > 0) return 0;
    }
    for (uint64_t v = addr; v < end; v += PAGE_SIZE) {
        uint64_t ptef = user_pte_flags(v);
        if (!(ptef & PTE_PRESENT) || !(ptef & PTE_USER)) {
            return user_mmap_fail(cur, "mprotect-page-missing", (uint64_t)-ENOMEM,
                                  addr, len, prot, 0, -1, 0, 0);
        }
        if ((prot & LINUX_PROT_WRITE) && !(ptef & PTE_WRITE)) {
            return user_mmap_fail(cur, "mprotect-page-ro", (uint64_t)-ENOMEM,
                                  addr, len, prot, 0, -1, 0, 0);
        }
    }
    return 0;
}

int64_t arch_mm_protect_range(uint64_t addr, uint64_t len,
                              uint64_t prot) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    int64_t result;

    if (!memory) return -EINVAL;
    process_user_vma_mutation_lock(memory);
    result = arch_mm_protect_range_locked(addr, len, prot);
    process_user_vma_mutation_unlock(memory);
    return result;
}

uintptr_t kernel_sysv_shm_arch_current_address_space(void) {
    task_t *current = process_current_task();
    return (uintptr_t)(current ? process_vm_task(current) : 0);
}

int kernel_sysv_shm_arch_page_allocate(kernel_sysv_shm_page_t *page) {
    int index;
    if (!page) return -EINVAL;
    index = process_user_mmap_alloc_backing_page();
    if (index < 0) return -ENOMEM;
    *page = (uint64_t)(uint32_t)index;
    return 0;
}

void kernel_sysv_shm_arch_page_release(kernel_sysv_shm_page_t page) {
    if (page > INT32_MAX) return;
    process_user_mmap_release_backing_page((int)page);
}

int kernel_sysv_shm_arch_map(uintptr_t address_space,
                             uint64_t requested_address,
                             uint64_t length,
                             const kernel_sysv_shm_page_t *pages,
                             uint32_t page_count,
                             uint32_t flags,
                             uint64_t *mapped_address) {
    task_t *mm = (task_t *)address_space;
    uint64_t base = requested_address;
    uint32_t protection = LINUX_PROT_READ;
    int writable = (flags & KERNEL_SYSV_SHM_RDONLY) == 0;

    if (!mm || !pages || !page_count || !length || !mapped_address)
        return -EINVAL;
    if (writable) protection |= LINUX_PROT_WRITE;
    if (flags & KERNEL_SYSV_SHM_EXEC) protection |= LINUX_PROT_EXEC;
    if (base) {
        if (!user_range_ok(base, length)) return -EINVAL;
        if (user_vma_range_overlaps(mm, base, base + length) ||
            user_range_has_present_pages(base, base + length)) {
            return -EINVAL;
        }
    } else {
        base = user_vma_find_hint_gap(
            mm, USER_MMAP_BASE_ADDR, USER_MMAP_LIMIT_ADDR, length, PAGE_SIZE);
        if (!base)
            base = user_vma_find_topdown_gap(
                mm, USER_MMAP_BASE_ADDR, USER_MMAP_LIMIT_ADDR, length,
                PAGE_SIZE);
        if (!base) return -ENOMEM;
    }
    for (uint32_t page = 0; page < page_count; ++page) {
        if (pages[page] > INT32_MAX ||
            process_user_mmap_map_backing_page(
                mm, base + (uint64_t)page * PAGE_SIZE,
                (int)pages[page], writable) < 0) {
            process_user_mmap_unmap(mm, base, (uint64_t)page * PAGE_SIZE);
            return -ENOMEM;
        }
    }
    if (user_vma_record(mm, base, base + length, protection,
                        LINUX_MAP_SHARED) < 0) {
        process_user_mmap_unmap(mm, base, length);
        return -ENOMEM;
    }
    if (base >= USER_MMAP_BASE_ADDR && base < USER_MMAP_LIMIT_ADDR &&
        base < mm->user_mmap_next)
        mm->user_mmap_next = base;
    *mapped_address = base;
    return 0;
}

int kernel_sysv_shm_arch_unmap(uintptr_t address_space,
                               uint64_t address, uint64_t length) {
    task_t *mm = (task_t *)address_space;
    if (!mm || !length) return -EINVAL;
    if (user_vma_remove_range(mm, address, address + length) < 0)
        return -ENOMEM;
    process_user_mmap_unmap(mm, address, length);
    return 0;
}

int64_t arch_current_sleep_until(uint64_t deadline_microseconds,
                                 uint64_t remaining_user,
                                 int write_remaining,
                                 void *user_registers) {
    uint64_t result;
    (void)user_registers;
    result = do_sys_sleep_until_us(deadline_microseconds);
    if ((int64_t)result == -EINTR && write_remaining && remaining_user) {
        struct edge_timespec remaining = {0, 0};
        uint64_t now = boottime_monotonic_us();
        if (deadline_microseconds > now) {
            uint64_t usec = deadline_microseconds - now;
            remaining.tv_sec = (int64_t)(usec / 1000000u);
            remaining.tv_nsec =
                (int64_t)((usec % 1000000u) * 1000u);
        }
        if (copy_to_user(remaining_user, &remaining,
                         sizeof(remaining)) < 0)
            return -EFAULT;
    }
    return (int64_t)result;
}

static spinlock_t g_syslog_wait_lock;
static task_t *g_syslog_waiters[PROC_MAX_TASKS];

static int syslog_waiter_index_locked(const task_t *task) {
    for (int index = 0; index < PROC_MAX_TASKS; ++index)
        if (g_syslog_waiters[index] == task) return index;
    return -1;
}

static void syslog_waiter_remove(task_t *task) {
    uint64_t flags = spin_lock_irqsave(&g_syslog_wait_lock);
    int index = syslog_waiter_index_locked(task);
    if (index >= 0) g_syslog_waiters[index] = 0;
    spin_unlock_irqrestore(&g_syslog_wait_lock, flags);
}

int arch_syslog_wait_for_data(uint64_t observed_next,
                              void *user_registers) {
    task_t *task = process_current_task();
    int slot = -1;
    (void)user_registers;
    if (!task) return -EINVAL;
    if (bootlog_next_offset() != observed_next) return 1;
    {
        uint64_t flags = spin_lock_irqsave(&g_syslog_wait_lock);
        for (int index = 0; index < PROC_MAX_TASKS; ++index)
            if (!g_syslog_waiters[index]) {
                g_syslog_waiters[index] = task;
                slot = index;
                break;
            }
        spin_unlock_irqrestore(&g_syslog_wait_lock, flags);
    }
    if (slot < 0) return -EAGAIN;
    if (bootlog_next_offset() != observed_next) {
        syslog_waiter_remove(task);
        return 1;
    }
    for (;;) {
        uint64_t flags;
        if (signal_pending_interrupt()) {
            syslog_waiter_remove(task);
            return -EINTR;
        }
        flags = spin_lock_irqsave(&g_syslog_wait_lock);
        if (syslog_waiter_index_locked(task) < 0) {
            spin_unlock_irqrestore(&g_syslog_wait_lock, flags);
            return 1;
        }
        scheduler_task_set_blocked(task);
        spin_unlock_irqrestore(&g_syslog_wait_lock, flags);
        scheduler_yield();
    }
}

void arch_syslog_notify_data(void) {
    task_t *wake[PROC_MAX_TASKS];
    int count = 0;
    uint64_t flags = spin_lock_irqsave(&g_syslog_wait_lock);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *task = g_syslog_waiters[index];
        if (!task) continue;
        g_syslog_waiters[index] = 0;
        wake[count++] = task;
    }
    spin_unlock_irqrestore(&g_syslog_wait_lock, flags);
    for (int index = 0; index < count; ++index) {
        task_t *task = wake[index];
        if (task->state == TASK_BLOCKED)
            scheduler_task_make_runnable(
                task, task->assigned_cpu >= 0 ?
                    (uint32_t)task->assigned_cpu : scheduler_cpu_id());
    }
}

static void user_mmap_file_cache_deactivate_range(
    task_t *memory, uint64_t start, uint64_t end) {
    int live;

    if (!memory || end <= start) return;
    live = user_vma_live_limit(memory);
    user_mmap_file_cache_lock();
    for (int index = 0; index < live; ++index) {
        edge_user_vma_t *vma = &memory->user_vmas[index];
        uint64_t overlap_start;
        uint64_t overlap_end;

        if (vma->end <= vma->start || !vma->file_backed ||
            end <= vma->start || start >= vma->end)
            continue;
        overlap_start = start > vma->start ? start : vma->start;
        overlap_end = end < vma->end ? end : vma->end;
        for (uint64_t address = overlap_start;
             address < overlap_end; address += PAGE_SIZE) {
            uint64_t file_offset = vma->file_off + address - vma->start;
            int cache_slot = user_mmap_file_cache_hash_lookup(
                vma->file_slot, file_offset);
            if (cache_slot >= 0)
                kernel_mm_cache_state_deactivate(
                    &g_user_mmap_file_page_cache[cache_slot].reclaim);
        }
    }
    user_mmap_file_cache_unlock();
}

static uint32_t user_mmap_file_cache_pageout_range(
    task_t *memory, uint64_t start, uint64_t end,
    uint64_t *scanned_pages_out) {
    uint64_t scanned = 0;
    uint32_t reclaimed = 0;
    int live;

    if (scanned_pages_out) *scanned_pages_out = 0;
    if (!memory || end <= start) return 0;

    /* Pristine file-cache PTEs are distinct from private COW pages. */
    (void)process_user_mmap_drop_file_cache_range(
        memory, start, end - start);
    live = user_vma_live_limit(memory);
    user_mmap_file_cache_lock();
    for (int index = 0; index < live; ++index) {
        edge_user_vma_t *vma = &memory->user_vmas[index];
        uint64_t overlap_start;
        uint64_t overlap_end;

        if (vma->end <= vma->start || !vma->file_backed ||
            end <= vma->start || start >= vma->end)
            continue;
        overlap_start = start > vma->start ? start : vma->start;
        overlap_end = end < vma->end ? end : vma->end;
        for (uint64_t address = overlap_start;
             address < overlap_end; address += PAGE_SIZE) {
            uint64_t file_offset = vma->file_off + address - vma->start;
            int cache_slot = user_mmap_file_cache_hash_lookup(
                vma->file_slot, file_offset);
            user_mmap_file_page_cache_t *page;

            ++scanned;
            if (cache_slot < 0) continue;
            page = &g_user_mmap_file_page_cache[cache_slot];
            kernel_mm_cache_state_deactivate(&page->reclaim);
            if (process_user_mmap_backing_page_refcount(
                    page->backing_idx) != 1u ||
                process_user_mmap_backing_page_generation(
                    page->backing_idx) != page->backing_generation ||
                edge_mmap_file_cache_writeback_page(page) < 0)
                continue;
            user_mmap_file_cache_note_shadow(page, 0);
            user_mmap_file_cache_hash_remove_slot(cache_slot);
            process_user_mmap_release_backing_page(page->backing_idx);
            x86_page_writeback_forget_cache(page, (uint32_t)cache_slot);
            memset(page, 0, sizeof(*page));
            if (cache_slot < g_user_mmap_file_page_cache_free_hint)
                g_user_mmap_file_page_cache_free_hint = cache_slot;
            ++reclaimed;
        }
    }
    while (g_user_mmap_file_page_cache_high > 0 &&
           !g_user_mmap_file_page_cache[
                g_user_mmap_file_page_cache_high - 1].used)
        --g_user_mmap_file_page_cache_high;
    if (g_user_mmap_file_page_cache_free_hint >
        g_user_mmap_file_page_cache_high)
        g_user_mmap_file_page_cache_free_hint =
            g_user_mmap_file_page_cache_high;
    user_mmap_file_cache_unlock();
    if (scanned_pages_out) *scanned_pages_out = scanned;
    edge_mm_statistics_note_reclaim(scanned, reclaimed);
    return reclaimed;
}

int arch_mm_sealed_discard_allowed(
    int32_t pid, uint64_t address, uint64_t length) {
    task_t *target = task_by_pid_mutable_local(pid);
    task_t *memory;
    uint64_t end;
    int allowed = 1;
    int live;

    if (!target || target->state == TASK_UNUSED ||
        target->state == TASK_ZOMBIE)
        return -ESRCH;
    memory = process_vm_task(target);
    if (!memory || !length || length > UINT64_MAX - address)
        return -ENOMEM;
    end = page_align_up(address + length);
    process_user_vma_mutation_lock(memory);
    live = user_vma_live_limit(memory);
    for (int index = 0; index < live; ++index) {
        edge_user_vma_t *mapping = &memory->user_vmas[index];
        uint64_t overlap_start;
        uint64_t overlap_end;

        if (mapping->end <= mapping->start || end <= mapping->start ||
            address >= mapping->end)
            continue;
        overlap_start = address > mapping->start ?
                        address : mapping->start;
        overlap_end = end < mapping->end ? end : mapping->end;
        if (!mapping->file_backed && !(mapping->prot & LINUX_PROT_WRITE) &&
            kernel_mm_seal_space_overlaps(
                memory->cr3, overlap_start,
                overlap_end - overlap_start)) {
            allowed = 0;
            break;
        }
    }
    process_user_vma_mutation_unlock(memory);
    return allowed;
}

int arch_mm_process_madvise(
    int32_t pid, uint64_t address, uint64_t length,
    kernel_madvise_operation_t operation, int validate_only) {
    task_t *target;
    task_t *mm;
    uint64_t end;

    target = task_by_pid_mutable_local(pid);
    if (!target || target->state == TASK_UNUSED ||
        target->state == TASK_ZOMBIE)
        return -ESRCH;
    end = page_align_up(address + length);
    mm = process_vm_task(target);
    if (!mm)
        return -ENOMEM;

    if (operation == KERNEL_MADVISE_NOOP) {
        return user_madvise_noop_range_covered(mm, address, end) ?
               0 : -ENOMEM;
    }
    if (!user_vma_range_covered(mm, address, end)) return -ENOMEM;
    if (operation == KERNEL_MADVISE_SET_WIPE_ON_FORK ||
        operation == KERNEL_MADVISE_CLEAR_WIPE_ON_FORK) {
        int result;
        if (!user_vma_private_anonymous_range_covered(
                mm, address, end))
            return -EINVAL;
        if (validate_only) return 0;
        process_user_vma_mutation_lock(mm);
        if (!user_vma_private_anonymous_range_covered(
                mm, address, end)) {
            process_user_vma_mutation_unlock(mm);
            return -EINVAL;
        }
        result = user_vma_set_fork_policy_range(
            mm, address, end,
            operation == KERNEL_MADVISE_SET_WIPE_ON_FORK ?
                KERNEL_MM_VMA_FORK_WIPE : 0u);
        process_user_vma_mutation_unlock(mm);
        return result < 0 ? -ENOMEM : 0;
    }
    if (operation == KERNEL_MADVISE_LAZY_FREE) {
        if (!user_vma_private_anonymous_range_covered(
                mm, address, end))
            return -EINVAL;
        if (!validate_only)
            process_user_mmap_discard_private(
                mm, address, end - address);
        return 0;
    }
    if (operation == KERNEL_MADVISE_DEACTIVATE) {
        if (validate_only) return 0;
        user_mmap_file_cache_deactivate_range(
            mm, address, end);
        (void)process_user_mmap_deactivate_range(
            mm, address, end - address);
        return 0;
    }
    if (operation == KERNEL_MADVISE_PAGEOUT) {
        uint64_t scanned_pages = 0;
        if (validate_only) return 0;
        (void)process_user_mmap_deactivate_range(
            mm, address, end - address);
        (void)memfd_pageout_range(
            mm, address, end, &scanned_pages);
        (void)user_mmap_file_cache_pageout_range(
            mm, address, end, &scanned_pages);
        (void)process_user_mmap_pageout_range(
            mm, address, end - address, &scanned_pages);
        return 0;
    }
    if (operation == KERNEL_MADVISE_DISCARD) {
        if (!validate_only &&
            process_user_mmap_range_ok(address, end - address)) {
            process_user_mmap_discard_private(mm, address, end - address);
            kernel_userfaultfd_mapping_remove(
                mm->cr3, &(kernel_uffdio_range_t){
                    .start = address,
                    .length = end - address,
                });
        }
        return 0;
    }
    if (operation != KERNEL_MADVISE_POPULATE_READ &&
        operation != KERNEL_MADVISE_POPULATE_WRITE)
        return -EINVAL;

    if (validate_only) return 0;
    for (uint64_t page = address; page < end; page += PAGE_SIZE) {
        if (!process_user_mmap_handle_fault(
                mm, page, operation == KERNEL_MADVISE_POPULATE_WRITE))
            return -ENOMEM;
    }
    return 0;
}

int arch_mm_query_residency(uint64_t address, uint32_t page_count,
                            uint8_t *vector) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    uint64_t length;
    uint64_t end;
    length = (uint64_t)page_count * PAGE_SIZE;
    end = address + length;
    if (end < address || !memory ||
        !user_vma_range_covered(memory, address, end))
        return -ENOMEM;
    for (uint32_t index = 0; index < page_count; ++index) {
        uint64_t flags = user_pte_flags(address + (uint64_t)index * PAGE_SIZE);
        vector[index] = (flags & PTE_PRESENT) != 0 ? 1u : 0u;
    }
    return 0;
}

int arch_mm_lock_range(uint64_t address, uint64_t length, uint32_t flags) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    uint64_t end;
    end = address + length;
    if (!memory) return -ESRCH;
    process_user_vma_mutation_lock(memory);
    if (!user_vma_range_covered(memory, address, end)) {
        process_user_vma_mutation_unlock(memory);
        return -ENOMEM;
    }
    process_user_vma_mutation_unlock(memory);

    if (!(flags & KERNEL_MM_LOCK_RANGE_ONFAULT)) {
        for (uint64_t page = address; page < end; page += PAGE_SIZE) {
            if (!process_user_mmap_handle_fault(memory, page, 0))
                return -ENOMEM;
        }
    }
    process_user_vma_mutation_lock(memory);
    if (!user_vma_range_covered(memory, address, end)) {
        process_user_vma_mutation_unlock(memory);
        return -ENOMEM;
    }
    {
        int status = kernel_mm_lock_space_add_limited(
            memory->cr3, address, length,
            memory->rlimits[EDGE_LINUX_RLIMIT_MEMLOCK][0]);
        process_user_vma_mutation_unlock(memory);
        return status;
    }
}

int arch_mm_unlock_range(uint64_t address, uint64_t length) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    uint64_t end = address + length;
    int status;

    if (!memory) return -ESRCH;
    process_user_vma_mutation_lock(memory);
    if (!user_vma_range_covered(memory, address, end)) {
        process_user_vma_mutation_unlock(memory);
        return -ENOMEM;
    }
    status = kernel_mm_lock_space_remove(
        memory->cr3, address, length);
    process_user_vma_mutation_unlock(memory);
    return status;
}

int arch_mm_lock_all(uint32_t flags) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    uint32_t range_flags = (flags & KERNEL_MM_LOCK_ALL_ONFAULT) ?
                           KERNEL_MM_LOCK_RANGE_ONFAULT : 0u;
    int live;

    if (!memory) return -ESRCH;
    process_user_vma_mutation_lock(memory);
    live = user_vma_live_limit(memory);
    if (flags & KERNEL_MM_LOCK_ALL_CURRENT) {
        uint64_t bytes = 0;
        uint64_t limit =
            memory->rlimits[EDGE_LINUX_RLIMIT_MEMLOCK][0];
        for (int index = 0; index < live; ++index) {
            edge_user_vma_t *mapping = &memory->user_vmas[index];
            uint64_t mapping_bytes;
            if (mapping->end <= mapping->start) continue;
            mapping_bytes = mapping->end - mapping->start;
            if (mapping_bytes > limit || bytes > limit - mapping_bytes) {
                process_user_vma_mutation_unlock(memory);
                return -ENOMEM;
            }
            bytes += mapping_bytes;
        }
    }
    if ((flags & KERNEL_MM_LOCK_ALL_CURRENT) &&
        kernel_mm_lock_space_reserve(
            memory->cr3, (uint32_t)live) < 0) {
        process_user_vma_mutation_unlock(memory);
        return -ENOMEM;
    }
    if ((flags & KERNEL_MM_LOCK_ALL_CURRENT) && !range_flags) {
        for (int index = 0; index < live; ++index) {
            edge_user_vma_t mapping = memory->user_vmas[index];
            if (mapping.end <= mapping.start) continue;
            for (uint64_t page = mapping.start;
                 page < mapping.end; page += PAGE_SIZE) {
                if (!process_user_mmap_handle_fault(
                        memory, page, 0)) {
                    process_user_vma_mutation_unlock(memory);
                    return -ENOMEM;
                }
            }
        }
    }
    if (flags & KERNEL_MM_LOCK_ALL_CURRENT) {
        for (int index = 0; index < live; ++index) {
            edge_user_vma_t *mapping = &memory->user_vmas[index];
            if (mapping->end <= mapping->start) continue;
            if (kernel_mm_lock_space_add_limited(
                    memory->cr3, mapping->start,
                    mapping->end - mapping->start,
                    memory->rlimits[EDGE_LINUX_RLIMIT_MEMLOCK][0]) < 0) {
                process_user_vma_mutation_unlock(memory);
                return -ENOMEM;
            }
        }
    }
    if (kernel_mm_lock_space_set_future(
            memory->cr3,
            (flags & KERNEL_MM_LOCK_ALL_FUTURE) ?
                (KERNEL_MM_LOCK_ALL_FUTURE |
                 (flags & KERNEL_MM_LOCK_ALL_ONFAULT)) : 0u) < 0) {
        process_user_vma_mutation_unlock(memory);
        return -ENOMEM;
    }
    process_user_vma_mutation_unlock(memory);
    return 0;
}

int arch_mm_unlock_all(void) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;

    if (!memory) return -ESRCH;
    process_user_vma_mutation_lock(memory);
    kernel_mm_lock_space_clear(memory->cr3);
    process_user_vma_mutation_unlock(memory);
    return 0;
}

uint64_t arch_mm_current_address_space(void) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    return memory ? memory->cr3 : 0u;
}

int arch_mm_range_mapped(uint64_t address, uint64_t length) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    uint64_t end;
    int covered;

    if (!memory || !length || length > UINT64_MAX - address)
        return -ENOMEM;
    end = address + length;
    process_user_vma_mutation_lock(memory);
    covered = user_vma_range_covered(memory, address, end);
    process_user_vma_mutation_unlock(memory);
    return covered ? 0 : -ENOMEM;
}

static edge_user_vma_t *user_vma_find_at(task_t *t, uint64_t addr);

static task_t *x86_mm_task_for_address_space(uint64_t address_space) {
    if (!address_space) return 0;
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        const task_t *view = process_task_by_index(index);
        task_t *task;

        if (!view || view->state == TASK_UNUSED ||
            view->cr3 != address_space)
            continue;
        task = process_task_by_pid(view->pid);
        return task ? process_vm_task(task) : 0;
    }
    return 0;
}

int arch_mm_address_space_range_mapped(
        uint64_t address_space, uint64_t address, uint64_t length) {
    task_t *memory = x86_mm_task_for_address_space(address_space);
    uint64_t end;
    int covered;

    if (!memory || !length || length > UINT64_MAX - address)
        return -ENOMEM;
    end = address + length;
    process_user_vma_mutation_lock(memory);
    covered = user_vma_range_covered(memory, address, end);
    process_user_vma_mutation_unlock(memory);
    return covered ? 0 : -ENOMEM;
}

int arch_mm_address_space_page_resident(
        uint64_t address_space, uint64_t address) {
    task_t *memory = x86_mm_task_for_address_space(address_space);
    uint64_t page = address & ~(PAGE_SIZE - 1u);
    int covered;

    if (!memory) return -ENOMEM;
    process_user_vma_mutation_lock(memory);
    covered = user_vma_range_covered(memory, page, page + PAGE_SIZE);
    process_user_vma_mutation_unlock(memory);
    if (!covered) return -ENOMEM;
    return (user_pte_flags_address_space(
        address_space & ~0xfffULL, address) & PTE_PRESENT) != 0u;
}

static int x86_user_vma_shmem_snapshot(
        task_t *memory, uint64_t address, edge_user_vma_t *snapshot) {
    const edge_user_vma_t *mapping;
    const char *path;
    vfs_superblock_t *superblock = 0;
    vfs_inode_t inode;
    int supported = 0;

    if (!memory || !snapshot) return 0;
    process_user_vma_mutation_lock(memory);
    mapping = user_vma_find_at(memory, address);
    if (mapping && mapping->file_backed) {
        path = user_mmap_file_path(mapping->file_slot);
        if (memfd_id_from_path(path) > 0) {
            *snapshot = *mapping;
            supported = 1;
        } else if (user_vma_get_file_inode(
                       mapping, &inode, &superblock) == 0 &&
                   superblock &&
                   (strcmp(superblock->fs_name, "tmpfs") == 0 ||
                    strcmp(superblock->fs_name, "shmem") == 0)) {
            *snapshot = *mapping;
            supported = 1;
        }
    }
    process_user_vma_mutation_unlock(memory);
    return supported;
}

int arch_mm_address_space_shmem_range_supported(
        uint64_t address_space, uint64_t address, uint64_t length) {
    task_t *memory = x86_mm_task_for_address_space(address_space);
    uint64_t end;
    uint64_t cursor;

    if (!memory || !length || length > UINT64_MAX - address)
        return -EINVAL;
    end = address + length;
    for (cursor = address; cursor < end;) {
        edge_user_vma_t mapping;
        uint64_t next;

        if (!x86_user_vma_shmem_snapshot(memory, cursor, &mapping))
            return -EINVAL;
        next = mapping.end < end ? mapping.end : end;
        if (next <= cursor) return -EINVAL;
        cursor = next;
    }
    return 0;
}

int arch_mm_address_space_shmem_page_state(
        uint64_t address_space, uint64_t address) {
    task_t *memory = x86_mm_task_for_address_space(address_space);
    edge_user_vma_t mapping;
    const char *path;
    uint64_t file_offset;
    int memfd_id;

    if (!memory || !x86_user_vma_shmem_snapshot(
            memory, address, &mapping))
        return -EINVAL;
    file_offset = mapping.file_off +
                  (address & ~(PAGE_SIZE - 1u)) - mapping.start;
    path = user_mmap_file_path(mapping.file_slot);
    memfd_id = memfd_id_from_path(path);
    if (memfd_id > 0) {
        edge_memfd_t *memfd = memfd_get(memfd_id);
        if (!memfd || file_offset >= memfd->size) return 0;
        return memfd_storage_page(
                   memfd, file_offset / PAGE_SIZE, 0) >= 0 ? 1 : 0;
    }
    {
        vfs_inode_t inode;
        vfs_superblock_t *superblock = 0;
        uint64_t physical;

        if (file_offset > UINT32_MAX ||
            user_vma_get_file_inode(
                &mapping, &inode, &superblock) < 0)
            return -EINVAL;
        return tmpfs_shared_page(
                   superblock, &inode, (uint32_t)file_offset, 0,
                   &physical) == 0 ? 1 : 0;
    }
}

int arch_mm_address_space_copy(
        uint64_t address_space, uint64_t address, void *buffer,
        uint64_t size, kernel_mm_process_vm_operation_t operation) {
    task_t *memory = x86_mm_task_for_address_space(address_space);
    if (!memory || (!buffer && size) || size > UINT64_MAX - address)
        return -EFAULT;
    if (operation == KERNEL_MM_PROCESS_VM_READ)
        return process_read_user_memory(
            memory->pid, address, buffer, size) < 0 ? -EFAULT : 0;
    if (operation == KERNEL_MM_PROCESS_VM_WRITE) {
        uint64_t end = address + size;
        uint64_t page = address & ~(PAGE_SIZE - 1u);

        while (page < end) {
            if (!(user_pte_flags_address_space(
                    address_space & ~0xfffULL, page) & PTE_PRESENT) &&
                !process_user_mmap_handle_fault(memory, page, 1))
                return -EFAULT;
            page += PAGE_SIZE;
        }
        return process_write_user_memory(
            memory->pid, address, buffer, size) < 0 ? -EFAULT : 0;
    }
    return -EINVAL;
}

int arch_mm_address_space_write_protect(
        uint64_t address_space, uint64_t address, uint64_t length,
        int enable) {
    task_t *memory = x86_mm_task_for_address_space(address_space);

    if (!memory || !length || length > UINT64_MAX - address)
        return -ENOMEM;
    return process_user_mmap_write_protect(
        memory, address, length, enable) < 0 ? -ENOMEM : 0;
}

int arch_mm_address_space_move_validate(
        uint64_t address_space, uint64_t source, uint64_t destination,
        uint64_t length) {
    task_t *memory = x86_mm_task_for_address_space(address_space);
    edge_user_vma_t *source_vma;
    edge_user_vma_t *destination_vma;
    uint64_t source_end;
    uint64_t destination_end;
    int status = -EINVAL;

    if (!memory || !length || length > UINT64_MAX - source ||
        length > UINT64_MAX - destination)
        return -EINVAL;
    source_end = source + length;
    destination_end = destination + length;
    if (source < destination_end && destination < source_end)
        return -EINVAL;
    process_user_vma_mutation_lock(memory);
    source_vma = user_vma_find_at(memory, source);
    destination_vma = user_vma_find_at(memory, destination);
    if (source_vma && destination_vma &&
        source_end <= source_vma->end &&
        destination_end <= destination_vma->end &&
        !source_vma->file_backed && !destination_vma->file_backed &&
        !(source_vma->flags & LINUX_MAP_SHARED) &&
        !(destination_vma->flags & LINUX_MAP_SHARED) &&
        (source_vma->prot & LINUX_PROT_WRITE) &&
        source_vma->prot == destination_vma->prot)
        status = 0;
    process_user_vma_mutation_unlock(memory);
    return status;
}

int arch_mm_address_space_move_page(
        uint64_t address_space, uint64_t source, uint64_t destination,
        int allow_source_hole) {
    task_t *memory = x86_mm_task_for_address_space(address_space);
    int source_resident;
    int destination_resident;

    if (!memory) return -EINVAL;
    destination_resident = arch_mm_address_space_page_resident(
        address_space, destination);
    if (destination_resident < 0) return destination_resident;
    if (destination_resident) return -EEXIST;
    source_resident = arch_mm_address_space_page_resident(
        address_space, source);
    if (source_resident < 0) return source_resident;
    if (!source_resident)
        return allow_source_hole ? 0 : -ENOENT;
    return process_user_mmap_move_present(
        memory, source, destination, PAGE_SIZE) < 0 ? -ENOMEM : 0;
}

int arch_mm_address_space_poison_page(
        uint64_t address_space, uint64_t address) {
    task_t *memory = x86_mm_task_for_address_space(address_space);
    int result;

    if (!memory) return -EINVAL;
    result = process_user_mmap_poison_page(memory, address);
    if (result > 0) return -EEXIST;
    if (result < 0) return -ENOMEM;
    return 0;
}

int arch_mm_address_space_page_poisoned(
        uint64_t address_space, uint64_t address) {
    task_t *memory = x86_mm_task_for_address_space(address_space);

    if (!memory) return -EINVAL;
    return process_user_mmap_page_poisoned(memory, address);
}

int arch_mm_sync_range(uint64_t address, uint64_t length, uint32_t flags) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    uint64_t end;
    int status;

    (void)flags;
    end = address + length;
    /*
     * Linux validates mmap VMAs, including sparse and device mappings.  The
     * older eager-user-range check rejects valid fbdev and demand-paged VMAs.
     */
    if (!memory || !user_vma_range_covered(memory, address, end))
        return -ENOMEM;
    status = user_vma_sync_shared_file_range(memory, address, end);
    return status < 0 ? status : 0;
}

static int user_vma_lookup_uniform(task_t *t, uint64_t start, uint64_t end, uint32_t *prot_out, uint32_t *flags_out) {
    uint64_t pos;
    uint32_t prot = 0;
    uint32_t flags = 0;
    int have = 0;
    int live;
    if (!t || end <= start) return -1;
    live = user_vma_live_limit(t);
    pos = start;
    while (pos < end) {
        edge_user_vma_t *hit = 0;
        for (int i = 0; i < live; ++i) {
            edge_user_vma_t *v = &t->user_vmas[i];
            if (v->end <= v->start) continue;
            if (pos >= v->start && pos < v->end) {
                hit = v;
                break;
            }
        }
        if (!hit) return -1;
        if (!have) {
            prot = hit->prot;
            flags = hit->flags;
            have = 1;
        } else if (hit->prot != prot || hit->flags != flags) {
            return -1;
        }
        pos = hit->end < end ? hit->end : end;
    }
    if (!have) return -1;
    if (prot_out) *prot_out = prot;
    if (flags_out) *flags_out = flags;
    return 0;
}

static edge_user_vma_t *user_vma_find_at(task_t *t, uint64_t addr) {
    int live;
    if (!t) return 0;
    live = user_vma_live_limit(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        if (v->end <= v->start) continue;
        if (addr >= v->start && addr < v->end) return v;
    }
    return 0;
}

static int user_vma_populate_shared_anon_range(task_t *t, uint64_t start,
                                               uint64_t len) {
    edge_user_vma_t *v;
    if (!t || !len) return -1;
    v = user_vma_find_at(t, start);
    if (!v || v->file_backed ||
        (v->flags & LINUX_MAP_ANON) == 0 ||
        (v->flags & LINUX_MAP_SHARED) == 0)
        return 0;
    if (start + len < start || start + len > v->end) return -1;
    if (process_user_mmap_commit(t, start, len) < 0) return -1;
    return process_user_mmap_protect(t, start, len, v->prot);
}

static uint64_t user_vma_file_len_slice(const edge_user_vma_t *v, uint64_t off, uint64_t len) {
    uint64_t left;
    if (!v || !v->file_backed || off >= v->file_len) return 0;
    left = v->file_len - off;
    return left < len ? left : len;
}

static int user_vma_record_from_source(task_t *t, const edge_user_vma_t *v,
                                       uint64_t src_start, uint64_t len,
                                       uint64_t dst_start) {
    uint64_t off;
    const char *path = 0;
    if (!t || !v || len == 0) return -1;
    if (src_start < v->start || src_start + len > v->end ||
        src_start + len < src_start || dst_start + len < dst_start) {
        return -1;
    }
    off = src_start - v->start;
    if (v->file_backed) path = user_mmap_file_path(v->file_slot);
    return user_vma_record_ex_slot(t, dst_start, dst_start + len, v->prot, v->flags,
                                   path, v->file_off + off,
                                   user_vma_file_len_slice(v, off, len),
                                   v->fork_policy,
                                   v->file_backed ? v->file_slot : -1);
}

static int user_vma_clone_range(task_t *t, uint64_t src_start, uint64_t dst_start, uint64_t len) {
    uint64_t pos;
    if (!t || len == 0 || src_start + len < src_start || dst_start + len < dst_start) return -1;
    pos = src_start;
    while (pos < src_start + len) {
        edge_user_vma_t *v = user_vma_find_at(t, pos);
        uint64_t seg_end;
        uint64_t seg_len;
        uint64_t dst_seg;
        if (!v) return -1;
        seg_end = v->end < src_start + len ? v->end : src_start + len;
        if (seg_end <= pos) return -1;
        seg_len = seg_end - pos;
        dst_seg = dst_start + (pos - src_start);
        if (user_vma_record_from_source(t, v, pos, seg_len, dst_seg) < 0) return -1;
        pos = seg_end;
    }
    return 0;
}

static int user_vma_record_mremap_tail(task_t *t, uint64_t old_end,
                                       uint64_t dst_start, uint64_t len) {
    edge_user_vma_t *v;
    const char *path = 0;
    uint64_t file_off = 0;
    if (!t || len == 0 || old_end == 0) return -1;
    v = user_vma_find_at(t, old_end - 1);
    if (!v) return -1;
    if (v->file_backed) {
        path = user_mmap_file_path(v->file_slot);
        file_off = v->file_off + (old_end - v->start);
    }
    return user_vma_record_ex_slot(t, dst_start, dst_start + len, v->prot, v->flags,
                                   path, file_off, v->file_backed ? len : 0,
                                   v->fork_policy,
                                   v->file_backed ? v->file_slot : -1);
}

static int64_t arch_mm_remap_range_locked(
    uint64_t old_addr_u, uint64_t old_size_u,
    uint64_t new_size_u, uint32_t flags,
    uint64_t new_addr_u) {
    uint64_t old_addr = old_addr_u;
    uint64_t old_size = old_size_u;
    uint64_t new_size = new_size_u;
    uint64_t old_end;
    uint64_t new_end;
    uint64_t base = 0;
    task_t *cur = process_current_task();
    task_t *mm = 0;

    old_end = old_addr + old_size;
    new_end = old_addr + new_size;
    if (old_end < old_addr || new_end < old_addr) return (uint64_t)-EINVAL;
    if (!cur) return (uint64_t)-EINVAL;
    mm = process_vm_task(cur);
    if (!mm) return (uint64_t)-EINVAL;
    if (!process_user_mmap_range_ok(old_addr, old_size)) return (uint64_t)-EFAULT;
    if (!user_vma_range_covered(mm, old_addr, old_end)) return (uint64_t)-EFAULT;

    if (!(flags & KERNEL_MM_REMAP_FIXED) && new_size <= old_size) {
        if (new_size < old_size) {
            user_mmap_trace_op(cur, "mremap-shrink", old_addr, old_size, new_size, flags, old_addr, 0);
            if (user_vma_remove_range(mm, old_addr + new_size, old_end) < 0) return (uint64_t)-ENOMEM;
            process_user_mmap_unmap(mm, old_addr + new_size, old_size - new_size);
        }
        if (new_size == old_size) user_mmap_trace_op(cur, "mremap-same", old_addr, old_size, new_size, flags, old_addr, 0);
        return old_addr;
    }

    if (!(flags & KERNEL_MM_REMAP_FIXED) &&
        !user_vma_range_overlaps(mm, old_end, new_end) &&
        process_user_mmap_range_ok(old_addr, new_size)) {
        user_mmap_trace_op(cur, "mremap-grow", old_addr, old_size, new_size, flags, old_addr, 0);
        if (user_vma_record_mremap_tail(mm, old_end, old_end, new_size - old_size) < 0) {
            (void)user_vma_remove_range(mm, old_end, new_end);
            return (uint64_t)-ENOMEM;
        }
        if (user_vma_populate_shared_anon_range(
                mm, old_end, new_size - old_size) < 0) {
            (void)user_vma_remove_range(mm, old_end, new_end);
            process_user_mmap_unmap(mm, old_end, new_size - old_size);
            return (uint64_t)-ENOMEM;
        }
        return old_addr;
    }

    if ((flags & KERNEL_MM_REMAP_MAYMOVE) == 0) return (uint64_t)-ENOMEM;

    if (flags & KERNEL_MM_REMAP_FIXED) {
        base = new_addr_u;
        if (!process_user_mmap_range_ok(base, new_size)) return (uint64_t)-ENOMEM;
        if (base < old_end && base + new_size > old_addr) return (uint64_t)-EINVAL;
        int remove_rc = user_vma_remove_range(mm, base, base + new_size);
        if (remove_rc < 0) return (uint64_t)-ENOMEM;
        if (remove_rc > 0) {
            process_user_mmap_unmap(mm, base, new_size);
        }
    } else {
        base = user_vma_find_hint_gap(mm, USER_MMAP_BASE_ADDR, USER_MMAP_LIMIT_ADDR, new_size, PAGE_SIZE);
        if (base == 0) {
            base = user_vma_find_topdown_gap(mm, USER_MMAP_BASE_ADDR, USER_MMAP_LIMIT_ADDR, new_size, PAGE_SIZE);
        }
        if (base == 0) return (uint64_t)-ENOMEM;
    }

    if (user_vma_clone_range(mm, old_addr, base, old_size) < 0) {
        (void)user_vma_remove_range(mm, base, base + new_size);
        process_user_mmap_unmap(mm, base, new_size);
        return (uint64_t)-ENOMEM;
    }
    if (new_size > old_size) {
        if (user_vma_record_mremap_tail(mm, old_end, base + old_size, new_size - old_size) < 0) {
            (void)user_vma_remove_range(mm, base, base + new_size);
            process_user_mmap_unmap(mm, base, new_size);
            return (uint64_t)-ENOMEM;
        }
        if (user_vma_populate_shared_anon_range(
                mm, base + old_size, new_size - old_size) < 0) {
            (void)user_vma_remove_range(mm, base, base + new_size);
            process_user_mmap_unmap(mm, base, new_size);
            return (uint64_t)-ENOMEM;
        }
    }
    if (process_user_mmap_move_present(mm, old_addr, base, old_size) < 0) {
        (void)user_vma_remove_range(mm, base, base + new_size);
        process_user_mmap_unmap(mm, base, new_size);
        return (uint64_t)-ENOMEM;
    }
    if (user_vma_remove_range(mm, old_addr, old_end) < 0) return (uint64_t)-ENOMEM;
    process_user_mmap_unmap(mm, old_addr, old_size);
    user_mmap_trace_op(cur, "mremap-move", old_addr, old_size, new_size, flags, base, 0);
    if (base >= USER_MMAP_BASE_ADDR && base < USER_MMAP_LIMIT_ADDR && base < mm->user_mmap_next) {
        mm->user_mmap_next = base;
    }
    return base;
}

int64_t arch_mm_remap_range(uint64_t old_addr_u, uint64_t old_size_u,
                            uint64_t new_size_u, uint32_t flags,
                            uint64_t new_addr_u) {
    task_t *current = process_current_task();
    task_t *memory = current ? process_vm_task(current) : 0;
    int64_t result;

    if (!memory) return -EINVAL;
    process_user_vma_mutation_lock(memory);
    result = arch_mm_remap_range_locked(
        old_addr_u, old_size_u, new_size_u, flags, new_addr_u);
    process_user_vma_mutation_unlock(memory);
    return result;
}

static int64_t futex_wait_block(edge_futex_waiter_t *waiter,
                                task_t *current) {
    uint64_t flags;
    for (;;) {
        if (waiter->deadline_us &&
            boottime_monotonic_us() >= waiter->deadline_us) {
            flags = spin_lock_irqsave(&g_futex_lock);
            futex_waiter_clear(waiter);
            spin_unlock_irqrestore(&g_futex_lock, flags);
            current->futex_timeout_count++;
            current->last_futex_result = -ETIMEDOUT;
            return -ETIMEDOUT;
        }
        if (signal_pending_interrupt()) {
            flags = spin_lock_irqsave(&g_futex_lock);
            futex_waiter_clear(waiter);
            spin_unlock_irqrestore(&g_futex_lock, flags);
            current->futex_intr_count++;
            current->last_futex_result = -EINTR;
            return -EINTR;
        }
        flags = spin_lock_irqsave(&g_futex_lock);
        if (!waiter->waiting) {
            int result = waiter->result;
            current->futex_woken_count++;
            futex_waiter_clear(waiter);
            spin_unlock_irqrestore(&g_futex_lock, flags);
            current->last_futex_result = result;
            return result;
        }
        spin_unlock_irqrestore(&g_futex_lock, flags);

        current->sleep_deadline_us = waiter->deadline_us;
        current->sleep_wait_active = waiter->deadline_us != 0;
        current->futex_block_count++;
        scheduler_task_set_blocked(current);

        /* Close the wake-before-block transition without losing a wakeup. */
        flags = spin_lock_irqsave(&g_futex_lock);
        if (!waiter->waiting) {
            int result = waiter->result;
            current->futex_woken_count++;
            current->futex_missed_wake_count++;
            current->sleep_wait_active = 0;
            current->sleep_deadline_us = 0;
            scheduler_task_set_running(current);
            futex_waiter_clear(waiter);
            spin_unlock_irqrestore(&g_futex_lock, flags);
            current->last_futex_result = result;
            return result;
        }
        spin_unlock_irqrestore(&g_futex_lock, flags);
        scheduler_yield();
        current = process_current_task();
        if (!current) return -EINTR;
        current->futex_block_return_count++;
        current->sleep_wait_active = 0;
        current->sleep_deadline_us = 0;
    }
}

static int64_t futex_wait_execute(const kernel_futex_request_t *request,
                                  task_t *current) {
    edge_futex_waiter_t *waiter;
    uint64_t key_address;
    int private_key;
    uint32_t observed;
    uint64_t flags;
    int status;

    status = futex_key_for_task(
        current, request->address, request->private_futex,
        &key_address, &private_key);
    if (status < 0) return status;

    flags = spin_lock_irqsave(&g_futex_lock);
    if (copy_from_user(&observed, request->address,
                       sizeof(observed)) < 0) {
        spin_unlock_irqrestore(&g_futex_lock, flags);
        return -EFAULT;
    }
    current->last_futex_wait_observed = (int32_t)observed;
    if (observed != request->expected_value) {
        spin_unlock_irqrestore(&g_futex_lock, flags);
        current->last_futex_result = -EAGAIN;
        return -EAGAIN;
    }
    waiter = futex_waiter_alloc_slot_for_pid(current->pid);
    if (!waiter) {
        spin_unlock_irqrestore(&g_futex_lock, flags);
        current->last_futex_result = -EAGAIN;
        return -EAGAIN;
    }
    futex_waiter_clear(waiter);
    waiter->used = 1;
    waiter->waiting = 1;
    waiter->pid = current->pid;
    waiter->private_key = private_key;
    waiter->uaddr = key_address;
    waiter->bitset = request->bitset;
    waiter->deadline_us = request->has_timeout ? request->deadline_us : 0;
    current->futex_wait_count++;
    current->last_futex_wait_uaddr = request->address;
    current->last_futex_wait_expected = (int32_t)request->expected_value;
    current->last_futex_bitset = request->bitset;
    current->last_futex_deadline_us = waiter->deadline_us;
    spin_unlock_irqrestore(&g_futex_lock, flags);
    return futex_wait_block(waiter, current);
}

static int64_t futex_wait_vector_execute(
    const kernel_futex_request_t *request, task_t *current) {
    edge_futex_waiter_t *waiter;
    uint64_t flags;

    flags = spin_lock_irqsave(&g_futex_lock);
    waiter = futex_waiter_alloc_slot_for_pid(current->pid);
    if (!waiter) {
        spin_unlock_irqrestore(&g_futex_lock, flags);
        return -EAGAIN;
    }
    futex_waiter_clear(waiter);
    for (uint32_t index = 0; index < request->waiter_count; ++index) {
        uint32_t observed;
        int status = futex_key_for_task(
            current, request->waiters[index].address,
            request->waiters[index].private_futex,
            &waiter->waitv_keys[index].uaddr,
            &waiter->waitv_keys[index].private_key);
        if (status < 0 || copy_from_user(
                &observed, request->waiters[index].address,
                sizeof(observed)) < 0) {
            futex_waiter_clear(waiter);
            spin_unlock_irqrestore(&g_futex_lock, flags);
            return -EFAULT;
        }
        if (observed != request->waiters[index].expected_value) {
            futex_waiter_clear(waiter);
            spin_unlock_irqrestore(&g_futex_lock, flags);
            return -EAGAIN;
        }
    }
    waiter->used = 1;
    waiter->waiting = 1;
    waiter->pid = current->pid;
    waiter->bitset = UINT32_MAX;
    waiter->deadline_us = request->has_timeout ? request->deadline_us : 0;
    waiter->waitv_count = request->waiter_count;
    current->futex_wait_count++;
    current->last_futex_wait_uaddr = request->waiters[0].address;
    current->last_futex_wait_expected =
        (int32_t)request->waiters[0].expected_value;
    current->last_futex_bitset = UINT32_MAX;
    current->last_futex_deadline_us = waiter->deadline_us;
    spin_unlock_irqrestore(&g_futex_lock, flags);
    return futex_wait_block(waiter, current);
}

static int x86_futex_resolve_key(
    void *context, uint64_t address, int private_futex,
    kernel_futex_key_t *key) {
    task_t *current = process_current_task();
    uint64_t value;
    int private_key;
    int status;
    (void)context;
    if (!key || !current) return -EINVAL;
    status = futex_key_for_task(
        current, address, private_futex, &value, &private_key);
    if (status < 0) return status;
    key->value = value;
    key->scope = (uintptr_t)(uint32_t)private_key;
    return 0;
}

static int64_t x86_futex_wait(
    void *context, const kernel_futex_request_t *request) {
    task_t *current = process_current_task();
    (void)context;
    return current ? futex_wait_execute(request, current) : -EINVAL;
}

static int64_t x86_futex_wait_vector(
    void *context, const kernel_futex_request_t *request) {
    task_t *current = process_current_task();
    (void)context;
    return current ? futex_wait_vector_execute(request, current) : -EINVAL;
}

static uintptr_t x86_futex_lock(void *context) {
    (void)context;
    return (uintptr_t)spin_lock_irqsave(&g_futex_lock);
}

static void x86_futex_unlock(void *context, uintptr_t lock_state) {
    (void)context;
    spin_unlock_irqrestore(&g_futex_lock, (uint64_t)lock_state);
}

static int x86_futex_read_word_locked(
    void *context, uint64_t address, uint32_t *value) {
    (void)context;
    if (!value || copy_from_user(value, address, sizeof(*value)) < 0)
        return -EFAULT;
    return 0;
}

static int x86_futex_compare_exchange_word_locked(
    void *context, uint64_t address, uint32_t *expected,
    uint32_t desired) {
    uint32_t observed;
    int exchanged;

    (void)context;
    if (!expected || (address & 3u) != 0u ||
        !user_access_ok(address, sizeof(uint32_t), 1))
        return -EFAULT;
    observed = *expected;
    exchanged = __atomic_compare_exchange_n(
        (volatile uint32_t *)(uintptr_t)address, &observed, desired, 0,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    *expected = observed;
    return exchanged ? 0 : 1;
}

static int x86_futex_wake_locked(
    void *context, const kernel_futex_key_t *key,
    uint32_t maximum, uint32_t bitset) {
    (void)context;
    if (!key) return -EINVAL;
    return futex_waiter_wake_matching_locked(
        key->value, (int)(uint32_t)key->scope,
        maximum, bitset, 0);
}

static int x86_futex_requeue_locked(
    void *context, const kernel_futex_key_t *source,
    const kernel_futex_key_t *destination,
    uint32_t maximum, uint32_t bitset) {
    (void)context;
    if (!source || !destination) return -EINVAL;
    return futex_waiter_requeue_matching_locked(
        source->value, (int)(uint32_t)source->scope,
        destination->value, (int)(uint32_t)destination->scope,
        maximum, bitset);
}

static int x86_futex_requeue_tid_locked(
    void *context, const kernel_futex_key_t *source,
    const kernel_futex_key_t *destination, int32_t tid) {
    edge_futex_waiter_t *waiter = futex_waiter_find_slot_by_pid(tid);
    (void)context;
    if (!source || !destination || !waiter || !waiter->used ||
        !waiter->waiting || waiter->waitv_count ||
        waiter->uaddr != source->value ||
        waiter->private_key != (int)(uint32_t)source->scope)
        return 0;
    waiter->uaddr = destination->value;
    waiter->private_key = (int)(uint32_t)destination->scope;
    return 1;
}

static int32_t x86_futex_current_tid(void *context) {
    task_t *current = process_current_task();
    (void)context;
    return current ? current->pid : 0;
}

static int x86_futex_waiter_precedes_locked(
    void *context, int32_t candidate_tid, int32_t current_tid) {
    task_t *candidate =
        (task_t *)(uintptr_t)process_get_task(candidate_tid);
    task_t *current =
        (task_t *)(uintptr_t)process_get_task(current_tid);
    (void)context;
    if (!candidate) return -1;
    if (!current) return 1;
    return edge_linux_scheduler_state_compare(
        &candidate->scheduler, &current->scheduler);
}

static int x86_futex_prepare_pi_wait_locked(
    void *context, const kernel_futex_request_t *request,
    const kernel_futex_key_t *key) {
    task_t *current = process_current_task();
    edge_futex_waiter_t *waiter;
    (void)context;
    if (!current || !request || !key) return -EINVAL;
    waiter = futex_waiter_alloc_slot_for_pid(current->pid);
    if (!waiter) return -EAGAIN;
    futex_waiter_clear(waiter);
    waiter->used = 1;
    waiter->waiting = 1;
    waiter->pid = current->pid;
    waiter->private_key = (int)(uint32_t)key->scope;
    waiter->uaddr = key->value;
    waiter->bitset = UINT32_MAX;
    waiter->deadline_us = request->has_timeout ?
        request->deadline_us : 0u;
    current->futex_wait_count++;
    current->last_futex_wait_uaddr = request->address;
    current->last_futex_deadline_us = waiter->deadline_us;
    return 0;
}

static int64_t x86_futex_block_pi_wait(
    void *context, const kernel_futex_request_t *request) {
    task_t *current = process_current_task();
    edge_futex_waiter_t *waiter;
    (void)context;
    (void)request;
    if (!current) return -ESRCH;
    waiter = futex_waiter_find_slot_by_pid(current->pid);
    if (!waiter) return -EAGAIN;
    return futex_wait_block(waiter, current);
}

static int x86_futex_wake_tid_locked(
    void *context, const kernel_futex_key_t *key,
    int32_t tid, int result) {
    edge_futex_waiter_t *waiter = futex_waiter_find_slot_by_pid(tid);
    task_t *task = (task_t *)(uintptr_t)process_get_task(tid);
    (void)context;
    if (!key || !waiter || !waiter->used || !waiter->waiting ||
        waiter->uaddr != key->value ||
        waiter->private_key != (int)(uint32_t)key->scope)
        return -ESRCH;
    waiter->waiting = 0;
    waiter->result = result;
    if (task && task->state == TASK_BLOCKED)
        scheduler_task_make_runnable(task, scheduler_cpu_id());
    return 0;
}

static int x86_futex_waiter_active_locked(
    void *context, const kernel_futex_key_t *key, int32_t tid) {
    edge_futex_waiter_t *waiter = futex_waiter_find_slot_by_pid(tid);
    (void)context;
    return key && waiter && waiter->used && waiter->waiting &&
           waiter->uaddr == key->value &&
           waiter->private_key == (int)(uint32_t)key->scope;
}

static int x86_futex_task_exists_locked(void *context, int32_t tid) {
    task_t *task = (task_t *)(uintptr_t)process_get_task(tid);
    (void)context;
    return task && task->state != TASK_UNUSED &&
           task->state != TASK_ZOMBIE;
}

static void x86_futex_recompute_pi_owner_locked(
    void *context, int32_t owner_tid, int32_t donor_tid) {
    task_t *owner = (task_t *)(uintptr_t)process_get_task(owner_tid);
    task_t *donor = donor_tid > 0 ?
        (task_t *)(uintptr_t)process_get_task(donor_tid) : 0;
    uint64_t affinity;
    (void)context;
    if (!owner) return;
    if (!owner->futex_pi_boosted) {
        if (!donor) return;
        owner->futex_pi_base_scheduler = owner->scheduler;
        owner->futex_pi_boosted = 1u;
    }
    affinity = owner->futex_pi_base_scheduler.affinity_mask;
    owner->scheduler = owner->futex_pi_base_scheduler;
    if (donor && edge_linux_scheduler_state_compare(
            &donor->scheduler, &owner->scheduler) > 0) {
        owner->scheduler = donor->scheduler;
        owner->scheduler.affinity_mask = affinity;
    }
    if (!donor) owner->futex_pi_boosted = 0u;
}

static void x86_futex_record_request(
    void *context, const kernel_futex_request_t *request) {
    task_t *current = process_current_task();
    (void)context;
    if (!current || !request) return;
    current->last_futex_op = request->raw_operation;
    current->last_futex_result = 0;
    if (request->operation != KERNEL_FUTEX_WAKE) return;
    current->futex_wake_count++;
    current->last_futex_wake_uaddr = request->address;
    current->last_futex_wake_requested = request->wake_count;
    current->last_futex_bitset = request->bitset;
}

static void x86_futex_record_result(
    void *context, const kernel_futex_request_t *request,
    int64_t result) {
    task_t *current = process_current_task();
    (void)context;
    if (!current || !request ||
        request->operation != KERNEL_FUTEX_WAKE)
        return;
    current->last_futex_wake_matched = (int)result;
}

static const kernel_futex_backend_ops_t x86_futex_backend_ops = {
    .resolve_key = x86_futex_resolve_key,
    .wait = x86_futex_wait,
    .wait_vector = x86_futex_wait_vector,
    .lock = x86_futex_lock,
    .unlock = x86_futex_unlock,
    .read_word_locked = x86_futex_read_word_locked,
    .compare_exchange_word_locked =
        x86_futex_compare_exchange_word_locked,
    .wake_locked = x86_futex_wake_locked,
    .requeue_locked = x86_futex_requeue_locked,
    .requeue_tid_locked = x86_futex_requeue_tid_locked,
    .current_tid = x86_futex_current_tid,
    .waiter_precedes_locked = x86_futex_waiter_precedes_locked,
    .prepare_pi_wait_locked = x86_futex_prepare_pi_wait_locked,
    .block_pi_wait = x86_futex_block_pi_wait,
    .wake_tid_locked = x86_futex_wake_tid_locked,
    .waiter_active_locked = x86_futex_waiter_active_locked,
    .task_exists_locked = x86_futex_task_exists_locked,
    .recompute_pi_owner_locked = x86_futex_recompute_pi_owner_locked,
    .record_request = x86_futex_record_request,
    .record_result = x86_futex_record_result,
};

static int signal_delivery_diag_task(const task_t *t, uint64_t sig);

int edge_process_runtime_signal_state(
    void *task_context, kernel_signal_runtime_state_t *state) {
    task_t *task = task_context ? (task_t *)task_context :
                                  process_current_task();
    return task_signal_runtime_state(task, state);
}

int64_t kernel_arch_signal_wait_block(
    kernel_signal_wait_operation_t operation, uint64_t selected_mask,
    uint64_t information_user, uint64_t deadline_us,
    void *user_registers) {
    task_t *t = process_current_task();
    int has_timeout = deadline_us != UINT64_MAX;
    (void)information_user;
    (void)user_registers;
    if (!t) return -EINVAL;
    if (operation != KERNEL_SIGNAL_WAIT_TIMED &&
        operation != KERNEL_SIGNAL_WAIT_SUSPEND) {
        return -EINVAL;
    }
    task_timer_poll();
    {
        kernel_signal_runtime_state_t state;
        if (task_signal_runtime_state(t, &state) < 0) return -EINVAL;
        if (operation == KERNEL_SIGNAL_WAIT_SUSPEND &&
            kernel_signal_pending_has_wake(&state, *state.blocked_mask))
            return 0;
        if (operation == KERNEL_SIGNAL_WAIT_TIMED &&
            (kernel_signal_pending_next(&state, selected_mask) ||
             kernel_signal_pending_has_wake(&state, *state.blocked_mask)))
            return 0;
    }
    if (operation == KERNEL_SIGNAL_WAIT_TIMED && has_timeout) {
        if (boottime_monotonic_us() >= deadline_us) return 0;
        t->sleep_deadline_us = deadline_us;
        t->sleep_wait_active = 1;
    }
    scheduler_task_set_blocked(t);
    scheduler_yield();
    t = process_current_task();
    if (!t) return -EINTR;
    if (operation == KERNEL_SIGNAL_WAIT_TIMED && has_timeout) {
        t->sleep_wait_active = 0;
        t->sleep_deadline_us = 0;
    }
    return 0;
}

static int x86_itimer_current_thread_group(
    void *context, int32_t *tgid) {
    task_t *task = process_current_task();
    (void)context;
    if (!task || !tgid) return -ESRCH;
    *tgid = task->tgid > 0 ? task->tgid : task->pid;
    return 0;
}

static int x86_itimer_send_signal(
    void *context, int32_t tgid, uint32_t signal) {
    (void)context;
    return process_send_signal(tgid, (int)signal);
}

static const kernel_itimer_backend_ops_t x86_itimer_backend_ops = {
    .current_thread_group = x86_itimer_current_thread_group,
    .send_signal = x86_itimer_send_signal,
};

static int x86_64_user_on_sigaltstack(const task_t *t, uint64_t rsp) {
    return t && kernel_signal_altstack_contains(
        t->sigaltstack_sp, t->sigaltstack_size,
        t->sigaltstack_flags, rsp);
}

int kernel_arch_signal_user_stack_pointer(
    void *user_registers, uint64_t *stack_pointer) {
    REGISTERS *registers = (REGISTERS *)user_registers;
    if (!registers || !stack_pointer) return -EINVAL;
    *stack_pointer = registers->rsp;
    return 0;
}

static uint32_t x86_64_saved_sigaltstack_flags(const task_t *t, uint64_t rsp) {
    uint32_t flags;
    if (!t || (t->sigaltstack_flags & EDGE_LINUX_SS_DISABLE) != 0)
        return EDGE_LINUX_SS_DISABLE;
    flags = t->sigaltstack_flags & EDGE_LINUX_SS_AUTODISARM;
    if (x86_64_user_on_sigaltstack(t, rsp))
        flags |= EDGE_LINUX_SS_ONSTACK;
    return flags;
}

static void x86_64_fxsave_user_signal(void *state) {
    __asm__ __volatile__("fxsave (%0)" :: "r"(state) : "memory");
}

static void x86_64_fxrstor_user_signal(const void *state) {
    __asm__ __volatile__("fxrstor (%0)" :: "r"(state) : "memory");
}

static uint32_t x86_64_supported_mxcsr_mask(void) {
    static uint32_t supported_mask;
    uint8_t state[EDGE_X86_64_FPSTATE_SIZE] __attribute__((aligned(16)));

    if (supported_mask) return supported_mask;
    x86_64_fxsave_user_signal(state);
    memcpy(&supported_mask, state + 28, sizeof(supported_mask));
    /* Pre-SSE2 CPUs may report zero even though the architectural base mask
     * remains valid.  Linux uses the same architectural fallback. */
    if (!supported_mask) supported_mask = 0x0000ffbfu;
    return supported_mask;
}

static int x86_64_fxstate_valid(const uint8_t state[EDGE_X86_64_FPSTATE_SIZE],
                                uint32_t *mxcsr_out,
                                uint32_t *supported_mask_out) {
    uint32_t mxcsr;
    uint32_t supported_mask = x86_64_supported_mxcsr_mask();

    memcpy(&mxcsr, state + 24, sizeof(mxcsr));
    if (mxcsr_out) *mxcsr_out = mxcsr;
    if (supported_mask_out) *supported_mask_out = supported_mask;
    /* FXRSTOR raises #GP only for bits outside the processor's MXCSR_MASK.
     * A fixed 0xffbf mask incorrectly rejects DAZ on CPUs that advertise it. */
    return (mxcsr & ~supported_mask) == 0;
}

static void x86_64_sigcontext_from_regs(edge_x86_64_linux_sigcontext_t *sc,
                                        const REGISTERS *r,
                                        uint64_t fpstate_u,
                                        uint64_t oldmask) {
    uint64_t cr2 = 0;
    memset(sc, 0, sizeof(*sc));
    sc->r8 = r->r8;
    sc->r9 = r->r9;
    sc->r10 = r->r10;
    sc->r11 = r->r11;
    sc->r12 = r->r12;
    sc->r13 = r->r13;
    sc->r14 = r->r14;
    sc->r15 = r->r15;
    sc->rdi = r->rdi;
    sc->rsi = r->rsi;
    sc->rbp = r->rbp;
    sc->rbx = r->rbx;
    sc->rdx = r->rdx;
    sc->rax = r->rax;
    sc->rcx = r->rcx;
    sc->rsp = r->rsp;
    sc->rip = r->rip;
    sc->rflags = r->rflags;
    sc->cs = (uint16_t)r->cs;
    sc->ss = (uint16_t)r->ss;
    sc->err = r->err_code;
    sc->trapno = r->int_no;
    sc->oldmask = oldmask;
    if (r->int_no == 14) __asm__ __volatile__("mov %%cr2, %0" : "=r"(cr2));
    sc->cr2 = cr2;
    sc->fpstate = fpstate_u;
}

static int x86_64_regs_from_sigcontext(REGISTERS *r,
                                       const edge_x86_64_linux_sigcontext_t *sc) {
    const uint64_t user_rflags = 0x0000000000050dd5ULL;
    if (!r || !sc || !user_range_ok(sc->rip, 1) || !user_range_ok(sc->rsp, 1)) {
        return -EFAULT;
    }
    r->r8 = sc->r8;
    r->r9 = sc->r9;
    r->r10 = sc->r10;
    r->r11 = sc->r11;
    r->r12 = sc->r12;
    r->r13 = sc->r13;
    r->r14 = sc->r14;
    r->r15 = sc->r15;
    r->rdi = sc->rdi;
    r->rsi = sc->rsi;
    r->rbp = sc->rbp;
    r->rbx = sc->rbx;
    r->rdx = sc->rdx;
    r->rax = sc->rax;
    r->rcx = sc->rcx;
    r->rsp = sc->rsp;
    r->rip = sc->rip;
    r->rflags = (sc->rflags & user_rflags) | 0x202ULL;
    r->cs = USER_CS;
    r->ss = USER_DS;
    r->err_code = sc->err;
    r->int_no = sc->trapno;
    return 0;
}

static int signal_delivery_diag_task(const task_t *t, uint64_t sig) {
    if (!t) return 0;
    if (!linux_sig_is_rt(sig) && sig != LINUX_SIGIO && sig != LINUX_SIGCHLD) return 0;
    return gui_diag_task(t);
}

static int signal_trace_task(const task_t *t, uint64_t sig) {
    if (!t || !t->name[0]) return 0;
    if (sig != LINUX_SIGCHLD && sig != LINUX_SIGALRM &&
        sig != LINUX_SIGIO && !linux_sig_is_rt(sig)) return 0;
    return strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0;
}

static int install_user_sig_stub(task_t *t) {
    static const uint8_t code[] = {
        0x48, 0xC7, 0xC0, 0x0F, 0x00, 0x00, 0x00, /* mov $15,%rax */
        0x0F, 0x05                                      /* syscall */
    };
    if (!t) return -1;
    if (t->sig_stub_installed) return 0;
    if (copy_to_user(EDGE_SIGTRAMP_ADDR, code, sizeof(code)) < 0) return -1;
    t->sig_stub_installed = 1;
    return 0;
}

static int task_signal_info_peek(task_t *task, uint64_t signal,
                                 void *information) {
    kernel_signal_runtime_state_t state;
    return task_signal_runtime_state(task, &state) == 0 &&
        kernel_signal_pending_peek(
            &state, (uint32_t)signal, information);
}

static int task_signal_info_consume(task_t *task, uint64_t signal) {
    kernel_signal_runtime_state_t state;
    int same_signal_remains = 0;
    if (task_signal_runtime_state(task, &state) < 0) return 0;
    (void)kernel_signal_pending_consume(
        &state, (uint32_t)signal, 0, &same_signal_remains);
    return same_signal_remains;
}

static int maybe_deliver_signal_on_sysret(REGISTERS *r) {
    task_t *t = process_current_task();
    uint64_t blocked = 0;
    uint64_t handler = LINUX_SIG_DFL;
    uint64_t action_mask = 0;
    uint64_t action_flags = 0;
    uint64_t action_restorer = 0;
    uint64_t sig = 0;
    edge_linux_signal_action_t *action = 0;
    edge_linux_signal_default_disposition_t default_disposition;
    uint64_t old_rsp, stack_top, frame_u, fpstate_u;
    const uint64_t x86_64_redzone = 128;
    uint64_t restorer = EDGE_SIGTRAMP_ADDR;
    int entering_altstack = 0;
    edge_x86_64_linux_rt_sigframe_t frame;
    struct edge_linux_siginfo_min siginfo;
    struct edge_linux_siginfo_min queued_siginfo;
    struct edge_linux_siginfo_sigsys sigsys_info;
    int queued_siginfo_valid;
    uint8_t fpstate_frame[EDGE_X86_64_FPSTATE_FRAME_SIZE]
        __attribute__((aligned(64)));
    static int gui_signal_diag_budget = EDGE_GUI_DEEP_TRACE ? 16 : 0;
    static int gui_signal_fail_budget =
        EDGE_GUI_DEEP_TRACE ? 16 : 0;
    static int signal_trace_budget = EDGE_GUI_DEEP_TRACE ? 128 : 0;

    if (!t || !r) return 0;
    task_timer_poll();
select_signal:
    blocked = t->sigmask;

    sig = (uint64_t)task_next_unblocked_signal(t, blocked);
    if (!sig) return 0;
    if (t->ptrace.tracer_pid > 0 && sig != LINUX_SIGKILL) {
        if (t->ptrace.suppress_signal_stop &&
            t->ptrace.injected_signal == sig) {
            t->ptrace.suppress_signal_stop = 0;
            t->ptrace.injected_signal = 0;
        } else {
            t->ptrace.suppress_signal_stop = 0;
            t->ptrace.injected_signal = 0;
            if (edge_linux_ptrace_signal_stop(r, (uint32_t)sig))
                goto select_signal;
        }
    }
    action = task_signal_action_local(t, (uint32_t)sig);
    if (!action) return 0;
    handler = action->handler;
    action_mask = action->mask;
    action_flags = action->flags;
    action_restorer = action->restorer;
    default_disposition =
        edge_linux_signal_default_disposition((uint32_t)sig);

    memset(&queued_siginfo, 0, sizeof(queued_siginfo));
    queued_siginfo_valid = task_signal_info_peek(
        t, sig, &queued_siginfo);

    if (x11_debug_task(t)) {
        printf("[x11dbg] signal-deliver pid=%d cmd=%s sig=%u handler=0x%x blocked=0x%x pending=0x%x rip=0x%x\n",
               t->pid, t->name, (unsigned)sig, (uint32_t)handler,
               (uint32_t)blocked, task_pending_signal_bits(t), (uint32_t)r->rip);
    }
    if (signal_trace_budget > 0 && signal_trace_task(t, sig)) {
        signal_trace_budget--;
        printf("[signal-trace] deliver-start pid=%d cmd=%s sig=%u handler=0x%x flags=0x%x restorer=0x%x blocked=0x%x pending=0x%x rip=0x%x rsp=0x%x budget=%d\n",
               t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
               (uint32_t)action_flags, (uint32_t)action_restorer,
               (uint32_t)blocked, task_pending_signal_bits(t),
               (uint32_t)r->rip, (uint32_t)r->rsp,
               signal_trace_budget);
    }
    if (gui_diag_task(t) && sig == LINUX_SIGALRM) {
        static int sigalrm_gui_budget = EDGE_GUI_DEEP_TRACE ? 32 : 0;
        if (sigalrm_gui_budget-- > 0) {
            printf("[sigalrm-abi] deliver pid=%d cmd=%s handler=0x%x flags=0x%x blocked=0x%x pending=0x%x rip=0x%x rsp=0x%x budget=%d\n",
                   t->pid, t->name, (uint32_t)handler, (uint32_t)action_flags,
                   (uint32_t)blocked, task_pending_signal_bits(t),
                   (uint32_t)r->rip, (uint32_t)r->rsp, sigalrm_gui_budget);
        }
    }
    if (g_dropbear_debug_armed && t &&
        (strcmp(t->name, "-sh") == 0 || strcmp(t->name, "sh") == 0 || strcmp(t->name, "busybox") == 0)) {
        printf("[sshdbg] signal-deliver pid=%d cmd=%s sig=%u handler=0x%x blocked=0x%x\n",
               t->pid, t->name, (unsigned)sig, (uint32_t)handler, (uint32_t)blocked);
    }
    if (handler == LINUX_SIG_IGN) {
        if (gui_signal_fail_budget > 0 && signal_delivery_diag_task(t, sig)) {
            gui_signal_fail_budget--;
            printf("[signal-gui] pid=%d cmd=%s sig=%u why=ignore handler=0x%x flags=0x%x blocked=0x%x pending=0x%x budget=%d\n",
                   t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
                   (uint32_t)action_flags, (uint32_t)blocked,
                   task_pending_signal_bits(t), gui_signal_fail_budget);
        }
        (void)task_signal_info_consume(t, sig);
        return 0;
    }
    if (handler == LINUX_SIG_DFL) {
        if (gui_signal_fail_budget > 0 && signal_delivery_diag_task(t, sig)) {
            gui_signal_fail_budget--;
            printf("[signal-gui] pid=%d cmd=%s sig=%u why=default handler=0x%x flags=0x%x blocked=0x%x pending=0x%x budget=%d\n",
                   t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
                   (uint32_t)action_flags, (uint32_t)blocked,
                   task_pending_signal_bits(t), gui_signal_fail_budget);
        }
        (void)task_signal_info_consume(t, sig);
        if (default_disposition == EDGE_LINUX_SIGNAL_DEFAULT_IGNORE ||
            default_disposition == EDGE_LINUX_SIGNAL_DEFAULT_CONTINUE)
            return 0;
        /* Linux protects init from signals whose disposition remains default. */
        if (t->pid == 1 || (t->tgid > 0 && t->tgid == 1)) return 0;
        if (default_disposition == EDGE_LINUX_SIGNAL_DEFAULT_STOP) {
            process_stop_current_group((int)sig);
            scheduler_yield();
            return 0;
        }
        t->termination_signal = (uint8_t)sig;
        fd_release_current_if_last_thread();
        scheduler_kill_current_group_and_yield(128 + (int)sig);
        return 0;
    }
    if (!user_range_ok(handler, 1)) {
        if (gui_signal_fail_budget > 0 && signal_delivery_diag_task(t, sig)) {
            gui_signal_fail_budget--;
            printf("[signal-gui] pid=%d cmd=%s sig=%u why=bad-handler handler=0x%x flags=0x%x restorer=0x%x blocked=0x%x pending=0x%x rip=0x%x rsp=0x%x budget=%d\n",
                   t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
                   (uint32_t)action_flags, (uint32_t)action_restorer,
                   (uint32_t)blocked, task_pending_signal_bits(t),
                   (uint32_t)r->rip, (uint32_t)r->rsp,
                   gui_signal_fail_budget);
        }
        return 0;
    }
    if ((action_flags & EDGE_LINUX_SA_RESTORER) &&
        user_range_ok(action_restorer, 1)) {
        restorer = action_restorer;
    } else if (install_user_sig_stub(t) < 0) {
        if (gui_signal_fail_budget > 0 && signal_delivery_diag_task(t, sig)) {
            gui_signal_fail_budget--;
            printf("[signal-gui] pid=%d cmd=%s sig=%u why=stub handler=0x%x flags=0x%x restorer=0x%x blocked=0x%x pending=0x%x budget=%d\n",
                   t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
                   (uint32_t)action_flags, (uint32_t)action_restorer,
                   (uint32_t)blocked, task_pending_signal_bits(t),
                   gui_signal_fail_budget);
        }
        return 0;
    }

    old_rsp = r->rsp;
    stack_top = old_rsp;
    /*
     * Linux removes the interrupted red zone on the normal stack.  Switching
     * to a fresh alternate stack starts at its top instead; nested delivery on
     * that stack again protects the interrupted handler's red zone.
     */
    if ((action_flags & EDGE_LINUX_SA_ONSTACK) &&
        (t->sigaltstack_flags & EDGE_LINUX_SS_DISABLE) == 0 &&
        t->sigaltstack_sp != 0 && t->sigaltstack_size >= LINUX_MINSIGSTKSZ &&
        !x86_64_user_on_sigaltstack(t, old_rsp)) {
        uint64_t alt_top = t->sigaltstack_sp + t->sigaltstack_size;
        if (alt_top > t->sigaltstack_sp &&
            user_range_ok(t->sigaltstack_sp, t->sigaltstack_size)) {
            stack_top = alt_top;
            entering_altstack = 1;
        }
    }
    if (!entering_altstack) {
        if (stack_top < USER_MIN_ADDR + x86_64_redzone) return 0;
        stack_top -= x86_64_redzone;
    }
    if (stack_top < USER_MIN_ADDR + EDGE_X86_64_FPSTATE_FRAME_SIZE +
                    sizeof(frame) + 64 ||
        stack_top > USER_MAX_ADDR) {
        if (gui_signal_fail_budget > 0 && signal_delivery_diag_task(t, sig)) {
            gui_signal_fail_budget--;
            printf("[signal-gui] pid=%d cmd=%s sig=%u why=bad-oldrsp handler=0x%x flags=0x%x oldrsp=0x%x blocked=0x%x pending=0x%x budget=%d\n",
                   t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
                   (uint32_t)action_flags, (uint32_t)old_rsp,
                   (uint32_t)blocked, task_pending_signal_bits(t),
                   gui_signal_fail_budget);
        }
        return 0;
    }

    fpstate_u = (stack_top - EDGE_X86_64_FPSTATE_FRAME_SIZE) &
                ~(EDGE_X86_64_FPSTATE_ALIGN - 1ULL);
    frame_u = ((fpstate_u - sizeof(frame)) & ~15ULL) - 8ULL;
    if (!user_range_ok(frame_u, sizeof(frame)) ||
        !user_range_ok(fpstate_u, EDGE_X86_64_FPSTATE_FRAME_SIZE) ||
        (frame_u & 15ULL) != 8ULL) {
        if (gui_signal_fail_budget > 0 && signal_delivery_diag_task(t, sig)) {
            gui_signal_fail_budget--;
            printf("[signal-gui] pid=%d cmd=%s sig=%u why=bad-frame-range handler=0x%x oldrsp=0x%x frame=0x%x fp=0x%x budget=%d\n",
                   t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
                   (uint32_t)old_rsp, (uint32_t)frame_u,
                   (uint32_t)fpstate_u, gui_signal_fail_budget);
        }
        return 0;
    }
    if ((entering_altstack || x86_64_user_on_sigaltstack(t, old_rsp)) &&
        frame_u < t->sigaltstack_sp) {
        if (gui_signal_fail_budget > 0 && signal_delivery_diag_task(t, sig)) {
            gui_signal_fail_budget--;
            printf("[signal-gui] pid=%d cmd=%s sig=%u why=altstack-overflow oldrsp=0x%x frame=0x%x alt=0x%x size=0x%x budget=%d\n",
                   t->pid, t->name, (uint32_t)sig, (uint32_t)old_rsp,
                   (uint32_t)frame_u, (uint32_t)t->sigaltstack_sp,
                   (uint32_t)t->sigaltstack_size, gui_signal_fail_budget);
        }
        return 0;
    }

    memset(&frame, 0, sizeof(frame));
    memset(&siginfo, 0, sizeof(siginfo));
    memset(&sigsys_info, 0, sizeof(sigsys_info));
    frame.pretcode = restorer;
    frame.ucontext.flags = EDGE_X86_64_UC_SIGCONTEXT_SS |
                           EDGE_X86_64_UC_STRICT_RESTORE_SS;
    frame.ucontext.stack.sp = t->sigaltstack_sp;
    frame.ucontext.stack.size = t->sigaltstack_size;
    frame.ucontext.stack.flags = (int32_t)x86_64_saved_sigaltstack_flags(t, old_rsp);
    frame.ucontext.sigmask = task_signal_frame_sigmask(t);
    x86_64_sigcontext_from_regs(&frame.ucontext.mcontext, r, fpstate_u,
                                frame.ucontext.sigmask);
    if (sig == LINUX_SIGSYS && t->seccomp_sigsys_valid) {
        /*
         * SECCOMP_RET_TRAP exposes the interrupted syscall register image.
         * The dispatcher has already staged -ENOSYS as the default return
         * value by the time signals are delivered, but x86-64 trap handlers
         * use RAX from ucontext to identify the syscall and reject a frame
         * whose RAX disagrees with si_syscall.  Restore the entry value in the
         * userspace frame; rt_sigreturn will use any value written by the
         * handler as the syscall result.
         */
        frame.ucontext.mcontext.rax =
            (uint64_t)(uint32_t)t->seccomp_sigsys_nr;
        sigsys_info.si_signo = LINUX_SIGSYS;
        sigsys_info.si_errno = t->seccomp_sigsys_errno;
        sigsys_info.si_code = 1; /* SYS_SECCOMP */
        sigsys_info.si_call_addr = t->seccomp_sigsys_call_addr;
        sigsys_info.si_syscall = t->seccomp_sigsys_nr;
        sigsys_info.si_arch = t->seccomp_sigsys_arch;
        memcpy(frame.siginfo, &sigsys_info, sizeof(sigsys_info));
    } else if (queued_siginfo_valid) {
        memcpy(frame.siginfo, &queued_siginfo, sizeof(queued_siginfo));
    } else {
        siginfo.si_signo = (int32_t)sig;
        siginfo.si_code = 0;
        siginfo.si_pid = 0;
        siginfo.si_uid = 0;
        memcpy(frame.siginfo, &siginfo, sizeof(siginfo));
    }
    /*
     * Linux reserves the complete extended-state signal area even when the
     * task currently uses only the legacy 512-byte FXSAVE image.  libc treats
     * the ucontext and the following state area as one copyable object, so a
     * 512-byte-only allocation can make a valid handler cross the end of a
     * small alternate stack.  Keep a zeroed compatibility tail while the
     * restore path continues to consume the architectural FXSAVE prefix.
     */
    memset(fpstate_frame, 0, sizeof(fpstate_frame));
    x86_64_fxsave_user_signal(fpstate_frame);
    if (copy_to_user(frame_u, &frame, sizeof(frame)) < 0 ||
        copy_to_user(fpstate_u, fpstate_frame, sizeof(fpstate_frame)) < 0) {
        if (gui_signal_fail_budget > 0 && signal_delivery_diag_task(t, sig)) {
            gui_signal_fail_budget--;
            printf("[signal-gui] pid=%d cmd=%s sig=%u why=copy-frame handler=0x%x frame=0x%x fp=0x%x budget=%d\n",
                   t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
                   (uint32_t)frame_u, (uint32_t)fpstate_u,
                   gui_signal_fail_budget);
        }
        return 0;
    }

    if (gui_signal_diag_budget > 0 && signal_delivery_diag_task(t, sig)) {
        gui_signal_diag_budget--;
        printf("[signal-gui] pid=%d cmd=%s sig=%u why=deliver handler=0x%x flags=0x%x restorer=0x%x oldrip=0x%x oldrsp=0x%x frame=0x%x pending=0x%x budget=%d\n",
               t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
               (uint32_t)action_flags, (uint32_t)restorer,
               (uint32_t)r->rip, (uint32_t)old_rsp,
               (uint32_t)frame_u, task_pending_signal_bits(t),
               gui_signal_diag_budget);
    }

    (void)task_signal_info_consume(t, sig);
    if (sig == LINUX_SIGSYS && t->seccomp_sigsys_valid)
        t->seccomp_sigsys_valid = 0;
    if (action_flags & EDGE_LINUX_SA_RESETHAND) {
        process_update_thread_group_signal_action(
            (int)sig, LINUX_SIG_DFL, 0, 0, 0);
    }
    t->active_signal_restorer_rsp = frame_u;
    t->active_signal_frame = frame_u;
    if (entering_altstack &&
        (t->sigaltstack_flags & EDGE_LINUX_SS_AUTODISARM)) {
        t->sigaltstack_sp = 0;
        t->sigaltstack_size = 0;
        t->sigaltstack_flags = EDGE_LINUX_SS_DISABLE;
    }
    if (signal_trace_budget > 0 && signal_trace_task(t, sig)) {
        signal_trace_budget--;
        printf("[signal-trace] installed pid=%d cmd=%s sig=%u handler=0x%x restorer=0x%x oldrip=0x%x oldrsp=0x%x newrsp=0x%x frame=0x%x mask=0x%x budget=%d\n",
               t->pid, t->name, (uint32_t)sig, (uint32_t)handler,
               (uint32_t)restorer, (uint32_t)r->rip,
               (uint32_t)old_rsp, (uint32_t)frame_u,
               (uint32_t)t->active_signal_frame, (uint32_t)t->sigmask,
               signal_trace_budget);
    }
    /*
     * Linux masks the currently delivered signal while its handler runs unless
     * SA_NODEFER is set.  Nested delivery remains correct because every signal
     * carries its complete restore state in its own userspace frame.
     */
    t->sigmask |= action_mask;
    if ((action_flags & EDGE_LINUX_SA_NODEFER) == 0)
        t->sigmask |= edge_linux_signal_mask_bit((uint32_t)sig);
    t->sigmask = edge_linux_signal_sanitize_mask(t->sigmask);
    r->rsp = frame_u;
    r->rip = handler;
    r->cs = USER_CS;
    r->ss = USER_DS;
    r->rflags = (r->rflags | 0x2ull) & ~(1ull << 8);
    r->rax = 0;
    r->rdi = sig;
    r->rsi = frame_u + (uint64_t)__builtin_offsetof(edge_x86_64_linux_rt_sigframe_t, siginfo);
    r->rdx = frame_u + (uint64_t)__builtin_offsetof(edge_x86_64_linux_rt_sigframe_t, ucontext);
    return 1;
}

int edgeos_x86_64_deliver_signal_on_user_return(REGISTERS *frame) {
    return maybe_deliver_signal_on_sysret(frame);
}

static uint64_t do_sys_arch_prctl(uint64_t code, uint64_t addr_u) {
    if (code == ARCH_SET_FS || code == ARCH_SET_GS) {
        if (addr_u >= EDGE_USER_MAX_ADDR) return (uint64_t)-EPERM;
        if (code == ARCH_SET_FS) {
            return process_set_fs_base(addr_u) == 0 ? 0 : (uint64_t)-EINVAL;
        }
        return process_set_gs_base(addr_u) == 0 ? 0 : (uint64_t)-EINVAL;
    }
    if (code == ARCH_GET_FS) {
        uint64_t fs = process_get_fs_base();
        if (!addr_u) return (uint64_t)-EFAULT;
        if (copy_to_user(addr_u, &fs, sizeof(fs)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if (code == ARCH_GET_GS) {
        uint64_t gs = process_get_gs_base();
        if (!addr_u) return (uint64_t)-EFAULT;
        if (copy_to_user(addr_u, &gs, sizeof(gs)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    return (uint64_t)-EINVAL;
}

struct edge_x86_user_desc {
    uint32_t entry_number;
    uint32_t base_addr;
    uint32_t limit;
    uint32_t flags;
};

#define EDGE_X86_USER_DESC_SEG_32BIT (1u << 0)
#define EDGE_X86_USER_DESC_CONTENTS_MASK (3u << 1)
#define EDGE_X86_USER_DESC_READ_EXEC_ONLY (1u << 3)
#define EDGE_X86_USER_DESC_LIMIT_IN_PAGES (1u << 4)
#define EDGE_X86_USER_DESC_SEG_NOT_PRESENT (1u << 5)
#define EDGE_X86_USER_DESC_USEABLE (1u << 6)
#define EDGE_X86_LDT_ENTRIES 8192u
#define EDGE_X86_LDT_BYTES (EDGE_X86_LDT_ENTRIES * 8u)

_Static_assert(sizeof(struct edge_x86_user_desc) == 16u,
               "Linux x86 user_desc layout");

static uint32_t edge_x86_user_desc_contents(
    const struct edge_x86_user_desc *description) {
    return (description->flags & EDGE_X86_USER_DESC_CONTENTS_MASK) >> 1;
}

static int edge_x86_user_desc_empty(
    const struct edge_x86_user_desc *description) {
    uint32_t expected = EDGE_X86_USER_DESC_READ_EXEC_ONLY |
                        EDGE_X86_USER_DESC_SEG_NOT_PRESENT;

    return description->base_addr == 0 && description->limit == 0 &&
           (description->flags & 0x7fu) == expected;
}

static uint64_t edge_x86_pack_ldt_descriptor(
    const struct edge_x86_user_desc *description, int old_mode) {
    uint64_t descriptor = 0;
    uint32_t contents = edge_x86_user_desc_contents(description);
    uint32_t type = ((description->flags &
                      EDGE_X86_USER_DESC_READ_EXEC_ONLY) ? 0u : 2u) |
                    (contents << 2) | 1u;

    descriptor |= description->limit & 0xffffu;
    descriptor |= ((uint64_t)description->base_addr & 0xffffu) << 16;
    descriptor |= ((uint64_t)(description->base_addr >> 16) & 0xffu) << 32;
    descriptor |= (uint64_t)type << 40;
    descriptor |= UINT64_C(1) << 44;
    descriptor |= UINT64_C(3) << 45;
    if (!(description->flags & EDGE_X86_USER_DESC_SEG_NOT_PRESENT))
        descriptor |= UINT64_C(1) << 47;
    descriptor |= ((uint64_t)(description->limit >> 16) & 0x0fu) << 48;
    if (!old_mode &&
        (description->flags & EDGE_X86_USER_DESC_USEABLE))
        descriptor |= UINT64_C(1) << 52;
    if (description->flags & EDGE_X86_USER_DESC_SEG_32BIT)
        descriptor |= UINT64_C(1) << 54;
    if (description->flags & EDGE_X86_USER_DESC_LIMIT_IN_PAGES)
        descriptor |= UINT64_C(1) << 55;
    descriptor |= ((uint64_t)(description->base_addr >> 24) & 0xffu) << 56;
    return descriptor;
}

static uint64_t edge_x86_modify_ldt_result(int32_t result) {
    /* Linux defines modify_ldt as an int-returning syscall on x86-64. */
    return (uint64_t)(uint32_t)result;
}

static uint64_t do_sys_modify_ldt(uint64_t function_u, uint64_t pointer_u,
                                  uint64_t byte_count_u) {
#ifndef CONFIG_MODIFY_LDT_SYSCALL
    (void)function_u;
    (void)pointer_u;
    (void)byte_count_u;
    return (uint64_t)(int64_t)-ENOSYS;
#else
    task_t *current = process_current_task();
    uint32_t function = (uint32_t)function_u;
    uint64_t byte_count = byte_count_u;

    if (!current || !current->scratch)
        return edge_x86_modify_ldt_result(-ESRCH);
    if (function == 0u) {
        int copied;

        if (byte_count > EDGE_X86_LDT_BYTES)
            byte_count = EDGE_X86_LDT_BYTES;
        copied = process_x86_ldt_snapshot(
            current, current->scratch->xattr_scratch,
            (uint32_t)byte_count);
        if (copied < 0) return edge_x86_modify_ldt_result(-EINVAL);
        if (!copied) return 0;
        if (!pointer_u || copy_to_user(
                pointer_u, current->scratch->xattr_scratch,
                (uint32_t)copied) < 0)
            return edge_x86_modify_ldt_result(-EFAULT);
        return (uint64_t)(uint32_t)copied;
    }
    if (function == 2u) {
        uint32_t copied = byte_count > 128u ? 128u : (uint32_t)byte_count;

        if (!copied) return 0;
        memset(current->scratch->xattr_scratch, 0, copied);
        if (!pointer_u || copy_to_user(
                pointer_u, current->scratch->xattr_scratch, copied) < 0)
            return edge_x86_modify_ldt_result(-EFAULT);
        return copied;
    }
    if (function == 1u || function == 0x11u) {
        struct edge_x86_user_desc description;
        uint64_t descriptor;
        uint32_t contents;
        int old_mode = function == 1u;

        if (byte_count != sizeof(description))
            return edge_x86_modify_ldt_result(-EINVAL);
        if (!pointer_u || copy_from_user(
                &description, pointer_u, sizeof(description)) < 0)
            return edge_x86_modify_ldt_result(-EFAULT);
        if (description.entry_number >= EDGE_X86_LDT_ENTRIES)
            return edge_x86_modify_ldt_result(-EINVAL);
        contents = edge_x86_user_desc_contents(&description);
        if (contents == 3u &&
            (old_mode || !(description.flags &
                           EDGE_X86_USER_DESC_SEG_NOT_PRESENT)))
            return edge_x86_modify_ldt_result(-EINVAL);
        if ((old_mode && !description.base_addr && !description.limit) ||
            edge_x86_user_desc_empty(&description)) {
            descriptor = 0;
        } else {
#ifndef CONFIG_X86_16BIT
            if (!(description.flags & EDGE_X86_USER_DESC_SEG_32BIT))
                return edge_x86_modify_ldt_result(-EINVAL);
#endif
            descriptor = edge_x86_pack_ldt_descriptor(
                &description, old_mode);
        }
        if (process_x86_ldt_write(
                current, description.entry_number, descriptor) < 0)
            return edge_x86_modify_ldt_result(-ENOMEM);
        return 0;
    }
    return edge_x86_modify_ldt_result(-ENOSYS);
#endif
}

static void syscall_trace(uint64_t nr, int64_t ret) {
    task_t *t = process_current_task();
    int pid = t ? t->pid : -1;
    const char *name = (t && t->name[0]) ? t->name : "?";
    if (!EDGE_SYSCALL_DEBUG) {
        return;
    }
    if (ret < 0) {
        printf("[syscall] pid=%d cmd=%s nr=%u ret=%d errno=%d\n",
               pid, name, (uint32_t)nr, (int32_t)ret, (int32_t)(-ret));
    } else {
        printf("[syscall] pid=%d cmd=%s nr=%u ret=%d\n",
               pid, name, (uint32_t)nr, (int32_t)ret);
    }
}

static void publish_vfs_inode(vfs_superblock_t *superblock,
                              const vfs_inode_t *inode) {
    if (!superblock || !inode) return;
    for (int process = 0; process < EDGE_MAX_FD_PROCS; ++process) {
        for (int descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
            edge_fd_proc_t *owner = g_fd_procs[process];
            edge_fd_t *entry;
            if (!owner) continue;
            entry = &owner->fds[descriptor];
            if (entry->kind == FD_VFS &&
                vfs_inode_same_object(entry->sb, &entry->inode,
                                      superblock, inode))
                entry->inode = *inode;
        }
    }
}

static void publish_memfd_truncate(int memory_id, uint64_t length) {
    for (int process = 0; process < EDGE_MAX_FD_PROCS; ++process) {
        for (int descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
            edge_fd_proc_t *owner = g_fd_procs[process];
            edge_fd_t *entry;
            if (!owner) continue;
            entry = &owner->fds[descriptor];
            if (entry->kind == FD_MEMFD && entry->pipe_id == memory_id)
                entry->inode.size = (uint32_t)length;
        }
    }
}

int arch_vfs_truncate_prepare(vfs_superblock_t *superblock,
                              const vfs_inode_t *inode,
                              uint32_t old_length, uint32_t new_length) {
    if (new_length < old_length &&
        edge_mmap_file_cache_sync_inode(superblock, inode, 1) < 0)
        return -EDGE_LINUX_EIO;
    return 0;
}

void arch_vfs_truncate_commit(vfs_superblock_t *superblock,
                              const vfs_inode_t *inode,
                              uint32_t old_length, uint32_t new_length) {
    (void)old_length;
    publish_vfs_inode(superblock, inode);
    edge_mmap_file_cache_resize(superblock, inode, new_length);
}

int arch_vfs_truncate_descriptor(int32_t descriptor, uint32_t length) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry;
    int result;
    if (!process) return -EDGE_LINUX_EBADF;
    entry = fd_get(process, descriptor);
    if (!entry) return -EDGE_LINUX_EBADF;
    if (entry->kind == FD_MEMFD) {
        edge_memfd_t *memory = memfd_get(entry->pipe_id);
        if (!memory) return -EDGE_LINUX_EBADF;
        if (memory->secret && memory->size)
            return -EDGE_LINUX_EINVAL;
        result = memfd_truncate(memory, length);
        if (result < 0) return result;
        publish_memfd_truncate(entry->pipe_id, length);
        return 0;
    }
    if (entry->kind != FD_VFS || !entry->sb)
        return -EDGE_LINUX_EINVAL;
    result = kernel_vfs_truncate_inode_transaction(
        entry->sb, &entry->inode, length);
    if (result < 0) return result;
    entry->dirty = 1;
    if (entry->path[0]) {
        edge_inotify_notify_path(entry->path, EDGE_IN_MODIFY, 0);
    }
    return 0;
}

static uint64_t do_sys_iopl(uint64_t level_u) {
    task_t *task;
    if (level_u > 3u) return (uint64_t)-EINVAL;
    if (level_u == 0u) return 0;
    task = process_current_task();
    if (!task) return (uint64_t)-ESRCH;
    if (!(task->capabilities.effective &
          (UINT64_C(1) << EDGE_LINUX_CAP_SYS_RAWIO)))
        return (uint64_t)-EPERM;
    return 0;
}

static uint64_t do_sys_ioperm(uint64_t from_u, uint64_t num_u, uint64_t turn_on_u) {
    task_t *task;
    (void)turn_on_u;
    if (from_u > UINT64_C(65536) ||
        num_u > UINT64_C(65536) - from_u)
        return (uint64_t)-EINVAL;
    task = process_current_task();
    if (!task) return (uint64_t)-ESRCH;
    if (!(task->capabilities.effective &
          (UINT64_C(1) << EDGE_LINUX_CAP_SYS_RAWIO)))
        return (uint64_t)-EPERM;
    return 0;
}

static __attribute__((noreturn)) void x86_64_sigreturn_badframe(REGISTERS *r,
                                                                uint64_t frame_u,
                                                                const char *why) {
    task_t *t = process_current_task();
    static int diag_budget = 32;
    if (diag_budget-- > 0) {
        printf("[sigreturn-bad] pid=%d cmd=%s frame=0x%x why=%s rip=0x%x rsp=0x%x\n",
               t ? t->pid : -1, t ? t->name : "?", (uint32_t)frame_u,
               why ? why : "invalid", (uint32_t)(r ? r->rip : 0),
               (uint32_t)(r ? r->rsp : 0));
    }
    if (t) t->termination_signal = LINUX_SIGSEGV;
    scheduler_kill_current_group_and_yield(128 + LINUX_SIGSEGV);
    for (;;) __asm__ __volatile__("sti; hlt");
}

static uint64_t do_sys_rt_sigreturn(REGISTERS *r) {
    edge_x86_64_linux_rt_sigframe_t frame;
    edge_x86_64_linux_sigcontext_t *sc = &frame.ucontext.mcontext;
    struct edge_linux_stack64 signal_stack;
    REGISTERS restored;
    task_t *t = process_current_task();
    uint64_t frame_u;
    uint64_t restored_mask;
    uint32_t mxcsr = 0;
    uint32_t supported_mxcsr_mask = 0;
    uint8_t fxstate[EDGE_X86_64_FPSTATE_SIZE] __attribute__((aligned(16)));

    if (!r || !t || r->rsp < USER_MIN_ADDR + sizeof(uint64_t)) {
        x86_64_sigreturn_badframe(r, r ? r->rsp : 0, "stack");
    }
    /* The handler's RET consumed pretcode, leaving RSP at frame + 8. */
    frame_u = r->rsp - sizeof(uint64_t);
    if (!user_range_ok(frame_u, sizeof(frame)) ||
        copy_from_user(&frame, frame_u, sizeof(frame)) < 0) {
        x86_64_sigreturn_badframe(r, frame_u, "frame");
    }
    if ((frame.ucontext.flags &
         ~(EDGE_X86_64_UC_SIGCONTEXT_SS | EDGE_X86_64_UC_STRICT_RESTORE_SS)) != 0) {
        x86_64_sigreturn_badframe(r, frame_u, "ucontext-flags");
    }
    restored = *r;
    if (x86_64_regs_from_sigcontext(&restored, sc) < 0) {
        x86_64_sigreturn_badframe(r, frame_u, "registers");
    }

    if (sc->fpstate) {
        if (!user_range_ok(sc->fpstate, sizeof(fxstate)))
            x86_64_sigreturn_badframe(r, frame_u, "fpstate-range");
        if (copy_from_user(fxstate, sc->fpstate, sizeof(fxstate)) < 0)
            x86_64_sigreturn_badframe(r, frame_u, "fpstate-copy");
        if (!x86_64_fxstate_valid(fxstate, &mxcsr,
                                  &supported_mxcsr_mask)) {
            printf("[sigreturn-fpstate] pid=%d fp=0x%x mxcsr=0x%x mask=0x%x\n",
                   t->pid, (uint32_t)sc->fpstate, mxcsr,
                   supported_mxcsr_mask);
            x86_64_sigreturn_badframe(r, frame_u, "fpstate-mxcsr");
        }
    } else {
        memset(fxstate, 0, sizeof(fxstate));
        fxstate[0] = 0x7f;
        fxstate[1] = 0x03;
        fxstate[24] = 0x80;
        fxstate[25] = 0x1f;
        fxstate[28] = 0xbf;
        fxstate[29] = 0xff;
    }
    signal_stack.sp = frame.ucontext.stack.sp;
    signal_stack.flags = frame.ucontext.stack.flags;
    signal_stack.padding = 0;
    signal_stack.size = frame.ucontext.stack.size;
    restored_mask = edge_linux_signal_sanitize_mask(frame.ucontext.sigmask);
    if (edge_linux_signal_frame_restore(
            r, restored_mask, &signal_stack) < 0)
        x86_64_sigreturn_badframe(r, frame_u, "signal-state");
    task_cancel_wait_sigmask_restore(t);
    memcpy(t->fxsave_region, fxstate, sizeof(fxstate));
    x86_64_fxrstor_user_signal(fxstate);
    if (t->active_signal_frame == frame_u) {
        t->active_signal_frame = 0;
        t->active_signal_restorer_rsp = 0;
    }
    *r = restored;

    return r->rax;
}

int arch_namespace_descriptor_get(
    int32_t descriptor, kernel_namespace_descriptor_t *information) {
    edge_fd_proc_t *proc = fd_proc_with_stdio();
    edge_fd_t *entry = fd_get(proc, descriptor);

    if (!entry) return -EBADF;
    if (entry->kind != FD_NAMESPACE) return -ENOTTY;
    if (entry->namespace_kind >= EDGE_NAMESPACE_KIND_COUNT) return -EINVAL;
    information->kind = (edge_namespace_kind_t)entry->namespace_kind;
    information->id = entry->namespace_id;
    return 0;
}

static int process_vm_range_overlaps_secret(
        task_t *memory, uint64_t address, uint64_t size) {
    uint64_t end;
    int live;

    if (!memory || !size || size > UINT64_MAX - address) return size != 0;
    end = address + size;
    live = user_vma_live_limit(memory);
    for (int index = 0; index < live; ++index) {
        const edge_user_vma_t *mapping = &memory->user_vmas[index];
        if (mapping->end <= mapping->start ||
            !(mapping->flags & KERNEL_MM_MAP_SECRET))
            continue;
        if (address < mapping->end && end > mapping->start)
            return 1;
    }
    return 0;
}

int arch_mm_process_vm_copy(
        int32_t pid, uint64_t address, void *buffer, uint64_t size,
        kernel_mm_process_vm_operation_t operation) {
    task_t *target = (task_t *)process_get_task(pid);
    task_t *memory;

    if (!target) return -ESRCH;
    memory = process_vm_task(target);
    if (process_vm_range_overlaps_secret(memory, address, size))
        return -EFAULT;
    if (operation == KERNEL_MM_PROCESS_VM_READ)
        return process_read_user_memory(pid, address, buffer, size) < 0 ?
            -EFAULT : 0;
    if (operation == KERNEL_MM_PROCESS_VM_WRITE)
        return process_write_user_memory(pid, address, buffer, size) < 0 ?
            -EFAULT : 0;
    return -EINVAL;
}

static int64_t fd_read_kernel(uint64_t fd_u, void *buf, uint32_t len) {
    edge_fd_proc_t *p = fd_proc_with_stdio();
    edge_fd_t *e = p ? fd_get(p, (int)fd_u) : 0;
    int r;
    if (!buf && len) return -EFAULT;
    if (!e) return -EBADF;
    if (e->kind == FD_PIPE_R || e->kind == FD_PIPE_RW) {
        edge_pipe_t *pp;
        kernel_pipe_io_decision_t decision;
        uint32_t n;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PIPES) return -EBADF;
        pp = &g_pipes[e->pipe_id];
        if (!pp->used) return -EBADF;
        for (;;) {
            decision = kernel_pipe_read_decide(
                pp, (e->flags & LINUX_O_NONBLOCK) != 0);
            if (decision == KERNEL_PIPE_IO_READY) break;
            if (decision == KERNEL_PIPE_IO_COMPLETE) return 0;
            if (decision == KERNEL_PIPE_IO_INVALID) return -EBADF;
            if (decision == KERNEL_PIPE_IO_WOULD_BLOCK) return -EAGAIN;
            if (signal_pending_interrupt()) return (int64_t)tty_interrupt_current_ret();
            {
                task_t *cur = process_current_task();
                pipe_read_waiter_add(e->pipe_id, cur ? cur->pid : 0);
            }
            socket_blocking_wait_step(0);
        }
        n = kernel_pipe_read_kernel(pp, buf, len);
        if (n > 0) fd_wake_pipe_waiters(e->pipe_id);
        return (int64_t)n;
    }
    if (e->kind != FD_VFS) return -EINVAL;
    if ((e->inode.mode & 0xF000) == VFS_INODE_DIR) return -EISDIR;
    if ((e->inode.mode & 0xF000) == VFS_INODE_CHR || (e->inode.mode & 0xF000) == VFS_INODE_BLK) return -ESPIPE;
    if (!e->sb || !e->sb->ops || !e->sb->ops->read) return -EINVAL;
    if (fd_description_offset(e) > UINT32_MAX) return 0;
    r = e->sb->ops->read(e->sb, &e->inode,
                         (uint32_t)fd_description_offset(e), buf, len);
    if (r > 0) fd_description_advance(e, (uint64_t)r);
    return r;
}

static int64_t fd_write_kernel(uint64_t fd_u, const void *buf, uint32_t len) {
    edge_fd_proc_t *p = fd_proc_with_stdio();
    edge_fd_t *e = p ? fd_get(p, (int)fd_u) : 0;
    int w;
    uint64_t write_offset;
    if (!buf && len) return -EFAULT;
    if (!e) return -EBADF;
    if (e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW) {
        edge_pipe_t *pp;
        uint32_t done = 0;
        const int nonblocking = (e->flags & LINUX_O_NONBLOCK) != 0;
        const int atomic_write = len <= KERNEL_PIPE_RUNTIME_BUF;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PIPES) return -EBADF;
        pp = &g_pipes[e->pipe_id];
        if (!pp->used) return -EBADF;
        /*
         * Kernel-assisted copy helpers such as splice(2), sendfile(2), and
         * copy_file_range(2) move bytes without a userspace buffer.  BusyBox
         * cat uses these paths for "cat file | cmd"; if they only accepted VFS
         * endpoints, regular read/write still worked but file-to-pipe copies
         * appeared as EOF to the reader.  Keep the same blocking/short-write
         * behavior as the public write(2) pipe path, but consume the kernel
         * bounce buffer directly.
        */
        while (done < len) {
            kernel_pipe_io_decision_t decision =
                kernel_pipe_write_decide(
                    pp, len - done, atomic_write, nonblocking);
            if (decision == KERNEL_PIPE_IO_COMPLETE) break;
            if (decision == KERNEL_PIPE_IO_INVALID)
                return done ? (int64_t)done : -EBADF;
            if (decision == KERNEL_PIPE_IO_BROKEN)
                return done ? (int64_t)done : -EPIPE;
            if (decision == KERNEL_PIPE_IO_WOULD_BLOCK)
                return done ? (int64_t)done : -EAGAIN;
            if (decision == KERNEL_PIPE_IO_WAIT) {
                if (signal_pending_interrupt()) return done ? (int64_t)done : (int64_t)tty_interrupt_current_ret();
                /*
                 * Bytes already queued must be visible to readers before a
                 * blocking writer sleeps for more room.  Waiting until the
                 * whole kernel-assisted write completes can wedge producer /
                 * consumer helpers when the write is larger than pipe space.
                 */
                if (done > 0) fd_wake_pipe_waiters(e->pipe_id);
                {
                    task_t *cur = process_current_task();
                    pipe_write_waiter_add(e->pipe_id, cur ? cur->pid : 0);
                }
                socket_blocking_wait_step(0);
                continue;
            }
            {
                uint32_t was_empty = (pp->count == 0);
                done += kernel_pipe_write_kernel(
                    pp, &((const uint8_t *)buf)[done], len - done);
                if (was_empty || pp->count >= EDGE_PIPE_SIZE || done == len) {
                    fd_wake_pipe_waiters(e->pipe_id);
                }
            }
        }
        if (done > 0) fd_wake_pipe_waiters(e->pipe_id);
        return (int64_t)done;
    }
    if (e->kind == FD_CONSOLE) {
        int line_id = console_line_from_fd_entry(e);
        edge_console_line_t *line = console_line_state(line_id);
        for (uint32_t i = 0; i < len; ++i) {
            char c = ((const char *)buf)[i];
            if (c == '\n' && line &&
                (line->termios.c_oflag & LINUX_OPOST) != 0 &&
                (line->termios.c_oflag & LINUX_ONLCR) != 0) {
                console_line_write_char(line_id, '\r');
            }
            console_line_write_char(line_id, c);
        }
        return (int64_t)len;
    }
    if (e->kind == FD_VFS && path_is_tty_device(e->path)) {
        int line_id = console_line_from_fd_entry(e);
        edge_console_line_t *line = console_line_state(line_id);
        for (uint32_t i = 0; i < len; ++i) {
            char c = ((const char *)buf)[i];
            if (c == '\n' && line &&
                (line->termios.c_oflag & LINUX_OPOST) != 0 &&
                (line->termios.c_oflag & LINUX_ONLCR) != 0) {
                console_line_write_char(line_id, '\r');
            }
            console_line_write_char(line_id, c);
        }
        return (int64_t)len;
    }
    if (e->kind != FD_VFS) return -EINVAL;
    if ((e->inode.mode & 0xF000) == VFS_INODE_DIR) return -EISDIR;
    if ((e->inode.mode & 0xF000) == VFS_INODE_CHR || (e->inode.mode & 0xF000) == VFS_INODE_BLK) return -ESPIPE;
    if (!e->sb || !e->sb->ops || !e->sb->ops->write) return -EINVAL;
    if ((e->flags & LINUX_O_APPEND) != 0)
        fd_description_set_offset(e, e->inode.size);
    if (fd_description_offset(e) > UINT32_MAX) return -EFBIG;
    write_offset = fd_description_offset(e);
    w = e->sb->ops->write(e->sb, &e->inode,
                          (uint32_t)write_offset, buf, len);
    if (w > 0) {
        uint64_t end_pos;
        fd_description_advance(e, (uint64_t)w);
        end_pos = fd_description_offset(e);
        edge_mmap_file_cache_apply_write(
            e->sb, &e->inode, write_offset, buf, (uint32_t)w);
        /*
         * Kernel-assisted copy paths must maintain the same observable inode
         * metadata as write(2).  BusyBox/coreutils can populate redirected
         * tmpfs files through splice/sendfile-style helpers; if the fd-local
         * inode size and VFS path cache are left stale, stat(2)/test -s report
         * a zero-length file even though read(2) can return the data.  Linux
         * updates i_size before userspace observes the completed write.
         */
        if (end_pos > e->inode.size) e->inode.size = (uint32_t)end_pos;
        e->dirty = 1;
        vfs_path_cache_invalidate(e->path);
    }
    return w;
}

int64_t arch_io_kernel_write_current(int32_t descriptor,
                                     const void *buffer, uint32_t length,
                                     void *user_registers) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry = process ? fd_get(process, descriptor) : 0;
    (void)user_registers;
    if (!entry) return -EBADF;
    if (!buffer && length) return -EFAULT;
    if (entry->kind == FD_SOCKET)
        return socket_stream_send_kernel(socket_from_fd(descriptor), entry,
                                         buffer, length);
    return fd_write_kernel((uint64_t)descriptor, buffer, length);
}

int64_t arch_io_pipe_tee_current(int32_t input_descriptor,
                                 int32_t output_descriptor,
                                 uint64_t length, uint32_t flags,
                                 void *user_registers) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *input;
    edge_fd_t *output;
    edge_pipe_t *input_pipe;
    edge_pipe_t *output_pipe;
    task_t *current = process_current_task();
    uint32_t source_position;
    uint64_t copied = 0;
    uint64_t limit;
    int nonblocking;
    (void)user_registers;

    if (!process || input_descriptor < 0 || output_descriptor < 0)
        return -EBADF;
    input = fd_get(process, input_descriptor);
    output = fd_get(process, output_descriptor);
    if (!input || !output) return -EBADF;
    if (input->kind != FD_PIPE_R && input->kind != FD_PIPE_RW)
        return input->kind == FD_PIPE_W ? -EBADF : -EINVAL;
    if (output->kind != FD_PIPE_W && output->kind != FD_PIPE_RW)
        return output->kind == FD_PIPE_R ? -EBADF : -EINVAL;
    if (input->pipe_id < 0 || input->pipe_id >= EDGE_MAX_PIPES ||
        output->pipe_id < 0 || output->pipe_id >= EDGE_MAX_PIPES)
        return -EBADF;
    if (input->pipe_id == output->pipe_id) return -EINVAL;
    input_pipe = &g_pipes[input->pipe_id];
    output_pipe = &g_pipes[output->pipe_id];
    if (!input_pipe->used || !output_pipe->used) return -EBADF;
    nonblocking = (flags & 2u) ||
                  (input->flags & LINUX_O_NONBLOCK) ||
                  (output->flags & LINUX_O_NONBLOCK);

    for (;;) {
        if (!output_pipe->readers) {
            if (current)
                (void)process_send_signal(current->pid,
                                          EDGE_LINUX_SIGPIPE);
            return -EPIPE;
        }
        if (!input_pipe->count) {
            if (!input_pipe->writers) return 0;
            if (nonblocking) return -EAGAIN;
            if (signal_pending_interrupt())
                return (int64_t)tty_interrupt_current_ret();
            pipe_read_waiter_add(input->pipe_id,
                                 current ? current->pid : 0);
            if (input_pipe->count || !input_pipe->writers) {
                if (current) waiter_remove_pid(current->pid);
                continue;
            }
            socket_blocking_wait_step(0);
            continue;
        }
        if (output_pipe->count >= EDGE_PIPE_SIZE) {
            if (nonblocking) return -EAGAIN;
            if (signal_pending_interrupt())
                return (int64_t)tty_interrupt_current_ret();
            pipe_write_waiter_add(output->pipe_id,
                                  current ? current->pid : 0);
            if (output_pipe->count < EDGE_PIPE_SIZE ||
                !output_pipe->readers) {
                if (current) waiter_remove_pid(current->pid);
                continue;
            }
            socket_blocking_wait_step(0);
            continue;
        }
        break;
    }

    limit = length;
    if (limit > input_pipe->count) limit = input_pipe->count;
    if (limit > EDGE_PIPE_SIZE - output_pipe->count)
        limit = EDGE_PIPE_SIZE - output_pipe->count;
    source_position = input_pipe->read_position;
    while (copied < limit) {
        uint64_t count = limit - copied;
        uint64_t source_contiguous = EDGE_PIPE_SIZE - source_position;
        uint64_t output_contiguous =
            EDGE_PIPE_SIZE - output_pipe->write_position;
        if (count > source_contiguous) count = source_contiguous;
        if (count > output_contiguous) count = output_contiguous;
        memcpy(&output_pipe->data[output_pipe->write_position],
               &input_pipe->data[source_position], (size_t)count);
        source_position =
            (source_position + (uint32_t)count) % EDGE_PIPE_SIZE;
        output_pipe->write_position =
            (output_pipe->write_position + (uint32_t)count) %
                EDGE_PIPE_SIZE;
        output_pipe->count += (uint32_t)count;
        copied += count;
    }
    if (copied) fd_wake_pipe_waiters(output->pipe_id);
    return (int64_t)copied;
}

static int64_t splice_copy_current(int32_t input_descriptor,
                                   uint64_t *input_offset,
                                   int32_t output_descriptor,
                                   uint64_t *output_offset,
                                   uint64_t length, uint32_t flags,
                                   edge_fd_t *input, edge_fd_t *output) {
    uint8_t buf[8192];
    uint64_t done = 0;
    uint64_t in_saved = 0, out_saved = 0;
    int64_t terminal_error = 0;
    int restore_in = 0, restore_out = 0;
    if (length == 0) return 0;
    if (input_offset) {
        uint64_t off = *input_offset;
        uint64_t cur = do_sys_lseek((uint64_t)input_descriptor, 0,
                                    LINUX_SEEK_CUR);
        if ((int64_t)cur < 0) return (int64_t)cur;
        if ((int64_t)off < 0) return -EINVAL;
        if ((int64_t)do_sys_lseek((uint64_t)input_descriptor, off,
                                  LINUX_SEEK_SET) < 0)
            return -EINVAL;
        in_saved = cur;
        restore_in = 1;
    }
    if (output_offset) {
        uint64_t off = *output_offset;
        uint64_t cur = do_sys_lseek((uint64_t)output_descriptor, 0,
                                    LINUX_SEEK_CUR);
        if ((int64_t)cur < 0) {
            if (restore_in)
                (void)do_sys_lseek((uint64_t)input_descriptor, in_saved,
                                   LINUX_SEEK_SET);
            return (int64_t)cur;
        }
        if ((int64_t)off < 0 ||
            (int64_t)do_sys_lseek((uint64_t)output_descriptor, off,
                                  LINUX_SEEK_SET) < 0) {
            if (restore_in)
                (void)do_sys_lseek((uint64_t)input_descriptor, in_saved,
                                   LINUX_SEEK_SET);
            return -EINVAL;
        }
        out_saved = cur;
        restore_out = 1;
    }
    while (done < length) {
        uint64_t n = length - done;
        uint64_t r, w;
        edge_pipe_t *input_pipe = 0;
        if (n > sizeof(buf)) n = sizeof(buf);
        if (input &&
            (input->kind == FD_PIPE_R || input->kind == FD_PIPE_RW)) {
            task_t *current = process_current_task();
            input_pipe = &g_pipes[input->pipe_id];
            while (!input_pipe->count) {
                if (!input_pipe->writers) break;
                if ((flags & KERNEL_IO_SPLICE_F_NONBLOCK) ||
                    (input->flags & LINUX_O_NONBLOCK)) {
                    terminal_error = -EAGAIN;
                    break;
                }
                if (signal_pending_interrupt()) {
                    terminal_error = (int64_t)tty_interrupt_current_ret();
                    break;
                }
                pipe_read_waiter_add(input->pipe_id,
                                     current ? current->pid : 0);
                if (input_pipe->count || !input_pipe->writers) {
                    if (current) waiter_remove_pid(current->pid);
                    continue;
                }
                socket_blocking_wait_step(0);
            }
            if (terminal_error || !input_pipe->count) break;
            if (n > input_pipe->count) n = input_pipe->count;
        }
        if (flags & KERNEL_IO_SPLICE_F_NONBLOCK) {
            if (output &&
                (output->kind == FD_PIPE_W || output->kind == FD_PIPE_RW)) {
                edge_pipe_t *pipe = &g_pipes[output->pipe_id];
                uint64_t room;
                if (!pipe->readers) {
                    terminal_error = -EPIPE;
                    break;
                }
                room = EDGE_PIPE_SIZE - pipe->count;
                if (!room) {
                    terminal_error = -EAGAIN;
                    break;
                }
                if (n > room) n = room;
            }
        }
        if (input_pipe) {
            uint32_t source_position = input_pipe->read_position;
            uint64_t copied = 0;
            while (copied < n) {
                uint64_t count = n - copied;
                uint64_t contiguous = EDGE_PIPE_SIZE - source_position;
                if (count > contiguous) count = contiguous;
                memcpy(buf + copied, input_pipe->data + source_position,
                       (size_t)count);
                copied += count;
                source_position =
                    (source_position + (uint32_t)count) % EDGE_PIPE_SIZE;
            }
            r = n;
        } else {
            r = (uint64_t)fd_read_kernel((uint64_t)input_descriptor,
                                         buf, (uint32_t)n);
        }
        if ((int64_t)r < 0) {
            terminal_error = (int64_t)r;
            break;
        }
        if (r == 0) break;
        w = (uint64_t)fd_write_kernel((uint64_t)output_descriptor,
                                      buf, (uint32_t)r);
        if ((int64_t)w < 0) {
            terminal_error = (int64_t)w;
            break;
        }
        if (input_pipe && w) {
            input_pipe->read_position =
                (input_pipe->read_position + (uint32_t)w) %
                    EDGE_PIPE_SIZE;
            input_pipe->count -= (uint32_t)w;
            fd_wake_pipe_waiters(input->pipe_id);
        }
        done += w;
        if (w < r) break;
    }
    if (input_offset) {
        uint64_t pos = do_sys_lseek((uint64_t)input_descriptor, 0,
                                    LINUX_SEEK_CUR);
        *input_offset = pos;
    }
    if (output_offset) {
        uint64_t pos = do_sys_lseek((uint64_t)output_descriptor, 0,
                                    LINUX_SEEK_CUR);
        *output_offset = pos;
    }
    if (restore_in)
        (void)do_sys_lseek((uint64_t)input_descriptor, in_saved,
                           LINUX_SEEK_SET);
    if (restore_out)
        (void)do_sys_lseek((uint64_t)output_descriptor, out_saved,
                           LINUX_SEEK_SET);
    return done ? (int64_t)done : terminal_error;
}

static int memfd_fallocate_storage(edge_memfd_t *mf, uint32_t mode,
                                   uint64_t offset, uint64_t length) {
    uint64_t end;
    if (!mf || !length || (int64_t)offset < 0 || (int64_t)length < 0)
        return -EINVAL;
    end = offset + length;
    if (end < offset || end > (uint64_t)EDGE_MEMFD_MAX_PAGES * PAGE_SIZE)
        return -EFBIG;

    if (mode & VFS_FALLOC_FL_PUNCH_HOLE) {
        uint64_t stop;
        uint64_t page;
        if (mode != (VFS_FALLOC_FL_PUNCH_HOLE | VFS_FALLOC_FL_KEEP_SIZE))
            return -EOPNOTSUPP;
        if (offset >= mf->size) return 0;
        stop = end < mf->size ? end : mf->size;
        page = offset / PAGE_SIZE;
        while (page <= (stop - 1u) / PAGE_SIZE) {
            uint64_t page_start = page * PAGE_SIZE;
            uint64_t from = offset > page_start ? offset - page_start : 0;
            uint64_t to = stop < page_start + PAGE_SIZE ?
                          stop - page_start : PAGE_SIZE;
            int idx;

            if (from == 0 && to == PAGE_SIZE) {
                memfd_drop_storage_page(mf, page);
                page++;
                continue;
            }
            idx = memfd_storage_page(mf, page, 0);
            if (idx >= 0 && to > from) {
                void *data = process_user_mmap_backing_page_ptr(idx);
                if (!data) return -EIO;
                memset((uint8_t *)data + from, 0, (size_t)(to - from));
            }
            page++;
        }
        return 0;
    }

    if (mode & VFS_FALLOC_FL_COLLAPSE_RANGE) {
        uint8_t buffer[1024];
        uint64_t source;
        if (mode != VFS_FALLOC_FL_COLLAPSE_RANGE || end > mf->size ||
            (offset & (PAGE_SIZE - 1u)) || (length & (PAGE_SIZE - 1u)))
            return -EINVAL;
        source = end;
        while (source < mf->size) {
            uint64_t count = mf->size - source;
            int rc;
            if (count > sizeof(buffer)) count = sizeof(buffer);
            rc = memfd_read_to_kernel(mf, source, buffer, count);
            if (rc != (int)count) return rc < 0 ? rc : -EIO;
            rc = memfd_write_from_kernel(mf, source - length, buffer, count);
            if (rc != (int)count) return rc < 0 ? rc : -EIO;
            source += count;
        }
        return memfd_truncate(mf, mf->size - length);
    }

    if (mode & VFS_FALLOC_FL_INSERT_RANGE) {
        uint8_t buffer[1024];
        uint64_t remaining;
        uint64_t old_size = mf->size;
        if (mode != VFS_FALLOC_FL_INSERT_RANGE || offset > old_size ||
            (offset & (PAGE_SIZE - 1u)) || (length & (PAGE_SIZE - 1u)))
            return -EINVAL;
        remaining = old_size - offset;
        while (remaining) {
            uint64_t count = remaining > sizeof(buffer) ? sizeof(buffer) : remaining;
            uint64_t source = offset + remaining - count;
            int rc = memfd_read_to_kernel(mf, source, buffer, count);
            if (rc != (int)count) return rc < 0 ? rc : -EIO;
            rc = memfd_write_from_kernel(mf, source + length, buffer, count);
            if (rc != (int)count) return rc < 0 ? rc : -EIO;
            remaining -= count;
        }
        for (uint64_t page = offset / PAGE_SIZE;
             page <= (end - 1u) / PAGE_SIZE; ++page) {
            int idx = memfd_storage_page(mf, page, 1);
            void *data;
            if (idx < 0) return -ENOMEM;
            data = process_user_mmap_backing_page_ptr(idx);
            if (!data) return -EIO;
            memset(data, 0, PAGE_SIZE);
        }
        mf->size = old_size + length;
        return 0;
    }

    if (mode & VFS_FALLOC_FL_ZERO_RANGE) {
        return -EOPNOTSUPP;
    } else if (mode & ~(VFS_FALLOC_FL_KEEP_SIZE | VFS_FALLOC_FL_UNSHARE_RANGE)) {
        return -EOPNOTSUPP;
    }

    for (uint64_t page = offset / PAGE_SIZE;
         page <= (end - 1u) / PAGE_SIZE; ++page) {
        int idx = memfd_storage_page(mf, page, 1);
        if (idx < 0) return -ENOMEM;
    }
    if (!(mode & VFS_FALLOC_FL_KEEP_SIZE) && end > mf->size) mf->size = end;
    return 0;
}

int arch_vfs_fallocate_prepare(vfs_superblock_t *superblock,
                               const vfs_inode_t *inode, uint32_t mode,
                               uint64_t offset, uint64_t length) {
    (void)offset;
    (void)length;
    if ((mode & (VFS_FALLOC_FL_PUNCH_HOLE |
                 VFS_FALLOC_FL_ZERO_RANGE |
                 VFS_FALLOC_FL_COLLAPSE_RANGE |
                 VFS_FALLOC_FL_INSERT_RANGE)) &&
        edge_mmap_file_cache_sync_inode(superblock, inode, 1) < 0)
        return -EDGE_LINUX_EIO;
    return 0;
}

void arch_vfs_fallocate_commit(vfs_superblock_t *superblock,
                               const vfs_inode_t *inode, uint32_t mode,
                               uint64_t offset, uint64_t length) {
    publish_vfs_inode(superblock, inode);
    if (mode & (VFS_FALLOC_FL_PUNCH_HOLE |
                VFS_FALLOC_FL_ZERO_RANGE)) {
        edge_mmap_file_cache_invalidate_range(
            superblock, inode, offset, length);
    } else if (mode & (VFS_FALLOC_FL_COLLAPSE_RANGE |
                       VFS_FALLOC_FL_INSERT_RANGE)) {
        edge_mmap_file_cache_invalidate_range(
            superblock, inode, offset, UINT64_MAX - offset);
    }
    edge_mmap_file_cache_resize(superblock, inode, inode->size);
}

int arch_vfs_fallocate_descriptor(int32_t descriptor, uint32_t mode,
                                  uint64_t offset, uint64_t length) {
    edge_fd_proc_t *p = fd_proc_with_stdio();
    edge_fd_t *e;
    int rc;
    if (!p) return -EDGE_LINUX_EBADF;
    e = fd_get(p, descriptor);
    if (!e) return -EDGE_LINUX_EBADF;
    if (e->kind == FD_MEMFD) {
        edge_memfd_t *mf = memfd_get(e->pipe_id);
        if (!mf) return -EDGE_LINUX_EBADF;
        if (mf->secret) return -EDGE_LINUX_EOPNOTSUPP;
        rc = memfd_fallocate_storage(mf, mode, offset, length);
        return rc;
    }
    if (e->kind != FD_VFS || !e->sb) return -EDGE_LINUX_EINVAL;
    rc = kernel_vfs_fallocate_inode_transaction(
        e->sb, &e->inode, mode, offset, length);
    if (rc < 0) return rc;
    e->dirty = 1;
    if (e->path[0]) {
        edge_inotify_notify_path(e->path, EDGE_IN_MODIFY, 0);
    }
    return 0;
}

int64_t arch_io_splice_current(int32_t input_descriptor,
                               uint64_t input_offset_user,
                               int32_t output_descriptor,
                               uint64_t output_offset_user,
                               uint64_t length, uint32_t flags,
                               void *user_registers) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *input;
    edge_fd_t *output;
    uint64_t input_offset = 0;
    uint64_t output_offset = 0;
    uint64_t *input_offset_pointer = 0;
    uint64_t *output_offset_pointer = 0;
    int64_t result;
    int input_pipe;
    int output_pipe;
    (void)user_registers;

    if (!process) return -EBADF;
    input = fd_get(process, input_descriptor);
    output = fd_get(process, output_descriptor);
    if (!input || !output) return -EBADF;
    if (input->kind == FD_PIPE_W || output->kind == FD_PIPE_R)
        return -EBADF;
    input_pipe = input->kind == FD_PIPE_R || input->kind == FD_PIPE_RW;
    output_pipe = output->kind == FD_PIPE_W || output->kind == FD_PIPE_RW;
    if (!input_pipe && !output_pipe) return -EINVAL;
    if ((input_pipe &&
         (input->pipe_id < 0 || input->pipe_id >= EDGE_MAX_PIPES ||
          !g_pipes[input->pipe_id].used)) ||
        (output_pipe &&
         (output->pipe_id < 0 || output->pipe_id >= EDGE_MAX_PIPES ||
          !g_pipes[output->pipe_id].used)))
        return -EBADF;
    if ((input_pipe && input_offset_user) ||
        (output_pipe && output_offset_user))
        return -ESPIPE;
    if (input_offset_user) {
        if (copy_from_user(&input_offset, input_offset_user,
                           sizeof(input_offset)) < 0 ||
            copy_to_user(input_offset_user, &input_offset,
                         sizeof(input_offset)) < 0)
            return -EFAULT;
        input_offset_pointer = &input_offset;
    }
    if (output_offset_user) {
        if (copy_from_user(&output_offset, output_offset_user,
                           sizeof(output_offset)) < 0 ||
            copy_to_user(output_offset_user, &output_offset,
                         sizeof(output_offset)) < 0)
            return -EFAULT;
        output_offset_pointer = &output_offset;
    }
    result = splice_copy_current(
        input_descriptor, input_offset_pointer,
        output_descriptor, output_offset_pointer,
        length, flags, input, output);
    if (input_offset_user &&
        copy_to_user(input_offset_user, &input_offset,
                     sizeof(input_offset)) < 0 && result <= 0)
        result = -EFAULT;
    if (output_offset_user &&
        copy_to_user(output_offset_user, &output_offset,
                     sizeof(output_offset)) < 0 && result <= 0)
        result = -EFAULT;
    if (result == -EPIPE) {
        task_t *current = process_current_task();
        if (current)
            (void)process_send_signal(current->pid,
                                      EDGE_LINUX_SIGPIPE);
    }
    return result;
}

int64_t arch_io_splice_values_current(int32_t input_descriptor,
                                      uint64_t input_offset,
                                      int32_t output_descriptor,
                                      uint64_t output_offset,
                                      uint64_t length, uint32_t flags,
                                      void *user_registers) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *input;
    edge_fd_t *output;
    uint64_t *input_offset_pointer =
        input_offset == UINT64_MAX ? 0 : &input_offset;
    uint64_t *output_offset_pointer =
        output_offset == UINT64_MAX ? 0 : &output_offset;
    int input_pipe;
    int output_pipe;
    int64_t result;
    (void)user_registers;

    if (!process) return -EBADF;
    input = fd_get(process, input_descriptor);
    output = fd_get(process, output_descriptor);
    if (!input || !output) return -EBADF;
    if (input->kind == FD_PIPE_W || output->kind == FD_PIPE_R)
        return -EBADF;
    input_pipe = input->kind == FD_PIPE_R || input->kind == FD_PIPE_RW;
    output_pipe = output->kind == FD_PIPE_W || output->kind == FD_PIPE_RW;
    if (!input_pipe && !output_pipe) return -EINVAL;
    if ((input_pipe && input_offset_pointer) ||
        (output_pipe && output_offset_pointer))
        return -ESPIPE;
    result = splice_copy_current(
        input_descriptor, input_offset_pointer,
        output_descriptor, output_offset_pointer,
        length, flags, input, output);
    if (result == -EPIPE) {
        task_t *current = process_current_task();
        if (current)
            (void)process_send_signal(current->pid,
                                      EDGE_LINUX_SIGPIPE);
    }
    return result;
}

static int alloc_special_fd(edge_fd_kind_t kind, int obj_id, int flags) {
    edge_fd_proc_t *p = fd_proc_with_stdio();
    int fd;
    if (!p) return -ENOMEM;
    fd = fd_alloc(p, 0);
    if (fd < 0) return -EMFILE;
    p->fds[fd].kind = kind;
    p->fds[fd].file_ref = file_ref_alloc(
        (uint32_t)flags &
        (LINUX_O_NONBLOCK | LINUX_O_RDWR | LINUX_O_WRONLY));
    if (!p->fds[fd].file_ref) {
        fd_abort_reserved(p, fd);
        return -ENFILE;
    }
    p->fds[fd].pipe_id = obj_id;
    p->fds[fd].flags = flags & (LINUX_O_NONBLOCK | LINUX_O_RDWR | LINUX_O_WRONLY);
    p->fds[fd].fd_flags = (flags & LINUX_O_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    if (fd_publish(p, fd) < 0) {
        (void)file_ref_put(p->fds[fd].file_ref);
        fd_abort_reserved(p, fd);
        return -EBADF;
    }
    return fd;
}

static int x86_anonymous_fd_install(
    void *context, kernel_anonymous_fd_kind_t kind, int32_t object_id,
    uint32_t status_flags, uint32_t descriptor_flags) {
    edge_fd_kind_t local_kind;
    (void)context;
    switch (kind) {
    case KERNEL_ANONYMOUS_FD_EVENT:
        local_kind = FD_EVENTFD;
        break;
    case KERNEL_ANONYMOUS_FD_TIMER:
        local_kind = FD_TIMERFD;
        break;
    case KERNEL_ANONYMOUS_FD_SIGNAL:
        local_kind = FD_SIGNALFD;
        break;
    case KERNEL_ANONYMOUS_FD_INOTIFY:
        local_kind = FD_INOTIFY;
        break;
    case KERNEL_ANONYMOUS_FD_FANOTIFY:
        local_kind = FD_FANOTIFY;
        break;
    case KERNEL_ANONYMOUS_FD_USERFAULTFD:
        local_kind = FD_USERFAULTFD;
        break;
    case KERNEL_ANONYMOUS_FD_PERF_EVENT:
        local_kind = FD_PERF_EVENT;
        break;
    case KERNEL_ANONYMOUS_FD_PRIME:
        local_kind = FD_DMA_BUF;
        break;
    case KERNEL_ANONYMOUS_FD_MOUNT:
        local_kind = FD_MOUNT;
        break;
    case KERNEL_ANONYMOUS_FD_MESSAGE_QUEUE:
        local_kind = FD_MQUEUE;
        break;
    case KERNEL_ANONYMOUS_FD_IO_URING:
        local_kind = FD_IO_URING;
        break;
    case KERNEL_ANONYMOUS_FD_LANDLOCK:
        local_kind = FD_LANDLOCK;
        break;
    case KERNEL_ANONYMOUS_FD_BPF:
        local_kind = FD_BPF;
        break;
    case KERNEL_ANONYMOUS_FD_SECCOMP:
        local_kind = FD_SECCOMP;
        break;
    default:
        return -EINVAL;
    }
    return alloc_special_fd(
        local_kind, object_id,
        (int)status_flags |
            (descriptor_flags ? LINUX_O_CLOEXEC : 0));
}

static int x86_anonymous_fd_object_id(
    void *context, int32_t descriptor, kernel_anonymous_fd_kind_t kind) {
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry = fd_get(process, descriptor);
    edge_fd_kind_t expected;
    (void)context;
    if (!entry) return -EBADF;
    switch (kind) {
    case KERNEL_ANONYMOUS_FD_EVENT:
        expected = FD_EVENTFD;
        break;
    case KERNEL_ANONYMOUS_FD_TIMER:
        expected = FD_TIMERFD;
        break;
    case KERNEL_ANONYMOUS_FD_SIGNAL:
        expected = FD_SIGNALFD;
        break;
    case KERNEL_ANONYMOUS_FD_INOTIFY:
        expected = FD_INOTIFY;
        break;
    case KERNEL_ANONYMOUS_FD_FANOTIFY:
        expected = FD_FANOTIFY;
        break;
    case KERNEL_ANONYMOUS_FD_USERFAULTFD:
        expected = FD_USERFAULTFD;
        break;
    case KERNEL_ANONYMOUS_FD_PERF_EVENT:
        expected = FD_PERF_EVENT;
        break;
    case KERNEL_ANONYMOUS_FD_PRIME:
        expected = FD_DMA_BUF;
        break;
    case KERNEL_ANONYMOUS_FD_MOUNT:
        expected = FD_MOUNT;
        break;
    case KERNEL_ANONYMOUS_FD_MESSAGE_QUEUE:
        expected = FD_MQUEUE;
        break;
    case KERNEL_ANONYMOUS_FD_IO_URING:
        expected = FD_IO_URING;
        break;
    case KERNEL_ANONYMOUS_FD_LANDLOCK:
        expected = FD_LANDLOCK;
        break;
    case KERNEL_ANONYMOUS_FD_BPF:
        expected = FD_BPF;
        break;
    case KERNEL_ANONYMOUS_FD_SECCOMP:
        expected = FD_SECCOMP;
        break;
    default:
        return -EINVAL;
    }
    return entry->kind == expected ? entry->pipe_id : -EINVAL;
}

static void x86_anonymous_fd_state_changed(
    void *context, kernel_anonymous_fd_kind_t kind, int32_t object_id) {
    task_t *current;
    (void)context;
    if (kind == KERNEL_ANONYMOUS_FD_TIMER) {
        fd_wake_timerfd_waiters(object_id);
        return;
    }
    if (kind != KERNEL_ANONYMOUS_FD_SIGNAL &&
        kind != KERNEL_ANONYMOUS_FD_MESSAGE_QUEUE &&
        kind != KERNEL_ANONYMOUS_FD_BPF)
        return;
    current = process_current_task();
    fd_proc_registry_read_begin();
    for (int process_index = 0;
         process_index < EDGE_MAX_FD_PROCS; ++process_index) {
        edge_fd_proc_t *process = __atomic_load_n(
            &g_fd_procs[process_index], __ATOMIC_ACQUIRE);
        if (!process || !process->pid ||
            __atomic_load_n(&process->detached, __ATOMIC_ACQUIRE))
            continue;
        for (int descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
            edge_fd_t *entry = &process->fds[descriptor];
            edge_fd_kind_t expected_kind =
                kind == KERNEL_ANONYMOUS_FD_SIGNAL ?
                FD_SIGNALFD : kind == KERNEL_ANONYMOUS_FD_BPF ?
                FD_BPF : FD_MQUEUE;
            if (!entry->used || entry->kind != expected_kind ||
                (object_id >= 0 && entry->pipe_id != object_id))
                continue;
            fd_wake_fd_owner_tasks(
                process->pid, current,
                kind == KERNEL_ANONYMOUS_FD_SIGNAL ?
                    "signalfd" : kind == KERNEL_ANONYMOUS_FD_BPF ?
                    "bpf" : "mqueue");
            break;
        }
    }
    fd_proc_registry_read_end();
}

static const kernel_anonymous_fd_backend_ops_t
    x86_anonymous_fd_backend_ops = {
        .install = x86_anonymous_fd_install,
        .object_id = x86_anonymous_fd_object_id,
        .state_changed = x86_anonymous_fd_state_changed,
    };

static int x86_io_uring_page_allocate(
        void *context, kernel_io_uring_page_t *page) {
    int index;
    (void)context;
    if (!page) return -EINVAL;
    index = process_user_mmap_alloc_backing_page();
    if (index < 0) return -ENOMEM;
    page->address = process_user_mmap_backing_page_ptr(index);
    page->cookie = (uint32_t)index;
    if (!page->address) {
        process_user_mmap_release_backing_page(index);
        return -ENOMEM;
    }
    return 0;
}

static int x86_io_uring_page_retain(
        void *context, const kernel_io_uring_page_t *page) {
    (void)context;
    if (!page || page->cookie > INT32_MAX ||
        process_user_mmap_backing_page_ptr((int)page->cookie) !=
            page->address)
        return -EINVAL;
    process_user_mmap_retain_backing_page((int)page->cookie);
    return 0;
}

static int x86_io_uring_page_pin_user(
        void *context, uint64_t address_space, uint64_t user_address,
        kernel_io_uring_page_t *page) {
    uint64_t physical;
    uint32_t protection;
    int index;

    (void)context;
    if (!page || kernel_mm_resolve_user_page(
            address_space, user_address, ARCH_VM_PROT_WRITE) <= 0 ||
        arch_vm_translate(
            address_space, user_address, &physical, 0) < 0 ||
        arch_vm_user_page_protection(
            address_space, user_address, &protection) < 0 ||
        !(protection & ARCH_VM_PROT_WRITE))
        return -EFAULT;
    index = process_user_mmap_backing_page_index(
        (const void *)(uintptr_t)physical);
    if (index < 0 || !process_user_mmap_backing_page_active(index))
        return -EFAULT;
    process_user_mmap_retain_backing_page(index);
    page->address = process_user_mmap_backing_page_ptr(index);
    page->cookie = (uint32_t)index;
    return page->address ? 0 : -EFAULT;
}

static void x86_io_uring_page_release(
        void *context, const kernel_io_uring_page_t *page) {
    (void)context;
    if (!page || page->cookie > INT32_MAX) return;
    process_user_mmap_release_backing_page((int)page->cookie);
}

static const kernel_io_uring_page_allocator_t
    x86_io_uring_page_allocator = {
        .allocate = x86_io_uring_page_allocate,
        .retain = x86_io_uring_page_retain,
        .pin_user = x86_io_uring_page_pin_user,
        .release = x86_io_uring_page_release,
    };

static int x86_posix_timer_current_identity(
    void *context, int32_t *tid, int32_t *tgid) {
    task_t *task = process_current_task();
    (void)context;
    if (!task || !tid || !tgid) return -ESRCH;
    *tid = task->pid;
    *tgid = task->tgid > 0 ? task->tgid : task->pid;
    return 0;
}

static int x86_posix_timer_thread_group_for_tid(
    void *context, int32_t tid, int32_t *tgid) {
    const task_t *task = process_get_task(tid);
    (void)context;
    if (!task || !tgid) return -ESRCH;
    *tgid = task->tgid > 0 ? task->tgid : task->pid;
    return 0;
}

static int x86_posix_timer_enqueue_signal(
    void *context, int32_t target, uint32_t signal, int directed,
    const void *information) {
    (void)context;
    (void)directed;
    return process_send_signal_info(target, (int)signal, information);
}

static const kernel_posix_timer_backend_ops_t x86_posix_timer_backend_ops = {
    .current_identity = x86_posix_timer_current_identity,
    .thread_group_for_tid = x86_posix_timer_thread_group_for_tid,
    .enqueue_signal = x86_posix_timer_enqueue_signal,
};

static int x86_epoll_install_descriptor(void *context,
                                        int32_t epoll_index,
                                        uint32_t flags) {
    (void)context;
    return alloc_special_fd(FD_EPOLL, epoll_index,
                            (int)(flags & KERNEL_EPOLL_CLOEXEC));
}

static int x86_epoll_resolve_descriptor(void *context,
                                        int32_t descriptor,
                                        int32_t *epoll_index) {
    edge_fd_proc_t *p = fd_proc_with_stdio();
    uint64_t irq_flags;
    int32_t resolved_index;
    (void)context;
    if (!epoll_index) return -EINVAL;
    if (!p || descriptor < 0 || descriptor >= EDGE_MAX_FD)
        return -EBADF;
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &p->table_runtime, (uint32_t)descriptor) ||
        !__atomic_load_n(
            &p->fds[descriptor].used, __ATOMIC_ACQUIRE) ||
        p->fds[descriptor].kind != FD_EPOLL) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -EBADF;
    }
    resolved_index = p->fds[descriptor].pipe_id;
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    if (resolved_index < 0 || resolved_index >= EDGE_MAX_EPOLLS ||
        !kernel_epoll_object_exists(resolved_index))
        return -EBADF;
    *epoll_index = resolved_index;
    return 0;
}

static int x86_epoll_resolve_target(void *context, int32_t descriptor,
                                    uint64_t *description_id,
                                    int32_t *target_epoll_index) {
    edge_fd_proc_t *p = fd_proc_with_stdio();
    uint64_t irq_flags;
    uint64_t resolved_description;
    edge_fd_kind_t target_kind;
    int target_object;
    (void)context;
    if (!description_id || !target_epoll_index) return -EINVAL;
    if (!p || descriptor < 0 || descriptor >= EDGE_MAX_FD)
        return -EBADF;
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &p->table_runtime, (uint32_t)descriptor) ||
        !__atomic_load_n(
            &p->fds[descriptor].used, __ATOMIC_ACQUIRE) ||
        p->fds[descriptor].file_ref <= 0) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -EBADF;
    }
    resolved_description =
        file_ref_identity(p->fds[descriptor].file_ref);
    target_kind = p->fds[descriptor].kind;
    target_object = p->fds[descriptor].pipe_id;
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    if (!resolved_description) return -EBADF;
    *description_id = resolved_description;
    *target_epoll_index = -1;
    if (target_kind == FD_EPOLL) {
        if (target_object < 0 || target_object >= EDGE_MAX_EPOLLS ||
            !kernel_epoll_object_exists(target_object))
            return -EBADF;
        *target_epoll_index = target_object;
    }
    return 0;
}

static int x86_epoll_target_description_retain(
        void *context, uint64_t description_id) {
    (void)context;
    return file_ref_epoll_pin(description_id) == 0 ? 0 : -EBADF;
}

static void x86_epoll_target_description_release(
        void *context, uint64_t description_id) {
    (void)context;
    file_ref_epoll_unpin(description_id);
}

static int x86_epoll_capture_target_source(
        void *context, int32_t descriptor,
        uint64_t expected_description_id,
        kernel_epoll_target_source_t *source) {
    (void)context;
    return x86_epoll_target_source_capture(
        fd_proc_with_stdio(), descriptor,
        expected_description_id, source);
}

static void x86_epoll_release_target_source(
        void *context,
        const kernel_epoll_target_source_t *source) {
    (void)context;
    x86_epoll_target_source_release(source);
}

static int x86_epoll_observe_target_source(
        void *context,
        const kernel_epoll_target_source_t *captured,
        uint32_t requested_events, uint32_t *ready_events,
        uint64_t *read_ready_sequence,
        uint64_t *write_ready_sequence) {
    kernel_wait_observation_t observation;
    kernel_wait_source_t source;
    int status;

    (void)context;
    if (!captured || !ready_events || !read_ready_sequence ||
        !write_ready_sequence)
        return -EINVAL;
    status = x86_wait_source_from_captured(captured, &source);
    if (status < 0) return status;
    status = x86_wait_observe_source(
        0, &source,
        kernel_wait_epoll_to_poll_events(requested_events),
        &observation);
    if (status < 0) return status;
    *ready_events = observation.events;
    *read_ready_sequence = observation.read_sequence;
    *write_ready_sequence = observation.write_sequence;
    return 0;
}

static void x86_epoll_commit_target_source(
        void *context,
        const kernel_epoll_target_source_t *captured) {
    edge_fd_t entry;

    (void)context;
    if (x86_epoll_source_to_entry(captured, &entry) == 0 &&
        fd_is_mount_event_source(&entry))
        fd_mount_monitor_acknowledge(&entry);
}

static void x86_epoll_watch_set_changed(void *context,
                                        int32_t epoll_index) {
    task_t *current = process_current_task();
    (void)context;
    fd_proc_registry_read_begin();
    for (int process_index = 0;
         process_index < EDGE_MAX_FD_PROCS; ++process_index) {
        edge_fd_proc_t *process = __atomic_load_n(
            &g_fd_procs[process_index], __ATOMIC_ACQUIRE);
        uint64_t irq_flags;
        int owner_pid;
        int matched = 0;

        if (!process ||
            __atomic_load_n(&process->detached, __ATOMIC_ACQUIRE))
            continue;
        irq_flags = kernel_fd_table_lock(&process->table_runtime);
        owner_pid = process->pid;
        if (owner_pid <= 0) {
            kernel_fd_table_unlock(
                &process->table_runtime, irq_flags);
            continue;
        }
        for (int descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
            edge_fd_t *entry = &process->fds[descriptor];
            if (!kernel_fd_table_is_open_locked(
                    &process->table_runtime, (uint32_t)descriptor) ||
                !entry->used || entry->kind != FD_EPOLL)
                continue;
            /*
             * A task may wait only on a parent epoll descriptor while another
             * thread changes a nested child's watch set.  Wake roots that
             * transitively contain the changed object so the blocked task can
             * rebuild its recursive leaf registrations.  Looking only for a
             * descriptor of the child itself loses this wake after userspace
             * closes that descriptor but retains the nested watch.
             */
            if (entry->pipe_id != epoll_index &&
                !kernel_epoll_graph_reaches(entry->pipe_id, epoll_index))
                continue;
            matched = 1;
            break;
        }
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        if (matched)
            fd_wake_fd_owner_tasks(owner_pid, current, "epoll");
    }
    fd_proc_registry_read_end();
}

static const kernel_epoll_backend_ops_t x86_epoll_backend_ops = {
    .install_descriptor = x86_epoll_install_descriptor,
    .resolve_epoll_descriptor = x86_epoll_resolve_descriptor,
    .resolve_target_descriptor = x86_epoll_resolve_target,
    .target_description_retain =
        x86_epoll_target_description_retain,
    .target_description_release =
        x86_epoll_target_description_release,
    .capture_target_source =
        x86_epoll_capture_target_source,
    .release_target_source =
        x86_epoll_release_target_source,
    .observe_target_source =
        x86_epoll_observe_target_source,
    .commit_target_source =
        x86_epoll_commit_target_source,
    .watch_set_changed = x86_epoll_watch_set_changed,
};

static int epoll_post_register_ready(edge_fd_proc_t *process,
                                     int epoll_index) {
    return kernel_wait_epoll_has_ready(
        &g_x86_wait_backend_ops, process, epoll_index);
}

typedef struct x86_epoll_delivery_context {
    edge_fd_proc_t *process;
    uint64_t user_events;
    uint64_t epoll_descriptor;
    int epoll_watch_count;
    int first_ready_fd;
    int first_ready_kind;
    int first_ready_id;
    uint32_t first_ready_watch;
    uint32_t first_ready_events;
    int16_t first_ready_requested;
    int16_t first_ready_observed;
    uint64_t first_ready_read_sequence;
    uint64_t first_ready_write_sequence;
    uint32_t first_ready_socket_rx;
} x86_epoll_delivery_context_t;

static int x86_epoll_copy_event(
        void *opaque, uint32_t event_index,
        const kernel_epoll_event_t *event,
        const kernel_epoll_watch_t *watch,
        const kernel_wait_source_t *source,
        const kernel_wait_observation_t *observation) {
    x86_epoll_delivery_context_t *context =
        (x86_epoll_delivery_context_t *)opaque;
    edge_fd_t stable_entry;
    edge_fd_t *entry = 0;
    struct edge_linux_epoll_event result;
    uint64_t user_address;

    if (!context || !event || !watch || !observation)
        return -EINVAL;
    if (source)
        (void)x86_wait_source_entry(
            source, &stable_entry, &entry);
    if (event_index == 0) {
        context->first_ready_fd = watch->fd;
        context->first_ready_kind = entry ? (int)entry->kind :
            (watch->target_epoll_index >= 0 ? FD_EPOLL : -1);
        context->first_ready_id = entry ? entry->pipe_id :
            watch->target_epoll_index;
        context->first_ready_watch = watch->events;
        context->first_ready_events = event->events;
        context->first_ready_requested =
            kernel_wait_epoll_to_poll_events(watch->events);
        context->first_ready_observed =
            (int16_t)observation->events;
        context->first_ready_read_sequence =
            observation->read_sequence;
        context->first_ready_write_sequence =
            observation->write_sequence;
        context->first_ready_socket_rx =
            fd_epoll_socket_rx_len(entry);
    }
    if (xfce_debug_task(process_current_task()) &&
        g_xfce_epoll_trace_budget-- > 0) {
        printf("[xfcedbg] epoll-hit pid=%d cmd=%s ep=%d fd=%d kind=%d id=%d req=0x%x rev=0x%x eev=0x%x watch=0x%x path=%s nwatch=%d\n",
               process_getpid(),
               process_current_task() ?
                   process_current_task()->name : "?",
               (int)context->epoll_descriptor, watch->fd,
               entry ? (int)entry->kind : -1,
               entry ? entry->pipe_id : -1,
               (unsigned)kernel_wait_epoll_to_poll_events(
                   watch->events),
               (unsigned)observation->events,
               (unsigned)event->events,
               (unsigned)watch->events,
               (entry && entry->path[0]) ? entry->path : "-",
               context->epoll_watch_count);
    }
    result.events = event->events;
    memcpy(result.data, &event->data, sizeof(result.data));
    if (kernel_wait_array_element_address(
            context->user_events, event_index, sizeof(result),
            &user_address) < 0 ||
        copy_to_user(user_address, &result, sizeof(result)) < 0)
        return -EFAULT;
    return 0;
}

static void x86_epoll_commit_source(
        void *opaque, const kernel_wait_source_t *source) {
    edge_fd_t stable_entry;
    edge_fd_t *entry = 0;
    (void)opaque;
    if (source)
        (void)x86_wait_source_entry(
            source, &stable_entry, &entry);
    if (fd_is_mount_event_source(entry))
        fd_mount_monitor_acknowledge(entry);
}

static const kernel_wait_epoll_delivery_ops_t
    g_x86_epoll_delivery_ops = {
        .copy_event = x86_epoll_copy_event,
        .commit_source = x86_epoll_commit_source,
    };

typedef struct epoll_wait_post_block_context {
    edge_fd_proc_t *process;
    int epoll_index;
    uint64_t start_us;
    int64_t timeout_us;
} epoll_wait_post_block_context_t;

static int epoll_wait_post_block(void *opaque) {
    epoll_wait_post_block_context_t *context =
        (epoll_wait_post_block_context_t *)opaque;
    edge_fd_wait_plan_t plan;
    task_t *current = process_current_task();
    uint64_t deadline;

    if (!context || !current) return 1;
    epoll_wait_plan_build(
        &plan, context->process, context->epoll_index, current->pid);
    deadline = kernel_wait_plan_deadline(
        &plan, context->start_us, context->timeout_us,
        boottime_monotonic_us());
    fd_wait_shorten_current_deadline(deadline);
    if (deadline && boottime_monotonic_us() >= deadline) return 1;
    return epoll_post_register_ready(
        context->process, context->epoll_index);
}

static uint64_t do_sys_epoll_wait(uint64_t epfd_u, uint64_t events_u,
                                  uint64_t maxevents_u,
                                  int64_t timeout_microseconds) {
    edge_fd_proc_t *p = fd_proc_with_stdio();
    edge_fd_t *e = fd_get(p, (int)epfd_u);
    int epoll_index;
    int maxevents = (int)maxevents_u;
    uint64_t start_us;
    if (!e || e->kind != FD_EPOLL) return (uint64_t)-EBADF;
    if (maxevents <= 0) return (uint64_t)-EINVAL;
    if (maxevents > EDGE_EPOLL_MAX_WATCH)
        maxevents = EDGE_EPOLL_MAX_WATCH;
    if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_EPOLLS) return (uint64_t)-EBADF;
    epoll_index = e->pipe_id;
    if (!kernel_epoll_object_exists(epoll_index))
        return (uint64_t)-EBADF;
    start_us = boottime_monotonic_us();
    for (;;) {
        kernel_epoll_object_snapshot_t epoll;
        x86_epoll_delivery_context_t delivery = {
            .process = p,
            .user_events = events_u,
            .epoll_descriptor = epfd_u,
            .first_ready_fd = -1,
            .first_ready_kind = -1,
            .first_ready_id = -1,
        };
        int nout;
        int first_ready_fd;
        int first_ready_kind;
        int first_ready_id;
        uint32_t first_ready_watch;
        uint32_t first_ready_events;
        int16_t first_ready_req;
        int16_t first_ready_rev;
        uint64_t first_ready_rseq;
        uint64_t first_ready_wseq;
        uint32_t first_ready_rx;
        /*
         * Xorg waits for evdev input through epoll.  EdgeOS' USB/xHCI input
         * stack is currently poll-driven, so epoll must advance controllers
         * before testing fd readiness just like poll/select do.  Without this,
         * /dev/input/event* works for direct blocking readers, but Xorg can
         * sleep forever with keyboard/mouse fds registered in epoll.
         */
        lwip_stack_poll();
#ifdef CONFIG_USB
        usb_poll();
#endif
        keyboard_poll_controller();
        if (kernel_epoll_object_snapshot(epoll_index, &epoll) < 0)
            return (uint64_t)-EBADF;
        delivery.epoll_watch_count = epoll.nwatch;
        nout = kernel_wait_epoll_evaluate(
            &g_x86_wait_backend_ops, p,
            &g_x86_epoll_delivery_ops, &delivery,
            epoll_index, (uint32_t)maxevents);
        if (nout < 0) return (uint64_t)(int64_t)nout;
        first_ready_fd = delivery.first_ready_fd;
        first_ready_kind = delivery.first_ready_kind;
        first_ready_id = delivery.first_ready_id;
        first_ready_watch = delivery.first_ready_watch;
        first_ready_events = delivery.first_ready_events;
        first_ready_req = delivery.first_ready_requested;
        first_ready_rev = delivery.first_ready_observed;
        first_ready_rseq = delivery.first_ready_read_sequence;
        first_ready_wseq = delivery.first_ready_write_sequence;
        first_ready_rx = delivery.first_ready_socket_rx;
        if (nout > 0) {
            task_t *ct = process_current_task();
            if (g_gui_epoll_ready_trace_budget > 0 &&
                chromium_diag_task(ct)) {
                edge_fd_t *first = fd_get(p, first_ready_fd);
                uint64_t eventfd_counter = 0;
                uint64_t timerfd_exp = 0;
                int epoll_watch = -1;
                if (first && first->kind == FD_EVENTFD) {
                    eventfd_counter =
                        eventfd_counter_snapshot(first->pipe_id);
                } else if (first && first->kind == FD_TIMERFD) {
                    timerfd_exp =
                        timerfd_expiration_snapshot(first->pipe_id);
                } else if (first && first->kind == FD_EPOLL) {
                    kernel_epoll_object_snapshot_t nested;
                    if (kernel_epoll_object_snapshot(
                            first->pipe_id, &nested) == 0)
                        epoll_watch = nested.nwatch;
                }
                printf("[gui-epoll] pid=%d cmd=%s ep=%d nout=%d fd=%d kind=%d id=%d watch=0x%x req=0x%x rev=0x%x evcnt=%llu texp=%llu epn=%d rx=%u rseq=%u wseq=%u budget=%d\n",
                       ct ? ct->pid : -1, ct ? ct->name : "?",
                       (int)epfd_u, nout, first_ready_fd, first_ready_kind,
                       first_ready_id, (unsigned)first_ready_watch,
                       (unsigned)first_ready_req, (unsigned)first_ready_rev,
                       (unsigned long long)eventfd_counter,
                       (unsigned long long)timerfd_exp, epoll_watch,
                       first_ready_rx,
                       (unsigned)first_ready_rseq,
                       (unsigned)first_ready_wseq,
                       g_gui_epoll_ready_trace_budget - 1);
                g_gui_epoll_ready_trace_budget--;
            }
            if (timeout_microseconds == 0 &&
                g_epoll_spin_trace_budget-- > 0) {
                printf("[epoll-spin] pid=%d cmd=%s ep=%d nout=%d fd=%d kind=%d id=%d watch=0x%x req=0x%x rev=0x%x rseq=%u wseq=%u rx=%u budget=%d\n",
                       process_getpid(), ct ? ct->name : "?",
                       (int)epfd_u, nout, first_ready_fd, first_ready_kind,
                       first_ready_id, (unsigned)first_ready_watch,
                       (unsigned)first_ready_req, (unsigned)first_ready_rev,
                       (unsigned)first_ready_rseq,
                       (unsigned)first_ready_wseq, first_ready_rx,
                       g_epoll_spin_trace_budget);
            }
            if (xfce_debug_task(process_current_task()) && g_xfce_epoll_trace_budget-- > 0) {
                printf("[xfcedbg] epoll-ready pid=%d cmd=%s ep=%d nout=%d first_events=0x%x nwatch=%d\n",
                       process_getpid(), process_current_task() ? process_current_task()->name : "?",
                       (int)epfd_u, nout, first_ready_events,
                       epoll.nwatch);
            }
            /*
             * Preserve epoll readiness semantics, but provide the preemption
             * point Linux GUI stacks assume.  Xorg commonly calls epoll_wait()
             * with timeout 0 while draining client sockets; without a yield it
             * can monopolize EdgeOS long enough for xfdesktop/panel startup,
             * mouse input, and serial commands to look frozen.
             */
            /*
             * Xorg, DBus, GTK, and XFCE use dense nonblocking epoll/recvmsg
             * loops on AF_UNIX sockets.  Linux can preempt those loops between
             * syscalls; EdgeOS must provide the same scheduling opportunity or
             * one hot X server can starve the peers that need to handle its
             * requests.  Keep this as a generic GUI hot-loop fairness rule, not
             * a userspace/rootfs policy bypass.
             */
            if (gui_hot_poll_task(ct)) wait_gui_ready_preempt_step();
            return (uint64_t)nout;
        }
        /*
         * Linux reports already-visible readiness before an interrupting
         * signal, but an empty zero-timeout wait still observes a pending
         * signal before it reports a timeout.
         */
        if (signal_pending_interrupt()) return tty_interrupt_current_ret();
        if (timeout_microseconds == 0) {
            if (xfce_debug_task(process_current_task()) && g_xfce_epoll_trace_budget-- > 0) {
                printf("[xfcedbg] epoll-timeout0 pid=%d cmd=%s ep=%d nwatch=%d\n",
                       process_getpid(), process_current_task() ? process_current_task()->name : "?",
                       (int)epfd_u, epoll.nwatch);
            }
            return 0;
        }
        if (timeout_microseconds > 0) {
            uint64_t now = boottime_monotonic_us();
            if (now - start_us >= (uint64_t)timeout_microseconds) {
                if (xfce_debug_task(process_current_task()) && g_xfce_epoll_trace_budget-- > 0) {
                    printf("[xfcedbg] epoll-timeout pid=%d cmd=%s ep=%d timeout_us=%llu nwatch=%d\n",
                           process_getpid(), process_current_task() ? process_current_task()->name : "?",
                           (int)epfd_u,
                           (unsigned long long)timeout_microseconds,
                           epoll.nwatch);
                }
                return 0;
            }
        }
        {
            int waiter_pid = 0;
            task_t *cur = process_current_task();
            edge_fd_wait_plan_t plan;
            epoll_wait_post_block_context_t post_block_context = {
                .process = p,
                .epoll_index = epoll_index,
                .start_us = start_us,
                .timeout_us = timeout_microseconds,
            };
            int only_kernel_wakeup_fds;
            int needs_periodic_rescan;
            uint64_t deadline_us = 0;
            if (cur) {
                waiter_pid = cur->pid;
                epoll_wait_plan_build(
                    &plan, p, epoll_index, waiter_pid);
            } else {
                fd_wait_plan_init(&plan, p, 0);
                fd_wait_plan_mark_inexact(&plan);
            }
            only_kernel_wakeup_fds = plan.all_sources_exact;
            needs_periodic_rescan = plan.needs_periodic_rescan;
            deadline_us = kernel_wait_plan_deadline(
                &plan, start_us, timeout_microseconds,
                boottime_monotonic_us());
            /*
             * Linux epoll links the waiter before the final readiness check.
             * EdgeOS previously scanned, registered socket/event waiters, then
             * slept.  A peer write in the gap had no waiter to wake, so X11 and
             * DBus clients could sleep forever with bytes already queued.  Do
             * the second check before blocking and remove the temporary waiter
             * registrations when the loop must rescan immediately.
             */
            if (epoll_post_register_ready(p, epoll_index)) {
                waiter_remove_pid(waiter_pid);
                continue;
            }
            if (cur && cur->pid == 1 &&
                boottime_monotonic_us() >= 10000000ull) {
                static int pid1_epoll_watch_budget =
                    EDGE_XFCE_BOOT_TRACE ? 2 : 0;
                if (pid1_epoll_watch_budget > 0) {
                    --pid1_epoll_watch_budget;
                    printf("[pid1-epoll-block] ep=%d nwatch=%d budget=%d\n",
                           (int)epfd_u, epoll.nwatch,
                           pid1_epoll_watch_budget);
                    for (int i = 0; i < epoll.entry_high_water; ++i) {
                        kernel_epoll_watch_snapshot_t watch;
                        if (kernel_epoll_watch_snapshot(
                                epoll_index, (uint16_t)i, &watch) <= 0)
                            continue;
                        edge_fd_t stable_watch_fd;
                        edge_fd_t *watch_fd =
                            x86_epoll_watch_source_entry(
                                &watch.watch,
                                &stable_watch_fd) == 0 ?
                            &stable_watch_fd : 0;
                        const task_t *pidfd_task =
                            watch_fd && watch_fd->kind == FD_PIDFD ?
                            process_get_task(watch_fd->pipe_id) : 0;
                        int16_t requested = 0;
                        int16_t ready = 0;
                        if (watch.watch.events & (LINUX_EPOLLIN |
                                LINUX_EPOLLPRI | LINUX_EPOLLRDNORM |
                                LINUX_EPOLLRDBAND))
                            requested |= LINUX_POLLIN | LINUX_POLLPRI |
                                         LINUX_POLLRDNORM | LINUX_POLLRDBAND;
                        if (watch.watch.events & (LINUX_EPOLLOUT |
                                LINUX_EPOLLWRNORM | LINUX_EPOLLWRBAND))
                            requested |= LINUX_POLLOUT | LINUX_POLLWRNORM |
                                         LINUX_POLLWRBAND;
                        if (watch_fd)
                            ready = poll_fd_revents(watch_fd, requested);
                        printf("[pid1-epoll-watch] index=%d fd=%d kind=%d target=%d events=0x%x req=0x%x rev=0x%x delivered=0x%x disabled=%u target_state=%d\n",
                               i, watch.watch.fd,
                               watch_fd ? (int)watch_fd->kind : -1,
                               watch_fd ? watch_fd->pipe_id : -1,
                               (unsigned)watch.watch.events,
                               (unsigned)requested, (unsigned)ready,
                               (unsigned)watch.watch.ready_delivered,
                               (unsigned)watch.watch.oneshot_disabled,
                               pidfd_task ? (int)pidfd_task->state : -1);
                    }
                }
            }
            if (cur && strncmp(cur->name, "systemd-journal", 15) == 0) {
                static int journal_epoll_watch_budget =
                    EDGE_XFCE_BOOT_TRACE ? 2 : 0;
                if (journal_epoll_watch_budget > 0) {
                    --journal_epoll_watch_budget;
                    printf("[journal-epoll-block] ep=%d nwatch=%d budget=%d\n",
                           (int)epfd_u, epoll.nwatch,
                           journal_epoll_watch_budget);
                    for (int i = 0; i < epoll.entry_high_water; ++i) {
                        kernel_epoll_watch_snapshot_t watch;
                        if (kernel_epoll_watch_snapshot(
                                epoll_index, (uint16_t)i, &watch) <= 0)
                            continue;
                        edge_fd_t stable_watch_fd;
                        edge_fd_t *watch_fd =
                            x86_epoll_watch_source_entry(
                                &watch.watch,
                                &stable_watch_fd) == 0 ?
                            &stable_watch_fd : 0;
                        int16_t requested = 0;
                        int16_t ready = 0;
                        if (watch.watch.events & (LINUX_EPOLLIN |
                                LINUX_EPOLLPRI | LINUX_EPOLLRDNORM |
                                LINUX_EPOLLRDBAND))
                            requested |= LINUX_POLLIN | LINUX_POLLPRI |
                                         LINUX_POLLRDNORM | LINUX_POLLRDBAND;
                        if (watch.watch.events & (LINUX_EPOLLOUT |
                                LINUX_EPOLLWRNORM | LINUX_EPOLLWRBAND))
                            requested |= LINUX_POLLOUT | LINUX_POLLWRNORM |
                                         LINUX_POLLWRBAND;
                        if (watch_fd)
                            ready = poll_fd_revents(watch_fd, requested);
                        printf("[journal-epoll-watch] index=%d fd=%d kind=%d "
                               "target=%d events=0x%x req=0x%x rev=0x%x "
                               "delivered=0x%x disabled=%u\n",
                               i, watch.watch.fd,
                               watch_fd ? (int)watch_fd->kind : -1,
                               watch_fd ? watch_fd->pipe_id : -1,
                               (unsigned)watch.watch.events,
                               (unsigned)requested, (unsigned)ready,
                               (unsigned)watch.watch.ready_delivered,
                               (unsigned)watch.watch.oneshot_disabled);
                    }
                }
            }
            int xorg_epoll_wait_trace = (cur && strcmp(cur->name, "Xorg") == 0 &&
                                         g_xorg_epoll_wait_trace_budget > 0);
            if ((g_gui_wait_fd_trace_budget > 0 &&
                 chromium_diag_task(cur)) || xorg_epoll_wait_trace) {
                int logged = 0;
                printf("[epoll-wait] pid=%d cmd=%s ep=%d nwatch=%d deadline=%llu only=%d periodic=%d",
                       cur ? cur->pid : -1,
                       cur ? cur->name : "?",
                       (int)epfd_u,
                       epoll.nwatch,
                       (unsigned long long)deadline_us,
                       only_kernel_wakeup_fds,
                       needs_periodic_rescan);
                for (int i = 0; i < epoll.entry_high_water &&
                     logged < 4; ++i) {
                    kernel_epoll_watch_snapshot_t watch;
                    edge_fd_t stable_we;
                    edge_fd_t *we;
                    uint64_t eventfd_counter = 0;
                    uint32_t pipe_count = 0;
                    uint32_t socket_rx = 0;
                    int socket_peer = -1;
                    int socket_domain = -1;
                    int socket_listen = -1;
                    int socket_pending = -1;
                    if (kernel_epoll_watch_snapshot(
                            epoll_index, (uint16_t)i, &watch) <= 0)
                        continue;
                    we = x86_epoll_watch_source_entry(
                             &watch.watch, &stable_we) == 0 ?
                         &stable_we : 0;
                    if (we && we->kind == FD_EVENTFD) {
                        eventfd_counter =
                            eventfd_counter_snapshot(we->pipe_id);
                    } else if (we && (we->kind == FD_PIPE_R || we->kind == FD_PIPE_W || we->kind == FD_PIPE_RW) &&
                               we->pipe_id >= 0 && we->pipe_id < EDGE_MAX_PIPES &&
                               g_pipes[we->pipe_id].used) {
                        pipe_count = g_pipes[we->pipe_id].count;
                    } else if (we && we->kind == FD_SOCKET &&
                               we->pipe_id >= 0 && we->pipe_id < EDGE_MAX_SOCKETS &&
                               g_sockets[we->pipe_id].used) {
                        socket_rx = g_sockets[we->pipe_id].rx_len;
                        socket_peer = g_sockets[we->pipe_id].unix_peer_id;
                        socket_domain = g_sockets[we->pipe_id].domain;
                        socket_listen = g_sockets[we->pipe_id].listening;
                        socket_pending = socket_pending_count(
                            &g_sockets[we->pipe_id]);
                    }
                    printf(" fd%d=%d:%s/%d ev=0x%x fl=0x%x cnt=%llu pcnt=%u rx=%u peer=%d dom=%d lis=%d pend=%d",
                           i,
                           watch.watch.fd,
                           we ? fd_kind_name(we->kind) : "bad",
                           we ? we->pipe_id : -1,
                           (unsigned)watch.watch.events,
                           we ? (unsigned)we->flags : 0u,
                           (unsigned long long)eventfd_counter,
                           pipe_count, socket_rx, socket_peer,
                           socket_domain, socket_listen, socket_pending);
                    logged++;
                }
                if (xorg_epoll_wait_trace) {
                    printf(" budget=%d\n", g_xorg_epoll_wait_trace_budget - 1);
                    g_xorg_epoll_wait_trace_budget--;
                } else {
                    printf(" budget=%d\n", g_gui_wait_fd_trace_budget - 1);
                    g_gui_wait_fd_trace_budget--;
                }
            }
            socket_blocking_wait_step_checked(
                deadline_us, epoll_wait_post_block,
                &post_block_context);
        }
    }
}

int64_t arch_epoll_wait_descriptor(int32_t epoll_descriptor,
                                   uint64_t user_events,
                                   uint32_t maximum_events,
                                   int64_t timeout_microseconds,
                                   int replace_signal_mask,
                                   uint64_t signal_mask,
                                   void *user_registers) {
    task_t *cur = process_current_task();
    edge_fd_proc_t *process = fd_proc_with_stdio();
    edge_fd_t *entry = fd_get(process, epoll_descriptor);
    uint64_t old_sigmask = 0;
    uint64_t ret;
    int epoll_index;
    (void)user_registers;
    if (!entry || entry->kind != FD_EPOLL ||
        entry->pipe_id < 0 ||
        entry->pipe_id >= EDGE_MAX_EPOLLS)
        return -EBADF;
    epoll_index = entry->pipe_id;
    if (!cur) return -ESRCH;
    if (kernel_epoll_wait_lease_acquire(
            &cur->epoll_wait_lease, epoll_index) < 0)
        return -EBADF;
    if (replace_signal_mask && cur) {
        /*
         * Match Linux epoll_pwait(): install the supplied mask only for the
         * duration of the wait.  Xorg and GLib use this race-free wait form in
         * their main loops; treating it as plain epoll_wait() changes signal
         * interruption behavior and can turn idle desktop helpers into retry
         * loops under timer/child-signal load.
         */
        old_sigmask = cur->sigmask;
        task_install_wait_sigmask(cur, signal_mask);
    }
    ret = do_sys_epoll_wait((uint64_t)(uint32_t)epoll_descriptor,
                            user_events, maximum_events,
                            timeout_microseconds);
    kernel_epoll_wait_lease_release(&cur->epoll_wait_lease);
    if (replace_signal_mask && cur) {
        task_restore_wait_sigmask_unless(cur, (int64_t)ret == -(int64_t)EINTR);
    }
    if ((int64_t)ret < 0 && gui_diag_task(cur)) {
        static int epoll_pwait_neg_budget = EDGE_GUI_DEEP_TRACE ? 48 : 0;
        if (epoll_pwait_neg_budget-- > 0) {
            printf("[epoll-pwait-abi] pid=%d cmd=%s ep=%d timeout=%d ret=%d sigmask=%d old=0x%x new=0x%x pending=0x%x alrm=%u chld=%u io=%u rtmin=%u budget=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   epoll_descriptor,
                   timeout_microseconds < 0 ? -1 :
                       (int)(timeout_microseconds / 1000LL),
                   (int)(int64_t)ret,
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
                   epoll_pwait_neg_budget);
        }
    }
    return (int64_t)ret;
}
