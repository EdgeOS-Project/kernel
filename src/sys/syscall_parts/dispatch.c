static int syscall_should_yield_after_socket_io(uint64_t nr, uint64_t fd_u,
                                                int64_t result) {
    edge_socket_t *s;

    if (result < 0) return 0;
    if (nr == SYS_accept || nr == SYS_accept4) return 1;
    if (!(nr == SYS_recvfrom || nr == SYS_sendto ||
          nr == SYS_recvmsg || nr == SYS_sendmsg)) {
        return 0;
    }
    if (result == 0) return 0;

    s = socket_from_fd((int)fd_u);
    /*
     * This yield exists to let lwIP/TCP peers make progress after networking
     * syscalls.  AF_UNIX is different: X11/DBus peers are woken directly by the
     * socket helpers, and yielding from the #UD-emulated syscall frame under
     * dense local-socket traffic has exposed corrupted ring-0 continuations
     * returning into .bss.  Keep local IPC on the hot return path and reserve the
     * cooperative yield for real network sockets.
     */
    if (s && s->domain == LINUX_AF_UNIX) return 0;
    return 1;
}

static int syscall_requires_fixed_mapping_refresh(uint64_t nr) {
    switch (nr) {
        case SYS_brk:
        case SYS_mmap:
        case SYS_mprotect:
        case SYS_munmap:
        case SYS_mremap:
        case SYS_msync:
        case SYS_madvise:
        case SYS_mlock:
        case SYS_mlock2:
        case SYS_munlock:
        case SYS_mlockall:
        case SYS_munlockall:
        case SYS_pkey_mprotect:
        case SYS_shmat:
        case SYS_shmdt:
        case SYS_remap_file_pages:
        case EDGE_SYS_fork:
        case SYS_vfork:
        case SYS_clone:
        case SYS_clone3:
        case EDGE_SYS_execve:
        case SYS_execveat:
            return 1;
        default:
            return 0;
    }
}

static void syscall_maybe_pump_fbdev_mmap(void) {
    /*
     * Linux fbdev mmap clients expect drawing through the mapping to become
     * visible without an explicit write(2) or ioctl(2).  EdgeOS' virtio-gpu
     * backing buffer needs an explicit transfer/flush, but that transfer must
     * happen from ordinary kernel context.  Pumping here keeps Xorg/fbdev,
     * xfwm4, xfdesktop, and GTK windows visible while avoiding full-screen
     * virtio commands in the timer IRQ path.
     *
     * Red flag: keep this keyed only on active fbdev mmap ownership.  Do not
     * add process-name, rootfs, or XFCE-specific refresh hacks.
     */
    syscall_fbdev_mmap_pump_poll();
    fb_console_pump_deferred();
}

static int syscall_signal_restart_allowed(uint64_t nr) {
    /*
     * Linux does not automatically restart readiness waits after a signal
     * handler, even when the handler was installed with SA_RESTART.  Xorg and
     * GLib depend on poll/ppoll/epoll returning EINTR at those synchronization
     * points; restarting them in-kernel can strand timer-driven work such as
     * shadow framebuffer publication behind an apparently idle wait.
     */
    switch (nr) {
        case SYS_poll:
        case SYS_ppoll:
        case SYS_select:
        case SYS_pselect6:
        case SYS_epoll_wait:
        case SYS_epoll_pwait:
        case SYS_epoll_pwait2:
        case SYS_nanosleep:
        case SYS_clock_nanosleep:
            return 0;
        default:
            return 1;
    }
}

static int gui_einval_trace_task(const task_t *t) {
    if (!t || t->is_idle) return 0;
    return strcmp(t->name, "thunar") == 0 ||
           strcmp(t->name, "xfdesktop") == 0;
}

static int syscall_apply_seccomp(task_t *task, REGISTERS *r, uint64_t nr,
                                 uint64_t a1, uint64_t a2, uint64_t a3,
                                 uint64_t a4, uint64_t a5, uint64_t a6,
                                 int64_t *result_out) {
    static uint32_t trace_budget = 0;
    edge_seccomp_data_t data;
    uint32_t decision;
    uint32_t action;

    if (!task || !r || !result_out || !task->seccomp.length ||
        nr == SYS_rt_sigreturn)
        return 0;

    memset(&data, 0, sizeof(data));
    data.nr = (int32_t)nr;
    data.arch = 0xc000003eu; /* AUDIT_ARCH_X86_64 */
    data.instruction_pointer = r->int_no == 6 ? r->rcx : r->rip;
    data.args[0] = a1;
    data.args[1] = a2;
    data.args[2] = a3;
    data.args[3] = a4;
    data.args[4] = a5;
    data.args[5] = a6;

    decision = edge_seccomp_evaluate(&task->seccomp, &data);
    action = decision & EDGE_SECCOMP_RET_ACTION_FULL;
    if (action == EDGE_SECCOMP_RET_ALLOW) return 0;
    if (trace_budget) {
        --trace_budget;
        printf("[seccomp-decision] pid=%d cmd=%s nr=%u action=0x%x data=%u\n",
               task->pid, task->name[0] ? task->name : "?", (uint32_t)nr,
               action, decision & EDGE_SECCOMP_RET_DATA);
    }
    if (action == EDGE_SECCOMP_RET_LOG) {
        printf("[seccomp] log pid=%d nr=%u ip=0x%x\n", task->pid,
               (uint32_t)nr, (uint32_t)data.instruction_pointer);
        return 0;
    }
    if (action == EDGE_SECCOMP_RET_ERRNO) {
        *result_out = -(int64_t)(decision & EDGE_SECCOMP_RET_DATA);
        return 1;
    }
    if (action == EDGE_SECCOMP_RET_TRACE) {
        *result_out = -(int64_t)ENOSYS;
        return 1;
    }
    if (action == EDGE_SECCOMP_RET_TRAP) {
        uint8_t signal_information[KERNEL_SIGNAL_INFO_SIZE];
        task->seccomp_sigsys_errno =
            (int32_t)(decision & EDGE_SECCOMP_RET_DATA);
        task->seccomp_sigsys_nr = (int32_t)nr;
        task->seccomp_sigsys_arch = data.arch;
        task->seccomp_sigsys_call_addr = data.instruction_pointer;
        task->seccomp_sigsys_valid = 1;
        *result_out = -(int64_t)ENOSYS;
        kernel_signal_info_build_seccomp(
            signal_information, LINUX_SIGSYS, task->seccomp_sigsys_errno,
            data.instruction_pointer, (int32_t)nr, data.arch);
        if (process_send_signal_info(
                task->pid, LINUX_SIGSYS, signal_information) < 0) {
            task->termination_signal = LINUX_SIGSYS;
            process_exit_current_group(128 + LINUX_SIGSYS);
        }
        return 1;
    }

    task->termination_signal = LINUX_SIGSYS;
    if (action == EDGE_SECCOMP_RET_KILL_THREAD)
        process_exit_current(128 + LINUX_SIGSYS);
    else
        process_exit_current_group(128 + LINUX_SIGSYS);
    *result_out = -(int64_t)ENOSYS;
    return 1;
}

static int x86_linux_copy_from_user(void *context, void *destination,
                                    uint64_t source, uint64_t size) {
    (void)context;
    return copy_from_user(destination, source, size);
}

static int x86_linux_copy_to_user(void *context, uint64_t destination,
                                  const void *source, uint64_t size) {
    (void)context;
    return copy_to_user(destination, source, size);
}

static int x86_linux_validate_user_range_arch(void *context, uint64_t address,
                                              uint64_t size, int write) {
    (void)context;
    (void)write;
    return x86_user_range_arch_ok(address, size) ? 0 : -1;
}

static int x86_linux_copy_epoll_event_from_user(
    void *context, uint64_t source, kernel_epoll_event_t *event) {
    struct edge_linux_epoll_event packed;
    (void)context;
    if (!event || copy_from_user(&packed, source, sizeof(packed)) < 0)
        return -1;
    event->events = packed.events;
    memcpy(&event->data, packed.data, sizeof(event->data));
    return 0;
}

static const edge_linux_syscall_arch_ops_t x86_linux_syscall_ops = {
    .copy_from_user = x86_linux_copy_from_user,
    .copy_to_user = x86_linux_copy_to_user,
    .user_address_minimum = USER_MIN_ADDR,
    .user_address_limit = USER_MAX_ADDR,
    .validate_user_range_arch = x86_linux_validate_user_range_arch,
    .copy_stat_to_user = edge_x86_64_linux_stat_to_user,
    .copy_epoll_event_from_user = x86_linux_copy_epoll_event_from_user,
    .fcntl_setfl_mask = 0x00044000u, /* O_DIRECT | O_NOATIME */
    .machine = "x86_64",
    .release = CONFIG_LINUX_ABI_RELEASE,
    .version = EDGEOS_LINUX_ABI_VERSION,
};

static int syscall_ptrace_single_step(const task_t *task) {
    return task && task->ptrace.tracer_pid > 0 &&
           task->ptrace.resume_mode == EDGE_LINUX_PTRACE_RESUME_SINGLESTEP;
}

void edgeos_x86_64_syscall_dispatch(REGISTERS *r) {
    uint64_t nr = r->rax;
    /* Keep IRQs masked for the duration of the kernel-side syscall frame.
     * Re-entering the kernel on the same stack while the frame is live has
     * been corrupting user return state on int80/#UD-emulated syscall paths. */

    uint64_t arguments[6] = {r->rdi, r->rsi, r->rdx,
                             r->r10, r->r8, r->r9};
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t a4;
    uint64_t a5;
    uint64_t a6;
    const int emulated_syscall = r->int_no == 6;
    task_t *cur = process_current_task();
    if (cur && !cur->is_idle) cur->ptrace_live_frame = (uintptr_t)r;
    edge_linux_ptrace_syscall_enter(r, &nr, arguments);
    a1 = arguments[0];
    a2 = arguments[1];
    a3 = arguments[2];
    a4 = arguments[3];
    a5 = arguments[4];
    a6 = arguments[5];
    int trace_go_sys = trace_go_startup_syscall(cur, nr);
    int trace_dropbear_shell_sys = 0;
    static int init_sys_trace_budget = 0;
    int sigreturn_restored = 0;
    int signal_frame_installed = 0;
    int emulated_return_normalized = 0;
    int emulated_restart_prepared = 0;
    int64_t seccomp_result = 0;
    const int trace_exec_stage = 0;
    if (cur && !cur->is_idle) {
        cur->last_syscall_nr = nr;
        cur->last_syscall_args[0] = a1;
        cur->last_syscall_args[1] = a2;
        cur->last_syscall_args[2] = a3;
        cur->last_syscall_args[3] = a4;
        cur->last_syscall_args[4] = a5;
        cur->last_syscall_args[5] = a6;
        scheduler_account_current_mode_switch();
        cur->in_syscall = 1;
    }
    if (syscall_apply_seccomp(cur, r, nr, a1, a2, a3, a4, a5, a6,
                              &seccomp_result)) {
        r->rax = (uint64_t)seccomp_result;
        goto syscall_dispatch_complete;
    }
    if (cur && cur->pid > 0 && cur->pid <= 2 &&
        init_sys_trace_budget > 0) {
        reboot_trace_puts("[init-sys-enter] nr=");
        reboot_trace_dec((int)nr);
        reboot_trace_puts(" pid=");
        reboot_trace_dec(cur->pid);
        reboot_trace_puts(" a1=");
        reboot_trace_hex(a1);
        reboot_trace_puts(" a2=");
        reboot_trace_hex(a2);
        reboot_trace_puts(" a3=");
        reboot_trace_hex(a3);
        reboot_trace_puts(" rip=");
        reboot_trace_hex(r->rip);
        reboot_trace_puts("\n");
    }
    if (trace_exec_stage && cur && cur->pid == 2 && nr == EDGE_SYS_execve) {
        reboot_trace_puts("[exec-stage] dispatch-probe after-enter\n");
    }
    if (cur && g_dropbear_debug_armed &&
        (strcmp(cur->name, "dropbear") == 0 ||
         strcmp(cur->name, "-sh") == 0 || strcmp(cur->name, "sh") == 0 || strcmp(cur->name, "busybox") == 0)) {
        trace_dropbear_shell_sys = 1;
        printf("[sshdbg] sys-enter pid=%d cmd=%s nr=%u a1=0x%x a2=0x%x a3=0x%x rip=0x%x\n",
               cur->pid, cur->name, (uint32_t)nr,
               (uint32_t)a1, (uint32_t)a2, (uint32_t)a3, (uint32_t)r->rip);
    }
    if (trace_exec_stage && cur && cur->pid == 2 && nr == EDGE_SYS_execve) {
        reboot_trace_puts("[exec-stage] dispatch-probe after-dropbear\n");
    }
    if (trace_initd_console_task(cur) &&
        (nr == SYS_clone || nr == SYS_vfork || nr == SYS_clone3)) {
        printf("[initd-spawn] pid=%d syscall nr=%u a1=0x%x a2=0x%x a3=0x%x a4=0x%x a5=0x%x\n",
               cur ? cur->pid : -1,
               (uint32_t)nr,
               (uint32_t)a1, (uint32_t)a2, (uint32_t)a3, (uint32_t)a4, (uint32_t)a5);
    }
    if (trace_exec_stage && cur && cur->pid == 2 && nr == EDGE_SYS_execve) {
        reboot_trace_puts("[exec-stage] dispatch-probe after-initd\n");
    }
    if (trace_go_sys) {
        printf("[go-sys] enter pid=%d cmd=%s nr=%u a1=0x%x a2=0x%x a3=0x%x a4=0x%x a5=0x%x a6=0x%x\n",
               cur ? cur->pid : -1,
               (cur && cur->name[0]) ? cur->name : "?",
               (uint32_t)nr,
               (uint32_t)a1, (uint32_t)a2, (uint32_t)a3,
               (uint32_t)a4, (uint32_t)a5, (uint32_t)a6);
    }
    if (trace_exec_stage && cur && cur->pid == 2 && nr == EDGE_SYS_execve) {
        reboot_trace_puts("[exec-stage] dispatch-probe after-go\n");
    }
    if (xfce_debug_task(cur) && g_xfce_sys_trace_budget-- > 0 &&
        (nr == SYS_poll || nr == SYS_ppoll || nr == SYS_select ||
         nr == SYS_pselect6 || nr == SYS_epoll_wait ||
         nr == SYS_epoll_pwait || nr == SYS_epoll_ctl ||
         nr == SYS_epoll_create || nr == SYS_epoll_create1 ||
         nr == SYS_eventfd || nr == SYS_eventfd2 ||
         nr == SYS_timerfd_create || nr == SYS_timerfd_settime ||
         nr == SYS_signalfd || nr == SYS_signalfd4 ||
         nr == SYS_clone || nr == SYS_clone3 ||
         nr == SYS_futex || nr == SYS_set_tid_address ||
         nr == SYS_socket || nr == SYS_socketpair ||
         nr == SYS_accept || nr == SYS_accept4 || nr == SYS_connect ||
         nr == SYS_recvfrom || nr == SYS_sendto || nr == SYS_recvmsg ||
         nr == SYS_sendmsg || nr == SYS_readv || nr == SYS_writev ||
         nr == EDGE_SYS_read || nr == EDGE_SYS_write ||
         nr == SYS_pipe || nr == SYS_pipe2 || nr == SYS_wait4 ||
         nr == EDGE_SYS_execve ||
         nr == SYS_nanosleep || nr == SYS_clock_nanosleep ||
         nr == SYS_fcntl || nr == SYS_ioctl)) {
        printf("[xfcedbg] sys-enter pid=%d cmd=%s nr=%u a1=0x%x a2=0x%x a3=0x%x a4=0x%x rip=0x%x\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               (uint32_t)nr, (uint32_t)a1, (uint32_t)a2,
               (uint32_t)a3, (uint32_t)a4, (uint32_t)r->rip);
    }
    if (xfce_debug_task(cur) && g_xfce_boot_path_trace_budget > 0 &&
        (nr == EDGE_SYS_open || nr == SYS_openat || nr == SYS_openat2 ||
         nr == EDGE_SYS_read || nr == EDGE_SYS_write || nr == EDGE_SYS_close ||
         nr == SYS_stat || nr == SYS_lstat || nr == SYS_fstat ||
         nr == SYS_newfstatat || nr == SYS_statx ||
         nr == SYS_access || nr == SYS_faccessat || nr == SYS_faccessat2 ||
         nr == SYS_readlinkat || nr == SYS_getdents || nr == SYS_getdents64 ||
         nr == EDGE_SYS_mkdir || nr == SYS_mkdir || nr == SYS_mkdirat ||
         nr == SYS_pipe || nr == SYS_pipe2 ||
         nr == EDGE_SYS_fork || nr == SYS_vfork || nr == SYS_clone || nr == SYS_clone3 ||
         nr == EDGE_SYS_execve || nr == SYS_wait4 ||
         nr == SYS_poll || nr == SYS_ppoll || nr == SYS_select || nr == SYS_pselect6 ||
         nr == SYS_brk || nr == SYS_mmap || nr == SYS_munmap || nr == SYS_mprotect)) {
        g_xfce_boot_path_trace_budget--;
        printf("[xfceboot] enter pid=%d cmd=%s nr=%u a1=0x%x a2=0x%x a3=0x%x a4=0x%x rip=0x%x budget=%d\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               (uint32_t)nr, (uint32_t)a1, (uint32_t)a2,
               (uint32_t)a3, (uint32_t)a4, (uint32_t)r->rip,
               g_xfce_boot_path_trace_budget);
    }
    if (trace_exec_stage && cur && cur->pid == 2 && nr == EDGE_SYS_execve) {
        reboot_trace_puts("[exec-stage] dispatch-probe after-xfce\n");
    }
    g_syscall_debug_nr = nr;
    g_syscall_debug_rip = r->rip;
    g_syscall_debug_rsp = r->rsp;
    if (trace_exec_stage && cur && cur->pid == 2 && nr == EDGE_SYS_execve) {
        reboot_trace_puts("[exec-stage] dispatch-probe before-getpid\n");
    }
    g_syscall_debug_pid = process_getpid();
    if (trace_exec_stage && cur && cur->pid == 2 && nr == EDGE_SYS_execve) {
        reboot_trace_puts("[exec-stage] dispatch-probe after-getpid\n");
    }
    if (trace_exec_stage && cur && cur->pid > 0 && cur->pid <= 2 && nr == EDGE_SYS_execve) {
        reboot_trace_puts("[exec-stage] before-switch pid=");
        reboot_trace_dec(cur->pid);
        reboot_trace_puts(" nr=");
        reboot_trace_dec((int)nr);
        reboot_trace_puts("\n");
    }

    {
        edge_linux_syscall_context_t shared = {
            .id = EDGE_LINUX_SYS_INVALID,
            .architecture = EDGE_LINUX_ARCH_X86_64,
            .route_status = EDGE_LINUX_SYSCALL_IMPLEMENTED,
            .raw_number = nr,
            .arguments = {a1, a2, a3, a4, a5, a6},
            .current_task = cur,
            .user_registers = r,
            .arch_ops = &x86_linux_syscall_ops,
            .result = 0,
        };
        if (edge_linux_syscall_dispatch(&shared) ==
            EDGE_LINUX_SYSCALL_HANDLED) {
            r->rax = (uint64_t)shared.result;
            goto syscall_dispatch_complete;
        }
    }

    switch (nr) {
        case EDGE_SYS_spawn:
            r->rax = do_sys_spawn(a1, a2, a3);
            break;
        case EDGE_SYS_getcwd:
            r->rax = do_sys_getcwd(a1, a2);
            break;
        case EDGE_SYS_chdir:
            r->rax = do_sys_chdir(a1);
            break;
        case EDGE_SYS_ls:
            r->rax = do_sys_ls(a1, a2);
            break;
        case EDGE_SYS_mkdir:
            r->rax = do_sys_mkdir(a1);
            break;
        case EDGE_SYS_touch:
            r->rax = do_sys_touch(a1);
            break;
        case EDGE_SYS_unlink:
            r->rax = do_sys_unlink(a1);
            break;
        case EDGE_SYS_cat:
            r->rax = do_sys_cat(a1);
            break;
        case EDGE_SYS_statfs:
            r->rax = do_sys_statfs(a1, a2, a3);
            break;
        case EDGE_SYS_meminfo:
            r->rax = do_sys_meminfo(a1, a2, a3);
            break;
        case EDGE_SYS_mounts:
            r->rax = do_sys_mounts();
            break;
        case EDGE_SYS_mount:
            r->rax = do_sys_mount(a1, a2, a3);
            break;
        case EDGE_SYS_shutdown:
            r->rax = do_sys_shutdown();
            break;
        case EDGE_SYS_ps:
            r->rax = do_sys_ps();
            break;
        case EDGE_SYS_kill:
            r->rax = do_sys_kill(a1, a2);
            break;
        case EDGE_SYS_sleep:
            r->rax = do_sys_sleep(a1);
            break;
        case EDGE_SYS_dmesg:
            r->rax = do_sys_dmesg();
            break;
        case EDGE_SYS_stat:
            r->rax = do_sys_stat(a1);
            break;
        case EDGE_SYS_mv:
            r->rax = do_sys_mv(a1, a2);
            break;
        case EDGE_SYS_writefile:
            r->rax = do_sys_writefile(a1, a2, a3);
            break;
        case EDGE_SYS_readfile:
            r->rax = do_sys_readfile(a1, a2, a3);
            break;

        case SYS_iopl:
            r->rax = do_sys_iopl(a1);
            break;
        case SYS_ioperm:
            r->rax = do_sys_ioperm(a1, a2, a3);
            break;
        case SYS_rt_sigreturn:
            r->rax = do_sys_rt_sigreturn(r);
            sigreturn_restored = 1;
            break;
        case SYS_arch_prctl:
            r->rax = do_sys_arch_prctl(a1, a2);
            break;
        default:
            r->rax = (uint64_t)-ENOSYS;
            break;
    }
syscall_dispatch_complete:
    {
        int group_exit_code;
        if (cur && process_current_group_exit_requested(&group_exit_code)) {
            process_exit_current(group_exit_code);
            scheduler_yield();
            for (;;) __asm__ __volatile__("sti; hlt");
        }
    }
    /*
     * A syscall boundary is also a safe process-context bottom-half point.
     * This covers workloads that remain in kernel entry paths long enough to
     * prevent the timer preemption path from giving the idle worker a turn.
     * The atomic claim keeps the common case cheap and prevents duplicate
     * polling when the idle worker already consumed the notification.
     */
    if (scheduler_take_deferred_work())
        syscall_network_poll();
    if (cur && !cur->is_idle && cur->state != TASK_ZOMBIE &&
        cur->state != TASK_UNUSED) {
        int64_t ptrace_result = (int64_t)r->rax;
        edge_linux_ptrace_syscall_exit(r, &ptrace_result);
        r->rax = (uint64_t)ptrace_result;
        cur->ptrace_live_frame = (uintptr_t)r;
    }
    if (trace_go_sys) {
        int64_t rv = (int64_t)r->rax;
        if (rv < 0) {
            printf("[go-sys] exit pid=%d cmd=%s nr=%u ret=%lld errno=%d\n",
                   cur ? cur->pid : -1,
                   (cur && cur->name[0]) ? cur->name : "?",
                   (uint32_t)nr,
                   (long long)rv, (int)(-rv));
        } else {
            printf("[go-sys] exit pid=%d cmd=%s nr=%u ret=%lld\n",
                   cur ? cur->pid : -1,
                   (cur && cur->name[0]) ? cur->name : "?",
                   (uint32_t)nr,
                   (long long)rv);
        }
    }
    if (trace_dropbear_shell_sys) {
        uint8_t *pc = user_range_ok(r->rip, 8) ? (uint8_t *)(uintptr_t)r->rip : 0;
        printf("[sshdbg] sys-exit pid=%d cmd=%s nr=%u rax=%d rip=0x%x rsp=0x%x sigchld=%u\n",
               cur ? cur->pid : -1,
               (cur && cur->name[0]) ? cur->name : "?",
               (uint32_t)nr,
               (int)(int64_t)r->rax,
               (uint32_t)r->rip,
               (uint32_t)r->rsp,
               cur ? (unsigned)((task_pending_signal_mask(cur) &
                                 edge_linux_signal_mask_bit(LINUX_SIGCHLD)) != 0) : 0);
        if (pc) {
            printf("[sshdbg] rip-bytes %x %x %x %x %x %x %x %x\n",
                   (uint32_t)pc[0], (uint32_t)pc[1], (uint32_t)pc[2], (uint32_t)pc[3],
                   (uint32_t)pc[4], (uint32_t)pc[5], (uint32_t)pc[6], (uint32_t)pc[7]);
        }
    }
    if (x11_debug_task(cur) &&
        (nr == SYS_select || nr == SYS_pselect6 || nr == SYS_poll ||
         nr == SYS_epoll_wait || nr == SYS_epoll_pwait ||
         nr == SYS_accept || nr == SYS_accept4 || nr == SYS_connect ||
         nr == SYS_recvfrom || nr == SYS_sendto || nr == SYS_recvmsg ||
         nr == SYS_sendmsg)) {
        printf("[x11dbg] sys-exit pid=%d cmd=%s nr=%u ret=%d rip=0x%x rcx=0x%x\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               (uint32_t)nr, (int)(int64_t)r->rax,
               (uint32_t)r->rip, (uint32_t)r->rcx);
    }
    if (xfce_debug_task(cur) && g_xfce_sys_trace_budget-- > 0 &&
        (nr == SYS_poll || nr == SYS_ppoll || nr == SYS_select ||
         nr == SYS_pselect6 || nr == SYS_epoll_wait ||
         nr == SYS_epoll_pwait || nr == SYS_epoll_ctl ||
         nr == SYS_epoll_create || nr == SYS_epoll_create1 ||
         nr == SYS_eventfd || nr == SYS_eventfd2 ||
         nr == SYS_timerfd_create || nr == SYS_timerfd_settime ||
         nr == SYS_signalfd || nr == SYS_signalfd4 ||
         nr == SYS_clone || nr == SYS_clone3 ||
         nr == SYS_futex || nr == SYS_set_tid_address ||
         nr == SYS_socket || nr == SYS_socketpair ||
         nr == SYS_accept || nr == SYS_accept4 || nr == SYS_connect ||
         nr == SYS_recvfrom || nr == SYS_sendto || nr == SYS_recvmsg ||
         nr == SYS_sendmsg || nr == SYS_readv || nr == SYS_writev ||
         nr == EDGE_SYS_read || nr == EDGE_SYS_write ||
         nr == SYS_pipe || nr == SYS_pipe2 || nr == SYS_wait4 ||
         nr == EDGE_SYS_execve ||
         nr == SYS_fcntl || nr == SYS_ioctl)) {
        printf("[xfcedbg] sys-exit pid=%d cmd=%s nr=%u ret=%d rip=0x%x\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               (uint32_t)nr, (int)(int64_t)r->rax, (uint32_t)r->rip);
    }
    if (xfce_debug_task(cur) && g_xfce_boot_path_trace_budget > 0 &&
        (nr == EDGE_SYS_open || nr == SYS_openat || nr == SYS_openat2 ||
         nr == EDGE_SYS_read || nr == EDGE_SYS_write || nr == EDGE_SYS_close ||
         nr == SYS_stat || nr == SYS_lstat || nr == SYS_fstat ||
         nr == SYS_newfstatat || nr == SYS_statx ||
         nr == SYS_access || nr == SYS_faccessat || nr == SYS_faccessat2 ||
         nr == SYS_readlinkat || nr == SYS_getdents || nr == SYS_getdents64 ||
         nr == EDGE_SYS_mkdir || nr == SYS_mkdir || nr == SYS_mkdirat ||
         nr == SYS_pipe || nr == SYS_pipe2 ||
         nr == EDGE_SYS_fork || nr == SYS_vfork || nr == SYS_clone || nr == SYS_clone3 ||
         nr == EDGE_SYS_execve || nr == SYS_wait4 ||
         nr == SYS_poll || nr == SYS_ppoll || nr == SYS_select || nr == SYS_pselect6 ||
         nr == SYS_brk || nr == SYS_mmap || nr == SYS_munmap || nr == SYS_mprotect)) {
        g_xfce_boot_path_trace_budget--;
        printf("[xfceboot] exit pid=%d cmd=%s nr=%u ret=%d rip=0x%x budget=%d\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               (uint32_t)nr, (int)(int64_t)r->rax, (uint32_t)r->rip,
               g_xfce_boot_path_trace_budget);
    }
    {
        static int gui_einval_budget = EDGE_XFCE_TRACE ? 96 : 0;
        if (gui_einval_budget > 0 && gui_einval_trace_task(cur) &&
            (int64_t)r->rax == -(int64_t)EINVAL) {
            gui_einval_budget--;
            printf("[gui-einval] pid=%d cmd=%s nr=%u ret=-EINVAL a1=0x%x a2=0x%x a3=0x%x a4=0x%x a5=0x%x a6=0x%x rip=0x%x budget=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   (uint32_t)nr,
                   (uint32_t)a1, (uint32_t)a2, (uint32_t)a3,
                   (uint32_t)a4, (uint32_t)a5, (uint32_t)a6,
                   (uint32_t)r->rip, gui_einval_budget);
        }
    }
    if (!syscall_ptrace_single_step(cur))
        r->rflags &= ~(1ull << 8);
    if (cur && cur->pid > 0 && cur->pid <= 2 &&
        init_sys_trace_budget > 0) {
        reboot_trace_puts("[init-sys-exit] nr=");
        reboot_trace_dec((int)nr);
        reboot_trace_puts(" pid=");
        reboot_trace_dec(cur->pid);
        reboot_trace_puts(" ret=");
        reboot_trace_hex(r->rax);
        reboot_trace_puts(" rip=");
        reboot_trace_hex(r->rip);
        reboot_trace_puts("\n");
        init_sys_trace_budget--;
    }
    if (cur && !cur->is_idle) {
        cur->last_syscall_ret = (int64_t)r->rax;
        /*
         * Keep a small per-task syscall ring for Linux ABI debugging.  GLib
         * and Pango frequently park in futex after the syscall that exposed the
         * real incompatibility; /proc snapshots need that lead-in without
         * enabling high-volume serial tracing.
         */
        {
            uint32_t hp = cur->syscall_history_pos++ % TASK_SYSCALL_HISTORY;
            cur->syscall_history_nr[hp] = nr;
            cur->syscall_history_arg1[hp] = a1;
            cur->syscall_history_arg2[hp] = a2;
            cur->syscall_history_arg3[hp] = a3;
            cur->syscall_history_arg4[hp] = a4;
            cur->syscall_history_arg5[hp] = a5;
            cur->syscall_history_arg6[hp] = a6;
            cur->syscall_history_ret[hp] = (int64_t)r->rax;
        }
        scheduler_account_current_mode_switch();
        cur->in_syscall = 0;
    }
    if (syscall_requires_fixed_mapping_refresh(nr))
        process_refresh_fixed_user_mappings(cur);
    if (emulated_syscall && !sigreturn_restored &&
        (int64_t)r->rax == -(int64_t)EINTR &&
        syscall_signal_restart_allowed(nr) && signal_pending_restartable_syscall()) {
        uint64_t syscall_rip = r->rcx >= 2 ? r->rcx - 2 : 0;
        if (user_range_ok(syscall_rip, 2)) {
            const uint8_t *pc = (const uint8_t *)(uintptr_t)syscall_rip;
            if (pc[0] == 0x0f && pc[1] == 0x05) {
                /*
                 * Linux delivers the handler, then restarts SA_RESTART syscalls
                 * from the original syscall instruction after rt_sigreturn.
                 * The #UD syscall emulator enters here with rcx already set to
                 * the post-syscall RIP, so rebuild the user frame explicitly.
                 *
                 * rt_sigreturn itself restores the interrupted syscall's RAX,
                 * which may legitimately be -EINTR.  Never reinterpret that
                 * restored value as the result of syscall 15: doing so rewinds
                 * to an unrelated userspace SYSCALL instruction and attempts a
                 * second rt_sigreturn from an ordinary application stack.
                 */
                r->rax = nr;
                r->rip = syscall_rip;
                emulated_restart_prepared = 1;
            }
        }
    }
    if (emulated_syscall && !sigreturn_restored && !emulated_restart_prepared &&
        user_range_ok(r->rcx, 1)) {
        /*
         * The #UD syscall emulator enters with RIP still pointing at the
         * userspace syscall instruction and RCX/R11 holding the architectural
         * post-syscall return state.  If a signal is delivered before this
         * normalization, rt_sigreturn restores the interrupted frame to the
         * syscall instruction with the completed syscall result in RAX.  GLib
         * ppoll/futex paths then re-enter through stale state and corrupt their
         * event-source bookkeeping.  Linux-visible signal frames for ordinary
         * non-restarted syscalls must resume after the syscall instruction.
         */
        r->rip = r->rcx;
        r->rflags = (r->r11 | 0x2ull) & ~(1ull << 8);
        if (syscall_ptrace_single_step(cur)) r->rflags |= 1ull << 8;
        emulated_return_normalized = 1;
    }
    /*
     * Linux performs rseq notify-resume work before installing a signal frame.
     * Any blocking syscall has already resumed through this task's live trap
     * frame, so this also observes scheduler preemption that occurred inside
     * the syscall without keeping architecture-private rseq state.
     */
    syscall_rseq_prepare_user_return(&r->rip);
    signal_frame_installed = sigreturn_restored ? 0 : maybe_deliver_signal_on_sysret(r);
    if (!signal_frame_installed && !sigreturn_restored) {
        task_t *mask_task = process_current_task();
        if (mask_task && mask_task->signal_restore_mask_pending) {
            task_restore_wait_sigmask_unless(mask_task, 0);
        }
    }
    if (emulated_syscall && !signal_frame_installed && !sigreturn_restored &&
        !emulated_return_normalized && user_range_ok(r->rcx, 1)) {
        r->rip = r->rcx;
        r->rflags = (r->r11 | 0x2ull) & ~(1ull << 8);
        if (syscall_ptrace_single_step(cur)) r->rflags |= 1ull << 8;
    } else {
        if (!syscall_ptrace_single_step(cur)) r->rflags &= ~(1ull << 8);
    }
    {
        task_t *cur = process_current_task();
        if (cur && !cur->is_idle && cur->state == TASK_ZOMBIE) {
            scheduler_yield();
            for (;;) __asm__ __volatile__("sti; hlt");
        }
        if (cur && !cur->is_idle &&
            syscall_should_yield_after_socket_io(
                nr, a1, (int64_t)r->rax)) {
            /*
             * Linux can preempt a task between dense I/O syscalls.  EdgeOS is
             * still largely cooperative at syscall boundaries.  Yield after
             * successful accept and socket send/recv paths where networking
             * callbacks may need another task to run.  A nonblocking EAGAIN
             * made no progress and must return directly; yielding on every
             * failed browser probe creates a context-switch storm.  Keep hot
             * readiness probes and vector read/write paths out of this list:
             * fd/socket helpers already wake their peers directly.
             */
            scheduler_yield();
        }
        if (cur && !cur->is_idle && cur->need_resched) {
            scheduler_yield();
        }
    }
    /*
     * FS base is part of Linux thread context.  User TLS consumers such as
     * musl pthreads derive futex addresses from FS-relative thread state; if
     * a syscall path returns with a stale hardware FS base, userland can issue
     * futex waits against low/null-derived addresses (for example 0x38) and
     * spin on EFAULT.  Reload the saved task FS base after any syscall-side
     * scheduling or signal work so every return-to-user observes the current
     * task's TLS base.
     */
    if (cur && !cur->is_idle) {
        (void)process_set_fs_base(process_get_fs_base());
    }
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    bsd_kthread_pump();
#endif
    process_reap_detached_zombie_threads_periodic("sysret");
    syscall_vfs_writeback_poll();
    syscall_maybe_pump_fbdev_mmap();
    syscall_trace(nr, (int64_t)r->rax);
    g_syscall_debug_nr = 0;
    g_syscall_debug_rip = 0;
    g_syscall_debug_rsp = 0;
    g_syscall_debug_pid = 0;
    if (cur && cur->ptrace_live_frame == (uintptr_t)r)
        cur->ptrace_live_frame = 0;
}

void syscall_init(void) {
    (void)kernel_anonymous_fd_backend_register(
        &x86_anonymous_fd_backend_ops, 0);
    if (kernel_fd_backend_register(&x86_fd_backend_ops, 0) < 0) {
        printf("[syscall] ERROR fd backend registration failed\n");
        for (;;) __asm__ __volatile__("cli; hlt");
    }
    if (kernel_socket_rights_default_pool_initialize() < 0) {
        printf("[syscall] ERROR SCM_RIGHTS pool initialization failed\n");
        for (;;) __asm__ __volatile__("cli; hlt");
    }
    (void)kernel_epoll_backend_register(&x86_epoll_backend_ops, 0);
    (void)kernel_posix_timer_backend_register(
        &x86_posix_timer_backend_ops, 0);
    (void)kernel_itimer_backend_register(&x86_itimer_backend_ops, 0);
    (void)kernel_futex_backend_register(&x86_futex_backend_ops, 0);
    if (vfs_inode_lifetime_backend_register(
            &x86_mmap_lifetime_backend_ops, 0) < 0)
        printf("[mmap-file-cache] ERROR inode lifetime backend unavailable\n");
    tty_reset_defaults();
    net_init_defaults();
    process_register_user_vma_backing_hooks(file_vma_retain,
                                            file_vma_release);
    process_register_task_exit_hook(syscall_task_exit_cleanup);
    process_register_task_zombie_hook(syscall_task_zombie_cleanup);
    vfs_mount_namespace_set_change_notifier(fd_mount_event_notify);
    isr_register_interrupt_handler(128, edgeos_x86_64_syscall_dispatch);
    edgeos_x86_64_syscall_init();
}

int syscall_runtime_init(void) {
    uint64_t table_bytes = (uint64_t)EDGE_MAX_SOCKETS * sizeof(g_sockets[0]);
    uint32_t table_pages = (uint32_t)((table_bytes + 4095ULL) / 4096ULL);
    uint64_t rx_bytes = (uint64_t)EDGE_MAX_SOCKETS * EDGE_SOCKET_RX_BUF_SIZE;
    uint32_t rx_pages = (uint32_t)((rx_bytes + 4095ULL) / 4096ULL);

    g_sockets = 0;
    g_socket_table_phys = 0;
    g_socket_table_pages = 0;
    g_socket_table_ready = 0;
    g_socket_rx_storage = 0;
    g_socket_rx_storage_phys = 0;
    g_socket_rx_storage_pages = 0;
    g_socket_rx_storage_ready = 0;
    memset(g_socket_slot_claims, 0, sizeof(g_socket_slot_claims));
    kernel_socket_connect_deadline_tracker_initialize(
        &g_socket_connect_deadline_tracker);

    g_fd_proc_cache_count = 0;
    g_fd_proc_cache_reserved = 0;
    for (uint32_t index = 0; index < EDGE_FD_PROC_CACHE_CAPACITY; ++index) {
        edge_fd_proc_t *process = 0;
        uint32_t pages =
            (uint32_t)((sizeof(*process) + 4095u) / 4096u);

        if (process_kernel_runtime_reserve_pages(
                pages, (void **)&process, 0) < 0 || !process)
            break;
        g_fd_proc_cache[g_fd_proc_cache_count++] = process;
        g_fd_proc_cache_reserved++;
    }
    if (g_fd_proc_cache_reserved == 0u) {
        printf("[fd-table-cache] ERROR boot reserve unavailable\n");
        return -1;
    }
    printf("[fd-table-cache] reserved=%u table=%u KiB total=%u KiB\n",
           g_fd_proc_cache_reserved,
           (uint32_t)(sizeof(edge_fd_proc_t) / 1024u),
           (uint32_t)(((uint64_t)g_fd_proc_cache_reserved *
                       sizeof(edge_fd_proc_t)) / 1024u));

    if (process_kernel_runtime_reserve_pages(table_pages, (void **)&g_sockets,
                                             &g_socket_table_phys) < 0 ||
        !g_sockets) {
        printf("[socket-table] ERROR runtime carve failed sockets=%u bytes=%u KiB pages=%u\n",
               (uint32_t)EDGE_MAX_SOCKETS, (uint32_t)(table_bytes / 1024ULL), table_pages);
        return -1;
    }
    g_socket_table_pages = table_pages;
    g_socket_table_ready = 1;

    if (process_kernel_runtime_reserve_pages(
            rx_pages, (void **)&g_socket_rx_storage,
            &g_socket_rx_storage_phys) < 0 ||
        !g_socket_rx_storage) {
        printf("[socket-rx] ERROR runtime carve failed sockets=%u bytes=%u KiB pages=%u\n",
               (uint32_t)EDGE_MAX_SOCKETS, (uint32_t)(rx_bytes / 1024ULL), rx_pages);
        g_socket_table_ready = 0;
        return -1;
    }
    g_socket_rx_storage_pages = rx_pages;
    g_socket_rx_storage_ready = 1;
    /*
     * The reserved pool can contain firmware-era RAM contents.  Only the
     * allocation marker is observed before socket_alloc() clears the complete
     * descriptor and its private RX slice, so initialize those markers without
     * zeroing more than 552 MiB twice during every boot.
     */
    for (uint32_t i = 0; i < EDGE_MAX_SOCKETS; ++i)
        g_sockets[i].used = 0;
    printf("[socket-table] runtime sockets=%u bytes=%u KiB pages=%u phys=0x%llx kva=%p socket_size=%u\n",
           (uint32_t)EDGE_MAX_SOCKETS,
           (uint32_t)(table_bytes / 1024ULL),
           g_socket_table_pages,
           (unsigned long long)g_socket_table_phys,
           g_sockets,
           (uint32_t)sizeof(g_sockets[0]));
    printf("[socket-rx] runtime sockets=%u cap=%u bytes=%u KiB pages=%u phys=0x%llx kva=%p\n",
           (uint32_t)EDGE_MAX_SOCKETS,
           (uint32_t)EDGE_SOCKET_RX_BUF_SIZE,
           (uint32_t)(rx_bytes / 1024ULL),
           g_socket_rx_storage_pages,
           (unsigned long long)g_socket_rx_storage_phys,
           g_socket_rx_storage);
    return 0;
}

void syscall_tty_irq_poll(void) {
    uint32_t pending = keyboard_take_sigint_pending();
    edge_console_line_t *line;
    /*
     * Do not poll NICs from the timer IRQ.  lwIP is built NO_SYS and all of
     * its PCB/pbuf state must be driven from process/syscall context.  Polling
     * e1000 here re-enters lwIP while apk/nginx/python are in socket syscalls,
     * corrupting saved kernel continuations and eventually jumping into .bss.
     * Network wait loops call the serialized network poll entry explicitly
     * from process context; this timer path is only for cheap wakeups.
     */
    sleep_waiters_irq_poll();
    futex_waiters_irq_poll();
    fb_console_tty_batch_maybe_flush();
    console_line_wake_input_waiters();
    if (!pending) return;
    line = console_line_state(console_line_active_vt());
    if (line &&
        (line->termios.c_lflag & LINUX_ISIG) != 0 &&
        line->session.foreground_pgid > 0) {
        (void)process_send_signal_pgid(line->session.foreground_pgid, LINUX_SIGINT);
    }
}
