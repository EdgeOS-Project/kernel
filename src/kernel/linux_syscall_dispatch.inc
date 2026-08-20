/* SPDX-License-Identifier: MPL-2.0 */
/* Generated from tools/syscalls/linux_syscall_inventory.json. */
case EDGE_LINUX_SYS_access:
case EDGE_LINUX_SYS_faccessat:
case EDGE_LINUX_SYS_faccessat2:
    context->result = edge_linux_sys_access(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_bpf:
    context->result = edge_linux_sys_bpf(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_brk:
    context->result = edge_linux_sys_brk(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_cachestat:
    context->result = edge_linux_sys_cachestat(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_capget:
    context->result = edge_linux_sys_capget(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_capset:
    context->result = edge_linux_sys_capset(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_chmod:
case EDGE_LINUX_SYS_fchmod:
case EDGE_LINUX_SYS_fchmodat:
case EDGE_LINUX_SYS_fchmodat2:
    context->result = edge_linux_sys_chmod(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_chown:
case EDGE_LINUX_SYS_fchown:
case EDGE_LINUX_SYS_fchownat:
case EDGE_LINUX_SYS_lchown:
    context->result = edge_linux_sys_chown(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_clock_getres:
case EDGE_LINUX_SYS_clock_gettime:
    context->result = edge_linux_sys_clock(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_clone:
case EDGE_LINUX_SYS_clone3:
case EDGE_LINUX_SYS_fork:
case EDGE_LINUX_SYS_vfork:
    context->result = edge_linux_sys_clone(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_copy_file_range:
    context->result = edge_linux_sys_copy_file_range(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_epoll_create:
case EDGE_LINUX_SYS_epoll_create1:
case EDGE_LINUX_SYS_epoll_ctl:
case EDGE_LINUX_SYS_epoll_pwait:
case EDGE_LINUX_SYS_epoll_pwait2:
case EDGE_LINUX_SYS_epoll_wait:
    context->result = edge_linux_sys_epoll(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_eventfd:
case EDGE_LINUX_SYS_eventfd2:
    context->result = edge_linux_sys_eventfd(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_execve:
case EDGE_LINUX_SYS_execveat:
    context->result = edge_linux_sys_exec(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_exit:
case EDGE_LINUX_SYS_exit_group:
    context->result = edge_linux_sys_exit(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_fallocate:
    context->result = edge_linux_sys_fallocate(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_close:
case EDGE_LINUX_SYS_close_range:
case EDGE_LINUX_SYS_dup:
case EDGE_LINUX_SYS_dup2:
case EDGE_LINUX_SYS_dup3:
case EDGE_LINUX_SYS_fcntl:
    context->result = edge_linux_sys_fd_control(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_fadvise64:
case EDGE_LINUX_SYS_readahead:
    context->result = edge_linux_sys_file_advice(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_fdatasync:
case EDGE_LINUX_SYS_fsync:
case EDGE_LINUX_SYS_sync:
case EDGE_LINUX_SYS_sync_file_range:
case EDGE_LINUX_SYS_syncfs:
    context->result = edge_linux_sys_file_sync(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_flock:
    context->result = edge_linux_sys_flock(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_chdir:
case EDGE_LINUX_SYS_chroot:
case EDGE_LINUX_SYS_fchdir:
case EDGE_LINUX_SYS_getcwd:
    context->result = edge_linux_sys_fs_context(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_futex:
case EDGE_LINUX_SYS_futex_requeue:
case EDGE_LINUX_SYS_futex_wait:
case EDGE_LINUX_SYS_futex_waitv:
case EDGE_LINUX_SYS_futex_wake:
    context->result = edge_linux_sys_futex(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_get_mempolicy:
    context->result = edge_linux_sys_get_mempolicy(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getcpu:
    context->result = edge_linux_sys_getcpu(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getdents64:
    context->result = edge_linux_sys_getdents64(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getpriority:
    context->result = edge_linux_sys_getpriority(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getrandom:
    context->result = edge_linux_sys_getrandom(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getrusage:
    context->result = edge_linux_sys_getrusage(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getgroups:
case EDGE_LINUX_SYS_setgroups:
    context->result = edge_linux_sys_groups(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getegid:
case EDGE_LINUX_SYS_geteuid:
case EDGE_LINUX_SYS_getgid:
case EDGE_LINUX_SYS_getpid:
case EDGE_LINUX_SYS_getppid:
case EDGE_LINUX_SYS_gettid:
case EDGE_LINUX_SYS_getuid:
    context->result = edge_linux_sys_identity(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_inotify_add_watch:
case EDGE_LINUX_SYS_inotify_init:
case EDGE_LINUX_SYS_inotify_init1:
case EDGE_LINUX_SYS_inotify_rm_watch:
    context->result = edge_linux_sys_inotify(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_pread64:
case EDGE_LINUX_SYS_preadv:
case EDGE_LINUX_SYS_preadv2:
case EDGE_LINUX_SYS_pwrite64:
case EDGE_LINUX_SYS_pwritev:
case EDGE_LINUX_SYS_pwritev2:
case EDGE_LINUX_SYS_read:
case EDGE_LINUX_SYS_readv:
case EDGE_LINUX_SYS_write:
case EDGE_LINUX_SYS_writev:
    context->result = edge_linux_sys_io(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_ioctl:
    context->result = edge_linux_sys_ioctl(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_ioprio_get:
    context->result = edge_linux_sys_ioprio_get(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_ioprio_set:
    context->result = edge_linux_sys_ioprio_set(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_alarm:
case EDGE_LINUX_SYS_getitimer:
case EDGE_LINUX_SYS_setitimer:
    context->result = edge_linux_sys_itimer(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_kcmp:
    context->result = edge_linux_sys_kcmp(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_link:
case EDGE_LINUX_SYS_linkat:
    context->result = edge_linux_sys_link(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_lseek:
    context->result = edge_linux_sys_lseek(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_madvise:
    context->result = edge_linux_sys_madvise(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_membarrier:
    context->result = edge_linux_sys_membarrier(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_memfd_create:
    context->result = edge_linux_sys_memfd_create(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mincore:
    context->result = edge_linux_sys_mincore(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mkdir:
case EDGE_LINUX_SYS_mkdirat:
    context->result = edge_linux_sys_mkdir(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mknod:
case EDGE_LINUX_SYS_mknodat:
    context->result = edge_linux_sys_mknod(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mlock:
case EDGE_LINUX_SYS_mlock2:
case EDGE_LINUX_SYS_mlockall:
case EDGE_LINUX_SYS_munlock:
case EDGE_LINUX_SYS_munlockall:
    context->result = edge_linux_sys_mlock(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mmap:
    context->result = edge_linux_sys_mmap(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mount:
case EDGE_LINUX_SYS_pivot_root:
case EDGE_LINUX_SYS_umount2:
    context->result = edge_linux_sys_mount(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_move_mount:
case EDGE_LINUX_SYS_open_tree:
case EDGE_LINUX_SYS_open_tree_attr:
    context->result = edge_linux_sys_mount_api(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_fsconfig:
case EDGE_LINUX_SYS_fsmount:
case EDGE_LINUX_SYS_fsopen:
case EDGE_LINUX_SYS_fspick:
    context->result = edge_linux_sys_mount_context(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mount_setattr:
    context->result = edge_linux_sys_mount_setattr(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_listmount:
case EDGE_LINUX_SYS_statmount:
    context->result = edge_linux_sys_mount_stat(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mprotect:
    context->result = edge_linux_sys_mprotect(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mremap:
    context->result = edge_linux_sys_mremap(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mseal:
    context->result = edge_linux_sys_mseal(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_msync:
    context->result = edge_linux_sys_msync(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_munmap:
    context->result = edge_linux_sys_munmap(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_name_to_handle_at:
    context->result = edge_linux_sys_name_to_handle_at(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_setns:
case EDGE_LINUX_SYS_unshare:
    context->result = edge_linux_sys_namespace(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_clock_nanosleep:
case EDGE_LINUX_SYS_nanosleep:
    context->result = edge_linux_sys_nanosleep(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_mbind:
case EDGE_LINUX_SYS_migrate_pages:
case EDGE_LINUX_SYS_move_pages:
case EDGE_LINUX_SYS_set_mempolicy:
case EDGE_LINUX_SYS_set_mempolicy_home_node:
    context->result = edge_linux_sys_numa_policy(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_creat:
case EDGE_LINUX_SYS_open:
case EDGE_LINUX_SYS_openat:
case EDGE_LINUX_SYS_openat2:
    context->result = edge_linux_sys_open(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_open_by_handle_at:
    context->result = edge_linux_sys_open_by_handle_at(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_personality:
    context->result = edge_linux_sys_personality(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_pidfd_getfd:
    context->result = edge_linux_sys_pidfd_getfd(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_pidfd_open:
    context->result = edge_linux_sys_pidfd_open(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_pidfd_send_signal:
    context->result = edge_linux_sys_pidfd_send_signal(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_pipe:
case EDGE_LINUX_SYS_pipe2:
    context->result = edge_linux_sys_pipe(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_pkey_alloc:
case EDGE_LINUX_SYS_pkey_free:
case EDGE_LINUX_SYS_pkey_mprotect:
    context->result = edge_linux_sys_pkey(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_poll:
case EDGE_LINUX_SYS_ppoll:
    context->result = edge_linux_sys_poll(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_timer_create:
case EDGE_LINUX_SYS_timer_delete:
case EDGE_LINUX_SYS_timer_getoverrun:
case EDGE_LINUX_SYS_timer_gettime:
case EDGE_LINUX_SYS_timer_settime:
    context->result = edge_linux_sys_posix_timer(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_prctl:
    context->result = edge_linux_sys_prctl(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getpgid:
case EDGE_LINUX_SYS_getpgrp:
case EDGE_LINUX_SYS_getsid:
case EDGE_LINUX_SYS_setpgid:
case EDGE_LINUX_SYS_setsid:
    context->result = edge_linux_sys_process_group(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_process_madvise:
    context->result = edge_linux_sys_process_madvise(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_process_mrelease:
    context->result = edge_linux_sys_process_mrelease(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_process_vm_readv:
case EDGE_LINUX_SYS_process_vm_writev:
    context->result = edge_linux_sys_process_vm(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_ptrace:
    context->result = edge_linux_sys_ptrace(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_rt_sigqueueinfo:
case EDGE_LINUX_SYS_rt_tgsigqueueinfo:
    context->result = edge_linux_sys_queued_signal(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_readlink:
case EDGE_LINUX_SYS_readlinkat:
    context->result = edge_linux_sys_readlink(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_reboot:
    context->result = edge_linux_sys_reboot(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_rename:
case EDGE_LINUX_SYS_renameat:
case EDGE_LINUX_SYS_renameat2:
    context->result = edge_linux_sys_rename(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getresgid:
case EDGE_LINUX_SYS_getresuid:
    context->result = edge_linux_sys_res_identity(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getrlimit:
case EDGE_LINUX_SYS_prlimit64:
case EDGE_LINUX_SYS_setrlimit:
    context->result = edge_linux_sys_resource_limit(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_restart_syscall:
    context->result = edge_linux_sys_restart_syscall(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_get_robust_list:
case EDGE_LINUX_SYS_set_robust_list:
    context->result = edge_linux_sys_robust_list(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_rseq:
    context->result = edge_linux_sys_rseq(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_sched_get_priority_max:
case EDGE_LINUX_SYS_sched_get_priority_min:
    context->result = edge_linux_sys_sched_priority_limit(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_sched_getaffinity:
case EDGE_LINUX_SYS_sched_getattr:
case EDGE_LINUX_SYS_sched_getparam:
case EDGE_LINUX_SYS_sched_getscheduler:
case EDGE_LINUX_SYS_sched_rr_get_interval:
case EDGE_LINUX_SYS_sched_setaffinity:
case EDGE_LINUX_SYS_sched_setattr:
case EDGE_LINUX_SYS_sched_setparam:
case EDGE_LINUX_SYS_sched_setscheduler:
case EDGE_LINUX_SYS_sched_yield:
    context->result = edge_linux_sys_scheduler(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_seccomp:
    context->result = edge_linux_sys_seccomp(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_pselect6:
case EDGE_LINUX_SYS_select:
    context->result = edge_linux_sys_select(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_sendfile:
    context->result = edge_linux_sys_sendfile(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_setfsgid:
case EDGE_LINUX_SYS_setfsuid:
case EDGE_LINUX_SYS_setgid:
case EDGE_LINUX_SYS_setregid:
case EDGE_LINUX_SYS_setresgid:
case EDGE_LINUX_SYS_setresuid:
case EDGE_LINUX_SYS_setreuid:
case EDGE_LINUX_SYS_setuid:
    context->result = edge_linux_sys_set_credentials(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_set_tid_address:
    context->result = edge_linux_sys_set_tid_address(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_setdomainname:
case EDGE_LINUX_SYS_sethostname:
    context->result = edge_linux_sys_set_uts_name(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_clock_settime:
case EDGE_LINUX_SYS_settimeofday:
    context->result = edge_linux_sys_set_wall_time(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_setpriority:
    context->result = edge_linux_sys_setpriority(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_rt_sigaction:
    context->result = edge_linux_sys_signal_action(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_sigaltstack:
    context->result = edge_linux_sys_signal_altstack(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_rt_sigprocmask:
    context->result = edge_linux_sys_signal_mask(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_rt_sigpending:
    context->result = edge_linux_sys_signal_pending(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_kill:
case EDGE_LINUX_SYS_tgkill:
case EDGE_LINUX_SYS_tkill:
    context->result = edge_linux_sys_signal_target(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_pause:
case EDGE_LINUX_SYS_rt_sigsuspend:
case EDGE_LINUX_SYS_rt_sigtimedwait:
    context->result = edge_linux_sys_signal_wait(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_signalfd:
case EDGE_LINUX_SYS_signalfd4:
    context->result = edge_linux_sys_signalfd(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_accept:
case EDGE_LINUX_SYS_accept4:
    context->result = edge_linux_sys_socket_accept(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_bind:
case EDGE_LINUX_SYS_connect:
case EDGE_LINUX_SYS_getpeername:
case EDGE_LINUX_SYS_getsockname:
    context->result = edge_linux_sys_socket_address(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_recvfrom:
case EDGE_LINUX_SYS_sendto:
    context->result = edge_linux_sys_socket_buffer(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_listen:
case EDGE_LINUX_SYS_shutdown:
case EDGE_LINUX_SYS_socket:
case EDGE_LINUX_SYS_socketpair:
    context->result = edge_linux_sys_socket_core(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_recvmsg:
case EDGE_LINUX_SYS_sendmsg:
    context->result = edge_linux_sys_socket_message(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_recvmmsg:
case EDGE_LINUX_SYS_sendmmsg:
    context->result = edge_linux_sys_socket_mmsg(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_getsockopt:
case EDGE_LINUX_SYS_setsockopt:
    context->result = edge_linux_sys_socket_option(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_splice:
    context->result = edge_linux_sys_splice(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_fstat:
case EDGE_LINUX_SYS_lstat:
case EDGE_LINUX_SYS_newfstatat:
case EDGE_LINUX_SYS_stat:
    context->result = edge_linux_sys_stat(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_fstatfs:
case EDGE_LINUX_SYS_statfs:
    context->result = edge_linux_sys_statfs(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_statx:
    context->result = edge_linux_sys_statx(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_swapoff:
case EDGE_LINUX_SYS_swapon:
    context->result = edge_linux_sys_swap(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_symlink:
case EDGE_LINUX_SYS_symlinkat:
    context->result = edge_linux_sys_symlink(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_sysinfo:
    context->result = edge_linux_sys_sysinfo(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_syslog:
    context->result = edge_linux_sys_syslog(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_shmat:
case EDGE_LINUX_SYS_shmctl:
case EDGE_LINUX_SYS_shmdt:
case EDGE_LINUX_SYS_shmget:
    context->result = edge_linux_sys_sysv_shm(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_tee:
    context->result = edge_linux_sys_tee(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_timerfd_create:
case EDGE_LINUX_SYS_timerfd_gettime:
case EDGE_LINUX_SYS_timerfd_settime:
    context->result = edge_linux_sys_timerfd(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_times:
    context->result = edge_linux_sys_times(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_ftruncate:
case EDGE_LINUX_SYS_truncate:
    context->result = edge_linux_sys_truncate(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_umask:
    context->result = edge_linux_sys_umask(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_uname:
    context->result = edge_linux_sys_uname(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_rmdir:
case EDGE_LINUX_SYS_unlink:
case EDGE_LINUX_SYS_unlinkat:
    context->result = edge_linux_sys_unlink(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_futimesat:
case EDGE_LINUX_SYS_utime:
case EDGE_LINUX_SYS_utimensat:
case EDGE_LINUX_SYS_utimes:
    context->result = edge_linux_sys_utimens(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_vmsplice:
    context->result = edge_linux_sys_vmsplice(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_wait4:
case EDGE_LINUX_SYS_waitid:
    context->result = edge_linux_sys_wait(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_gettimeofday:
case EDGE_LINUX_SYS_time:
    context->result = edge_linux_sys_wall_time(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
case EDGE_LINUX_SYS_fgetxattr:
case EDGE_LINUX_SYS_flistxattr:
case EDGE_LINUX_SYS_fremovexattr:
case EDGE_LINUX_SYS_fsetxattr:
case EDGE_LINUX_SYS_getxattr:
case EDGE_LINUX_SYS_lgetxattr:
case EDGE_LINUX_SYS_listxattr:
case EDGE_LINUX_SYS_llistxattr:
case EDGE_LINUX_SYS_lremovexattr:
case EDGE_LINUX_SYS_lsetxattr:
case EDGE_LINUX_SYS_removexattr:
case EDGE_LINUX_SYS_setxattr:
    context->result = edge_linux_sys_xattr(context);
    return EDGE_LINUX_SYSCALL_HANDLED;
