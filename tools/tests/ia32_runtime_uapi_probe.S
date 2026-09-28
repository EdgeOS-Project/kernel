/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 runtime UAPI probe. */

    .equ SYS_exit, 1
    .equ SYS_fork, 2
    .equ SYS_read, 3
    .equ SYS_write, 4
    .equ SYS_close, 6
    .equ SYS_execve, 11
    .equ SYS_uname, 122
    .equ SYS_mprotect, 125
    .equ SYS_readv, 145
    .equ SYS_writev, 146
    .equ SYS_rt_sigprocmask, 175
    .equ SYS_mmap2, 192
    .equ SYS_stat64, 195
    .equ SYS_epoll_ctl, 255
    .equ SYS_epoll_wait, 256
    .equ SYS_set_tid_address, 258
    .equ SYS_openat, 295
    .equ SYS_epoll_create1, 329
    .equ SYS_pipe2, 331
    .equ SYS_getrandom, 355
    .equ SYS_clock_gettime64, 403
    .equ SYS_futex_time64, 422
    .equ SYS_munmap, 91
    .equ AT_FDCWD, -100
    .equ PROT_READ, 1
    .equ PROT_WRITE, 2
    .equ MAP_PRIVATE, 2
    .equ MAP_ANONYMOUS, 0x20
    .equ EPOLL_CTL_ADD, 1
    .equ EPOLLIN, 1
    .equ SIG_BLOCK, 0
    .equ SIGUSR1_MASK, 0x200
    .equ FUTEX_WAKE_PRIVATE, 129

    .section .rodata
.Ltarget_path:
    .asciz "/sbin/exec-target"
.Lpipe_first:
    .ascii "EDGE"
.Lpipe_second:
    .ascii "32"
.Lfork_byte:
    .byte 0x5a
.Lfail_memory:
    .ascii "IA32_RUNTIME_UAPI_PROBE_FAIL memory\n"
.Lfail_memory_end:
.Lfail_stat:
    .ascii "IA32_RUNTIME_UAPI_PROBE_FAIL stat64\n"
.Lfail_stat_end:
.Lfail_time:
    .ascii "IA32_RUNTIME_UAPI_PROBE_FAIL time64\n"
.Lfail_time_end:
.Lfail_signal:
    .ascii "IA32_RUNTIME_UAPI_PROBE_FAIL signal\n"
.Lfail_signal_end:
.Lfail_pipe:
    .ascii "IA32_RUNTIME_UAPI_PROBE_FAIL pipe_epoll_iovec\n"
.Lfail_pipe_end:
.Lfail_misc:
    .ascii "IA32_RUNTIME_UAPI_PROBE_FAIL misc\n"
.Lfail_misc_end:
.Lfail_exec:
    .ascii "IA32_RUNTIME_UAPI_PROBE_FAIL execve\n"
.Lfail_exec_end:

    .section .data
    .balign 4
.Lwrite_iov:
    .long .Lpipe_first, 4
    .long .Lpipe_second, 2
.Lread_iov:
    .long .Lpipe_buffer, 6
.Lepoll_event:
    .long EPOLLIN
    .long 0x13572468
    .long 0x24681357
.Lsignal_mask:
    .long SIGUSR1_MASK, 0
.Lexec_argv:
    .long .Ltarget_path, 0
.Lexec_envp:
    .long 0

    .section .bss
    .balign 8
.Lpipe_fds:
    .skip 8
.Lpipe_buffer:
    .skip 8
.Lepoll_result:
    .skip 12
.Lstat_buffer:
    .skip 96
.Ltimespec:
    .skip 16
.Lold_mask:
    .skip 8
.Lrandom:
    .skip 16
.Lutsname:
    .skip 390
    .balign 4
.Ltid_word:
    .skip 4
.Lfutex_word:
    .skip 4
.Lfork_buffer:
    .skip 4

    .section .text
    .code32
    .global _start
    .type _start, @function
_start:
    movl $SYS_mmap2, %eax
    xorl %ebx, %ebx
    movl $4096, %ecx
    movl $(PROT_READ | PROT_WRITE), %edx
    movl $(MAP_PRIVATE | MAP_ANONYMOUS), %esi
    movl $-1, %edi
    xorl %ebp, %ebp
    int $0x80
    cmpl $-4095, %eax
    jae .Lmemory_failed
    movl %eax, %edi
    movl $0x32c0ffee, (%edi)
    cmpl $0x32c0ffee, (%edi)
    jne .Lmemory_failed
    movl $SYS_mprotect, %eax
    movl %edi, %ebx
    movl $4096, %ecx
    movl $PROT_READ, %edx
    int $0x80
    testl %eax, %eax
    jne .Lmemory_failed
    movl $SYS_munmap, %eax
    movl %edi, %ebx
    movl $4096, %ecx
    int $0x80
    testl %eax, %eax
    jne .Lmemory_failed

    movl $SYS_stat64, %eax
    movl $.Ltarget_path, %ebx
    movl $.Lstat_buffer, %ecx
    int $0x80
    testl %eax, %eax
    jne .Lstat_failed
    movl .Lstat_buffer + 16, %eax
    andl $0xf000, %eax
    cmpl $0x8000, %eax
    jne .Lstat_failed
    movl .Lstat_buffer + 48, %eax
    orl .Lstat_buffer + 44, %eax
    jz .Lstat_failed
    movl .Lstat_buffer + 92, %eax
    orl .Lstat_buffer + 88, %eax
    jz .Lstat_failed

    movl $SYS_clock_gettime64, %eax
    movl $1, %ebx
    movl $.Ltimespec, %ecx
    int $0x80
    testl %eax, %eax
    jne .Ltime_failed
    cmpl $1000000000, .Ltimespec + 8
    jae .Ltime_failed
    cmpl $0, .Ltimespec + 12
    jne .Ltime_failed

    movl $SYS_rt_sigprocmask, %eax
    movl $SIG_BLOCK, %ebx
    movl $.Lsignal_mask, %ecx
    movl $.Lold_mask, %edx
    movl $8, %esi
    int $0x80
    testl %eax, %eax
    jne .Lsignal_failed

    movl $SYS_pipe2, %eax
    movl $.Lpipe_fds, %ebx
    xorl %ecx, %ecx
    int $0x80
    testl %eax, %eax
    jne .Lpipe_failed
    movl $SYS_epoll_create1, %eax
    xorl %ebx, %ebx
    int $0x80
    testl %eax, %eax
    js .Lpipe_failed
    movl %eax, %ebp
    movl $SYS_epoll_ctl, %eax
    movl %ebp, %ebx
    movl $EPOLL_CTL_ADD, %ecx
    movl .Lpipe_fds, %edx
    movl $.Lepoll_event, %esi
    int $0x80
    testl %eax, %eax
    jne .Lpipe_failed
    movl $SYS_writev, %eax
    movl .Lpipe_fds + 4, %ebx
    movl $.Lwrite_iov, %ecx
    movl $2, %edx
    int $0x80
    cmpl $6, %eax
    jne .Lpipe_failed
    movl $SYS_epoll_wait, %eax
    movl %ebp, %ebx
    movl $.Lepoll_result, %ecx
    movl $1, %edx
    xorl %esi, %esi
    int $0x80
    cmpl $1, %eax
    jne .Lpipe_failed
    cmpl $EPOLLIN, .Lepoll_result
    jne .Lpipe_failed
    cmpl $0x13572468, .Lepoll_result + 4
    jne .Lpipe_failed
    cmpl $0x24681357, .Lepoll_result + 8
    jne .Lpipe_failed
    movl $SYS_readv, %eax
    movl .Lpipe_fds, %ebx
    movl $.Lread_iov, %ecx
    movl $1, %edx
    int $0x80
    cmpl $6, %eax
    jne .Lpipe_failed
    cmpl $0x45474445, .Lpipe_buffer
    jne .Lpipe_failed
    cmpw $0x3233, .Lpipe_buffer + 4
    jne .Lpipe_failed
    movl $SYS_close, %eax
    movl %ebp, %ebx
    int $0x80
    movl $SYS_close, %eax
    movl .Lpipe_fds, %ebx
    int $0x80
    movl $SYS_close, %eax
    movl .Lpipe_fds + 4, %ebx
    int $0x80

    movl $SYS_set_tid_address, %eax
    movl $.Ltid_word, %ebx
    int $0x80
    testl %eax, %eax
    jle .Lmisc_failed
    movl $SYS_futex_time64, %eax
    movl $.Lfutex_word, %ebx
    movl $FUTEX_WAKE_PRIVATE, %ecx
    movl $1, %edx
    xorl %esi, %esi
    xorl %edi, %edi
    xorl %ebp, %ebp
    int $0x80
    testl %eax, %eax
    jne .Lmisc_failed
    movl $SYS_getrandom, %eax
    movl $.Lrandom, %ebx
    movl $16, %ecx
    xorl %edx, %edx
    int $0x80
    cmpl $16, %eax
    jne .Lmisc_failed
    movl $SYS_uname, %eax
    movl $.Lutsname, %ebx
    int $0x80
    testl %eax, %eax
    jne .Lmisc_failed
    cmpb $'L', .Lutsname
    jne .Lmisc_failed
    movl $SYS_openat, %eax
    movl $AT_FDCWD, %ebx
    movl $.Ltarget_path, %ecx
    xorl %edx, %edx
    xorl %esi, %esi
    int $0x80
    testl %eax, %eax
    js .Lmisc_failed
    movl %eax, %ebx
    movl $SYS_close, %eax
    int $0x80

    movl $SYS_pipe2, %eax
    movl $.Lpipe_fds, %ebx
    xorl %ecx, %ecx
    int $0x80
    testl %eax, %eax
    jne .Lmisc_failed
    movl $SYS_fork, %eax
    int $0x80
    testl %eax, %eax
    js .Lmisc_failed
    jz .Lfork_child
    movl $SYS_close, %eax
    movl .Lpipe_fds + 4, %ebx
    int $0x80
    movl $SYS_read, %eax
    movl .Lpipe_fds, %ebx
    movl $.Lfork_buffer, %ecx
    movl $1, %edx
    int $0x80
    cmpl $1, %eax
    jne .Lmisc_failed
    cmpb $0x5a, .Lfork_buffer
    jne .Lmisc_failed
    movl $SYS_close, %eax
    movl .Lpipe_fds, %ebx
    int $0x80
    jmp .Lexec
.Lfork_child:
    movl $SYS_close, %eax
    movl .Lpipe_fds, %ebx
    int $0x80
    movl $SYS_write, %eax
    movl .Lpipe_fds + 4, %ebx
    movl $.Lfork_byte, %ecx
    movl $1, %edx
    int $0x80
    xorl %ebx, %ebx
    movl $SYS_exit, %eax
    int $0x80

.Lexec:
    movl $SYS_execve, %eax
    movl $.Ltarget_path, %ebx
    movl $.Lexec_argv, %ecx
    movl $.Lexec_envp, %edx
    int $0x80
.Lexec_failed:
    movl $.Lfail_exec, %ecx
    movl $.Lfail_exec_end - .Lfail_exec, %edx
    jmp .Lfail
.Lmemory_failed:
    movl $.Lfail_memory, %ecx
    movl $.Lfail_memory_end - .Lfail_memory, %edx
    jmp .Lfail
.Lstat_failed:
    movl $.Lfail_stat, %ecx
    movl $.Lfail_stat_end - .Lfail_stat, %edx
    jmp .Lfail
.Ltime_failed:
    movl $.Lfail_time, %ecx
    movl $.Lfail_time_end - .Lfail_time, %edx
    jmp .Lfail
.Lsignal_failed:
    movl $.Lfail_signal, %ecx
    movl $.Lfail_signal_end - .Lfail_signal, %edx
    jmp .Lfail
.Lpipe_failed:
    movl $.Lfail_pipe, %ecx
    movl $.Lfail_pipe_end - .Lfail_pipe, %edx
    jmp .Lfail
.Lmisc_failed:
    movl $.Lfail_misc, %ecx
    movl $.Lfail_misc_end - .Lfail_misc, %edx
.Lfail:
    movl $2, %ebx
    movl $SYS_write, %eax
    int $0x80
    movl $1, %ebx
    movl $SYS_exit, %eax
    int $0x80

    .section .note.GNU-stack,"",@progbits
