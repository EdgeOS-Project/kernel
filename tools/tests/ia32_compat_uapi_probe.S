/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 compatibility-layout UAPI probe. */

    .equ SYS_exit, 1
    .equ SYS_read, 3
    .equ SYS_write, 4
    .equ SYS_close, 6
    .equ SYS_munmap, 91
    .equ SYS_mmap2, 192
    .equ SYS_io_setup, 245
    .equ SYS_io_destroy, 246
    .equ SYS_io_getevents, 247
    .equ SYS_io_submit, 248
    .equ SYS_openat, 295
    .equ SYS_unlinkat, 301
    .equ SYS_move_pages, 317
    .equ SYS_pipe2, 331
    .equ SYS_sendmmsg, 345
    .equ SYS_socketpair, 360
    .equ SYS_setsockopt, 366
    .equ SYS_recvmsg, 372
    .equ SYS_ioctl, 54

    .equ AT_FDCWD, -100
    .equ PROT_READ, 1
    .equ PROT_WRITE, 2
    .equ MAP_PRIVATE, 2
    .equ MAP_ANONYMOUS, 0x20
    .equ O_RDWR, 2
    .equ O_CREAT, 0100
    .equ AF_UNIX, 1
    .equ SOCK_STREAM, 1
    .equ SOL_SOCKET, 1
    .equ SO_ATTACH_FILTER, 26
    .equ FIONBIO, 0x5421
    .equ IOCB_CMD_FSYNC, 2

    .section .rodata
.Lpath:
    .asciz "/ia32-compat-uapi-probe"
.Lpayload_left:
    .ascii "ia32"
.Lpayload_right:
    .ascii "-compat"
.Lpass:
    .ascii "IA32_COMPAT_UAPI_PROBE_PASS\n"
.Lpass_end:
.Lfail_aio:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL aio_open\n"
.Lfail_aio_end:
.Lfail_aio_setup:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL aio_setup\n"
.Lfail_aio_setup_end:
.Lfail_aio_submit:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL aio_submit\n"
.Lfail_aio_submit_end:
.Lfail_aio_getevents:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL aio_getevents\n"
.Lfail_aio_getevents_end:
.Lfail_aio_result:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL aio_result\n"
.Lfail_aio_result_end:
.Lfail_aio_destroy:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL aio_destroy\n"
.Lfail_aio_destroy_end:
.Lfail_numa:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL move_pages\n"
.Lfail_numa_end:
.Lfail_ioctl:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL ioctl\n"
.Lfail_ioctl_end:
.Lfail_socket:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL socket_message\n"
.Lfail_socket_end:
.Lfail_filter:
    .ascii "IA32_COMPAT_UAPI_PROBE_FAIL socket_filter\n"
.Lfail_filter_end:

    .section .data
    .balign 8
.Laio_context:
    .long 0
.Laio_descriptor:
    .long -1
.Laio_list:
    .long .Laio_control
.Laio_control:
    .quad 0x1122334455667788
    .long 0
    .long 0
    .word IOCB_CMD_FSYNC
    .word 0
    .long 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .long 0
    .long 0
.Laio_timeout32:
    .long 1, 0
.Lsend_iov:
    .long .Lpayload_left, 4
    .long .Lpayload_right, 7
.Lrecv_iov:
    .long .Lreceive_left, 4
    .long .Lreceive_right, 7
.Lsend_message:
    .long 0, 0
    .long .Lsend_iov, 2
    .long 0, 0, 0
    .long 0
.Lrecv_header:
    .long 0, 0
    .long .Lrecv_iov, 2
    .long 0, 0, 0
.Lfilter_instruction:
    .word 0x06
    .byte 0, 0
    .long 0xffffffff
.Lfilter_program:
    .word 1, 0
    .long .Lfilter_instruction
.Lio_enabled:
    .long 1

    .section .bss
    .balign 8
.Laio_event:
    .skip 32
.Lpage_status:
    .skip 4
.Lpage_list:
    .skip 4
.Lpipe_fds:
    .skip 8
.Lsocket_fds:
    .skip 8
.Lreceive_left:
    .skip 4
.Lreceive_right:
    .skip 8

    .section .text
    .code32
    .global _start
    .type _start, @function
_start:
    movl $SYS_openat, %eax
    movl $AT_FDCWD, %ebx
    movl $.Lpath, %ecx
    movl $(O_CREAT | O_RDWR), %edx
    movl $0600, %esi
    int $0x80
    testl %eax, %eax
    js .Laio_failed
    movl %eax, .Laio_descriptor

    movl $SYS_io_setup, %eax
    movl $2, %ebx
    movl $.Laio_context, %ecx
    int $0x80
    testl %eax, %eax
    jne .Laio_setup_failed
    movl .Laio_descriptor, %eax
    movl %eax, .Laio_control + 20
    movl $SYS_io_submit, %eax
    movl .Laio_context, %ebx
    movl $1, %ecx
    movl $.Laio_list, %edx
    int $0x80
    cmpl $1, %eax
    jne .Laio_submit_failed
    movl $SYS_io_getevents, %eax
    movl .Laio_context, %ebx
    movl $1, %ecx
    movl $1, %edx
    movl $.Laio_event, %esi
    movl $.Laio_timeout32, %edi
    int $0x80
    cmpl $1, %eax
    jne .Laio_getevents_failed
    movl .Laio_event + 16, %eax
    orl .Laio_event + 20, %eax
    jne .Laio_result_failed
    movl $SYS_io_destroy, %eax
    movl .Laio_context, %ebx
    int $0x80
    testl %eax, %eax
    jne .Laio_destroy_result_failed
    movl $SYS_close, %eax
    movl .Laio_descriptor, %ebx
    int $0x80
    movl $SYS_unlinkat, %eax
    movl $AT_FDCWD, %ebx
    movl $.Lpath, %ecx
    xorl %edx, %edx
    int $0x80

    movl $SYS_mmap2, %eax
    xorl %ebx, %ebx
    movl $4096, %ecx
    movl $(PROT_READ | PROT_WRITE), %edx
    movl $(MAP_PRIVATE | MAP_ANONYMOUS), %esi
    movl $-1, %edi
    xorl %ebp, %ebp
    int $0x80
    cmpl $-4095, %eax
    jae .Lnuma_failed
    movl %eax, %edi
    movl $0x32c0ffee, (%edi)
    movl %edi, .Lpage_list
    movl $-1, .Lpage_status
    movl $SYS_move_pages, %eax
    xorl %ebx, %ebx
    movl $1, %ecx
    movl $.Lpage_list, %edx
    xorl %esi, %esi
    movl $.Lpage_status, %edi
    xorl %ebp, %ebp
    int $0x80
    testl %eax, %eax
    jne .Lnuma_failed
    cmpl $0, .Lpage_status
    jne .Lnuma_failed
    movl $SYS_munmap, %eax
    movl .Lpage_list, %ebx
    movl $4096, %ecx
    int $0x80

    movl $SYS_pipe2, %eax
    movl $.Lpipe_fds, %ebx
    xorl %ecx, %ecx
    int $0x80
    testl %eax, %eax
    jne .Lioctl_failed
    movl $SYS_ioctl, %eax
    movl .Lpipe_fds, %ebx
    movl $FIONBIO, %ecx
    movl $.Lio_enabled, %edx
    int $0x80
    testl %eax, %eax
    jne .Lioctl_failed
    movl $SYS_close, %eax
    movl .Lpipe_fds, %ebx
    int $0x80
    movl $SYS_close, %eax
    movl .Lpipe_fds + 4, %ebx
    int $0x80

    movl $SYS_socketpair, %eax
    movl $AF_UNIX, %ebx
    movl $SOCK_STREAM, %ecx
    xorl %edx, %edx
    movl $.Lsocket_fds, %esi
    int $0x80
    testl %eax, %eax
    jne .Lsocket_failed
    movl $SYS_sendmmsg, %eax
    movl .Lsocket_fds, %ebx
    movl $.Lsend_message, %ecx
    movl $1, %edx
    xorl %esi, %esi
    int $0x80
    cmpl $1, %eax
    jne .Lsocket_failed
    cmpl $11, .Lsend_message + 28
    jne .Lsocket_failed
    movl $SYS_recvmsg, %eax
    movl .Lsocket_fds + 4, %ebx
    movl $.Lrecv_header, %ecx
    xorl %edx, %edx
    int $0x80
    cmpl $11, %eax
    jne .Lsocket_failed
    cmpl $0x32336169, .Lreceive_left
    jne .Lsocket_failed
    cmpl $0x6d6f632d, .Lreceive_right
    jne .Lsocket_failed
    cmpw $0x6170, .Lreceive_right + 4
    jne .Lsocket_failed
    cmpb $'t', .Lreceive_right + 6
    jne .Lsocket_failed

    movl $SYS_setsockopt, %eax
    movl .Lsocket_fds, %ebx
    movl $SOL_SOCKET, %ecx
    movl $SO_ATTACH_FILTER, %edx
    movl $.Lfilter_program, %esi
    movl $8, %edi
    int $0x80
    testl %eax, %eax
    jne .Lfilter_failed
    movl $SYS_close, %eax
    movl .Lsocket_fds, %ebx
    int $0x80
    movl $SYS_close, %eax
    movl .Lsocket_fds + 4, %ebx
    int $0x80

    movl $1, %ebx
    movl $.Lpass, %ecx
    movl $.Lpass_end - .Lpass, %edx
    movl $SYS_write, %eax
    int $0x80
    xorl %ebx, %ebx
    movl $SYS_exit, %eax
    int $0x80

.Laio_setup_failed:
    movl $.Lfail_aio_setup, %ecx
    movl $.Lfail_aio_setup_end - .Lfail_aio_setup, %edx
    jmp .Lfail
.Laio_submit_failed:
    movl $.Lfail_aio_submit, %ecx
    movl $.Lfail_aio_submit_end - .Lfail_aio_submit, %edx
    jmp .Laio_destroy_then_fail
.Laio_getevents_failed:
    movl $.Lfail_aio_getevents, %ecx
    movl $.Lfail_aio_getevents_end - .Lfail_aio_getevents, %edx
    jmp .Laio_destroy_then_fail
.Laio_result_failed:
    movl $.Lfail_aio_result, %ecx
    movl $.Lfail_aio_result_end - .Lfail_aio_result, %edx
    jmp .Laio_destroy_then_fail
.Laio_destroy_result_failed:
    movl $.Lfail_aio_destroy, %ecx
    movl $.Lfail_aio_destroy_end - .Lfail_aio_destroy, %edx
    jmp .Lfail
.Laio_destroy_then_fail:
    pushl %ecx
    pushl %edx
    movl $SYS_io_destroy, %eax
    movl .Laio_context, %ebx
    int $0x80
    popl %edx
    popl %ecx
    jmp .Lfail
.Laio_failed:
    movl $.Lfail_aio, %ecx
    movl $.Lfail_aio_end - .Lfail_aio, %edx
    jmp .Lfail
.Lnuma_failed:
    movl $.Lfail_numa, %ecx
    movl $.Lfail_numa_end - .Lfail_numa, %edx
    jmp .Lfail
.Lioctl_failed:
    movl $.Lfail_ioctl, %ecx
    movl $.Lfail_ioctl_end - .Lfail_ioctl, %edx
    jmp .Lfail
.Lsocket_failed:
    movl $.Lfail_socket, %ecx
    movl $.Lfail_socket_end - .Lfail_socket, %edx
    jmp .Lfail
.Lfilter_failed:
    movl $.Lfail_filter, %ecx
    movl $.Lfail_filter_end - .Lfail_filter, %edx
.Lfail:
    movl $2, %ebx
    movl $SYS_write, %eax
    int $0x80
    movl $1, %ebx
    movl $SYS_exit, %eax
    int $0x80

    .section .note.GNU-stack,"",@progbits
