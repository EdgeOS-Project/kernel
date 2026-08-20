#include "sys/syscall.h"

#include "console.h"
#include "dev/fbdev.h"
#include "dev/devtmpfs.h"
#include "dev/memdev.h"
#include "fb.h"
#include "fb_console.h"
#include "elf/elf_loader.h"
#include "arch/x86_64/io_ports.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/isr.h"
#include "arch/x86_64/page_table.h"
#include "arch/x86_64/signal.h"
#include "arch/x86_64/syscall.h"
#include "arch/x86_64/user_layout.h"
#include "keyboard.h"
#include "serial_console.h"
#include "drivers/e1000.h"
#include "drivers/usb.h"
#ifdef CONFIG_ACPI
#include "drivers/acpi.h"
#endif
#ifdef CONFIG_VIRTIO_RNG
#include "drivers/virtio_rng.h"
#endif
#ifdef CONFIG_RTC
#include "drivers/rtc.h"
#endif
#ifdef CONFIG_WATCHDOG
#include "drivers/watchdog.h"
#endif
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO)
#include "drivers/audio.h"
#endif
#ifdef CONFIG_PCI
#include "drivers/pci.h"
#endif
#include "net/lwip_stack.h"
#include "stdio.h"
#include "string.h"
#include "sys/bootlog.h"
#include "sys/boottime.h"
#include "kernel/linux_time.h"
#include "kernel/console_device.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/anonymous_fd.h"
#include "kernel/event_runtime.h"
#include "kernel/exec_runtime.h"
#include "kernel/fbdev_runtime.h"
#include "kernel/eventfd.h"
#include "kernel/fd_runtime.h"
#include "kernel/fd_table_runtime.h"
#include "kernel/file_description_runtime.h"
#include "kernel/file_lock.h"
#include "kernel/file_mapping_policy.h"
#include "kernel/fs_context.h"
#include "kernel/futex_runtime.h"
#include "kernel/inotify.h"
#include "kernel/inotify_runtime.h"
#include "kernel/io_buffer.h"
#include "kernel/io_runtime.h"
#include "kernel/ioctl_runtime.h"
#include "kernel/linux_mount.h"
#include "kernel/mount_api.h"
#include "kernel/linux_genetlink.h"
#include "kernel/linux_netlink.h"
#include "kernel/linux_sock_diag.h"
#include "kernel/linux_tun.h"
#include "kernel/linux_ptrace.h"
#include "kernel/linux_seek.h"
#include "kernel/boot_logfile.h"
#include "kernel/linux_syscall.h"
#include "kernel/memfd_runtime.h"
#include "kernel/linux_packet.h"
#include "kernel/linux_utsname.h"
#include "kernel/mm_runtime.h"
#include "mm/statistics.h"
#include "kernel/namespace_runtime.h"
#include "kernel/pipe_runtime.h"
#include "kernel/pty_runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/clone_runtime.h"
#include "kernel/aio_runtime.h"
#include "kernel/itimer_runtime.h"
#include "kernel/posix_timer_runtime.h"
#include "kernel/posix_mq_runtime.h"
#include "kernel/random.h"
#include "kernel/signal_queue.h"
#include "kernel/signal_runtime.h"
#include "kernel/signalfd.h"
#include "kernel/signalfd_runtime.h"
#include "kernel/syslog_runtime.h"
#include "kernel/socket_accept_queue.h"
#include "kernel/socket_runtime.h"
#include "kernel/system_runtime.h"
#include "kernel/sysv_shm_runtime.h"
#include "kernel/socket_message.h"
#include "kernel/timerfd.h"
#include "kernel/timerfd_runtime.h"
#include "kernel/tty_session.h"
#include "kernel/vfs_runtime.h"
#include "kernel/wait_runtime.h"
#include "kernel/directory_runtime.h"
#include "kernel/drm_runtime.h"
#include "kernel/virtgpu_runtime.h"
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/cdev.h"
#endif
#include "mm/arch_vm.h"
#include "arch/x86_64/linux_abi.h"
#include "fs/swap.h"
#include "fs/cgroupfs.h"
#include "fs/devpts.h"
#include "fs/fuse.h"
#include "fs/sysfs.h"
#include "fs/tmpfs.h"
#include "sys/meminfo.h"
#include "sys/process.h"
#include "sys/scheduler.h"
#include "sys/spinlock.h"
#include "sys/user_exec.h"
#include "vfs/page_writeback.h"
#include "vfs/readahead.h"
#include "vfs/vfs.h"
#include "block/block.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/ip_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/ip6.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"

#ifndef EDGE_X11_TRACE
#define EDGE_X11_TRACE 0
#endif
#ifndef EDGE_X11_UNIX_TRACE
#define EDGE_X11_UNIX_TRACE 0
#endif
#ifndef EDGE_XFCE_TRACE
#define EDGE_XFCE_TRACE 0
#endif

/*
 * XFCE session bring-up is currently the highest-value Linux ABI smoke test in
 * the Alpine rootfs: it exercises D-Bus activation, GLib spawning, AF_UNIX/X11
 * sockets, procfs, and a burst of fork/exec.  Keep the broad hot-path trace off
 * by default.  Serial logging is synchronous and the desktop startup path does
 * thousands of opens/exec probes; enabling broad tracing can become the
 * workload and make X11/XFCE look hung.  Use the slow-path diagnostics (for
 * example ext4-slow) first, and only enable EDGE_XFCE_BOOT_TRACE for a focused
 * one-off trace.
 */
#ifndef EDGE_XFCE_BOOT_TRACE
#define EDGE_XFCE_BOOT_TRACE 0
#endif

/*
 * X11 protocol and poll tracing must be opt-in.  Serial output is synchronous,
 * and XFCE startup sends enough X/DBus traffic that even budgeted tracing can
 * become the workload and make input/display responsiveness look broken.
 */
#ifndef EDGE_X11_BOOT_TRACE
#define EDGE_X11_BOOT_TRACE 0
#endif

#ifndef EDGE_PTY_DIAG_TRACE
#define EDGE_PTY_DIAG_TRACE 0
#endif
#ifndef EDGE_XFCE_POLL_DETAIL_TRACE
#define EDGE_XFCE_POLL_DETAIL_TRACE 0
#endif
#ifndef EDGE_GUI_DEEP_TRACE
#define EDGE_GUI_DEEP_TRACE 0
#endif

#define ENOSYS 38
#define EPERM 1
#define ENOENT 2
#define ESRCH 3
#define EINTR 4
#define EIO 5
#define ENXIO 6
#define E2BIG 7
#define ENOEXEC 8
#define ENOMEM 12
#define EACCES 13
#define EINVAL 22
#define EFAULT 14
#define EBADF 9
#define ELOOP 40
#define EBUSY 16
#define ERANGE 34
#define ENAMETOOLONG 36
#define ENODEV 19
#define ENOTDIR 20
#define EISDIR 21
#define EAGAIN 11
#define EINPROGRESS 115
#define ECHILD 10
#define ENOTTY 25
#define ESPIPE 29
#define EROFS 30
#define ENOSPC 28
#define EEXIST 17
#define ENOTEMPTY 39
#define EPIPE 32
#define EMSGSIZE 90
#define ENOPROTOOPT 92
#define EXDEV 18
#define EPROTONOSUPPORT 93
#define EAFNOSUPPORT 97
#define ENOTSOCK 88
#define ENOTCONN 107
#define EISCONN 106
#define ECONNREFUSED 111
#define ECONNRESET 104
#define ENOBUFS 105
#define ETIMEDOUT 110
#define EOPNOTSUPP 95
#define EFBIG 27
#define EOVERFLOW 75
#define ESTALE 116
#define EADDRNOTAVAIL 99
#define EADDRINUSE 98
#define ENETUNREACH 101
#define EHOSTUNREACH 113
#define EMFILE 24
#define ENFILE 23
#define ENODATA 61

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_brk 12
#define SYS_getpid 39
#define SYS_execve 59

#define USER_MIN_ADDR EDGE_USER_MIN_ADDR
#define USER_MAX_ADDR EDGE_USER_MAX_ADDR
#define USER_LOW_BASE_ADDR X86_USER_LOW_BASE
#define USER_LOW_SIZE_ADDR X86_USER_LOW_SIZE
#define USER_TEXT_BASE_ADDR X86_USER_INTERP_BASE
#define USER_TEXT_SIZE_ADDR X86_USER_FIXED_WINDOW_SIZE
#define USER_STACK_BASE_ADDR X86_USER_STACK_BASE
#define USER_STACK_SIZE_ADDR X86_USER_FIXED_WINDOW_SIZE
#define BUSYBOX_CRASH_PAGE_LO 0x0000000000449000ULL
#define BUSYBOX_CRASH_PAGE_HI 0x000000000044A000ULL
#define SHELL_HEAP_PROBE_LO   0x00000000223FF000ULL
#define SHELL_HEAP_PROBE_HI   0x0000000022400000ULL
#define BB_CRASH_ADDR 0x000000000044949AULL
#define BB_CRASH_PROBE_LO (BB_CRASH_ADDR - 8ULL)
#define BB_CRASH_PROBE_LEN 24
#define USER_HEAP_BASE_ADDR X86_USER_HEAP_BASE
#define USER_HEAP_LIMIT_ADDR (USER_HEAP_BASE_ADDR + USER_HEAP_MAX_DELTA)
#define USER_HEAP_ABS_LIMIT_ADDR (USER_HEAP_LIMIT_ADDR + USER_HEAP_PY_EXTRA_DELTA)
#define USER_HEAP_EXT_BASE_ADDR USER_HEAP_LIMIT_ADDR
#define USER_BIGPIE_BASE_ADDR X86_USER_BIGPIE_BASE
#define USER_BIGPIE_SIZE_ADDR X86_USER_BIGPIE_SIZE
#define USER_MMAP_BASE_ADDR EDGE_USER_MMAP_ALLOC_BASE_ADDR
#define USER_MMAP_LIMIT_ADDR EDGE_USER_MMAP_ALLOC_LIMIT_ADDR
#define USER_MMAP_HIGH_BASE_ADDR EDGE_USER_MMAP_BASE_ADDR
#define USER_MMAP_HIGH_LIMIT_ADDR EDGE_USER_MMAP_LIMIT_ADDR
#define PAGE_SIZE 4096ULL
#define EDGE_SYSCALL_IO_CHUNK 8192u
#define EDGE_SIGTRAMP_ADDR 0x00000000007FF000ULL

#define LINUX_AT_FDCWD (-100)
#define LINUX_AT_REMOVEDIR 0x200
#define LINUX_AT_SYMLINK_FOLLOW 0x400
#define LINUX_O_ACCMODE 0x3
#define LINUX_O_RDONLY 0x0
#define LINUX_O_WRONLY 0x1
#define LINUX_O_RDWR 0x2
#define LINUX_O_CREAT 0x40
#define LINUX_O_EXCL 0x80
#define LINUX_O_NOCTTY 0x100
#define LINUX_O_TRUNC 0x200
#define LINUX_O_APPEND 0x400
#define LINUX_O_NONBLOCK 0x800
#define LINUX_O_ASYNC 0x2000
#define LINUX_O_DIRECTORY 0x10000
#define LINUX_O_NOFOLLOW 0x20000
#define LINUX_O_CLOEXEC 0x80000
#define LINUX_O_PATH 0x200000
#define LINUX_O_TMPFILE 0x410000

#define LINUX_SEEK_SET 0
#define LINUX_SEEK_CUR 1
#define LINUX_SEEK_END 2

#define LINUX_DT_UNKNOWN 0
#define LINUX_DT_FIFO 1
#define LINUX_DT_CHR 2
#define LINUX_DT_DIR 4
#define LINUX_DT_BLK 6
#define LINUX_DT_REG 8
#define LINUX_DT_LNK 10
#define LINUX_DT_SOCK 12

#define LINUX_MS_RDONLY      0x00000001UL
#define LINUX_MS_NOSUID      0x00000002UL
#define LINUX_MS_NODEV       0x00000004UL
#define LINUX_MS_NOEXEC      0x00000008UL
#define LINUX_MS_SYNCHRONOUS 0x00000010UL
#define LINUX_MS_REMOUNT     0x00000020UL
#define LINUX_MS_MANDLOCK    0x00000040UL
#define LINUX_MS_DIRSYNC     0x00000080UL
#define LINUX_MS_NOSYMFOLLOW 0x00000100UL
#define LINUX_MS_NOATIME     0x00000400UL
#define LINUX_MS_NODIRATIME  0x00000800UL
#define LINUX_MS_BIND        0x00001000UL
#define LINUX_MS_MOVE        0x00002000UL
#define LINUX_MS_REC         0x00004000UL
#define LINUX_MS_SILENT      0x00008000UL
#define LINUX_MS_POSIXACL    0x00010000UL
#define LINUX_MS_UNBINDABLE  0x00020000UL
#define LINUX_MS_PRIVATE     0x00040000UL
#define LINUX_MS_SLAVE       0x00080000UL
#define LINUX_MS_SHARED      0x00100000UL
#define LINUX_MS_RELATIME    0x00200000UL
#define LINUX_MS_I_VERSION   0x00800000UL
#define LINUX_MS_STRICTATIME 0x01000000UL
#define LINUX_MS_LAZYTIME    0x02000000UL
#define LINUX_MS_MGC_VAL     0xc0ed0000UL
#define LINUX_MS_MGC_MSK     0xffff0000UL

#define LINUX_MNT_FORCE       0x1u
#define LINUX_MNT_DETACH      0x2u
#define LINUX_MNT_EXPIRE      0x4u
#define LINUX_UMOUNT_NOFOLLOW 0x8u

#define LINUX_NSFS_MAGIC          0x6e736673u
#define LINUX_F_DUPFD 0
#define LINUX_F_GETFD 1
#define LINUX_F_SETFD 2
#define LINUX_F_GETFL 3
#define LINUX_F_SETFL 4
#define LINUX_F_SETOWN 8
#define LINUX_F_GETOWN 9
#define LINUX_F_SETSIG 10
#define LINUX_F_GETSIG 11
#define LINUX_FD_CLOEXEC 1
#define LINUX_F_DUPFD_CLOEXEC 1030
#define LINUX_F_SETPIPE_SZ 1031
#define LINUX_F_GETPIPE_SZ 1032
#define LINUX_F_ADD_SEALS 1033
#define LINUX_F_GET_SEALS 1034
#define LINUX_F_SEAL_SEAL 0x0001
#define LINUX_F_SEAL_SHRINK 0x0002
#define LINUX_F_SEAL_GROW 0x0004
#define LINUX_F_SEAL_WRITE 0x0008
#define LINUX_F_SEAL_FUTURE_WRITE 0x0010
#define LINUX_F_SEAL_VALID (LINUX_F_SEAL_SEAL | LINUX_F_SEAL_SHRINK | LINUX_F_SEAL_GROW | LINUX_F_SEAL_WRITE | LINUX_F_SEAL_FUTURE_WRITE)
#define LINUX_MAP_SHARED 0x01
#define LINUX_MAP_ANONYMOUS 0x20
#define LINUX_MAP_ANON LINUX_MAP_ANONYMOUS
#define LINUX_MAP_PRIVATE 0x02
#define LINUX_MAP_FIXED 0x10
#define LINUX_MAP_FIXED_NOREPLACE 0x100000
#define LINUX_S_IFIFO 0x1000
#define LINUX_S_IFCHR 0x2000
#define LINUX_S_IFDIR 0x4000
#define LINUX_S_IFBLK 0x6000
#define LINUX_S_IFREG 0x8000
#define LINUX_S_IFLNK 0xA000
#define LINUX_S_IFSOCK 0xC000
#define LINUX_WNOHANG 1
#define LINUX_WUNTRACED 2
#define LINUX_WCONTINUED 8
#define LINUX___WNOTHREAD 0x20000000
#define LINUX___WALL 0x40000000
#define LINUX___WCLONE 0x80000000
#define LINUX_PROT_READ 0x1
#define LINUX_PROT_WRITE 0x2
#define LINUX_PROT_EXEC 0x4
#define LINUX_SIGHUP 1
#define LINUX_SIGINT 2
#define LINUX_SIGQUIT 3
#define LINUX_SIGABRT 6
#define LINUX_SIGUSR1 10
#define LINUX_SIGUSR2 12
#define LINUX_SIGSEGV 11
#define LINUX_SIGCHLD 17
#define LINUX_SIGCONT 18
#define LINUX_SIGALRM 14
#define LINUX_SIGKILL 9
#define LINUX_SIGSTOP 19
#define LINUX_SIGTSTP 20
#define LINUX_SIGTTIN 21
#define LINUX_SIGTTOU 22
#define LINUX_SIGTERM 15
#define LINUX_SIGIO 29
#define LINUX_SIGSYS 31
#define LINUX_SIGRT_BASE 32
#define LINUX_SIGRTMAX 64
#define LINUX_SIG_DFL 0ULL
#define LINUX_SIG_IGN 1ULL
#define LINUX_SIG_BLOCK 0
#define LINUX_SIG_UNBLOCK 1
#define LINUX_SIG_SETMASK 2
#define LINUX_TCGETS 0x5401u
#define LINUX_TCSETS 0x5402u
#define LINUX_TCSETSW 0x5403u
#define LINUX_TCSETSF 0x5404u
#define LINUX_TCSBRK 0x5409u
#define LINUX_TCXONC 0x540Au
#define LINUX_TCFLSH 0x540Bu
#define LINUX_TIOCGPGRP 0x540Fu
#define LINUX_TIOCSPGRP 0x5410u
#define LINUX_TIOCGWINSZ 0x5413u
#define LINUX_TIOCSWINSZ 0x5414u
#define LINUX_TIOCCONS 0x541Du
#define LINUX_TCSBRKP 0x5425u
#define LINUX_TIOCPKT 0x5420u
#define LINUX_TIOCGPKT 0x80045438u
#define LINUX_TIOCGPTLCK 0x80045439u
#define LINUX_TIOCGPTN 0x80045430u
#define LINUX_TIOCSPTLCK 0x40045431u
#define LINUX_TIOCGPTPEER 0x5441u
#define LINUX_TIOCSCTTY 0x540Eu
#define LINUX_TIOCNOTTY 0x5422u
#define LINUX_TIOCGSID 0x5429u
#define LINUX_KDSETMODE 0x4B3Au
#define LINUX_KDGETMODE 0x4B3Bu
#define LINUX_GIO_FONT 0x4B60u
#define LINUX_PIO_FONT 0x4B61u
#define LINUX_GIO_FONTX 0x4B6Bu
#define LINUX_PIO_FONTX 0x4B6Cu
#define LINUX_PIO_FONTRESET 0x4B6Du
#define LINUX_KDFONTOP 0x4B72u
#define LINUX_KDGKBMODE 0x4B44u
#define LINUX_KDSKBMODE 0x4B45u
#define LINUX_KDMKTONE 0x4B30u
#define LINUX_KD_TEXT 0
#define LINUX_KD_GRAPHICS 1
#define LINUX_K_RAW 0
#define LINUX_K_XLATE 1
#define LINUX_K_MEDIUMRAW 2
#define LINUX_K_UNICODE 3
#define LINUX_K_OFF 4
#define LINUX_KD_FONT_OP_SET 0u
#define LINUX_KD_FONT_OP_GET 1u
#define LINUX_KD_FONT_OP_SET_DEFAULT 2u
#define LINUX_KD_FONT_OP_COPY 3u
#define LINUX_KD_FONT_OP_SET_TALL 4u
#define LINUX_KD_FONT_OP_GET_TALL 5u
#define LINUX_KD_FONT_FLAG_DONT_RECALC 1u
#define LINUX_VT_OPENQRY 0x5600u
#define LINUX_VT_GETMODE 0x5601u
#define LINUX_VT_SETMODE 0x5602u
#define LINUX_VT_GETSTATE 0x5603u
#define LINUX_VT_RELDISP 0x5605u
#define LINUX_VT_ACTIVATE 0x5606u
#define LINUX_VT_WAITACTIVE 0x5607u
#define LINUX_VT_AUTO 0
#define LINUX_VT_PROCESS 1
#define LINUX_VT_ACKACQ 2
#define LINUX_FIONREAD  0x541Bu
#define LINUX_FIOASYNC  0x5452u
#define LINUX_FIOSETOWN 0x8901u
#define LINUX_SIOCSPGRP 0x8902u
#define LINUX_FIOGETOWN 0x8903u
#define LINUX_SIOCGPGRP 0x8904u
#define LINUX_SIOCADDRT 0x890Bu
#define LINUX_SIOCDELRT 0x890Cu
#define LINUX_EVIOCGVERSION 0x80044501u
#define LINUX_EVIOCGID      0x80084502u
#define LINUX_EVIOCSCLOCKID 0x400445A0u
#define LINUX_EVIOCGBIT0    0x80084520u
#define LINUX_EVIOCGBIT1    0x80084521u
#define LINUX_EVIOCGBIT2    0x80084522u
#define LINUX_UI_DEV_CREATE 0x5501u
#define LINUX_UI_DEV_DESTROY 0x5502u
#define LINUX_RTC_AIE_ON      0x7001u
#define LINUX_RTC_AIE_OFF     0x7002u
#define LINUX_RTC_UIE_ON      0x7003u
#define LINUX_RTC_UIE_OFF     0x7004u
#define LINUX_RTC_PIE_ON      0x7005u
#define LINUX_RTC_PIE_OFF     0x7006u
#define LINUX_RTC_ALM_SET     0x40247007u
#define LINUX_RTC_ALM_READ    0x80247008u
#define LINUX_RTC_RD_TIME     0x80247009u
#define LINUX_RTC_SET_TIME    0x4024700Au
#define LINUX_RTC_IRQP_READ   0x8008700Bu
#define LINUX_RTC_IRQP_SET    0x4008700Cu
#define LINUX_RTC_EPOCH_READ  0x8008700Du
#define LINUX_RTC_EPOCH_SET   0x4008700Eu
#define LINUX_RTC_WIE_ON      0x700Fu
#define LINUX_RTC_WIE_OFF     0x7010u
#define LINUX_RTC_WKALM_SET   0x4028700Fu
#define LINUX_RTC_WKALM_RD    0x80287010u
#define LINUX_RTC_PLL_GET     0x80207011u
#define LINUX_RTC_PLL_SET     0x40207012u
#define LINUX_RTC_PARAM_GET   0x40187013u
#define LINUX_RTC_PARAM_SET   0x40187014u
#define LINUX_RTC_VL_READ     0x80047013u
#define LINUX_RTC_VL_CLR      0x7014u
#define LINUX_RTC_PARAM_FEATURES 0u
#define LINUX_WDIOC_GETSUPPORT   0x80285700u
#define LINUX_WDIOC_GETSTATUS    0x80045701u
#define LINUX_WDIOC_GETBOOTSTATUS 0x80045702u
#define LINUX_WDIOC_GETTEMP      0x80045703u
#define LINUX_WDIOC_SETOPTIONS   0x80045704u
#define LINUX_WDIOC_KEEPALIVE    0x80045705u
#define LINUX_WDIOC_SETTIMEOUT   0xC0045706u
#define LINUX_WDIOC_GETTIMEOUT   0x80045707u
#define LINUX_WDIOC_SETPRETIMEOUT 0xC0045708u
#define LINUX_WDIOC_GETPRETIMEOUT 0x80045709u
#define LINUX_WDIOC_GETTIMELEFT  0x8004570Au
#define LINUX_WDIOF_SETTIMEOUT   0x0080u
#define LINUX_WDIOF_KEEPALIVEPING 0x8000u
#define LINUX_WDIOS_DISABLECARD  0x0001u
#define LINUX_WDIOS_ENABLECARD   0x0002u
#define LINUX_WDIOS_TEMPPANIC    0x0004u
#define LINUX_INLCR 0x0040u
#define LINUX_IGNCR 0x0080u
#define LINUX_ICRNL 0x0100u
#define LINUX_OPOST 0x0001u
#define LINUX_ONLCR 0x0004u
#define LINUX_ICANON 0x0002u
#define LINUX_ECHO 0x0008u
#define LINUX_ECHOE 0x0010u
#define LINUX_ECHOK 0x0020u
#define LINUX_ECHOCTL 0x0200u
#define LINUX_ECHOKE 0x0800u
#define LINUX_IEXTEN 0x8000u
#define LINUX_ISIG 0x0001u
#define LINUX_POLLIN  0x0001
#define LINUX_POLLPRI 0x0002
#define LINUX_POLLOUT 0x0004
#define LINUX_POLLERR 0x0008
#define LINUX_POLLHUP 0x0010
#define LINUX_POLLNVAL 0x0020
#define LINUX_POLLRDNORM 0x0040
#define LINUX_POLLRDBAND 0x0080
#define LINUX_POLLWRNORM 0x0100
#define LINUX_POLLWRBAND 0x0200
#define LINUX_POLLMSG 0x0400
#define LINUX_POLLRDHUP 0x2000
#define TIMER_ABSTIME 1

#define LINUX_FUTEX_OWNER_DIED 0x40000000u
#define LINUX_FUTEX_TID_MASK 0x3fffffffu
#define LINUX_ROBUST_LIST_LIMIT 2048u
#define LINUX_FUTEX_ROBUST_MOD_PI 1u
#define LINUX_FUTEX_ROBUST_MOD_MASK LINUX_FUTEX_ROBUST_MOD_PI

#define LINUX_MREMAP_MAYMOVE 1
#define LINUX_MREMAP_FIXED 2
#define LINUX_MINSIGSTKSZ 2048
#define LINUX_PRIO_PROCESS 0
#define LINUX_AT_SYMLINK_NOFOLLOW 0x100
#define LINUX_AT_EACCESS 0x200
#define LINUX_AT_NO_AUTOMOUNT 0x800
#define LINUX_AT_EMPTY_PATH 0x1000
#define LINUX_AT_STATX_FORCE_SYNC 0x2000
#define LINUX_AT_STATX_DONT_SYNC 0x4000
#define LINUX_AT_STATX_SYNC_TYPE (LINUX_AT_STATX_FORCE_SYNC | LINUX_AT_STATX_DONT_SYNC)
#define LINUX_WAITID_P_ALL 0
#define LINUX_WAITID_P_PID 1
#define LINUX_WAITID_P_PGID 2
#define LINUX_WAITID_P_PIDFD 3
#define LINUX_WEXITED 0x00000004
#define LINUX_WNOWAIT 0x01000000
#define LINUX_CLD_EXITED 1
#define LINUX_CLD_KILLED 2
#define LINUX_CLD_DUMPED 3
#define LINUX_CLD_TRAPPED 4
#define LINUX_CLD_STOPPED 5
#define LINUX_CLD_CONTINUED 6
#define LINUX_SCHED_OTHER 0
#define LINUX_SCHED_FIFO 1
#define LINUX_SCHED_RR 2
#define LINUX_SCHED_BATCH 3
#define LINUX_SCHED_IDLE 5
#define LINUX_SCHED_DEADLINE 6

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

#define SYS_stat 4
#define SYS_poll 7
#define SYS_shmget 29
#define SYS_shmat 30
#define SYS_shmctl 31
#define SYS_semget 64
#define SYS_semop 65
#define SYS_semctl 66
#define SYS_msgget 68
#define SYS_msgsnd 69
#define SYS_msgrcv 70
#define SYS_msgctl 71
#define SYS_sched_yield 24
#define SYS_mremap 25
#define SYS_msync 26
#define SYS_madvise 28
#define SYS_lseek 8
#define SYS_fstat 5
#define SYS_lstat 6
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_getcwd 79
#define SYS_chdir 80
#define SYS_fchdir 81
#define SYS_mkdir 83
#define SYS_rename 82
#define SYS_rmdir 84
#define SYS_link 86
#define SYS_unlink 87
#define SYS_symlink 88
#define SYS_gettimeofday 96
#define SYS_getrlimit 97
#define SYS_getrusage 98
#define SYS_flock 73
#define SYS_sysinfo 99
#define SYS_times 100
#define SYS_syslog 103
#define SYS_ptrace 101
#define SYS_sigaltstack 131
#define SYS_umask 95
#define SYS_chmod 90
#define SYS_chown 92
#define SYS_lchown 94
#define SYS_fchmod 91
#define SYS_fchown 93
#define SYS_readlink 89
#define SYS_readv 19
#define SYS_writev 20
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigreturn 15
#define SYS_rt_sigpending 127
#define SYS_rt_sigtimedwait 128
#define SYS_rt_sigqueueinfo 129
#define SYS_rt_sigsuspend 130
#define SYS_ioctl 16
#define SYS_pread64 17
#define SYS_pwrite64 18
#define SYS_socket 41
#define SYS_sendfile 40
#define SYS_connect 42
#define SYS_accept 43
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_sendmsg 46
#define SYS_recvmsg 47
#define SYS_shutdown 48
#define SYS_bind 49
#define SYS_listen 50
#define SYS_getsockname 51
#define SYS_getpeername 52
#define SYS_socketpair 53
#define SYS_setsockopt 54
#define SYS_getsockopt 55
#define SYS_access 21
#define SYS_pipe 22
#define SYS_mincore 27
#define SYS_dup 32
#define SYS_dup2 33
#define SYS_pause 34
#define SYS_nanosleep 35
#define SYS_getitimer 36
#define SYS_alarm 37
#define SYS_setitimer 38
#define SYS_clone 56
#define SYS_fork 57
#define SYS_vfork 58
#define SYS_wait4 61
#define SYS_exit 60
#define SYS_kill 62
#define SYS_uname 63
#define SYS_creat 85
#define SYS_mknod 133
#define SYS_personality 135
#define SYS_shmdt 67
#define SYS_uselib 134
#define SYS_ustat 136
#define SYS_sysfs 139
#define SYS_vhangup 153
#define SYS_modify_ldt 154
#define SYS__sysctl 156
#define SYS_adjtimex 159
#define SYS_reboot 169
#define SYS_acct 163
#define SYS_umount2 166
#define SYS_swapon 167
#define SYS_swapoff 168
#define SYS_iopl 172
#define SYS_ioperm 173
#define SYS_sethostname 170
#define SYS_setdomainname 171
#define SYS_create_module 174
#define SYS_get_kernel_syms 177
#define SYS_query_module 178
#define SYS_quotactl 179
#define SYS_nfsservctl 180
#define SYS_getpmsg 181
#define SYS_putpmsg 182
#define SYS_afs_syscall 183
#define SYS_tuxcall 184
#define SYS_security 185
#define SYS_setrlimit 160
#define SYS_fcntl 72
#define SYS_fsync 74
#define SYS_fdatasync 75
#define SYS_truncate 76
#define SYS_ftruncate 77
#define SYS_getdents 78
#define SYS_statfs 137
#define SYS_fstatfs 138
#define SYS_getpriority 140
#define SYS_setpriority 141
#define SYS_sched_setparam 142
#define SYS_sched_getparam 143
#define SYS_sched_setscheduler 144
#define SYS_sched_getscheduler 145
#define SYS_sched_get_priority_max 146
#define SYS_sched_get_priority_min 147
#define SYS_sched_rr_get_interval 148
#define SYS_mlock 149
#define SYS_munlock 150
#define SYS_mlockall 151
#define SYS_munlockall 152
#define SYS_getdents64 217
#define SYS_gettid 186
#define SYS_readahead 187
#define SYS_futex 202
#define SYS_set_thread_area 205
#define SYS_io_setup 206
#define SYS_io_destroy 207
#define SYS_io_getevents 208
#define SYS_io_submit 209
#define SYS_io_cancel 210
#define SYS_get_thread_area 211
#define SYS_lookup_dcookie 212
#define SYS_epoll_ctl_old 214
#define SYS_epoll_wait_old 215
#define SYS_remap_file_pages 216
#define SYS_restart_syscall 219
#define SYS_semtimedop 220
#define SYS_fadvise64 221
#define SYS_timer_create 222
#define SYS_timer_settime 223
#define SYS_timer_gettime 224
#define SYS_timer_getoverrun 225
#define SYS_timer_delete 226
#define SYS_clock_settime 227
#define SYS_sched_setaffinity 203
#define SYS_sched_getaffinity 204
#define SYS_pidfd_send_signal 424
#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#define SYS_set_tid_address 218
#define SYS_clock_gettime 228
#define SYS_clock_getres 229
#define SYS_clock_nanosleep 230
#define SYS_exit_group 231
#define SYS_tkill 200
#define SYS_time 201
#define SYS_tgkill 234
#define SYS_utimes 235
#define SYS_vserver 236
#define SYS_mbind 237
#define SYS_set_mempolicy 238
#define SYS_get_mempolicy 239
#define SYS_mq_open 240
#define SYS_mq_unlink 241
#define SYS_mq_timedsend 242
#define SYS_mq_timedreceive 243
#define SYS_mq_notify 244
#define SYS_mq_getsetattr 245
#define SYS_kexec_load 246
#define SYS_waitid 247
#define SYS_add_key 248
#define SYS_request_key 249
#define SYS_keyctl 250
#define SYS_ioprio_set 251
#define SYS_ioprio_get 252
#define SYS_inotify_init 253
#define SYS_inotify_add_watch 254
#define SYS_inotify_rm_watch 255
#define SYS_migrate_pages 256
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_mknodat 259
#define SYS_fchownat 260
#define SYS_futimesat 261
#define SYS_unlinkat 263
#define SYS_renameat 264
#define SYS_linkat 265
#define SYS_symlinkat 266
#define SYS_readlinkat 267
#define SYS_fchmodat 268
#define SYS_faccessat 269
#define SYS_fchmodat2 452
#define SYS_newfstatat 262
#define SYS_utimensat 280
#define SYS_set_robust_list 273
#define SYS_get_robust_list 274
#define SYS_tee 276
#define SYS_sync_file_range 277
#define SYS_vmsplice 278
#define SYS_move_pages 279
#define SYS_prlimit64 302
#define SYS_clock_adjtime 305
#define SYS_syncfs 306
#define SYS_getcpu 309
#define SYS_dup3 292
#define SYS_pipe2 293
#define SYS_renameat2 316
#define SYS_getrandom 318
#define SYS_memfd_create 319
#define SYS_membarrier 324
#define SYS_mlock2 325
#define SYS_setxattr 188
#define SYS_lsetxattr 189
#define SYS_fsetxattr 190
#define SYS_getxattr 191
#define SYS_lgetxattr 192
#define SYS_fgetxattr 193
#define SYS_listxattr 194
#define SYS_llistxattr 195
#define SYS_flistxattr 196
#define SYS_removexattr 197
#define SYS_lremovexattr 198
#define SYS_fremovexattr 199
#define SYS_execveat 322
#define SYS_copy_file_range 326
#define SYS_statx 332
#define SYS_rseq 334
#define SYS_getuid 102
#define SYS_setuid 105
#define SYS_setgid 106
#define SYS_getgid 104
#define SYS_geteuid 107
#define SYS_getegid 108
#define SYS_getppid 110
#define SYS_setpgid 109
#define SYS_getpgrp 111
#define SYS_setsid 112
#define SYS_setreuid 113
#define SYS_setregid 114
#define SYS_getgroups 115
#define SYS_setgroups 116
#define SYS_setresuid 117
#define SYS_getresuid 118
#define SYS_setresgid 119
#define SYS_getresgid 120
#define SYS_getpgid 121
#define SYS_setfsuid 122
#define SYS_setfsgid 123
#define SYS_getsid 124
#define SYS_capget 125
#define SYS_capset 126
#define SYS_utime 132
#define SYS_pivot_root 155
#define SYS_prctl 157
#define SYS_arch_prctl 158
#define SYS_chroot 161
#define SYS_sync 162
#define SYS_settimeofday 164
#define SYS_mount 165
#define SYS_init_module 175
#define SYS_delete_module 176
#define SYS_select 23
#define SYS_pselect6 270
#define SYS_ppoll 271
#define SYS_signalfd 282
#define SYS_timerfd_create 283
#define SYS_eventfd 284
#define SYS_fallocate 285
#define SYS_timerfd_settime 286
#define SYS_timerfd_gettime 287
#define SYS_accept4 288
#define SYS_signalfd4 289
#define SYS_eventfd2 290
#define SYS_epoll_create1 291
#define SYS_inotify_init1 294
#define SYS_preadv 295
#define SYS_pwritev 296
#define SYS_rt_tgsigqueueinfo 297
#define SYS_perf_event_open 298
#define SYS_recvmmsg 299
#define SYS_fanotify_init 300
#define SYS_fanotify_mark 301
#define SYS_name_to_handle_at 303
#define SYS_open_by_handle_at 304
#define SYS_sendmmsg 307
#define SYS_process_vm_readv 310
#define SYS_process_vm_writev 311
#define SYS_kcmp 312
#define SYS_finit_module 313
#define SYS_sched_setattr 314
#define SYS_sched_getattr 315
#define SYS_bpf 321
#define SYS_userfaultfd 323
#define SYS_preadv2 327
#define SYS_pwritev2 328
#define SYS_pkey_mprotect 329
#define SYS_pkey_alloc 330
#define SYS_pkey_free 331
#define SYS_io_pgetevents 333
#define SYS_uretprobe 335
#define SYS_uprobe 336
#define SYS_kexec_file_load 320
#define SYS_openat2 437
#define SYS_faccessat2 439
#define SYS_pidfd_open 434
#define SYS_clone3 435
#define SYS_close_range 436
#define SYS_open_tree 428
#define SYS_move_mount 429
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#define SYS_fspick 433
#define SYS_pidfd_getfd 438
#define SYS_process_madvise 440
#define SYS_epoll_pwait2 441
#define SYS_mount_setattr 442
#define SYS_memfd_secret 447
#define SYS_process_mrelease 448
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#define SYS_futex_waitv 449
#define SYS_set_mempolicy_home_node 450
#define SYS_cachestat 451
#define SYS_quotactl_fd 443
#define SYS_map_shadow_stack 453
#define SYS_futex_wake 454
#define SYS_futex_wait 455
#define SYS_futex_requeue 456
#define SYS_statmount 457
#define SYS_listmount 458
#define SYS_lsm_get_self_attr 459
#define SYS_lsm_set_self_attr 460
#define SYS_lsm_list_modules 461
#define SYS_mseal 462
#define SYS_setxattrat 463
#define SYS_getxattrat 464
#define SYS_listxattrat 465
#define SYS_removexattrat 466
#define SYS_open_tree_attr 467
#define SYS_file_getattr 468
#define SYS_file_setattr 469
#define SYS_listns 470
#define SYS_rseq_slice_yield 471
#define SYS_epoll_create 213
#define SYS_epoll_wait 232
#define SYS_epoll_ctl 233
#define SYS_epoll_pwait 281

#define LINUX_MEMBARRIER_CMD_QUERY 0
#define LINUX_MEMBARRIER_CMD_GLOBAL (1 << 0)
#define LINUX_MEMBARRIER_CMD_GLOBAL_EXPEDITED (1 << 1)
#define LINUX_MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED (1 << 2)
#define LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED (1 << 3)
#define LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED (1 << 4)
#define LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE (1 << 5)
#define LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1 << 6)
#define LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ (1 << 7)
#define LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ (1 << 8)
#define LINUX_MEMBARRIER_CMD_GET_REGISTRATIONS (1 << 9)
#define LINUX_MEMBARRIER_CMD_FLAG_CPU (1 << 0)

#define LINUX_SCHED_RESET_ON_FORK 0x40000000
#define LINUX_PERSONALITY_QUERY 0xffffffffu
#define LINUX_ROBUST_LIST_HEAD_SIZE 24
#define LINUX_POSIX_FADV_NORMAL 0
#define LINUX_POSIX_FADV_RANDOM 1
#define LINUX_POSIX_FADV_SEQUENTIAL 2
#define LINUX_POSIX_FADV_WILLNEED 3
#define LINUX_POSIX_FADV_DONTNEED 4
#define LINUX_POSIX_FADV_NOREUSE 5

#define LINUX_RWF_HIPRI 0x00000001
#define LINUX_RWF_DSYNC 0x00000002
#define LINUX_RWF_SYNC 0x00000004
#define LINUX_RWF_NOWAIT 0x00000008
#define LINUX_RWF_APPEND 0x00000010
#define LINUX_RWF_NOAPPEND 0x00000020
#define LINUX_RWF_ATOMIC 0x00000040
#define LINUX_RWF_DONTCACHE 0x00000080
#define LINUX_RWF_NOSIGNAL 0x00000100
#define LINUX_RWF_SUPPORTED (LINUX_RWF_HIPRI | LINUX_RWF_DSYNC | LINUX_RWF_SYNC | \
                             LINUX_RWF_NOWAIT | LINUX_RWF_APPEND | LINUX_RWF_NOAPPEND | \
                             LINUX_RWF_ATOMIC | LINUX_RWF_DONTCACHE | LINUX_RWF_NOSIGNAL)

#define LINUX_AF_UNIX 1
#define LINUX_AF_INET 2
#define LINUX_AF_INET6 10
#define LINUX_AF_NETLINK 16
#define LINUX_AF_PACKET 17
#define LINUX_NLMSG_ERROR 2
#define LINUX_NLMSG_DONE 3
#define LINUX_NLM_F_ACK 4
#define LINUX_NLM_F_MULTI 2
#define LINUX_NLM_F_DUMP 0x300u
#define LINUX_RTM_NEWADDR 20
#define LINUX_RTM_DELADDR 21
#define LINUX_RTM_GETADDR 22
#define LINUX_RTM_NEWROUTE 24
#define LINUX_RTM_DELROUTE 25
#define LINUX_RTM_GETROUTE 26
#define LINUX_RTM_NEWNEIGH 28
#define LINUX_RTM_GETNEIGH 30
#define LINUX_RTM_NEWRULE 32
#define LINUX_RTM_DELRULE 33
#define LINUX_RTM_GETRULE 34
#define LINUX_RTM_NEWQDISC 36
#define LINUX_RTM_DELQDISC 37
#define LINUX_RTM_GETQDISC 38
#define LINUX_RTM_NEWMDB 84
#define LINUX_RTM_DELMDB 85
#define LINUX_RTM_GETMDB 86
#define LINUX_RTM_NEWNEXTHOP 104
#define LINUX_RTM_DELNEXTHOP 105
#define LINUX_RTM_GETNEXTHOP 106
#define LINUX_RTM_NEWLINK 16
#define LINUX_RTM_GETLINK 18
#define LINUX_IFLA_IFNAME 3
#define LINUX_IFA_ADDRESS 1
#define LINUX_IFA_LOCAL 2
#define LINUX_IFA_BROADCAST 4
#define LINUX_RTA_DST 1
#define LINUX_RTA_OIF 4
#define LINUX_RTA_GATEWAY 5
#define LINUX_RTA_PREFSRC 7
#define LINUX_NDA_DST 1
#define LINUX_NDA_LLADDR 2
#define LINUX_NUD_REACHABLE 0x02
#define LINUX_RT_TABLE_MAIN 254
#define LINUX_RTPROT_BOOT 3
#define LINUX_RT_SCOPE_UNIVERSE 0
#define LINUX_RT_SCOPE_LINK 253
#define LINUX_RT_SCOPE_HOST 254
#define LINUX_RTN_UNICAST 1
#define LINUX_ETH_P_IP 0x0800u
#define LINUX_SOCK_STREAM 1
#define LINUX_SOCK_DGRAM 2
#define LINUX_SOCK_RAW 3
#define LINUX_SOCK_SEQPACKET 5
#define LINUX_SOCK_NONBLOCK 0x800
#define LINUX_SOCK_CLOEXEC 0x80000
#define LINUX_EFD_SEMAPHORE 1
#define LINUX_EFD_CLOEXEC LINUX_O_CLOEXEC
#define LINUX_EFD_NONBLOCK LINUX_O_NONBLOCK
#define LINUX_TFD_NONBLOCK LINUX_O_NONBLOCK
#define LINUX_TFD_CLOEXEC LINUX_O_CLOEXEC
#define LINUX_TFD_TIMER_ABSTIME 1
#define LINUX_TFD_TIMER_CANCEL_ON_SET 2
#define LINUX_SFD_NONBLOCK LINUX_O_NONBLOCK
#define LINUX_SFD_CLOEXEC LINUX_O_CLOEXEC
#define LINUX_EPOLL_CLOEXEC LINUX_O_CLOEXEC
#define LINUX_EPOLL_CTL_ADD 1
#define LINUX_EPOLL_CTL_DEL 2
#define LINUX_EPOLL_CTL_MOD 3
#define LINUX_EPOLLIN 0x001u
#define LINUX_EPOLLPRI 0x002u
#define LINUX_EPOLLOUT 0x004u
#define LINUX_EPOLLERR 0x008u
#define LINUX_EPOLLHUP 0x010u
#define LINUX_EPOLLRDNORM 0x040u
#define LINUX_EPOLLRDBAND 0x080u
#define LINUX_EPOLLWRNORM 0x100u
#define LINUX_EPOLLWRBAND 0x200u
#define LINUX_EPOLLMSG 0x400u
#define LINUX_EPOLLRDHUP 0x2000u
#define LINUX_EPOLLWAKEUP (1u << 29)
#define LINUX_EPOLLONESHOT (1u << 30)
#define LINUX_EPOLLET 0x80000000u
#define LINUX_IPPROTO_ICMP 1
#define LINUX_IPPROTO_TCP 6
#define LINUX_IPPROTO_UDP 17
#define LINUX_IPPROTO_ICMPV6 58
#define LINUX_IPPROTO_RAW 255
#define LINUX_TCP_NODELAY 1
#define LINUX_TCP_KEEPIDLE 4
#define LINUX_TCP_KEEPINTVL 5
#define LINUX_TCP_KEEPCNT 6

#define LINUX_SIOCGIFNAME 0x8910u
#define LINUX_SIOCGIFCONF 0x8912u
#define LINUX_SIOCGIFFLAGS 0x8913u
#define LINUX_SIOCSIFFLAGS 0x8914u
#define LINUX_SIOCGIFADDR 0x8915u
#define LINUX_SIOCSIFADDR 0x8916u
#define LINUX_SIOCGIFDSTADDR 0x8917u
#define LINUX_SIOCSIFDSTADDR 0x8918u
#define LINUX_SIOCGIFBRDADDR 0x8919u
#define LINUX_SIOCSIFBRDADDR 0x891au
#define LINUX_SIOCGIFNETMASK 0x891bu
#define LINUX_SIOCSIFNETMASK 0x891cu
#define LINUX_SIOCGIFMETRIC 0x891du
#define LINUX_SIOCGIFMTU 0x8921u
#define LINUX_SIOCSIFMTU 0x8922u
#define LINUX_SIOCGIFHWADDR 0x8927u
#define LINUX_SIOCGIFINDEX 0x8933u
#define LINUX_SIOCGIFTXQLEN 0x8942u
#define LINUX_SIOCSIFTXQLEN 0x8943u

#define LINUX_IFF_UP 0x1u
#define LINUX_IFF_BROADCAST 0x2u
#define LINUX_IFF_LOOPBACK 0x8u
#define LINUX_IFF_RUNNING 0x40u
#define LINUX_IFF_MULTICAST 0x1000u

#define LINUX_ARPHRD_ETHER 1u
#define LINUX_ARPHRD_LOOPBACK 772u

#define LINUX_SOL_SOCKET 1
#define LINUX_SO_REUSEADDR 2
#define LINUX_SO_TYPE 3
#define LINUX_SO_ERROR 4
#define LINUX_SO_BROADCAST 6
#define LINUX_SO_SNDBUF 7
#define LINUX_SO_ACCEPTCONN 30
#define LINUX_SO_PROTOCOL 38
#define LINUX_SO_DOMAIN 39
#define LINUX_SO_BINDTODEVICE 25
#define LINUX_SO_ATTACH_FILTER 26
#define LINUX_SO_DETACH_FILTER 27
#define LINUX_SO_RCVBUF 8
#define LINUX_SO_KEEPALIVE 9
#define LINUX_SO_OOBINLINE 10
#define LINUX_SO_NO_CHECK 11
#define LINUX_SO_PRIORITY 12
#define LINUX_SO_LINGER 13
#define LINUX_SO_REUSEPORT 15
#define LINUX_SO_RCVTIMEO 20
#define LINUX_SO_SNDTIMEO 21
#define LINUX_SO_PASSCRED 16
#define LINUX_SO_PEERCRED 17
#define LINUX_SO_RCVLOWAT 18
#define LINUX_SO_SNDLOWAT 19
#define LINUX_SO_PEERSEC 31
#define LINUX_SO_TIMESTAMPNS 35
#define LINUX_SO_TIMESTAMPNS_NEW 64
#define LINUX_SO_PEERGROUPS 59
#define LINUX_SO_PASSPIDFD 76
#define LINUX_SO_PEERPIDFD 77
#define LINUX_SO_RCVTIMEO_NEW 66
#define LINUX_SO_SNDTIMEO_NEW 67
#define LINUX_SCM_RIGHTS 1
#define LINUX_SCM_CREDENTIALS 2
#define LINUX_MSG_PEEK EDGE_LINUX_MSG_PEEK
#define LINUX_MSG_CTRUNC EDGE_LINUX_MSG_CTRUNC
#define LINUX_MSG_TRUNC EDGE_LINUX_MSG_TRUNC
#define LINUX_MSG_DONTWAIT EDGE_LINUX_MSG_DONTWAIT
#define LINUX_MSG_EOR EDGE_LINUX_MSG_EOR
#define LINUX_MSG_NOSIGNAL EDGE_LINUX_MSG_NOSIGNAL
#define LINUX_MSG_CMSG_CLOEXEC EDGE_LINUX_MSG_CMSG_CLOEXEC

#define LINUX_BPF_LD    0x00u
#define LINUX_BPF_LDX   0x01u
#define LINUX_BPF_ST    0x02u
#define LINUX_BPF_STX   0x03u
#define LINUX_BPF_ALU   0x04u
#define LINUX_BPF_JMP   0x05u
#define LINUX_BPF_RET   0x06u
#define LINUX_BPF_MISC  0x07u
#define LINUX_BPF_W     0x00u
#define LINUX_BPF_H     0x08u
#define LINUX_BPF_B     0x10u
#define LINUX_BPF_IMM   0x00u
#define LINUX_BPF_ABS   0x20u
#define LINUX_BPF_IND   0x40u
#define LINUX_BPF_MEM   0x60u
#define LINUX_BPF_LEN   0x80u
#define LINUX_BPF_MSH   0xa0u
#define LINUX_BPF_ADD   0x00u
#define LINUX_BPF_SUB   0x10u
#define LINUX_BPF_MUL   0x20u
#define LINUX_BPF_DIV   0x30u
#define LINUX_BPF_OR    0x40u
#define LINUX_BPF_AND   0x50u
#define LINUX_BPF_LSH   0x60u
#define LINUX_BPF_RSH   0x70u
#define LINUX_BPF_NEG   0x80u
#define LINUX_BPF_MOD   0x90u
#define LINUX_BPF_XOR   0xa0u
#define LINUX_BPF_JA    0x00u
#define LINUX_BPF_JEQ   0x10u
#define LINUX_BPF_JGT   0x20u
#define LINUX_BPF_JGE   0x30u
#define LINUX_BPF_JSET  0x40u
#define LINUX_BPF_K     0x00u
#define LINUX_BPF_X     0x08u
#define LINUX_BPF_TAX   0x00u
#define LINUX_BPF_TXA   0x80u
#define LINUX_BPF_CLASS(c) ((c) & 0x07u)
#define LINUX_BPF_SIZE(c)  ((c) & 0x18u)
#define LINUX_BPF_MODE(c)  ((c) & 0xe0u)
#define LINUX_BPF_OP(c)    ((c) & 0xf0u)
#define LINUX_BPF_SRC(c)   ((c) & 0x08u)
#define EDGE_SOCKET_FILTER_MAX EDGE_LINUX_PACKET_FILTER_MAX
#define LINUX_GRND_NONBLOCK 0x0001
#define LINUX_SOL_IP 0
#define LINUX_IP_TOS 1
#define LINUX_IP_TTL 2
#define LINUX_IP_PKTINFO 8
#define LINUX_IP_MTU_DISCOVER 10
#define LINUX_IP_RECVERR 11
#define LINUX_IP_RECVTTL 12
#define LINUX_IP_MTU 14
#define LINUX_IP_FREEBIND 15
#define LINUX_IP_PMTUDISC_DONT 0
#define LINUX_IP_PMTUDISC_WANT 1
#define LINUX_IP_PMTUDISC_DO 2
#define LINUX_IP_PMTUDISC_PROBE 3
#define LINUX_IP_PMTUDISC_INTERFACE 4
#define LINUX_IP_PMTUDISC_OMIT 5
#define LINUX_IP_MULTICAST_TTL 33
#define LINUX_SOL_RAW 255
#define LINUX_IPV6_CHECKSUM 7
#define LINUX_SOL_IPV6 41
#define LINUX_IPV6_UNICAST_HOPS 16
#define LINUX_IPV6_RECVERR 25
#define LINUX_IPV6_V6ONLY 26
#define LINUX_IPV6_RECVPKTINFO 49
#define LINUX_IPV6_RECVHOPLIMIT 51
#define LINUX_IPV6_HOPLIMIT 52
#define LINUX_IPV6_RECVTCLASS 66
#define LINUX_IPV6_TCLASS 67

#define LINUX_ITIMER_REAL 0
#define LINUX_SIGEV_SIGNAL 0
#define LINUX_SIGEV_NONE 1
#define LINUX_SIGEV_THREAD 2
#define LINUX_SIGEV_THREAD_ID 4

#include <kernel/runtime_limits.h>
#define EDGE_MAX_FD 1024
#define EDGE_MAX_FD_PROCS PROC_MAX_TASKS
#define EDGE_MAX_PIPES EDGE_RUNTIME_MAX_PIPES
/*
 * Linux guarantees writes up to PIPE_BUF (4096 on x86) are atomic, but the
 * normal pipe capacity is larger.  Desktop stacks commonly move helper
 * protocol records larger than 4 KiB through anonymous pipes during startup
 * (for example plugin scanners).  Treating PIPE_BUF as the whole capacity
 * causes avoidable writer sleeps and can expose missed wakeups as XFCE/DBus
 * timeouts, so keep a Linux-like 16-page default capacity.
 */
#define EDGE_PIPE_SIZE KERNEL_PIPE_RUNTIME_CAPACITY
/*
 * X11, DBus, accessibility helpers, and desktop sessions keep many AF_UNIX
 * stream sockets open at once.  A pathname/abstract stream connect consumes a
 * client socket plus an accepted server-side child socket, and a full XFCE
 * session has several independent bus and X11 clients before the user opens
 * applications.  This is still a fixed table until EdgeOS grows dynamically
 * allocated socket objects, but it must be sized like a Linux desktop system:
 * exhausting it is visible to userspace as socket(AF_UNIX) == ENOMEM and makes
 * normal apps look frozen.  Receive queues are still fixed-size per socket in
 * this kernel, so keep the product of socket count and queue size under the
 * current bootstrap/linker static-data ceiling until socket buffers become
 * dynamically allocated.
 */
#define EDGE_MAX_SOCKETS EDGE_RUNTIME_MAX_SOCKETS
#define EDGE_SOCKET_RX_BUF_SIZE EDGE_RUNTIME_UNIX_SOCKET_BUFFER_SIZE
#define EDGE_SOCKET_PACKET_QUEUE EDGE_RUNTIME_UNIX_RECORD_QUEUE
#define EDGE_MAX_PTYS 64
#define EDGE_PTY_BUF_SIZE 4096
#define EDGE_SELECT_FD_MAX KERNEL_WAIT_DESCRIPTOR_MAX
#define EDGE_SELECT_FD_BYTES (EDGE_SELECT_FD_MAX / 8)
#define PTE_PRESENT 0x001ULL
#define PTE_WRITE 0x002ULL
#define PTE_USER 0x004ULL
#define PTE_PS 0x080ULL

struct edge_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

struct edge_timeval {
    int64_t tv_sec;
    int64_t tv_usec;
};

struct edge_linux_timezone {
    int32_t tz_minuteswest;
    int32_t tz_dsttime;
};

struct edge_linux_rusage {
    struct edge_timeval ru_utime;
    struct edge_timeval ru_stime;
    int64_t ru_maxrss;
    int64_t ru_ixrss;
    int64_t ru_idrss;
    int64_t ru_isrss;
    int64_t ru_minflt;
    int64_t ru_majflt;
    int64_t ru_nswap;
    int64_t ru_inblock;
    int64_t ru_oublock;
    int64_t ru_msgsnd;
    int64_t ru_msgrcv;
    int64_t ru_nsignals;
    int64_t ru_nvcsw;
    int64_t ru_nivcsw;
};

struct edge_linux_vt_mode {
    uint8_t mode;
    uint8_t waitv;
    int16_t relsig;
    int16_t acqsig;
    int16_t frsig;
};

struct edge_linux_vt_stat {
    uint16_t v_active;
    uint16_t v_signal;
    uint16_t v_state;
};

struct edge_linux_sigaction {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

struct edge_linux_utimbuf {
    int64_t actime;
    int64_t modtime;
};

struct edge_linux_siginfo_min {
    int32_t si_signo;
    int32_t si_errno;
    int32_t si_code;
    int32_t _pad0;
    int32_t si_pid;
    int32_t si_uid;
    int32_t si_status;
    int32_t _pad1;
    uint8_t _rest[128 - 32];
};

struct edge_linux_siginfo_sigsys {
    int32_t si_signo;
    int32_t si_errno;
    int32_t si_code;
    int32_t _pad0;
    uint64_t si_call_addr;
    int32_t si_syscall;
    uint32_t si_arch;
    uint8_t _rest[128 - 32];
};

struct edge_linux_input_id {
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
};

struct edge_linux_drm_version {
    int32_t version_major;
    int32_t version_minor;
    int32_t version_patchlevel;
    uint64_t name_len;
    uint64_t name;
    uint64_t date_len;
    uint64_t date;
    uint64_t desc_len;
    uint64_t desc;
};

struct edge_linux_drm_get_cap {
    uint64_t capability;
    uint64_t value;
};

struct edge_linux_epoll_event {
    uint32_t events;
    uint8_t data[8];
};

_Static_assert(sizeof(struct edge_linux_epoll_event) == 12,
               "x86_64 epoll_event ABI layout");

struct edge_linux_flock {
    int16_t l_type;
    int16_t l_whence;
    int64_t l_start;
    int64_t l_len;
    int32_t l_pid;
};

struct edge_winsize {
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
};

struct edge_linux_consolefontdesc {
    uint16_t charcount;
    uint16_t charheight;
    uint32_t __pad;
    uint64_t chardata;
};

struct edge_linux_console_font_op {
    uint32_t op;
    uint32_t flags;
    uint32_t width;
    uint32_t height;
    uint32_t charcount;
    uint32_t __pad;
    uint64_t data;
};

struct edge_termios {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[32];
};

#define LINUX_NCCS 19

/*
 * Linux x86-64 TCGETS/TCSETS use the legacy UAPI termios layout, not EdgeOS'
 * larger internal line-discipline state.  Copying the internal structure to
 * userspace corrupts callers that allocate struct termios, and BusyBox login
 * relies on this exact ABI while toggling ECHO for password input.
 */
struct linux_termios_abi {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[LINUX_NCCS];
};

#define LINUX_VINTR 0
#define LINUX_VERASE 2
#define LINUX_VKILL 3
#define LINUX_VEOF 4
#define LINUX_VTIME 5
#define LINUX_VMIN 6

struct edge_iovec {
    uint64_t iov_base;
    uint64_t iov_len;
};

typedef kernel_wait_pollfd_t edge_pollfd_t;

typedef enum {
    FD_NONE = 0,
    FD_CONSOLE,
    FD_VFS,
    FD_PIPE_R,
    FD_PIPE_W,
    FD_PIPE_RW,
    FD_SOCKET,
    FD_PTY_MASTER,
    FD_PTY_SLAVE,
    FD_EVENTFD,
    FD_TIMERFD,
    FD_SIGNALFD,
    FD_EPOLL,
    FD_PIDFD,
    FD_INOTIFY,
    FD_MEMFD,
    FD_DMA_BUF,
    FD_TUN,
    FD_NAMESPACE,
    FD_MOUNT,
    FD_MQUEUE,
} edge_fd_kind_t;

typedef struct {
    int used;
    edge_fd_kind_t kind;
    int file_ref;
    int flags;
    int fd_flags;
    uint32_t pidfd_flags;
    int async_owner;
    int async_signal;
    /*
     * Linux evdev keeps an event queue per open file description.  Xorg can
     * probe, duplicate, and poll input descriptors independently; a global
     * read cursor lets one fd consume another fd's keyboard/mouse events.
     */
    int input_event_tail;
    int dirty;
    uint8_t linkable_zero_link_inode;
    uint8_t namespace_kind;
    uint8_t namespace_padding[2];
    uint32_t namespace_id;
    uint64_t pos;
    vfs_inode_t inode;
    vfs_superblock_t *sb;
    uint64_t mount_id;
    char path[256];
    int pipe_id;
} edge_fd_t;

typedef struct edge_fd_proc {
    int pid;
    uint32_t references;
    uint32_t detached;
    uint32_t cache_owned;
    struct edge_fd_proc *retired_next;
    kernel_fd_table_runtime_t table_runtime;
    uint8_t slot_states[EDGE_MAX_FD];
    edge_fd_t fds[EDGE_MAX_FD];
} edge_fd_proc_t;

typedef kernel_pipe_runtime_t edge_pipe_t;

struct edge_sockaddr {
    uint16_t sa_family;
    char sa_data[14];
};

struct edge_sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t sin_zero[8];
};

struct edge_sockaddr_in6 {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t sin6_addr[16];
    uint32_t sin6_scope_id;
};

struct edge_sockaddr_un {
    uint16_t sun_family;
    char sun_path[108];
};

struct edge_linux_ifmap {
    uint64_t mem_start;
    uint64_t mem_end;
    uint16_t base_addr;
    uint8_t irq;
    uint8_t dma;
    uint8_t port;
    uint8_t __pad[3];
};

struct edge_linux_ifreq {
    char ifr_name[16];
    union {
        struct edge_sockaddr ifru_addr;
        struct edge_sockaddr ifru_dstaddr;
        struct edge_sockaddr ifru_broadaddr;
        struct edge_sockaddr ifru_netmask;
        struct edge_sockaddr ifru_hwaddr;
        int16_t ifru_flags;
        int32_t ifru_ivalue;
        int32_t ifru_mtu;
        int32_t ifru_ifindex;
        int32_t ifru_qlen;
        struct edge_linux_ifmap ifru_map;
        char ifru_slave[16];
        char ifru_newname[16];
        uint64_t ifru_data;
        uint8_t ifru_settings[24];
    } ifr_ifru;
};

struct edge_linux_ifconf {
    int32_t ifc_len;
    int32_t __pad;
    uint64_t ifc_buf;
};

struct edge_linux_rtentry {
    uint64_t rt_pad1;
    struct edge_sockaddr rt_dst;
    struct edge_sockaddr rt_gateway;
    struct edge_sockaddr rt_genmask;
    uint16_t rt_flags;
    int16_t rt_pad2;
    uint64_t rt_pad3;
    uint64_t rt_pad4;
    int16_t rt_metric;
    uint64_t rt_dev;
    uint64_t rt_mtu;
    uint64_t rt_window;
    uint16_t rt_irtt;
};

struct edge_linux_nlmsghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};

struct edge_linux_nlmsgerr {
    int32_t error;
    struct edge_linux_nlmsghdr msg;
};

struct edge_sockaddr_nl {
    uint16_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

struct edge_linux_ifinfomsg {
    uint8_t ifi_family;
    uint8_t __ifi_pad;
    uint16_t ifi_type;
    int32_t ifi_index;
    uint32_t ifi_flags;
    uint32_t ifi_change;
};

struct edge_linux_ifaddrmsg {
    uint8_t ifa_family;
    uint8_t ifa_prefixlen;
    uint8_t ifa_flags;
    uint8_t ifa_scope;
    uint32_t ifa_index;
};

struct edge_linux_rtmsg {
    uint8_t rtm_family;
    uint8_t rtm_dst_len;
    uint8_t rtm_src_len;
    uint8_t rtm_tos;
    uint8_t rtm_table;
    uint8_t rtm_protocol;
    uint8_t rtm_scope;
    uint8_t rtm_type;
    uint32_t rtm_flags;
};

struct edge_linux_ndmsg {
    uint8_t ndm_family;
    uint8_t ndm_pad1;
    uint16_t ndm_pad2;
    int32_t ndm_ifindex;
    uint16_t ndm_state;
    uint8_t ndm_flags;
    uint8_t ndm_type;
};

struct edge_linux_rtattr {
    uint16_t rta_len;
    uint16_t rta_type;
};

typedef struct {
    int up;
    char name[16];
    int ifindex;
    uint32_t flags;
    uint8_t mac[6];
    uint32_t mtu;
    uint32_t ipv4_addr_be;
    uint32_t ipv4_netmask_be;
    uint32_t ipv4_bcast_be;
    uint32_t ipv4_dst_be;
} edge_netif_t;

typedef struct {
    int used;
    int refs;
    /*
     * Protect receive-queue bytes, record metadata, and ancillary records.
     * AF_UNIX sendmsg must publish its first payload byte and SCM_RIGHTS as one
     * operation; otherwise a concurrent receiver can consume the byte before
     * the descriptor record exists and permanently detach the two.
     */
    spinlock_t io_lock;
    int domain;
    int type;
    int protocol;
    kernel_socket_option_state_t option_state;
    int nonblock;
    uint64_t recv_timeout_us;
    int connected;
    int connect_in_progress;
    /* Positive Linux errno retained for SO_ERROR until userspace consumes it. */
    int connect_error;
    uint64_t connect_start_us;
    int closed;
    int rx_closed;
    uint8_t shutdown_read;
    uint8_t shutdown_write;
    uint32_t shutdown_read_generation;
    uint32_t tcp_fin_rx_seen;
    uint8_t tcp_fin_pending;
    uint8_t peer_addr[128];
    uint32_t peer_len;
    uint8_t bind_addr[128];
    uint32_t bind_len;
    /*
     * Desktop Linux AF_UNIX streams need enough buffering for bursty X11/DBus
     * replies.  64 KiB was enough for simple xclock/xterm traffic but could
     * force Xorg or desktop daemons into long blocking send paths while clients
     * waited for property/window-tree replies.  Keep this generic: it is a
     * socket ABI capacity issue, not an Xorg/rootfs special case.
     */
    uint8_t *rx_buf;
    uint32_t rx_len;
    /*
     * Absolute receive positions keep SCM_RIGHTS associations stable while
     * the linear byte buffer and packet metadata rings are compacted.
     */
    uint64_t unix_stream_head_sequence;
    uint64_t unix_packet_head_sequence;
    /*
     * SOCK_DGRAM and SOCK_SEQPACKET preserve one record boundary per send.
     * Payload bytes remain in the normal receive buffer while this ring tracks
     * their lengths.  Keeping metadata separate avoids per-packet allocation
     * and lets recvmsg scatter one record across an arbitrary iovec chain.
     */
    uint32_t packet_lengths[EDGE_SOCKET_PACKET_QUEUE];
    uint64_t packet_timestamps_us[EDGE_SOCKET_PACKET_QUEUE];
    uint8_t packet_source_addresses[EDGE_SOCKET_PACKET_QUEUE][128];
    uint16_t packet_source_lengths[EDGE_SOCKET_PACKET_QUEUE];
    int32_t packet_sender_pids[EDGE_SOCKET_PACKET_QUEUE];
    uint32_t packet_sender_uids[EDGE_SOCKET_PACKET_QUEUE];
    uint32_t packet_sender_gids[EDGE_SOCKET_PACKET_QUEUE];
    kernel_socket_ip_receive_metadata_t
        packet_ip_metadata[EDGE_SOCKET_PACKET_QUEUE];
    kernel_socket_ip_receive_metadata_t received_ip_metadata;
    uint64_t received_timestamp_us;
    uint16_t packet_head;
    uint16_t packet_tail;
    uint16_t packet_count;
    uint32_t netlink_port_id;
    uint32_t netlink_groups;
    uint8_t rx_peer[128];
    uint32_t rx_peer_len;
    int32_t received_cred_pid;
    uint32_t received_cred_uid;
    uint32_t received_cred_gid;
    int ping_hw;
    uint16_t ping_id_be;
    uint8_t ping_req[256];
    uint32_t ping_req_len;
    uint8_t ping_peer[128];
    uint32_t ping_peer_len;
    uint16_t ping_next_seq_be;
    uint8_t ip_ttl;
    uint8_t ip_tos;
    uint8_t ip_pktinfo;
    uint8_t ip_recverr;
    uint8_t ip_recvttl;
    uint8_t ip_freebind;
    int ip_mtu_discover;
    uint8_t ipv6_v6only;
    uint8_t ipv6_recverr;
    uint8_t ipv6_recvpktinfo;
    uint8_t ipv6_recvhoplimit;
    uint8_t ipv6_recvtclass;
    uint8_t tcp_keepalive;
    int tcp_keepidle_sec;
    int tcp_keepintvl_sec;
    int tcp_keepcnt;
    void *lwip_pcb;
    uint16_t local_port_be;
    uint32_t network_namespace;
    int unix_peer_id;
    int cred_pid;
    uint32_t cred_uid;
    uint32_t cred_gid;
    int peer_cred_pid;
    uint32_t peer_cred_uid;
    uint32_t peer_cred_gid;
    int packet_handle;
    int ifindex;
    uint16_t filter_len;
    struct edge_linux_sock_filter filter[EDGE_SOCKET_FILTER_MAX];
    int listening;
    int backlog;
    kernel_socket_accept_queue_t accept_queue;
    int acceptq_refs;
    /*
     * Monotonic readiness generations for epoll edge-triggered watches.  Keep
     * read and write edges separate: X11/DBus streams are often readable and
     * writable at the same time, and treating a peer-drained write-space wake as
     * a new read edge makes EPOLLET users spin on unchanged incoming data.
     */
    kernel_socket_readiness_t readiness;
    kernel_socket_external_readiness_t external_readiness;
    kernel_socket_rights_queue_t rights;
} edge_socket_t;

#define EDGE_MAX_UNIX_BINDINGS 256
#define EDGE_UNIX_BINDING_KEY_SIZE 216
typedef struct {
    int used;
    int sock_id;
    /*
     * Internal AF_UNIX registry key.  Linux sun_path is 108 bytes, and
     * EdgeOS represents abstract names with an extra printable '@' prefix for
     * debug and registry lookups.  Keep headroom for that prefix plus NUL so a
     * full-length Linux abstract name is not silently truncated in the
     * in-kernel endpoint cache.
     */
    char path[EDGE_UNIX_BINDING_KEY_SIZE];
} edge_unix_binding_t;

#define EDGE_MAX_EVENTFDS EDGE_RUNTIME_MAX_EVENTFDS
#define EDGE_MAX_TIMERFDS EDGE_RUNTIME_MAX_TIMERFDS
#define EDGE_MAX_EPOLLS EDGE_RUNTIME_MAX_EPOLLS
#define EDGE_EPOLL_MAX_WATCH EDGE_RUNTIME_MAX_EPOLL_WATCHES

typedef kernel_epoll_watch_t edge_epoll_watch_t;
typedef kernel_epoll_object_t edge_epoll_t;

static int epoll_post_register_ready(edge_fd_proc_t *p, int epoll_index);

typedef struct {
    int used;
    int refs_master;
    int refs_slave;
    int unlocked;
    edge_linux_tty_session_state_t session;
    int packet_mode;
    devpts_slave_handle_t slave_inode;
    struct edge_termios termios;
    struct edge_winsize winsz;
    uint32_t m2s_rpos;
    uint32_t m2s_wpos;
    uint32_t m2s_count;
    uint8_t m2s_buf[EDGE_PTY_BUF_SIZE];
    uint32_t s2m_rpos;
    uint32_t s2m_wpos;
    uint32_t s2m_count;
    uint8_t s2m_buf[EDGE_PTY_BUF_SIZE];
} edge_pty_t;

typedef struct {
    struct edge_termios termios;
    edge_linux_tty_session_state_t session;
    /*
     * EdgeOS exposes a Linux-style /dev/console alias onto the active VT.
     * Boot scripts may also spawn a dedicated tty1 getty.  With the current
     * single foreground keyboard queue, multiple session leaders reading the
     * same active VT can steal each other's login input.  Track the foreground
     * line's first session opener so later duplicate gettys can be parked on
     * an inactive VT instead of racing the visible login.
     */
    int primary_open_pid;
    int primary_open_sid;
    uint8_t vt_mode;
    uint8_t vt_waitv;
    uint8_t kd_mode;
    uint8_t kbd_mode;
    int kd_owner_pid;
    int16_t vt_relsig;
    int16_t vt_acqsig;
    int16_t vt_frsig;
    /*
     * Linux N_TTY accepts large pasted command lines (N_TTY_BUF_SIZE is 4096).
     * Keep EdgeOS in that range so serial-driven validation and normal shell
     * use do not silently truncate long but valid input before userspace sees a
     * newline.
     */
    char linebuf[4096];
    int line_len;
    int line_pos;
    int line_drop_count;
    int line_drop_logged;
    char replybuf[64];
    int reply_len;
    int reply_pos;
    int dsr_state;
    int read_wait_pid;
} edge_console_line_t;

typedef struct {
    uint64_t uaddr;
    int private_key;
} edge_futex_wait_key_t;

typedef struct {
    int used;
    int waiting;
    int pid;
    int private_key;
    uint64_t uaddr;
    uint32_t bitset;
    uint64_t deadline_us;
    int result;
    int waitv_index;
    uint16_t waitv_count;
    edge_futex_wait_key_t waitv_keys[KERNEL_FUTEX_WAITV_MAX];
} edge_futex_waiter_t;

#define EDGE_MEMFD_MAX 128
#define EDGE_MEMFD_MAX_PAGES 16384
#define EDGE_MEMFD_NAME_MAX KERNEL_MEMFD_NAME_MAX

typedef struct {
    int used;
    uint32_t descriptor_refs;
    uint32_t mapping_refs;
    int id;
    uint32_t seals;
    uint64_t size;
    char name[EDGE_MEMFD_NAME_MAX + 1];
    int page_idx[EDGE_MEMFD_MAX_PAGES];
    uint64_t *swap_entries;
} edge_memfd_t;

/*
 * A files context is process-owned and shared by CLONE_FILES threads.  Keep
 * only pointers in the image and allocate the descriptor table when a process
 * first needs one.  Reserving EDGE_MAX_FD entries for every scheduler task in
 * .bss consumed hundreds of MiB and made browser thread capacity collide with
 * the fixed x86-64 userspace windows even though most threads shared one table.
 */
static edge_fd_proc_t *g_fd_procs[EDGE_MAX_FD_PROCS];
static spinlock_t g_fd_proc_registry_lock;
static uint32_t g_fd_proc_registry_readers;
static edge_fd_proc_t *g_fd_proc_retired_head;
/*
 * x86-64 backs general page allocations with the same sparse page pool used
 * by userspace.  A complete files table is intentionally large enough for
 * RLIMIT_NOFILE, so allocating it as one physical run after a desktop has
 * faulted thousands of pages can fail despite ample free memory.  Keep a
 * boot-reserved cache for the normal process high-water mark and retain the
 * dynamic allocator as overflow capacity.  Returned tables remain reusable;
 * normal fork/exit churn therefore does not depend on physical contiguity.
 */
#define EDGE_FD_PROC_CACHE_CAPACITY 128u
static edge_fd_proc_t *g_fd_proc_cache[EDGE_FD_PROC_CACHE_CAPACITY];
static uint32_t g_fd_proc_cache_count;
static uint32_t g_fd_proc_cache_reserved;
/*
 * O_ASYNC input notification is descriptor state, but walking every process
 * and every possible descriptor after each USB poll makes an idle evdev fd
 * disproportionately expensive.  Keep a dense list of the descriptors that
 * can currently receive SIGIO, plus a reverse index for constant-time fd
 * lifecycle updates.  The table has one slot for every possible descriptor,
 * so enabling asynchronous input never introduces a smaller compatibility
 * limit than RLIMIT_NOFILE and the process table already expose.
 */
#define EDGE_ASYNC_INPUT_SLOT_COUNT (EDGE_MAX_FD_PROCS * EDGE_MAX_FD)
static uint32_t g_async_input_watchers[EDGE_ASYNC_INPUT_SLOT_COUNT];
static uint32_t g_async_input_watch_positions[EDGE_ASYNC_INPUT_SLOT_COUNT];
static uint32_t g_async_input_watcher_count;
static spinlock_t g_async_input_watch_lock;
static edge_pipe_t g_pipes[EDGE_MAX_PIPES];
static edge_socket_t *g_sockets;
static uint8_t g_socket_slot_claims[EDGE_MAX_SOCKETS];
static uint64_t g_socket_table_phys;
static uint32_t g_socket_table_pages;
static int g_socket_table_ready;
static uint8_t *g_socket_rx_storage;
static uint64_t g_socket_rx_storage_phys;
static uint32_t g_socket_rx_storage_pages;
static int g_socket_rx_storage_ready;
static kernel_socket_connect_deadline_tracker_t
    g_socket_connect_deadline_tracker;

static uint8_t *socket_rx_buffer_for_id(int sock_id) {
    if (!g_socket_rx_storage_ready || !g_socket_rx_storage) return 0;
    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS) return 0;
    return g_socket_rx_storage + ((uint64_t)sock_id * EDGE_SOCKET_RX_BUF_SIZE);
}

static uint32_t socket_rx_capacity(const edge_socket_t *s) {
    return (s && s->rx_buf) ? (uint32_t)EDGE_SOCKET_RX_BUF_SIZE : 0;
}

static int socket_type_is_record(int type) {
    return type == LINUX_SOCK_DGRAM || type == LINUX_SOCK_SEQPACKET;
}

static void socket_unix_poll_snapshot(
    const edge_socket_t *socket,
    kernel_unix_socket_poll_result_t *result) {
    kernel_unix_socket_poll_state_t state;
    const edge_socket_t *peer;

    memset(&state, 0, sizeof(state));
    if (!socket || socket->domain != LINUX_AF_UNIX) {
        kernel_unix_socket_poll_policy(0, result);
        return;
    }
    state.type = (uint32_t)socket->type;
    state.connected = socket->connected != 0;
    state.shutdown_read = socket->shutdown_read != 0;
    state.shutdown_write = socket->shutdown_write != 0;
    state.peer_eof = socket->rx_closed || socket->closed;
    if (socket->unix_peer_id >= 0 &&
        socket->unix_peer_id < EDGE_MAX_SOCKETS) {
        peer = &g_sockets[socket->unix_peer_id];
        state.peer_valid = peer->used != 0;
        if (state.peer_valid) {
            state.peer_shutdown_read = peer->shutdown_read != 0;
            state.peer_receive_used = peer->rx_len;
            state.peer_receive_capacity = socket_rx_capacity(peer);
            state.peer_record_count = (uint32_t)peer->packet_count;
            state.peer_record_capacity = EDGE_SOCKET_PACKET_QUEUE;
        }
    }
    kernel_unix_socket_poll_policy(&state, result);
}

static int socket_has_receive_data(const edge_socket_t *s) {
    if (!s) return 0;
    if (s->domain == LINUX_AF_NETLINK) return s->packet_count != 0;
    if (socket_type_is_record(s->type) &&
        (s->domain == LINUX_AF_UNIX ||
         s->domain == LINUX_AF_INET ||
         s->domain == LINUX_AF_INET6))
        return s->packet_count != 0;
    return s->rx_len != 0;
}

static int socket_is_icmp_reader(const edge_socket_t *socket) {
    return socket && kernel_socket_is_icmp_reader(
        (uint32_t)socket->domain, (uint32_t)socket->type,
        (uint32_t)socket->protocol);
}

static uint32_t socket_packet_front_length(const edge_socket_t *s) {
    if (!s || s->packet_count == 0) return 0;
    return s->packet_lengths[s->packet_head];
}

static int socket_packet_push_source(edge_socket_t *s, uint32_t length,
                                     const void *source,
                                     uint32_t source_length,
                                     int32_t sender_pid,
                                     uint32_t sender_uid,
                                     uint32_t sender_gid,
                                     const kernel_socket_ip_receive_metadata_t
                                         *ip_metadata) {
    if (!s || s->packet_count >= EDGE_SOCKET_PACKET_QUEUE) return -1;
    if (source_length > sizeof(s->packet_source_addresses[0])) return -1;
    s->packet_lengths[s->packet_tail] = length;
    s->packet_timestamps_us[s->packet_tail] = boottime_realtime_us();
    s->packet_source_lengths[s->packet_tail] = (uint16_t)source_length;
    s->packet_sender_pids[s->packet_tail] = sender_pid;
    s->packet_sender_uids[s->packet_tail] = sender_uid;
    s->packet_sender_gids[s->packet_tail] = sender_gid;
    memset(&s->packet_ip_metadata[s->packet_tail], 0,
           sizeof(s->packet_ip_metadata[s->packet_tail]));
    if (ip_metadata)
        s->packet_ip_metadata[s->packet_tail] = *ip_metadata;
    memset(s->packet_source_addresses[s->packet_tail], 0,
           sizeof(s->packet_source_addresses[s->packet_tail]));
    if (source && source_length)
        memcpy(s->packet_source_addresses[s->packet_tail], source,
               source_length);
    s->packet_tail = (uint16_t)((s->packet_tail + 1u) % EDGE_SOCKET_PACKET_QUEUE);
    s->packet_count++;
    return 0;
}

static int socket_packet_push(edge_socket_t *s, uint32_t length) {
    return socket_packet_push_source(s, length, 0, 0, 0, 0, 0, 0);
}

static void socket_packet_pop(edge_socket_t *s) {
    if (!s || s->packet_count == 0) return;
    s->received_timestamp_us = s->packet_timestamps_us[s->packet_head];
    s->packet_lengths[s->packet_head] = 0;
    s->packet_timestamps_us[s->packet_head] = 0;
    s->packet_source_lengths[s->packet_head] = 0;
    s->packet_sender_pids[s->packet_head] = 0;
    s->packet_sender_uids[s->packet_head] = 0;
    s->packet_sender_gids[s->packet_head] = 0;
    memset(&s->packet_ip_metadata[s->packet_head], 0,
           sizeof(s->packet_ip_metadata[s->packet_head]));
    memset(s->packet_source_addresses[s->packet_head], 0,
           sizeof(s->packet_source_addresses[s->packet_head]));
    s->packet_head = (uint16_t)((s->packet_head + 1u) % EDGE_SOCKET_PACKET_QUEUE);
    s->packet_count--;
}

static void socket_packet_unpush(edge_socket_t *s) {
    uint16_t tail;
    if (!s || s->packet_count == 0) return;
    tail = (uint16_t)((s->packet_tail + EDGE_SOCKET_PACKET_QUEUE - 1u) %
                      EDGE_SOCKET_PACKET_QUEUE);
    s->packet_lengths[tail] = 0;
    s->packet_timestamps_us[tail] = 0;
    s->packet_source_lengths[tail] = 0;
    s->packet_sender_pids[tail] = 0;
    s->packet_sender_uids[tail] = 0;
    s->packet_sender_gids[tail] = 0;
    memset(&s->packet_ip_metadata[tail], 0,
           sizeof(s->packet_ip_metadata[tail]));
    memset(s->packet_source_addresses[tail], 0,
           sizeof(s->packet_source_addresses[tail]));
    s->packet_tail = tail;
    s->packet_count--;
}
/*
 * Socket poll/epoll waiters are the hottest wakeup path for X11 and DBus.
 * Keep a compact pid list per socket so AF_UNIX stream writes can wake the
 * blocked task directly instead of scanning every process' 1024-entry fd
 * table for every protocol record.  The broad fd-owner scan remains as a
 * fallback for close/dup/fork cases this compact table does not model yet.
 *
 * Store the requested poll mask beside the pid.  Waking every registered
 * socket waiter for every peer transition is observably wrong for X11/DBus:
 * GLib often has separate read-side and write-side waits, and a write-space
 * change on one endpoint must not keep a read-side helper runnable when there
 * is still no data to consume.
 */
#define EDGE_SOCKET_WAITERS 64
static int g_socket_waiter_pids[EDGE_MAX_SOCKETS][EDGE_SOCKET_WAITERS];
static uint16_t g_socket_waiter_events[EDGE_MAX_SOCKETS][EDGE_SOCKET_WAITERS];
static uint8_t g_socket_waiter_overflow[EDGE_MAX_SOCKETS];
#define EDGE_EVENTFD_WAITERS 64
static int g_eventfd_read_waiter_pids[EDGE_MAX_EVENTFDS][EDGE_EVENTFD_WAITERS];
static int g_eventfd_write_waiter_pids[EDGE_MAX_EVENTFDS][EDGE_EVENTFD_WAITERS];
#define EDGE_PIPE_WAITERS 64
static int g_pipe_read_waiter_pids[EDGE_MAX_PIPES][EDGE_PIPE_WAITERS];
static int g_pipe_write_waiter_pids[EDGE_MAX_PIPES][EDGE_PIPE_WAITERS];
static uint8_t g_pipe_read_waiter_overflow[EDGE_MAX_PIPES];
static uint8_t g_pipe_write_waiter_overflow[EDGE_MAX_PIPES];

#define EDGE_WAITER_BITMAP_WORDS(limit) (((limit) + 63u) / 64u)
typedef struct edge_waiter_owner {
    int pid;
    uint64_t sockets[EDGE_WAITER_BITMAP_WORDS(EDGE_MAX_SOCKETS)];
    uint64_t eventfd_read[EDGE_WAITER_BITMAP_WORDS(EDGE_MAX_EVENTFDS)];
    uint64_t eventfd_write[EDGE_WAITER_BITMAP_WORDS(EDGE_MAX_EVENTFDS)];
    uint64_t pipe_read[EDGE_WAITER_BITMAP_WORDS(EDGE_MAX_PIPES)];
    uint64_t pipe_write[EDGE_WAITER_BITMAP_WORDS(EDGE_MAX_PIPES)];
} edge_waiter_owner_t;

/*
 * Linux wait queues unlink a task from the objects it actually waited on.
 * Retain the per-object waiter tables as the source of truth, and keep this
 * reverse membership index so a poll/epoll wake does not scan every socket,
 * eventfd, and pipe in the system.  One owner slot per possible task preserves
 * full waiter capacity while reducing the common dequeue cost from tens of
 * thousands of cells to the handful of descriptors in the current wait set.
 */
static edge_waiter_owner_t g_waiter_owners[PROC_MAX_TASKS];
/*
 * Every waiter insertion is indexed before the task can block.  If that
 * invariant cannot be maintained, retain correctness by enabling the complete
 * table scan in waiter_remove_pid(); the normal indexed path never pays for it.
 */
static int g_waiter_index_degraded;
static spinlock_t g_waiter_lock;
static edge_pty_t g_ptys[EDGE_MAX_PTYS];
static edge_memfd_t g_memfds[EDGE_MEMFD_MAX];
static edge_unix_binding_t g_unix_bindings[EDGE_MAX_UNIX_BINDINGS];
static uint16_t g_next_ephemeral_port = 49152;
static edge_console_line_t g_console_lines[EDGE_FB_VT_COUNT + 1];
static edge_futex_waiter_t g_futex_waiters[PROC_MAX_TASKS];
static spinlock_t g_futex_lock;
static int g_active_vt = 1;
/*
 * Linux defaults /dev/console to the active VT when no explicit serial
 * console is selected.  EdgeOS used to default this to ttyS0, which made a
 * LiveCD graphical login look alive on fbcon while its getty was actually
 * reading COM1 and ignored PS/2/USB keyboard input.  Keep -1 as "use active
 * VT"; console=ttyS0 still sets line 0 explicitly during boot cmdline parsing.
 */
static int g_preferred_console_line = -1;
static int g_reserved_x11_vt = 7;
static int g_console_last_input_was_serial;
static uint32_t g_console_serial_wait_poll_ticks;
static int g_tty_read_log_pids[64];
static int g_tty_read_log_count;
static int g_tty_fg_fix_log_pids[64];
static int g_tty_fg_fix_log_count;
static int g_tty_ioctl_log_pids[64];
static int g_tty_ioctl_log_count;
static int g_fb_console_hold_count;
static int g_fb_console_tty_batch_active;
static uint64_t g_fb_console_tty_flush_deadline_us;
static uint64_t g_gui_fb_mmap_pump_next_us;
static uint32_t g_gui_fb_mmap_pump_poll_count;
static uint32_t g_vfs_writeback_poll_count;
static uint32_t g_gui_ready_preempt_burst;
static uint8_t g_console_font_ioctl_buf[512u * 32u];

static inline void syscall_fbdev_mmap_pump_poll(void) {
    uint64_t now_us;

    /*
     * The display cadence is time-based, but reading the clock on every
     * syscall and every short wait-loop iteration makes unrelated work pay
     * for a check that almost always returns early.  Eight process-context
     * opportunities are still substantially more frequent than a display
     * frame during active desktop work.
     */
    if ((++g_gui_fb_mmap_pump_poll_count & 7u) != 0) return;
    if (!fb_user_mmap_active()) return;
    now_us = boottime_monotonic_us();
    if (now_us < g_gui_fb_mmap_pump_next_us) return;
    g_gui_fb_mmap_pump_next_us = now_us + 10000ull;
    fb_user_mmap_tick((uint32_t)(now_us / 10000ull));
}

static inline void syscall_vfs_writeback_poll(void) {
    /*
     * Writeback has a five-second deadline.  Sampling it once per 64 syscall
     * returns preserves that cadence under active workloads without adding a
     * clock read to every small Linux ABI call.
     */
    if ((++g_vfs_writeback_poll_count & 63u) != 0) return;
    kernel_boot_log_poll();
    vfs_writeback_poll();
}

/*
 * Keep Linux-visible network interface state out of late .bss.  EdgeOS still
 * runs syscalls on task CR3s where selected low virtual ranges are Linux user
 * ABI windows; if these structs land in such a range, socket ioctls see user
 * pages instead of kernel netdev state.  The non-zero initializers force .data,
 * and net_init_defaults() still rewrites the canonical runtime values at boot.
 */
static edge_netif_t g_if_lo = {
    .up = 1,
    .name = "lo",
    .ifindex = 1,
    .flags = LINUX_IFF_UP | LINUX_IFF_RUNNING | LINUX_IFF_LOOPBACK,
    .mtu = 65536,
    .ipv4_addr_be = 0x0100007fu,
    .ipv4_netmask_be = 0x000000ffu,
    .ipv4_bcast_be = 0xffffff7fu,
    .ipv4_dst_be = 0x0100007fu,
};
static edge_netif_t g_if_eth0 = {
    .up = 1,
    .name = "eth0",
    .ifindex = 2,
    .flags = LINUX_IFF_UP | LINUX_IFF_RUNNING | LINUX_IFF_BROADCAST | LINUX_IFF_MULTICAST,
    .mac = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 },
    .mtu = 1500,
    .ipv4_addr_be = 0x0f02000au,
    .ipv4_netmask_be = 0x00ffffffu,
    .ipv4_bcast_be = 0xff02000au,
    .ipv4_dst_be = 0x0202000au,
};
static uint8_t g_raw_ipv4_tx[65535];
static spinlock_t g_raw_ipv4_tx_lock;

static int x11_debug_task(const task_t *t) {
#if EDGE_X11_TRACE
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "xsetroot") == 0 ||
           strcmp(t->name, "twm") == 0 ||
           strcmp(t->name, "xterm") == 0 ||
           strcmp(t->name, "xclock") == 0;
#else
    (void)t;
    return 0;
#endif
}

static int xfce_debug_task(const task_t *t) {
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "startxfce4") == 0 ||
           strcmp(t->name, "xrdb") == 0 ||
           strcmp(t->name, "cat") == 0 ||
#if EDGE_XFCE_TRACE
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "xfconfd") == 0 ||
           strcmp(t->name, "xfce4-terminal") == 0 ||
           strcmp(t->name, "gmain") == 0 ||
           strcmp(t->name, "gdbus") == 0 ||
           strcmp(t->name, "[pango] fontcon") == 0 ||
           strcmp(t->name, "dbus-run-sessio") == 0 ||
           strcmp(t->name, "dbus-run-session") == 0 ||
           strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "InputThread") == 0 ||
           strcmp(t->name, "dbus-launch") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0 ||
           strcmp(t->name, "xclock") == 0 ||
           strcmp(t->name, "xwininfo") == 0 ||
           strcmp(t->name, "xdpyinfo") == 0 ||
#endif
           0;
}

static int edge_x11_crash_trace_task(const task_t *t) {
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "Thunar") == 0 ||
           strcmp(t->name, "gdbus") == 0 ||
           strcmp(t->name, "gmain") == 0 ||
           strcmp(t->name, "xclock") == 0;
}

static int g_xfce_sys_trace_budget = EDGE_XFCE_TRACE ? 384 : 0;
static int g_pipe_lifecycle_trace_budget = EDGE_XFCE_TRACE ? 512 : 0;
static int g_xfce_pipe_lifecycle_armed = 0;

static int pipe_lifecycle_trace_task(const task_t *t) {
    if (!g_xfce_pipe_lifecycle_armed) return 0;
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "sh") == 0 ||
           strcmp(t->name, "-sh") == 0 ||
           strcmp(t->name, "busybox") == 0 ||
           strcmp(t->name, "startxfce4") == 0 ||
           strcmp(t->name, "cat") == 0 ||
           strcmp(t->name, "xrdb") == 0 ||
           strcmp(t->name, "dbus-run-sessio") == 0 ||
           strcmp(t->name, "dbus-run-session") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0;
}

static int gui_diag_task(const task_t *t) {
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "InputThread") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "xfconfd") == 0 ||
           strcmp(t->name, "xfce4-terminal") == 0 ||
           strcmp(t->name, "Terminal") == 0 ||
           strcmp(t->name, "Thunar") == 0 ||
           strcmp(t->name, "thunar") == 0 ||
           strcmp(t->name, "xclock") == 0 ||
           strcmp(t->name, "wrapper-2.0") == 0 ||
           strcmp(t->name, "gdbus") == 0 ||
           strcmp(t->name, "gmain") == 0 ||
           strcmp(t->name, "chromium") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0 ||
           strcmp(t->name, "dbus-launch") == 0 ||
           strcmp(t->name, "[pango] fontcon") == 0;
}

static int chromium_diag_task(const task_t *t) {
    const task_t *leader;
    int group;

    if (!t) return 0;
    if (strcmp(t->name, "chromium") == 0) return 1;
    group = t->tgid > 0 ? t->tgid : t->pid;
    leader = process_get_task(group);
    return leader && strcmp(leader->name, "chromium") == 0;
}

static int linux_sig_is_rt(uint64_t sig) {
    return sig >= LINUX_SIGRT_BASE && sig <= LINUX_SIGRTMAX;
}

static task_t *task_signal_group_leader_local(const task_t *task) {
    int group;
    const task_t *leader;
    if (!task) return 0;
    group = task->tgid > 0 ? task->tgid : task->pid;
    leader = process_get_task(group);
    return leader ? (task_t *)(uintptr_t)leader : (task_t *)(uintptr_t)task;
}

static int task_signal_runtime_state(
    task_t *task, kernel_signal_runtime_state_t *state) {
    task_t *leader;
    if (!task || !state) return -EINVAL;
    leader = task_signal_group_leader_local(task);
    memset(state, 0, sizeof(*state));
    state->tid = task->pid;
    state->tgid = leader ? leader->pid : task->pid;
    state->thread_pending = &task->signal_pending;
    state->shared_pending = leader ? &leader->signal_shared_pending :
                                     &task->signal_shared_pending;
    state->blocked_mask = &task->sigmask;
    state->saved_mask = &task->signal_saved_mask;
    state->restore_mask_pending = &task->signal_restore_mask_pending;
    state->actions = leader ? leader->signal_actions : task->signal_actions;
    state->altstack_pointer = &task->sigaltstack_sp;
    state->altstack_size = &task->sigaltstack_size;
    state->altstack_flags = &task->sigaltstack_flags;
    state->minimum_altstack_size = LINUX_MINSIGSTKSZ;
    state->seccomp_sigsys_pending = &task->seccomp_sigsys_valid;
    state->seccomp_sigsys_errno = task->seccomp_sigsys_errno;
    state->seccomp_sigsys_number = task->seccomp_sigsys_nr;
    state->seccomp_sigsys_architecture = task->seccomp_sigsys_arch;
    state->seccomp_sigsys_call_address = task->seccomp_sigsys_call_addr;
    return 0;
}

static edge_linux_signal_action_t *task_signal_action_local(
    const task_t *task, uint32_t signal) {
    task_t *leader;
    if (!task || !edge_linux_signal_valid(signal)) return 0;
    leader = task_signal_group_leader_local(task);
    return leader ? &leader->signal_actions[signal - 1u] : 0;
}

static uint64_t task_pending_signal_mask(const task_t *task) {
    kernel_signal_runtime_state_t state;
    return task_signal_runtime_state(
        (task_t *)(uintptr_t)task, &state) == 0 ?
        kernel_signal_pending_mask(&state) : 0;
}

static int task_next_unblocked_signal(const task_t *task, uint64_t blocked) {
    kernel_signal_runtime_state_t state;
    if (task_signal_runtime_state(
            (task_t *)(uintptr_t)task, &state) < 0)
        return 0;
    return (int)kernel_signal_pending_next(
        &state, ~blocked | EDGE_LINUX_SIGNAL_UNBLOCKABLE_MASK);
}

static void task_install_wait_sigmask(task_t *t, uint64_t new_sigmask) {
    kernel_signal_runtime_state_t state;
    /*
     * Linux wait syscalls such as ppoll(2), pselect6(2), and epoll_pwait(2)
     * install the caller-provided signal mask only for the wait.  If the wait
     * is interrupted, Linux leaves restoration pending so the signal frame
     * saves the original mask and rt_sigreturn restores it.  Restoring the old
     * mask before signal delivery changes which pending signals are visible to
     * the handler and can strand GUI/event-loop work behind an idle wait.
     */
    if (task_signal_runtime_state(t, &state) == 0)
        kernel_signal_wait_mask_install(&state, new_sigmask);
}

static void task_restore_wait_sigmask_unless(task_t *t, int interrupted) {
    kernel_signal_runtime_state_t state;
    if (task_signal_runtime_state(t, &state) == 0)
        kernel_signal_wait_mask_finish(&state, interrupted);
}

static uint64_t task_signal_frame_sigmask(task_t *t) {
    kernel_signal_runtime_state_t state;
    return task_signal_runtime_state(t, &state) == 0 ?
        kernel_signal_wait_mask_take_for_frame(&state) : 0;
}

static void task_cancel_wait_sigmask_restore(task_t *t) {
    kernel_signal_runtime_state_t state;
    if (task_signal_runtime_state(t, &state) == 0)
        kernel_signal_wait_mask_cancel(&state);
}

/*
 * Budgeted XFCE bring-up tracing.  Keep this off by default: serial logging is
 * synchronous enough to make GTK/XFCE startup look like a scheduler or input
 * bug.  Enable EDGE_XFCE_BOOT_TRACE only for focused diagnostics after first
 * reproducing the problem without trace traffic.
 */
static int xfce_boot_trace_task(const task_t *t) {
#if EDGE_XFCE_BOOT_TRACE
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "startxfce4") == 0 ||
           strcmp(t->name, "dbus-run-sessio") == 0 ||
           strcmp(t->name, "dbus-run-session") == 0 ||
           strcmp(t->name, "dbus-launch") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "xfconfd") == 0;
#else
    (void)t;
    return 0;
#endif
}

static int g_xfce_epoll_trace_budget = 0;
static int g_xfce_boot_trace_budget = EDGE_XFCE_BOOT_TRACE ? 320 : 0;
static int g_xfce_boot_path_trace_budget = EDGE_XFCE_BOOT_TRACE ? 192 : 0;
/*
 * Always-on, bounded diagnostics for desktop bring-up.  X11/XFCE readiness
 * paths are hot and serial output is synchronous on EdgeOS, so even "bounded"
 * logging can change Linux userspace timing enough to make normal desktop
 * startup look hung.  Keep the default breadcrumbs tiny; use the explicit
 * EDGE_XFCE_TRACE/EDGE_PTY_DIAG_TRACE switches for focused investigations.
 */
/*
 * Bounded GUI wait diagnostics.  Serial is synchronous and X11/GLib wake paths
 * are hot, so large budgets can create the same multi-minute stalls being
 * debugged.  Keep default breadcrumbs tiny and raise them only for a focused
 * local trace.
 */
static int g_gui_ready_detail_trace_budget = EDGE_GUI_DEEP_TRACE ? 12 : 0;
/*
 * Keep a tiny always-on budget for GUI epoll readiness.  XFCE startup is the
 * practical Linux ABI test for AF_UNIX, eventfd, timerfd, signalfd, and evdev
 * readiness.  False-ready events make GLib/Xorg spin in kernel syscalls while
 * userspace appears idle, so a handful of breadcrumbs is worth the serial cost.
 * Raise EDGE_GUI_DEEP_TRACE only for local focused work; do not add app/path
 * special cases here.
 */
static int g_gui_epoll_ready_trace_budget =
    EDGE_GUI_DEEP_TRACE ? 24 : 0;
static int g_gui_eventfd_trace_budget = EDGE_GUI_DEEP_TRACE ? 8 : 0;
static int g_gui_wait_block_trace_budget = EDGE_GUI_DEEP_TRACE ? 32 : 0;
static int g_gui_wait_fd_trace_budget =
    EDGE_GUI_DEEP_TRACE ? 24 : 0;
static int g_xorg_epoll_wait_trace_budget = EDGE_GUI_DEEP_TRACE ? 32 : 0;
static int g_sleep_trace_budget = 0;
/*
 * Hot epoll(timeout=0) loops are normal for Xorg/GLib/DBus while they drain
 * local sockets.  Serial logging from that path is synchronous and can turn a
 * working XFCE startup into a multi-minute crawl, so keep the default budget
 * tiny.  These breadcrumbs are specifically for Linux ABI mismatches where
 * epoll reports a readable AF_UNIX fd and the next recvmsg() returns EAGAIN,
 * which pins Xorg and makes the desktop look frozen.
 */
static int g_epoll_spin_trace_budget = EDGE_GUI_DEEP_TRACE ? 32 : 0;
static int g_pipe_hup_trace_budget = 0;
#if EDGE_BB_FD_TRACE
static int g_bb_fd_trace_budget = 64;
#endif

static void wake_new_child_and_yield(int child_pid) {
    if (child_pid <= 0) return;
    (void)process_publish_new_task(child_pid);
    /*
     * Linux may schedule the child immediately after clone/fork.  EdgeOS is
     * still cooperative at syscall boundaries, so without an explicit yield a
     * shell or desktop launcher can continue polling while its just-created
     * child sits runnable behind hot X11/DBus tasks.  That stretched XFCE
     * startup sleeps into minute-scale delays even though the child was ready.
     */
    scheduler_yield();
}

static void termios_init_sane(struct edge_termios *t) {
    if (!t) return;
    memset(t, 0, sizeof(*t));
    t->c_iflag = LINUX_ICRNL;
    t->c_oflag = LINUX_OPOST | LINUX_ONLCR;
    t->c_lflag = LINUX_ICANON | LINUX_ECHO | LINUX_ECHOE |
                 LINUX_ECHOK | LINUX_ECHOCTL | LINUX_ECHOKE |
                 LINUX_IEXTEN | LINUX_ISIG;
    t->c_cc[LINUX_VINTR] = 3;
    t->c_cc[LINUX_VERASE] = 127;
    t->c_cc[LINUX_VKILL] = 21;
    t->c_cc[LINUX_VEOF] = 4;
    t->c_cc[LINUX_VTIME] = 0;
    t->c_cc[LINUX_VMIN] = 1;
}

static void termios_to_linux_abi(const struct edge_termios *src, struct linux_termios_abi *dst) {
    if (!src || !dst) return;
    memset(dst, 0, sizeof(*dst));
    dst->c_iflag = src->c_iflag;
    dst->c_oflag = src->c_oflag;
    dst->c_cflag = src->c_cflag;
    dst->c_lflag = src->c_lflag;
    dst->c_line = src->c_line;
    for (unsigned i = 0; i < LINUX_NCCS; ++i) dst->c_cc[i] = src->c_cc[i];
}

static void termios_from_linux_abi(struct edge_termios *dst, const struct linux_termios_abi *src) {
    if (!dst || !src) return;
    dst->c_iflag = src->c_iflag;
    dst->c_oflag = src->c_oflag;
    dst->c_cflag = src->c_cflag;
    dst->c_lflag = src->c_lflag;
    dst->c_line = src->c_line;
    for (unsigned i = 0; i < LINUX_NCCS; ++i) dst->c_cc[i] = src->c_cc[i];
}

static int console_line_is_serial(int line_id) {
    return line_id == 0;
}

static int console_line_valid(int line_id) {
    return line_id >= 0 && line_id <= EDGE_FB_VT_COUNT;
}

static int console_line_active_vt(void) {
    if (g_active_vt < 1 || g_active_vt > EDGE_FB_VT_COUNT) g_active_vt = 1;
    return g_active_vt;
}

static int console_line_default(void) {
    if (g_preferred_console_line >= 0 && g_preferred_console_line <= EDGE_FB_VT_COUNT) {
        return g_preferred_console_line;
    }
    return console_line_active_vt();
}

static inline void wait_poll_yield_step(void);
static inline void wait_gui_ready_preempt_step(void);
static inline void wait_blocking_step(void);

static edge_console_line_t *console_line_state(int line_id) {
    if (!console_line_valid(line_id)) return 0;
    return &g_console_lines[line_id];
}

static int console_line_has_input_for_waiter(int line_id) {
    edge_console_line_t *line = console_line_state(line_id);
    if (!line) return 0;
    if (line->reply_pos < line->reply_len) return 1;
    if ((line->termios.c_lflag & LINUX_ICANON) != 0) {
        for (int i = line->line_pos; i < line->line_len; ++i) {
            if (line->linebuf[i] == '\n') return 1;
        }
    } else if (line->line_pos < line->line_len) {
        return 1;
    }
    if (console_line_is_serial(line_id)) return serial_console_haschar();
    if (line_id == console_line_active_vt()) return keyboard_haschar();
    return 0;
}

static int console_line_has_buffered_input_for_waiter(int line_id) {
    edge_console_line_t *line = console_line_state(line_id);
    if (!line) return 0;
    if (line->reply_pos < line->reply_len) return 1;
    if ((line->termios.c_lflag & LINUX_ICANON) != 0) {
        for (int i = line->line_pos; i < line->line_len; ++i) {
            if (line->linebuf[i] == '\n') return 1;
        }
    } else if (line->line_pos < line->line_len) {
        return 1;
    }
    /*
     * This helper is used from the timer-side sleeping-tty wake path.  Do not
     * touch COM1 hardware here: serial_console_haschar() drains the 16550 with
     * an idle loop, and doing that on every timer tick made an idle serial
     * login shell consume a host CPU.  The fallback below performs a low-rate
     * hardware poll for the QEMU pty cases that miss an IRQ edge.
     */
    if (console_line_is_serial(line_id)) return serial_console_buffered();
    if (line_id == console_line_active_vt()) return keyboard_haschar();
    return 0;
}

static void console_line_wake_read_waiter(int line_id) {
    edge_console_line_t *line = console_line_state(line_id);
    task_t *t;
    int pid;
    if (!line || line->read_wait_pid <= 0) return;
    if (!console_line_has_buffered_input_for_waiter(line_id)) {
        /*
         * ttyS0 is backed by QEMU's pty/16550 emulation in the normal serial
         * debug path.  Most input arrives through IRQ4, but a pty byte can be
         * visible only after an explicit LSR probe.  Keep this as a low-rate,
         * single-byte serial-only probe: the full inter-byte drain belongs in
         * the foreground read path, while this timer path must stay cheap for
         * idle shells and X sessions.
         */
        if (!console_line_is_serial(line_id)) return;
        if ((++g_console_serial_wait_poll_ticks & 3u) != 0) return;
        if (!serial_console_probechar()) return;
        g_console_serial_wait_poll_ticks = 0;
    } else if (console_line_is_serial(line_id)) {
        g_console_serial_wait_poll_ticks = 0;
    }
    pid = line->read_wait_pid;
    line->read_wait_pid = 0;
    t = (task_t *)(uintptr_t)process_get_task(pid);
    if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) return;
    if (t->state == TASK_BLOCKED) {
        /*
         * Console/serial input is an interrupt-side wait queue.  Until EdgeOS
         * has remote reschedule IPIs, waking a blocked reader on a stale
         * assigned CPU can make UART input appear dead even though bytes were
         * received.  Queue on the CPU currently handling the input poll.
         *
         * Red flag: keep this generic for tty wakeups; do not special-case
         * login shells, Alpine, or the verification VM.
         */
        uint32_t cpu = scheduler_cpu_id();
        scheduler_task_make_runnable(t, cpu);
    }
}

static void console_line_wake_input_waiters(void) {
    for (int i = 0; i <= EDGE_FB_VT_COUNT; ++i) {
        console_line_wake_read_waiter(i);
    }
}

static int console_line_from_vt(int vt);

void syscall_console_keyboard_input_ready(void) {
    int line_id = console_line_active_vt();
    edge_console_line_t *line = console_line_state(line_id);
    task_t *t;
    int pid;
    if (!line) return;
    /*
     * Keyboard IRQ/USB-HID completion has already queued a decoded character
     * before calling here.  Wake the active VT reader directly instead of
     * routing through console_line_wake_read_waiter(), which probes keyboard
     * input again and can recurse back into USB polling while the xHCI event
     * path is still unwinding.
     */
    pid = line->read_wait_pid;
    if (pid > 0) {
        line->read_wait_pid = 0;
        t = (task_t *)(uintptr_t)process_get_task(pid);
        if (t && t->state != TASK_UNUSED && t->state != TASK_ZOMBIE) {
            if (t->state == TASK_BLOCKED) {
                scheduler_task_make_runnable(t, scheduler_cpu_id());
            }
            return;
        }
    }

    /*
     * EdgeOS' compact tty read path has only one explicit waiter slot per
     * line.  A reader can lose that slot if it is rescheduled through an older
     * blocking path before input arrives.  Linux tty input wakeups are keyed to
     * the tty, not to a transient userspace loop marker, so recover by waking
     * blocked tasks whose controlling terminal is the active VT.
     */
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        t = (task_t *)(uintptr_t)process_task_by_index(i);
        if (!t || t->state != TASK_BLOCKED) continue;
        if (t->is_idle || t->pid <= 0) continue;
        if (t->ctty_kind != PROCESS_CTTY_CONSOLE) continue;
        int task_line = console_line_valid(t->ctty_id) ? t->ctty_id : console_line_from_vt(t->ctty_id);
        if (task_line != line_id) continue;
        scheduler_task_make_runnable(t, scheduler_cpu_id());
    }
}

static void console_line_sleep_for_input_until(int line_id, uint64_t deadline_us) {
    edge_console_line_t *line = console_line_state(line_id);
    task_t *cur = process_current_task();
    if (!line || !cur || cur->is_idle) {
        wait_blocking_step();
        return;
    }
    /*
     * TTY reads are sleepable in Linux.  Keeping getty/shell readers runnable
     * while no serial/VT input exists makes an idle guest consume a full vCPU.
     * Record the one foreground reader for this compact tty line, recheck input
     * to avoid a missed wake, then block until timer-side tty polling observes
     * buffered input or a signal wakes the task.
     */
    line->read_wait_pid = cur->pid;
    if (console_line_has_input_for_waiter(line_id) ||
        (deadline_us && boottime_monotonic_us() >= deadline_us)) {
        line->read_wait_pid = 0;
        return;
    }
    if (deadline_us) {
        cur->sleep_deadline_us = deadline_us;
        cur->sleep_wait_active = 1;
    } else {
        cur->sleep_deadline_us = 0;
        cur->sleep_wait_active = 0;
    }
    scheduler_task_set_blocked(cur);
    scheduler_yield();

    cur = process_current_task();
    if (line->read_wait_pid == (cur ? cur->pid : 0)) {
        line->read_wait_pid = 0;
    }
    if (cur && !cur->is_idle) {
        cur->sleep_deadline_us = 0;
        cur->sleep_wait_active = 0;
    }
}

static void console_line_sleep_for_input(int line_id) {
    console_line_sleep_for_input_until(line_id, 0);
}

static int console_line_from_vt(int vt) {
    if (vt == 0) return 0;
    if (vt < 1 || vt > EDGE_FB_VT_COUNT) return console_line_active_vt();
    return vt;
}

static int console_line_from_path(const char *path) {
    if (!path || !path[0]) return console_line_active_vt();
    if (strcmp(path, "/dev/ttyS0") == 0) return 0;
    if (strcmp(path, "/dev/console") == 0) {
        /*
         * Linux keeps /dev/console as the selected system console.  EdgeOS VM
         * boot defaults select serial as that console.  Keep this mapping
         * independent from framebuffer VTs: Alpine's stock inittab can start a
         * /dev/console getty and tty1..tty4 gettys at the same time, and Linux
         * exposes those as separate tty devices rather than mirrored streams.
         */
        return console_line_default();
    }
    if (strcmp(path, "/dev/tty0") == 0 || strcmp(path, "/dev/tty") == 0) {
        return console_line_active_vt();
    }
    if (strncmp(path, "/dev/tty", 8) == 0) {
        int vt = 0;
        const char *p = path + 8;
        if (!*p) return console_line_active_vt();
        while (*p >= '0' && *p <= '9') {
            vt = vt * 10 + (*p - '0');
            ++p;
        }
        if (*p == 0 && vt >= 1 && vt <= EDGE_FB_VT_COUNT) return vt;
    }
    return console_line_active_vt();
}

static int console_line_from_fd_entry(const edge_fd_t *e);

static int console_line_supports_linux_vt(const edge_fd_t *e) {
    int line_id = console_line_from_fd_entry(e);
    return line_id >= 1 && line_id <= EDGE_FB_VT_COUNT;
}

static int console_line_open_query(void) {
    if (g_reserved_x11_vt >= 1 && g_reserved_x11_vt <= EDGE_FB_VT_COUNT) return g_reserved_x11_vt;
    return EDGE_FB_VT_COUNT;
}

static void console_line_reset(edge_console_line_t *line) {
    if (!line) return;
    termios_init_sane(&line->termios);
    line->session.session_id = 0;
    line->session.foreground_pgid = 0;
    line->primary_open_pid = 0;
    line->primary_open_sid = 0;
    line->vt_mode = LINUX_VT_AUTO;
    line->vt_waitv = 0;
    line->kd_mode = LINUX_KD_TEXT;
    line->kbd_mode = LINUX_K_XLATE;
    line->kd_owner_pid = 0;
    line->vt_relsig = 0;
    line->vt_acqsig = 0;
    line->vt_frsig = 0;
    line->line_len = 0;
    line->line_pos = 0;
    line->line_drop_count = 0;
    line->line_drop_logged = 0;
    line->reply_len = 0;
    line->reply_pos = 0;
    line->dsr_state = 0;
    line->read_wait_pid = 0;
}

void syscall_console_activate_vt(int vt) {
    if (vt < 1 || vt > EDGE_FB_VT_COUNT) return;
    g_active_vt = vt;
    console_activate_vt(vt);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *task = (task_t *)(uintptr_t)process_task_by_index(index);
        if (!task || task->state != TASK_BLOCKED ||
            !task->vt_wait_active || task->vt_wait_target != (uint8_t)vt)
            continue;
        task->vt_wait_active = 0;
        task->vt_wait_target = 0;
        scheduler_task_make_runnable(task, scheduler_cpu_id());
    }
}

void syscall_console_set_preferred_line(int line_id) {
    if (line_id < 0 || line_id > EDGE_FB_VT_COUNT) return;
    g_preferred_console_line = line_id;
}

int syscall_console_default_line(void) {
    return console_line_default();
}

int syscall_console_active_vt_in_graphics(void) {
    edge_console_line_t *line = console_line_state(console_line_active_vt());
    return line && line->kd_mode == LINUX_KD_GRAPHICS;
}

int syscall_console_any_vt_in_graphics(void) {
    for (int vt = 1; vt <= EDGE_FB_VT_COUNT; ++vt) {
        edge_console_line_t *line = console_line_state(vt);
        if (line && line->kd_mode == LINUX_KD_GRAPHICS) return 1;
    }
    return 0;
}

static void fd_ensure_stdio(edge_fd_proc_t *p);
static void fd_ensure_console_stdio(edge_fd_proc_t *p, int line_id);
static void tty_session_release_task(task_t *task);
static int fd_add_backing_object(edge_fd_t *e);
static void fd_drop_backing_object(edge_fd_t *e);
static int fd_file_lock_info_for_entry(
    const edge_fd_t *entry, const task_t *task,
    kernel_file_lock_info_t *information);
static int fd_proc_has_pty_fd(int pid);
static int file_ref_get(int id);
static int file_ref_put(int id);
static int fd_release_entry(edge_fd_t *entry, task_t *task,
                            int close_process_locks,
                            int notify_last_close);
static void fd_mount_monitor_initialize(edge_fd_t *e);
static int fd_mount_monitor_snapshot(const edge_fd_t *e,
                                     uint32_t *namespace_id,
                                     uint32_t *observed_generation);
static int fd_mount_monitor_pending(const edge_fd_t *e);
static void fd_mount_monitor_acknowledge(edge_fd_t *e);
static int fd_is_mount_event_source(const edge_fd_t *e);
static void fd_mount_event_notify(uint32_t namespace_id);
static uint64_t fd_description_offset(const edge_fd_t *e);
static void fd_description_set_offset(edge_fd_t *e, uint64_t offset);
static void fd_description_advance(edge_fd_t *e, uint64_t amount);
static int fd_description_input_tail(const edge_fd_t *e);
static void fd_description_set_input_tail(edge_fd_t *e, int tail);
static void fd_description_set_input_clock(edge_fd_t *e, int clock_id);
static int fd_description_read_input(edge_fd_t *e, int event_id,
                                     char *buffer, uint32_t length);
static uint64_t do_sys_close(uint64_t fd_u);
static uint64_t do_sys_sleep(uint64_t ms);
static const char *fd_kind_name(edge_fd_kind_t kind);
static void pipe_drop_reader(int pipe_id);
static void pipe_drop_writer(int pipe_id);
static void socket_add_ref(int sock_id);
static void socket_drop_ref(int sock_id);
static void socket_acceptq_release(int sock_id);
static int socket_pending_count(const edge_socket_t *listener);
static void fd_wake_socket_waiters(int sock_id);
static void fd_wake_socket_waiters_events(int sock_id, uint16_t events);
static void fd_wake_pipe_waiters(int pipe_id);
static void fd_wake_eventfd_read_waiters(int eventfd_id);
static void fd_wake_eventfd_write_waiters(int eventfd_id);
static void fd_wake_timerfd_waiters(int timerfd_id);
static void fd_wake_pidfd_waiters(int target_pid);
static void fd_wake_fd_owner_tasks(int fd_owner_pid, task_t *current,
                                   const char *source);
static void fd_wake_tun_description(uint64_t description_identity);
static int gui_wake_trace_task(const task_t *t);
static inline void wait_poll_yield_step(void);
static inline void wait_gui_ready_preempt_step(void);
typedef int (*fd_wait_post_block_fn)(void *context);
static void socket_blocking_wait_step(uint64_t deadline_us);
static void socket_blocking_wait_step_checked(
    uint64_t deadline_us, fd_wait_post_block_fn post_block,
    void *post_block_context);
static int socket_waiter_add(int sock_id, int pid, uint16_t events);
static void waiter_remove_pid(int pid);
static int eventfd_read_waiter_add(int eventfd_id, int pid);
static int eventfd_write_waiter_add(int eventfd_id, int pid);
static uint64_t edge_inotify_read_obj(edge_fd_t *e, uint64_t buf_u, uint64_t len_u);
static int pipe_read_waiter_add(int pipe_id, int pid);
static int pipe_write_waiter_add(int pipe_id, int pid);
static edge_fd_proc_t *fd_proc_with_stdio(void);
static int fd_proc_table_retain(edge_fd_proc_t *process);
static void fd_proc_table_release(edge_fd_proc_t *process);
static int fd_alloc(edge_fd_proc_t *p, int minfd);
static int fd_reserve_exact(edge_fd_proc_t *p, int fd);
static int fd_publish(edge_fd_proc_t *p, int fd);
static int fd_install_reserved(edge_fd_proc_t *p, int fd,
                               const edge_fd_t *entry);
static void fd_abort_reserved(edge_fd_proc_t *p, int fd);
static int fd_snapshot_retain(edge_fd_proc_t *p, int fd,
                              edge_fd_t *snapshot);
static int fd_remove_open(edge_fd_proc_t *p, int fd,
                          edge_fd_t *closing);
static int fd_replace_exact(edge_fd_proc_t *p, int fd,
                            const edge_fd_t *replacement,
                            edge_fd_t *closing, int *replaced);
static int fd_clone_table_contents(edge_fd_proc_t *source,
                                   edge_fd_proc_t *destination);
static edge_fd_t *fd_get(edge_fd_proc_t *p, int fd);
static uint64_t x86_socket_sendto_raw(uint64_t fd_u, uint64_t buf_u,
                                     uint64_t len_u, uint64_t flags_u,
                                     uint64_t addr_u, uint64_t addrlen_u,
                                     const kernel_socket_iovec_source_t
                                         *datagram_source,
                                     const kernel_socket_ip_send_metadata_t
                                         *send_metadata);
static uint64_t x86_socket_sendto_entry_raw(
    int fd, edge_fd_t *entry, uint64_t buf_u, uint64_t len_u,
    uint64_t flags_u, uint64_t addr_u, uint64_t addrlen_u,
    const kernel_socket_iovec_source_t *datagram_source,
    const kernel_socket_ip_send_metadata_t *send_metadata);
static uint64_t x86_socket_recvfrom_raw(uint64_t fd_u, uint64_t buf_u,
                                       uint64_t len_u, uint64_t flags_u,
                                       uint64_t addr_u, uint64_t addrlen_u);
static uint64_t x86_socket_recvfrom_entry_raw(
    int fd, edge_fd_t *entry, uint64_t buf_u, uint64_t len_u,
    uint64_t flags_u, uint64_t addr_u, uint64_t addrlen_u);
int64_t kernel_vfs_open_at(const kernel_vfs_open_request_t *request);
static inline uint64_t page_align_up(uint64_t v);
static int user_vma_record(task_t *t, uint64_t start, uint64_t end, uint32_t prot, uint32_t flags);
static int user_vma_remove_range(task_t *t, uint64_t start, uint64_t end);
static int user_vma_range_overlaps(task_t *t, uint64_t start, uint64_t end);
static int user_vma_range_covered(task_t *t, uint64_t start, uint64_t end);
static uint64_t user_vma_find_topdown_gap(task_t *t, uint64_t floor, uint64_t top, uint64_t need, uint64_t align);
static void user_mmap_file_rename_path(const char *old_path, const char *new_path);
static void fd_log_lifecycle(const char *ev, int pid, int fd, const edge_fd_t *e, int extra);
static void fd_debug_slot_once(const char *tag, int pid, int fd, const edge_fd_t *e);
static int file_ref_alloc(uint32_t initial_status_flags);
static int file_ref_get(int id);
static int file_ref_put(int id);
static uint64_t file_ref_identity(int id);
static edge_memfd_t *memfd_get(int id);
static void memfd_add_ref(int id);
static void memfd_drop_ref(int id);
static void memfd_destroy_if_unreferenced(edge_memfd_t *mf);
static int file_vma_retain(const edge_user_vma_t *vma);
static void file_vma_release(const edge_user_vma_t *vma);
static int memfd_read_to_kernel(edge_memfd_t *mf, uint64_t off, void *buf, uint64_t len);
static int memfd_write_from_kernel(edge_memfd_t *mf, uint64_t off, const void *buf, uint64_t len);
static int memfd_write_mapping_from_kernel(edge_memfd_t *mf, uint64_t off,
                                           const void *buf, uint64_t len);
static void memfd_unmap_truncated_pages(int memfd_id, uint64_t length);
static uint32_t memfd_pageout_range(task_t *memory, uint64_t start,
                                    uint64_t end,
                                    uint64_t *scanned_pages_out);
static uint32_t memfd_pressure_reclaim(uint32_t cgroup_id,
                                       uint32_t target_pages,
                                       uint64_t *scanned_pages_out);
static int memfd_truncate(edge_memfd_t *mf, uint64_t len);
static int memfd_storage_page(edge_memfd_t *mf, uint64_t page_no, int create);
static int memfd_id_from_path(const char *path);
static int memfd_has_writable_shared_mapping(int memfd_id);
static uint64_t memfd_fcntl_add_seals(edge_fd_t *e, uint64_t seals_u);
static int path_is_console_tty(const char *path);
static int path_is_tty_device(const char *path);
static int path_is_mouse_input(const char *path);
static int path_is_event_input(const char *path);
static int path_input_event_index(const char *path);
static int path_is_uinput_device(const char *path);
static int path_is_dri_device(const char *path);
static int pty_alloc(void);
static void pty_add_ref(int pty_id, int is_master);
static void pty_drop_ref(int pty_id, int is_master);
static void pty_console_redirect_release_reference(void *context);
static void pty_maybe_assign_controlling_tty(int pty_id, int flags);
static uint64_t do_sys_write_console_line(int line_id, uint64_t buf, uint64_t len);
static uint64_t do_sys_read_console_line(int line_id, uint64_t buf, uint64_t len);
static uint64_t do_sys_fd_read(uint64_t fd_u, uint64_t buf_u, uint64_t len_u);
static uint64_t do_sys_fd_write(uint64_t fd_u, uint64_t buf_u, uint64_t len_u);
static edge_socket_t *socket_from_fd(int fd);
static uint64_t tty_interrupt_current_ret(void);
static int signal_pending_interrupt(void);
