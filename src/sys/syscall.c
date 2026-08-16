/*
 * Syscall implementation wrapper.
 *
 * The implementation is split into ordered part files to keep each source file
 * manageable while preserving the original single-translation-unit ABI and all
 * static helper relationships.
 */
#include "dev/alsa.h"
#include "dev/alsa_user_io.h"
#include "dev/uvc.h"
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/kthread.h"
#endif
#include "syscall_parts/prelude.c"

#define EDGE_LWIP_CALL(expression) ({ \
    __typeof__(expression) edge_lwip_result; \
    lwip_stack_core_enter(); \
    edge_lwip_result = (expression); \
    lwip_stack_core_exit(); \
    edge_lwip_result; \
})

#define EDGE_LWIP_DO(expression) do { \
    lwip_stack_core_enter(); \
    expression; \
    lwip_stack_core_exit(); \
} while (0)

#include "syscall_parts/fd_tty_ipc.c"
#include "syscall_parts/fs_fd.c"
#include "syscall_parts/net_socket.c"
#include "syscall_parts/process_mm_misc.c"
#include "syscall_parts/dispatch.c"
