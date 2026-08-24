#include "sys/process.h"
#include "sys/scheduler.h"
#include "sys/spinlock.h"
#include "sys/syscall.h"
#include "elf/elf_loader.h"
#include "arch/x86_64/user_layout.h"
#include "arch/x86_64/syscall.h"
#include "arch/x86_64/gdt.h"
#include "fb.h"
#include "fb_console.h"
#include "dev/fbdev.h"
#include "stdio.h"
#include "string.h"
#include "serial_console.h"
#include "sys/boottime.h"
#include "sys/user_exec.h"
#include "sys/mmio.h"
#include "kernel/credentials.h"
#include "kernel/exec_payload.h"
#include "kernel/exec_runtime.h"
#include "kernel/file_lock.h"
#include "kernel/fs_context.h"
#include "kernel/arch_cpu.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_ptrace.h"
#include "kernel/namespace_runtime.h"
#include "kernel/pid_index.h"
#include "kernel/process_runtime.h"
#include "kernel/process_accounting.h"
#include "kernel/proc_maps.h"
#include "kernel/signal_queue.h"
#include "kernel/signal_runtime.h"
#include "kernel/smp.h"
#include "kernel/sysv_shm_runtime.h"
#include "kernel/sysv_sem_runtime.h"
#include "kernel/userfaultfd.h"
#include "kernel/vfs_runtime.h"
#include "fs/cgroupfs.h"
#include "fs/swap.h"
#include "mm/arch_vm.h"
#include "mm/swap_map.h"
#include "mm/statistics.h"
#include "net/lwip_stack.h"
#include "sys/meminfo.h"
#include "vfs/vfs.h"
#include "arch/x86_64/boot/multiboot.h"

#define PAGE_PRESENT 0x001ULL
#define PAGE_WRITE   0x002ULL
#define PAGE_USER    0x004ULL
#define PAGE_PWT     0x008ULL
#define PAGE_PCD     0x010ULL
#define PAGE_ACCESSED 0x020ULL
#define PAGE_DIRTY   0x040ULL
#define PAGE_PS      0x080ULL
#define PAGE_COW     0x200ULL /* software bit: sparse private page is copy-on-write */
#define PAGE_FILE_CACHE 0x400ULL /* software bit: PTE references global file-page cache */
#define PAGE_DEVICE  0x800ULL /* software bit: externally owned device page */
#define PAGE_POISONED 0x800ULL /* software bit: non-present poisoned page */

#define DEVICE_MEMORY_UNCACHEABLE 0
#define DEVICE_MEMORY_WRITE_COMBINING 1
#define DEVICE_MEMORY_WRITE_THROUGH 2
#define DEVICE_MEMORY_WRITE_PROTECTED 3
#define DEVICE_MEMORY_WEAK_UNCACHEABLE 5
#define DEVICE_MEMORY_DEVICE 6
#define DEVICE_MEMORY_DEVICE_NP 7

#ifndef EDGE_GUI_DEEP_TRACE
#define EDGE_GUI_DEEP_TRACE 0
#endif

#define USER_TEXT_BASE   X86_USER_INTERP_BASE
#define USER_STACK_BASE  X86_USER_STACK_BASE
#define USER_HEAP_BASE   X86_USER_HEAP_BASE
#define USER_HEAP_EXT_BASE (USER_HEAP_BASE + USER_HEAP_MAX_DELTA)
#define USER_HEAP_EXT_SIZE USER_HEAP_PY_EXTRA_DELTA
#define USER_MMAP_BASE   EDGE_USER_MMAP_BASE_ADDR
#define USER_BIGPIE_BASE  X86_USER_BIGPIE_BASE
#define USER_BIGPIE_SIZE  X86_USER_BIGPIE_SIZE
#define USER_BIGPIE_ALIAS_SIZE USER_BIGPIE_SIZE
#define USER_SPARSE_MMAP_BASE EDGE_USER_MMAP_BASE_ADDR
#define USER_SPARSE_MMAP_LIMIT EDGE_USER_MMAP_LIMIT_ADDR
#define USER_LOW_SPARSE_MMAP_BASE EDGE_USER_MMAP_ALLOC_BASE_ADDR
#define USER_LOW_SPARSE_MMAP_LIMIT EDGE_USER_MMAP_ALLOC_LIMIT_ADDR
#define USER_SPARSE_MMAP_PML4_IDX ((uint32_t)(USER_SPARSE_MMAP_BASE >> 39))
#define USER_LOW_SPARSE_MMAP_PML4_IDX ((uint32_t)(USER_LOW_SPARSE_MMAP_BASE >> 39))
#define USER_LOW_SPARSE_MMAP_PDPT_FIRST ((uint32_t)((USER_LOW_SPARSE_MMAP_BASE >> 30) & 0x1FF))
#define USER_LOW_SPARSE_MMAP_PDPT_LAST_EXCL ((uint32_t)((((USER_LOW_SPARSE_MMAP_LIMIT - 1ULL) >> 30) & 0x1FF) + 1u))
#define USER_LOW_SPARSE_MMAP_PDPT_COUNT \
    (USER_LOW_SPARSE_MMAP_PDPT_LAST_EXCL - USER_LOW_SPARSE_MMAP_PDPT_FIRST)
#define USER_SPARSE_MMAP_PML4_FIRST USER_SPARSE_MMAP_PML4_IDX
#define USER_SPARSE_MMAP_PML4_LAST_EXCL USER_PCI_MMIO_PML4_IDX
#define USER_SPARSE_MMAP_PML4_COUNT \
    (USER_SPARSE_MMAP_PML4_LAST_EXCL - USER_SPARSE_MMAP_PML4_FIRST)
#define USER_PDPT_COUNT 512
#define USER_LOW_PDPT_COUNT 4
#define USER_KERNEL_IDENTITY_PDPT_COUNT 512
#define USER_PCI_MMIO_PML4_IDX EDGE_PCI_MMIO_HIGH_PML4_INDEX
#define USER_PCI_MMIO_PML4_BASE EDGE_PCI_MMIO_HIGH_BASE
#define USER_SPARSE_MMAP_PDPT_FIRST ((uint32_t)((USER_SPARSE_MMAP_BASE >> 30) & 0x1FF))
#define USER_SPARSE_MMAP_PDPT_LAST_EXCL ((uint32_t)((((USER_SPARSE_MMAP_LIMIT - 1ULL) >> 30) & 0x1FF) + 1u))
/*
 * Shared sparse mmap backing is the global pool for demand-mapped user pages.
 * Full process slots below reserve large fixed backing for Linux-compatible
 * fork/exec behavior.  Python/Tk and X11 consume sparse mmap pages for shared
 * objects, stacks, and GUI heaps; setting this near 96 MiB let IDLE launch but
 * left new Python processes failing to map libpython with ENOMEM.  Normal X11
 * + Tk + IDLE-with-subprocess needs more shared-object mmap headroom than a
 * shell workload, especially when the IDLE GUI parent forks a child that
 * imports _tkinter/libfontconfig before connecting back.  XFCE needs
 * substantially more than the IDLE-era 128 MiB:
 * xfce4-session, xfwm4, xfce4-panel, xfsettingsd, AT-SPI, GLib workers, and
 * terminal/font stacks all fault shared-object and anonymous sparse pages at
 * once.  A full Alpine XFCE session also starts xfce4-power-manager, which can
 * pull in Mesa/LLVM through the normal graphics stack even with virtio-gpu and
 * no virgl; 448 MiB exhausted at libLLVM.so.20.1 before the panel/desktop
 * completed.  Later correctness fixes stopped sharing MAP_PRIVATE executable
 * file pages in the temporary mmap cache; that matches Linux COW behavior more
 * closely but means a full XFCE login can cross the old 768 MiB cap while GLib,
 * DBus, panel, desktop, and settings helpers are all starting.  Keep this as a
 * kernel compatibility resource, not an Alpine or rootfs special case.
 *
 * Red flag: do not put this pool back into .bss.  A large static array plus
 * desktop-scale fixed address spaces can push _kernel_end into the physical
 * framebuffer/MMIO window.  Then Xorg/fbdev writes corrupt kernel data and the
 * next innocent /proc reader or scheduler switch explodes.  The pages are
 * therefore selected at boot from firmware-reported usable memory and only
 * tracked by small metadata arrays here.
 */
#define USER_SPARSE_MMAP_BACKING_BYTES (4096ULL * 1024ULL * 1024ULL)

#define EDGE_PROCESS_SYMLINK_PREFIX "edgeos-symlink:"
#define USER_MAP_SHARED_FLAG 0x01u
#ifndef EDGE_FD_LIFETIME_TRACE
#define EDGE_FD_LIFETIME_TRACE 0
#endif

#if EDGE_FD_LIFETIME_TRACE
static int g_fd_lifetime_trace_budget = 128;
#endif

static int process_read_symlink_target(const char *path, char *target, int target_sz) {
    char buf[512];
    int n;
    int prefix_len = (int)strlen(EDGE_PROCESS_SYMLINK_PREFIX);
    if (!path || !target || target_sz <= 0) return -1;
    n = vfs_read_file(path, buf, (uint32_t)(sizeof(buf) - 1));
    if (n < prefix_len) return -1;
    if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
    buf[n] = 0;
    if (strncmp(buf, EDGE_PROCESS_SYMLINK_PREFIX, (uint32_t)prefix_len) != 0) return -1;
    strncpy(target, buf + prefix_len, (uint32_t)(target_sz - 1));
    target[target_sz - 1] = 0;
    return target[0] ? 0 : -1;
}

static int process_resolve_symlink_path_once(const char *path, char *out, int out_sz) {
    char target[256];
    int pi = 0;
    int oi = 0;
    if (!path || !out || out_sz <= 1) return -1;
    if (process_read_symlink_target(path, target, (int)sizeof(target)) < 0) return -1;
    if (target[0] == '/') {
        strncpy(out, target, (uint32_t)(out_sz - 1));
        out[out_sz - 1] = 0;
        return 0;
    }
    for (int i = 0; path[i]; ++i) {
        if (path[i] == '/') pi = i;
    }
    if (pi <= 0) {
        out[oi++] = '/';
    } else {
        for (int i = 0; i < pi && oi < out_sz - 1; ++i) out[oi++] = path[i];
        if (oi == 0) out[oi++] = '/';
        if (oi < out_sz - 1 && out[oi - 1] != '/') out[oi++] = '/';
    }
    for (int i = 0; target[i] && oi < out_sz - 1; ++i) out[oi++] = target[i];
    out[oi] = 0;
    return 0;
}

static const char *process_resolve_spawn_path(const char *path, char *resolved, int resolved_sz) {
    if (!path || !resolved || resolved_sz <= 1) return path;
    strncpy(resolved, path, (uint32_t)(resolved_sz - 1));
    resolved[resolved_sz - 1] = 0;
    for (int i = 0; i < 8; ++i) {
        char next[256];
        if (process_resolve_symlink_path_once(resolved, next, (int)sizeof(next)) < 0) break;
        strncpy(resolved, next, (uint32_t)(resolved_sz - 1));
        resolved[resolved_sz - 1] = 0;
    }
    return resolved;
}
#define USER_SPARSE_MMAP_BACKING_PAGES (USER_SPARSE_MMAP_BACKING_BYTES / 4096ULL)
#define USER_SPARSE_MMAP_PT_TRACKED_PAGES USER_SPARSE_MMAP_BACKING_PAGES
#define USER_VMA_LOOKUP_CACHE_SLOTS 16u
#define USER_FBDEV_BASE   EDGE_FBDEV_USER_BASE
#define USER_FBDEV_MAX_PAGES EDGE_FBDEV_USER_MAX_PAGES
#define USER_REGION_SIZE (2 * 1024 * 1024)
#define USER_HEAP_PDE_CNT (USER_HEAP_MAX_DELTA / USER_REGION_SIZE)
#define USER_HEAP_SIZE    (USER_HEAP_PDE_CNT * USER_REGION_SIZE)
#define USER_HEAP_EXT_PDE_CNT (USER_HEAP_EXT_SIZE / USER_REGION_SIZE)
#define USER_HEAP_TOTAL_PDE_CNT (USER_HEAP_PDE_CNT + USER_HEAP_EXT_PDE_CNT)
#define USER_HEAP_TOTAL_SIZE (USER_HEAP_SIZE + USER_HEAP_EXT_SIZE)
#define USER_BIGPIE_PDE_CNT (USER_BIGPIE_SIZE / USER_REGION_SIZE)
#define USER_STACK_TOP   (USER_STACK_BASE + USER_REGION_SIZE)
/*
 * These slots own fixed userspace address-space backing.  Keep the pool small
 * because each slot reserves real kernel memory, but it must be large enough
 * for normal Linux package maintainer scripts: apk/busybox/fontconfig can have
 * login shells, gettys, apk, script shells, and several pipeline commands live
 * at once.  X11 plus IDLE also needs headroom for the Python subprocess used by
 * IDLE's shell RPC.  Sparse mmap COW keeps fork from eagerly copying Python/Tk
 * mappings, but shell pipelines and OpenRC services still need a little fixed
 * process headroom.  XFCE starts enough cooperating daemons, helpers, and
 * terminals to exceed 20 independent address spaces.  A real XFCE session also
 * starts session DBus, xfconf, AT-SPI, panel helpers, Thunar, fontconfig/Pango
 * worker processes, power-manager, and transient shell pipelines.  The former
 * 96-slot limit was reached during an otherwise healthy Debian XFCE startup
 * before a browser or an interactive shell could start.  Fixed loader, brk,
 * leaf-table, VMA, and task storage is now demand-backed; a slot primarily
 * reserves roots, metadata, and a kernel stack.  Keep enough independent
 * address spaces for the desktop and browser process models while retaining
 * most shared task slots for threads.  Keep process.c and elf_loader.c
 * synchronized with the architecture layout; never shrink the range or
 * special-case an executable to recover capacity.
 */
#define USER_AS_MAX_TASKS 256
#define USER_PAGE_SIZE   4096ULL
#define EDGE_TASK_KSTACK_PAGES ((uint32_t)(EDGE_TASK_KSTACK_SIZE / USER_PAGE_SIZE))
#define EDGE_TASK_ONLY_SLOTS ((PROC_MAX_TASKS > USER_AS_MAX_TASKS) ? (PROC_MAX_TASKS - USER_AS_MAX_TASKS) : 0)
#define EDGE_TASK_ONLY_KSTACK_PAGES ((uint32_t)(EDGE_TASK_ONLY_SLOTS * EDGE_TASK_KSTACK_PAGES))
#define USER_LOW_BASE    X86_USER_LOW_BASE
#define USER_LOW_LIMIT   X86_USER_LOW_LIMIT
#define USER_LOW_SIZE    X86_USER_LOW_SIZE
#define USER_LOW_PDE_CNT (USER_LOW_SIZE / (2 * 1024 * 1024))

#ifndef EDGE_SECURITY_DEBUG
#define EDGE_SECURITY_DEBUG 0
#endif

#ifndef EDGE_SPAWN_DEBUG
#define EDGE_SPAWN_DEBUG 0
#endif

#ifndef EDGE_SCHED_PROC_DEBUG
#define EDGE_SCHED_PROC_DEBUG 0
#endif

#ifndef EDGE_X11_TRACE
#define EDGE_X11_TRACE 0
#endif

#define LINUX_SIGINT 2
#define LINUX_SIGQUIT 3
#define LINUX_SIGTRAP 5
#define LINUX_SIGABRT 6
#define LINUX_SIGUSR1 10
#define LINUX_SIGUSR2 12
#define LINUX_SIGALRM 14
#define LINUX_SIGCHLD 17
#define LINUX_SIGCONT 18
#define LINUX_SIGSTOP 19
#define LINUX_SIGTSTP 20
#define LINUX_SIGTTIN 21
#define LINUX_SIGTTOU 22
#define LINUX_SIGIO 29
#define LINUX_SIGSYS 31
#define LINUX_SIGKILL 9
#define LINUX_SIGTERM 15
#define LINUX_CLD_EXITED 1
#define LINUX_CLD_KILLED 2
#define LINUX_CLD_TRAPPED 4
#define LINUX_CLD_STOPPED 5
#define LINUX_CLD_CONTINUED 6
#define LINUX_SIG_DFL 0ULL
#define LINUX_SIG_IGN 1ULL

static task_t *g_tasks;
static uint64_t g_tasks_phys;
static uint32_t g_tasks_pages;
static uint8_t g_tasks_ready;
static uint64_t g_user_vma_pool_phys;
static uint32_t g_user_vma_pool_pages;
static int g_next_pid;
static edge_pid_index_t g_task_pid_index;
static uint64_t g_next_fs_context_id = 1u;
static uint64_t g_next_sighand_context_id = 1u;
static spinlock_t g_task_lock;
static process_task_prestart_hook_t g_task_prestart_hook;
static process_task_exit_hook_t g_task_exit_hook;
static process_task_exit_hook_t g_task_zombie_hook;
static process_user_vma_retain_hook_t g_user_vma_retain_hook;
static process_user_vma_release_hook_t g_user_vma_release_hook;
static uint64_t g_kernel_cr3;
static uint8_t g_default_fxsave_region[512] __attribute__((aligned(16)));

static uint64_t task_sighand_context_alloc(void) {
    uint64_t context_id = g_next_sighand_context_id++;
    if (!context_id) context_id = g_next_sighand_context_id++;
    return context_id;
}

static int process_signal_send_info_internal(
    task_t *task, int signal, int thread_directed,
    const void *signal_information);

static void task_signal_actions_copy(task_t *dst, const task_t *src) {
    if (!dst || !src) return;
    memcpy(dst->signal_actions, src->signal_actions,
           sizeof(dst->signal_actions));
    dst->signal_pending = 0;
    dst->signal_shared_pending = 0;
}

static void task_signal_actions_reset(task_t *t) {
    if (!t) return;
    memset(t->signal_actions, 0, sizeof(t->signal_actions));
    t->signal_pending = 0;
    t->signal_shared_pending = 0;
}

static void task_sigsys_action_copy(task_t *dst, const task_t *src) {
    (void)src;
    if (!dst || !src) return;
    dst->seccomp_sigsys_valid = 0;
    dst->seccomp_notification_id = 0;
}

static void task_sigsys_action_reset(task_t *t) {
    if (!t) return;
    t->seccomp_sigsys_valid = 0;
    t->seccomp_notification_id = 0;
}

static int task_seccomp_inherit(task_t *dst, const task_t *src) {
    if (!dst || !src) return -1;
    dst->seccomp = src->seccomp;
    if (edge_seccomp_state_retain(&dst->seccomp) < 0) {
        edge_seccomp_state_init(&dst->seccomp);
        return -1;
    }
    return 0;
}

// Page tables
static uint64_t g_pml4[USER_AS_MAX_TASKS][512] __attribute__((aligned(4096)));
static uint64_t g_pdpt[USER_AS_MAX_TASKS][512] __attribute__((aligned(4096)));
static uint64_t g_pdpt_pci_mmio[USER_AS_MAX_TASKS][512] __attribute__((aligned(4096)));
static uint64_t g_pdpt_mmio_low_alias[USER_AS_MAX_TASKS][EDGE_MMIO_LOW_ALIAS_PML4_COUNT][512]
    __attribute__((aligned(4096)));
/*
 * Only low PDPT entries need per-task page directories.  Higher entries are
 * installed as 1 GiB identity mappings in g_pdpt, so allocating 512 page
 * directories for every task wasted roughly 128 MiB of static kernel address
 * space and made desktop-scale process slots impossible to link.
 */
static uint64_t g_pd[USER_AS_MAX_TASKS][USER_LOW_PDPT_COUNT][512] __attribute__((aligned(4096)));
/*
 * Linux loaders rely on page-granular permissions for fixed executable
 * windows: PT_GNU_RELRO and non-writable PT_LOAD pages are protected with
 * mprotect(2) after relocations.  The legacy EdgeOS fixed executable windows
 * used writable 2 MiB leaf PDEs, so mprotect either did nothing or was undone
 * by the post-syscall mapping refresh.  Xorg/XFCE exposed that as executable
 * bytes later turning into heap-looking data and #GP/#UD faults.  Keep the
 * fixed backing arrays, but route executable windows through 4 KiB PTEs and
 * preserve their permission bits across refreshes.
 */
/*
 * Linux ET_EXEC images commonly start at 0x400000, but that address is a
 * linker convention rather than an ABI minimum.  Keep leaf tables for the
 * complete low executable range and allocate them only when a PT_LOAD page is
 * touched; EDGE_USER_MIN_ADDR keeps the null page unavailable.
 */
static uint64_t *g_user_low_pt[USER_AS_MAX_TASKS][USER_LOW_PDE_CNT];
static uint64_t *g_user_text_pt[USER_AS_MAX_TASKS];
static uint64_t *g_user_stack_pt[USER_AS_MAX_TASKS];
static uint64_t *g_user_heap_pt[USER_AS_MAX_TASKS][USER_HEAP_TOTAL_PDE_CNT];
static uint64_t *g_user_bigpie_pt[USER_AS_MAX_TASKS][USER_BIGPIE_PDE_CNT];
static uint64_t g_user_fbdev_pt[USER_AS_MAX_TASKS][USER_FBDEV_MAX_PAGES][512] __attribute__((aligned(4096)));
/*
 * High sparse roots are allocated from the common page-table pool only when
 * a page is committed in that PML4 slot.  Reserving a multi-terabyte VMA must
 * not allocate hundreds of empty PDPT/PD pages as a static task cost.
 */
static uint64_t
    *g_pdpt_sparse[USER_AS_MAX_TASKS][USER_SPARSE_MMAP_PML4_COUNT];
static uint8_t g_kstack_fixed[USER_AS_MAX_TASKS][EDGE_TASK_KSTACK_SIZE] __attribute__((aligned(16)));
static uint8_t *g_kstack_task_only;
static uint64_t g_kstack_task_only_phys;
static uint32_t g_kstack_task_only_pages;
static uint8_t g_kstack_task_only_ready;
static uint8_t g_user_fixed_zero_page[USER_PAGE_SIZE] __attribute__((aligned(USER_PAGE_SIZE)));
static uint64_t g_user_bigpie_dirty_bytes[USER_AS_MAX_TASKS];
/*
 * Page-table pages use the same reclaimable physical-page allocator as user
 * backing.  The former global 4096-page static pool was a machine-wide cap:
 * a normal XFCE plus Chromium session exhausted it while most guest RAM was
 * still free.  Track which backing pages are page tables so teardown and
 * diagnostics remain exact without imposing a second artificial capacity.
 */
static uint64_t
    g_user_mmap_pt_used[(USER_SPARSE_MMAP_PT_TRACKED_PAGES + 63u) / 64u];
static uint64_t g_user_mmap_backing_phys[USER_SPARSE_MMAP_BACKING_PAGES];
static uint64_t g_user_mmap_backing_used[(USER_SPARSE_MMAP_BACKING_PAGES + 63u) / 64u];
static uint16_t g_user_mmap_backing_refcnt[USER_SPARSE_MMAP_BACKING_PAGES];
static uint16_t g_user_mmap_backing_cgroup_owner[USER_SPARSE_MMAP_BACKING_PAGES];
static uint32_t g_user_mmap_backing_user_aliases[USER_SPARSE_MMAP_BACKING_PAGES];
static int16_t
    g_user_vma_lookup_cache[USER_AS_MAX_TASKS][USER_VMA_LOOKUP_CACHE_SLOTS];
static uint8_t g_user_vma_lookup_cache_next[USER_AS_MAX_TASKS];
static uint32_t *g_user_mmap_backing_generation;
static uint64_t g_user_mmap_backing_generation_phys;
static uint32_t g_user_mmap_backing_generation_entries;
static uint32_t g_user_mmap_backing_generation_pages;
static uint32_t g_user_mmap_backing_ready_pages;
static uint32_t g_user_mmap_backing_alloc_hint;
static uint64_t g_user_mmap_backing_allocations;
static uint64_t g_user_mmap_backing_frees;
static uint64_t g_user_mmap_backing_allocation_failures;
static spinlock_t g_user_mmap_backing_lock;
static uint8_t g_user_fbdev_owner_active[USER_AS_MAX_TASKS];
static int g_sparse_mmap_oom_log_budget = 32;
static int g_sparse_mmap_fault_log_budget = 0;
extern char _kernel_start;
extern char _kernel_end;

#define EDGE_MMAP_BOOT_RESERVED_MAX 32u

typedef struct edge_mmap_reserved_range {
    uint64_t start;
    uint64_t end;
} edge_mmap_reserved_range_t;

static edge_mmap_reserved_range_t g_mmap_boot_reserved[EDGE_MMAP_BOOT_RESERVED_MAX];
static uint32_t g_mmap_boot_reserved_count;

// --- Helper Functions ---

static void fixed_user_pt_release_for_idx(int idx);
static int fixed_user_backing_prepare_for_idx(int idx);
static void fixed_user_release_data_for_idx(int idx);
static int sparse_mmap_backing_index_from_phys(uint64_t phys);
static uint8_t *sparse_mmap_backing_ptr(int idx);
static uint64_t sparse_mmap_backing_phys(int idx);
static int sparse_mmap_alloc_backing_index_mode_local(int clear_page);
static int sparse_mmap_alloc_backing_index_local(void);
static void sparse_mmap_retain_backing_index_local(int idx);
static uint16_t sparse_mmap_backing_refcnt_local(int idx);
static void sparse_mmap_release_backing_index_local(int idx);
static int sparse_mmap_user_alias_acquire(task_t *t, int idx);
static void sparse_mmap_user_alias_release(int idx);
static void sparse_mmap_flush_task(task_t *t);

static void proc_trace_puts(const char *s) {
    if (!s) return;
    while (*s) serial_console_write_raw(*s++);
}

static void proc_emerg_puts(const char *s) {
    if (!s) return;
    while (*s) serial_console_write_emergency(*s++);
}

static void proc_trace_dec(int v) {
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

static void proc_emerg_dec(int v) {
    char buf[16];
    int n = 0;
    unsigned int u;
    if (v < 0) {
        serial_console_write_emergency('-');
        u = (unsigned int)(-v);
    } else {
        u = (unsigned int)v;
    }
    do {
        buf[n++] = (char)('0' + (u % 10u));
        u /= 10u;
    } while (u && n < (int)sizeof(buf));
    while (n > 0) serial_console_write_emergency(buf[--n]);
}

static void proc_trace_hex(uint64_t v) {
    static const char hex[] = "0123456789abcdef";
    proc_trace_puts("0x");
    for (int i = 15; i >= 0; --i) {
        serial_console_write_raw(hex[(v >> ((uint64_t)i * 4u)) & 0xfu]);
    }
}

static void proc_emerg_hex(uint64_t v) {
    static const char hex[] = "0123456789abcdef";
    proc_emerg_puts("0x");
    for (int i = 15; i >= 0; --i) {
        serial_console_write_emergency(hex[(v >> ((uint64_t)i * 4u)) & 0xfu]);
    }
}

static void proc_emerg_task_name(const task_t *t) {
    int n = 0;
    if (!t || !t->name[0]) {
        proc_emerg_puts("?");
        return;
    }
    while (t->name[n] && n < 31) {
        serial_console_write_emergency(t->name[n++]);
    }
}

static inline void cr3_write(uint64_t v) { 
    __asm__ __volatile__("mov %0, %%cr3" :: "r"(v) : "memory"); 
}

static inline uint64_t cr3_read_local_process(void) {
    uint64_t v;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));
    return v;
}

static uint64_t backing_access_enter(uint64_t *rflags_out) {
    uint64_t rflags;
    uint64_t old_cr3;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(rflags) :: "memory");
    old_cr3 = cr3_read_local_process();
    if (g_kernel_cr3 && old_cr3 != g_kernel_cr3) cr3_write(g_kernel_cr3);
    if (rflags_out) *rflags_out = rflags;
    return old_cr3;
}

static void backing_access_leave(uint64_t old_cr3, uint64_t rflags) {
    if (old_cr3 && old_cr3 != cr3_read_local_process()) cr3_write(old_cr3);
    if (rflags & (1ULL << 9)) __asm__ __volatile__("sti");
}

static inline uint64_t cr3_read(void) {
    uint64_t v;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));
    return v;
}

static inline void fxsave_region(void *region) {
    __asm__ __volatile__("fxsave (%0)" :: "r"(region) : "memory");
}

static inline void fxrstor_region(const void *region) {
    __asm__ __volatile__("fxrstor (%0)" :: "r"(region) : "memory");
}

static uint64_t task_heap_used_bytes(task_t *t, uint64_t *heap_ext_out);
static uint64_t task_bigpie_used_bytes(task_t *t);
static void task_save_user_region_watermarks(task_t *t);

static void task_init_default_fx(task_t *t) {
    if (!t) return;
    memcpy(t->fxsave_region, g_default_fxsave_region, sizeof(t->fxsave_region));
}

static void init_default_fxsave_region(void) {
    __asm__ __volatile__("fninit" ::: "memory");
    {
        uint32_t mxcsr = 0x00001F80u;
        __asm__ __volatile__("ldmxcsr %0" :: "m"(mxcsr) : "memory");
    }
    fxsave_region(g_default_fxsave_region);
}

extern void ret_from_fork(void);
extern void process_spawn_entry(void);
__attribute__((noreturn)) void process_enter_user_current(void);
static task_t *task_find_by_pid(int pid);
static int process_tgid_of_task(const task_t *t);
static int process_signal_one(task_t *task, int signal);
static task_t *process_signal_group_leader(task_t *task);
static int process_signal_mark_pending(task_t *target, int signal,
                                       int thread_directed);
static int process_signal_send_info_internal(
    task_t *task, int signal, int thread_directed,
    const void *signal_information);

static void task_child_unlink(task_t *child) {
    task_t *parent;
    if (!child) return;
    parent = child->parent;
    if (child->sibling_prev) child->sibling_prev->sibling_next = child->sibling_next;
    else if (parent) parent->first_child = child->sibling_next;
    if (child->sibling_next) child->sibling_next->sibling_prev = child->sibling_prev;
    child->sibling_prev = 0;
    child->sibling_next = 0;
    child->parent = 0;
}

static void task_child_link(task_t *parent, task_t *child) {
    if (!child) return;
    task_child_unlink(child);
    child->parent = parent;
    if (parent) {
        child->sibling_next = parent->first_child;
        if (parent->first_child) parent->first_child->sibling_prev = child;
        parent->first_child = child;
        child->ppid = parent->pid;
    } else {
        child->ppid = 0;
    }
}

static int process_queue_child_event(task_t *recipient, const task_t *child,
                                     int32_t code, int32_t status) {
    uint8_t information[KERNEL_SIGNAL_INFO_SIZE];
    task_t *leader;
    int32_t visible_child_pid;
    uint64_t user_ticks;
    uint64_t system_ticks;
    uint64_t bit;
    if (!recipient || !child || recipient->pid <= 0) return 0;
    user_ticks = (child->rusage_user_time_us +
                  child->rusage_child_user_time_us) / 10000u;
    system_ticks = (child->rusage_sys_time_us +
                    child->rusage_child_sys_time_us) / 10000u;
    if (edge_pid_namespace_global_to_visible(
            recipient->namespaces.pid, child->pid,
            &visible_child_pid) < 0)
        return 0;
    kernel_signal_info_build_child(
        information, LINUX_SIGCHLD, code, visible_child_pid,
        child->uid, status,
        user_ticks, system_ticks);
    if (process_signal_send_info_internal(
            recipient, LINUX_SIGCHLD, 0, information) < 0)
        return 0;
    leader = task_find_by_pid(process_tgid_of_task(recipient));
    bit = edge_linux_signal_mask_bit(LINUX_SIGCHLD);
    return ((recipient->signal_pending |
             (leader ? leader->signal_shared_pending : 0u)) & bit) != 0;
}

static void process_notify_parent_exit(task_t *parent, const task_t *child,
                                       uint8_t exit_signal) {
    int parent_tgid;
    int signal_pending = 0;
    if (!parent) return;
    if (parent->state == TASK_UNUSED || parent->state == TASK_ZOMBIE) return;
    parent_tgid = parent->tgid > 0 ? parent->tgid : parent->pid;
    if (exit_signal == LINUX_SIGCHLD &&
        parent->signal_actions[LINUX_SIGCHLD - 1].handler != LINUX_SIG_IGN) {
        if (child) {
            int32_t code = child->termination_signal ?
                LINUX_CLD_KILLED : LINUX_CLD_EXITED;
            int32_t status = child->termination_signal ?
                child->termination_signal : child->exit_code;
            signal_pending = process_queue_child_event(
                parent, child, code, status);
        }
    }

    /*
     * A Linux child belongs to the parent's thread group. wait4()/waitid() may
     * therefore sleep in a non-leader thread even though the child is linked to
     * the group leader for getppid() and orphan handling. Wake the actual wait
     * thread, and wake the leader separately when SIGCHLD needs delivery.
     */
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *waiter = &g_tasks[i];
        int waiter_tgid;
        if (waiter->state == TASK_UNUSED || waiter->state == TASK_ZOMBIE)
            continue;
        waiter_tgid = waiter->tgid > 0 ? waiter->tgid : waiter->pid;
        if (waiter_tgid != parent_tgid) continue;
        if (waiter->state == TASK_BLOCKED &&
            (waiter->child_wait_active ||
             (signal_pending && waiter == parent))) {
            /*
             * Until EdgeOS has cross-CPU reschedule IPIs, queue the waiter on
             * the current CPU so it cannot remain asleep on a stale run queue.
             */
            scheduler_task_make_runnable(waiter, scheduler_cpu_id());
        }
    }
}

static void process_notify_waiter_for_task(task_t *task) {
    task_t *recipient;
    int recipient_tgid;
    if (!task) return;
    recipient = task->ptrace.tracer_pid > 0 ?
        task_find_by_pid(task->ptrace.tracer_pid) : task->parent;
    if (!recipient || recipient->state == TASK_UNUSED ||
        recipient->state == TASK_ZOMBIE)
        return;
    recipient_tgid = process_tgid_of_task(recipient);
    if (recipient->signal_actions[LINUX_SIGCHLD - 1].handler !=
        LINUX_SIG_IGN) {
        int32_t code;
        int32_t status;
        if (task->state == TASK_ZOMBIE) {
            code = task->termination_signal ?
                LINUX_CLD_KILLED : LINUX_CLD_EXITED;
            status = task->termination_signal ?
                task->termination_signal : task->exit_code;
        } else if (task->continued_pending) {
            code = LINUX_CLD_CONTINUED;
            status = LINUX_SIGCONT;
        } else {
            code = task->ptrace.tracer_pid > 0 ?
                LINUX_CLD_TRAPPED : LINUX_CLD_STOPPED;
            status = task->stop_signal;
        }
        (void)process_queue_child_event(recipient, task, code, status);
    }
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *waiter = &g_tasks[index];
        if (waiter->state == TASK_UNUSED || waiter->state == TASK_ZOMBIE ||
            process_tgid_of_task(waiter) != recipient_tgid)
            continue;
        if (waiter->state == TASK_BLOCKED && waiter->child_wait_active)
            scheduler_task_make_runnable(waiter, scheduler_cpu_id());
    }
}

static void process_wake_vfork_parent(task_t *child) {
    task_t *parent;
    if (!child || child->vfork_parent_pid <= 0) return;
    parent = task_find_by_pid(child->vfork_parent_pid);
    if (parent && parent->vfork_child_pid == child->pid) {
        parent->vfork_child_pid = 0;
        if (parent->state == TASK_BLOCKED) {
            scheduler_task_make_runnable(parent, scheduler_cpu_id());
        }
    }
    child->vfork_parent_pid = 0;
}

// --- Task Management ---

static task_t *task_find_by_pid(int pid) {
    int slot;

    if (!g_tasks) return 0;
    slot = edge_pid_index_lookup(&g_task_pid_index, pid);
    if (slot >= 0 && slot < PROC_MAX_TASKS &&
        g_tasks[slot].state != TASK_UNUSED && g_tasks[slot].pid == pid)
        return &g_tasks[slot];
    /*
     * Preserve process semantics if lifecycle code ever misses an index
     * update. Repairing the index here turns that defect into a measurable
     * slow path instead of an incorrect ESRCH.
     */
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        if (g_tasks[i].state != TASK_UNUSED && g_tasks[i].pid == pid) {
            (void)edge_pid_index_insert(&g_task_pid_index, pid, (uint32_t)i);
            return &g_tasks[i];
        }
    }
    return 0;
}

static int task_index(const task_t *t) {
    uintptr_t base;
    uintptr_t end;
    uintptr_t p;
    if (!t) return -1;
    if (!g_tasks) return -1;
    base = (uintptr_t)g_tasks;
    end = base + (uintptr_t)PROC_MAX_TASKS * sizeof(g_tasks[0]);
    p = (uintptr_t)t;
    if (p < base || p >= end) return -1;
    if (((p - base) % sizeof(g_tasks[0])) != 0) return -1;
    return (int)((p - base) / sizeof(g_tasks[0]));
}

int process_task_pointer_valid(const task_t *task) {
    return task_index(task) >= 0;
}

task_t *process_task_for_kernel_stack(uint64_t stack_pointer) {
    uintptr_t base;
    uintptr_t end;
    uintptr_t pointer = (uintptr_t)stack_pointer;
    int index;
    task_t *task;

    if (!g_tasks) return 0;

    base = (uintptr_t)&g_kstack_fixed[0][0];
    end = base + (uintptr_t)USER_AS_MAX_TASKS * EDGE_TASK_KSTACK_SIZE;
    if (pointer >= base && pointer < end) {
        index = (int)((pointer - base) / EDGE_TASK_KSTACK_SIZE);
        task = &g_tasks[index];
        if (task->state != TASK_UNUSED && task->kernel_stack_top &&
            stack_pointer >=
                task->kernel_stack_top - EDGE_TASK_KSTACK_SIZE &&
            stack_pointer < task->kernel_stack_top)
            return task;
        return 0;
    }

    if (!g_kstack_task_only_ready || !g_kstack_task_only) return 0;
    base = (uintptr_t)g_kstack_task_only;
    end = base + (uintptr_t)g_kstack_task_only_pages * USER_PAGE_SIZE;
    if (pointer < base || pointer >= end) return 0;
    index = USER_AS_MAX_TASKS +
            (int)((pointer - base) / EDGE_TASK_KSTACK_SIZE);
    if (index < USER_AS_MAX_TASKS || index >= PROC_MAX_TASKS) return 0;
    task = &g_tasks[index];
    if (task->state == TASK_UNUSED || !task->kernel_stack_top ||
        stack_pointer <
            task->kernel_stack_top - EDGE_TASK_KSTACK_SIZE ||
        stack_pointer >= task->kernel_stack_top)
        return 0;
    return task;
}

static void task_set_root_caps(task_t *t) {
    if (!t) return;
    linux_capabilities_init_root(&t->capabilities);
}

static void task_clear_groups(task_t *t) {
    if (!t) return;
    linux_group_list_release(&t->supplementary_groups);
    linux_group_list_init(&t->supplementary_groups);
}

static int task_copy_groups(task_t *child, const task_t *parent) {
    if (!child || !parent) return -1;
    return linux_group_list_retain(&child->supplementary_groups,
                                   &parent->supplementary_groups);
}

static void task_init_resource_limits(task_t *task) {
    uint32_t resource;
    if (!task) return;
    for (resource = 0; resource < EDGE_LINUX_RLIMIT_COUNT; ++resource) {
        task->rlimits[resource][0] = EDGE_LINUX_RLIM_INFINITY;
        task->rlimits[resource][1] = EDGE_LINUX_RLIM_INFINITY;
    }
    task->rlimits[EDGE_LINUX_RLIMIT_STACK][0] = 8u * 1024u * 1024u;
    task->rlimits[EDGE_LINUX_RLIMIT_NOFILE][0] = EDGE_PROCESS_FD_LIMIT;
    task->rlimits[EDGE_LINUX_RLIMIT_NOFILE][1] = EDGE_PROCESS_FD_LIMIT;
    task->rlimits[EDGE_LINUX_RLIMIT_NICE][0] = 0;
    task->rlimits[EDGE_LINUX_RLIMIT_NICE][1] = 0;
    task->rlimits[EDGE_LINUX_RLIMIT_RTPRIO][0] = 0;
    task->rlimits[EDGE_LINUX_RLIMIT_RTPRIO][1] = 0;
}

static void task_copy_resource_limits(task_t *child, const task_t *parent) {
    if (!child || !parent) return;
    memcpy(child->rlimits, parent->rlimits, sizeof(child->rlimits));
}

static void task_copy_process_control(task_t *child, const task_t *parent) {
    const edge_linux_scheduler_state_t *scheduler;
    if (!child || !parent) return;
    scheduler = parent->futex_pi_boosted ?
        &parent->futex_pi_base_scheduler : &parent->scheduler;
    edge_linux_scheduler_state_inherit(&child->scheduler,
                                       scheduler);
    child->futex_pi_base_scheduler = child->scheduler;
    child->futex_pi_boosted = 0u;
    edge_linux_scheduler_entity_inherit(
        &child->scheduler_entity, &child->scheduler,
        boottime_monotonic_us());
    child->scheduler_vruntime_us = parent->scheduler_vruntime_us;
    child->scheduler_vruntime_valid = parent->scheduler_vruntime_valid;
    child->io_priority = parent->io_priority;
    kernel_linux_thread_state_clone(&child->linux_thread,
                                    &parent->linux_thread);
    child->timer_slack_ns = parent->timer_slack_ns;
    child->default_timer_slack_ns = parent->timer_slack_ns;
    child->thp_disabled = parent->thp_disabled;
    child->oom_score_adj = parent->oom_score_adj;
    child->oom_score_adj_min = parent->oom_score_adj_min;
}

static int task_copy_exec_identity(task_t *child, const task_t *parent) {
    if (!child || !parent) return -1;
    strncpy(child->name, parent->name, sizeof(child->name) - 1u);
    child->name[sizeof(child->name) - 1u] = 0;
    strncpy(child->exec_path, parent->exec_path,
            sizeof(child->exec_path) - 1u);
    child->exec_path[sizeof(child->exec_path) - 1u] = 0;
    child->exec_file_handle = parent->exec_file_handle;
    if (child->exec_file_handle &&
        kernel_exec_file_retain(child->exec_file_handle) < 0) {
        child->exec_file_handle = KERNEL_EXEC_FILE_HANDLE_NONE;
        return -1;
    }
    return 0;
}

static void task_copy_caps(task_t *child, const task_t *parent) {
    if (!child || !parent) return;
    linux_capabilities_copy(&child->capabilities, &parent->capabilities);
}

static void task_copy_credentials(task_t *child, const task_t *parent) {
    if (!child || !parent) return;
    child->uid = parent->uid;
    child->gid = parent->gid;
    child->euid = parent->euid;
    child->egid = parent->egid;
    child->suid = parent->suid;
    child->sgid = parent->sgid;
    child->fsuid = parent->fsuid;
    child->fsgid = parent->fsgid;
    child->dumpable = parent->dumpable;
    child->no_new_privs = parent->no_new_privs;
}

static void task_apply_exec_file_creds(task_t *t, uint16_t mode,
                                       uint32_t file_uid, uint32_t file_gid,
                                       uint32_t mount_flags) {
    uint32_t old_euid;
    uint32_t old_egid;
    int allow_setid;
    int setuid_exec;
    int setgid_exec;
    int credentials_changed;
    if (!t) return;
    old_euid = t->euid;
    old_egid = t->egid;
    allow_setid = !t->no_new_privs && !(mount_flags & VFS_MOUNT_NOSUID);
    setuid_exec = allow_setid && (mode & 04000u);
    setgid_exec = allow_setid && (mode & 02000u) && (mode & 00010u);

    /*
     * Linux execve commits set-user-ID and set-group-ID file bits as part of
     * installing the new image.  MS_NOSUID and no_new_privs suppress those
     * transitions, and saved/filesystem IDs follow the resulting effective
     * credentials.
     */
    if (setuid_exec) t->euid = file_uid;
    if (setgid_exec) t->egid = file_gid;
    credentials_changed = t->euid != old_euid || t->egid != old_egid;
    t->suid = t->euid;
    t->sgid = t->egid;
    t->fsuid = t->euid;
    t->fsgid = t->egid;
    t->dumpable = credentials_changed ? 0u : 1u;
    if (credentials_changed) t->parent_death_signal = 0;
    if (t->euid == 0) {
        task_set_root_caps(t);
    } else {
        t->capabilities.permitted = 0;
        t->capabilities.effective = 0;
        t->capabilities.inheritable &= EDGE_LINUX_CAP_FULL_SET;
        t->capabilities.ambient = 0;
    }
}

static int process_vm_owner_pid_of_task_raw(const task_t *t) {
    if (!t) return 0;
    return t->vm_owner_pid > 0 ? t->vm_owner_pid : t->pid;
}

static void task_release_unused(task_t *t);
static void task_clear_user_vmas(task_t *t);
static int process_user_vma_is_fbdev(const edge_user_vma_t *v);
static int process_user_any_fbdev_mapping(void);
static void task_clear_user_regions(task_t *t);
static void task_dump_slots_local(const char *reason);
static const char *task_state_name_local(task_state_t state);
static int process_thread_group_has_other_live(task_t *target, int tgid);
static int kernel_task_view_from_task(const task_t *task,
                                      kernel_proc_task_view_t *view);
static volatile uint32_t g_detached_zombie_reap_pending;

static int process_vm_live_users_raw(int owner_pid, const task_t *exclude) {
    int count = 0;
    if (owner_pid <= 0) return 0;
    if (!g_tasks) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *t = &g_tasks[i];
        if (t == exclude) continue;
        if (t->state == TASK_UNUSED) continue;
        /*
         * A zombie retains the mm only while its final kernel continuation is
         * still running on a CPU.  Once the scheduler has retired it, the task
         * no longer executes or faults and must not pin the address space while
         * waiting for detached-thread cleanup or a parent wait operation.
         */
        if (t->state == TASK_ZOMBIE &&
            scheduler_task_reap_ready((task_t *)t))
            continue;
        if (process_vm_owner_pid_of_task_raw(t) == owner_pid) count++;
    }
    return count;
}

static int task_is_detached_zombie_candidate_raw(const task_t *t) {
    int tgid;
    if (!t || t->state != TASK_ZOMBIE) return 0;
    if (!t->parent && t->ppid == 0) return 1;
    tgid = t->tgid > 0 ? t->tgid : t->pid;
    return tgid > 0 && tgid != t->pid;
}

static int task_is_detached_zombie_raw(const task_t *t) {
    int tgid;
    if (!task_is_detached_zombie_candidate_raw(t)) return 0;
    /*
     * A thread publishes TASK_ZOMBIE before its final scheduler_yield().
     * Another CPU can observe that state while the exiting thread still owns
     * its live kernel stack.  Reusing the slot in that window discards the
     * continuation that must complete the context switch and can strand the
     * userspace runtime on an M that no longer has a kernel task.  The
     * scheduler clears on_cpu when the thread has actually switched away.
     */
    if (!scheduler_task_reap_ready((task_t *)t)) return 0;
    if (!t->parent && t->ppid == 0) return 1;
    tgid = t->tgid > 0 ? t->tgid : t->pid;
    /*
     * Linux CLONE_THREAD tasks are thread-group members, not independent
     * waitable children of the creator.  Their exit is reported to pthread
     * joiners through clear_child_tid/futex and thread-group state, so the
     * internal task slot may be reused once the task is no longer running.
     * Do not apply this to group leaders: parents must still be able to wait4()
     * those zombies and shared-mm children may keep the leader's mm alive.
     */
    return tgid > 0 && tgid != t->pid;
}

static int process_reap_detached_zombies(const char *reason) {
    task_t *release[PROC_MAX_TASKS];
    task_t *cur = process_current_task();
    int nrelease = 0;
    int retry = 0;

    (void)reason;

    if (!g_tasks) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (t == cur) continue;
        if (!task_is_detached_zombie_candidate_raw(t)) continue;
        if (!scheduler_task_reap_ready(t)) {
            retry = 1;
            continue;
        }
        if (nrelease < PROC_MAX_TASKS) release[nrelease++] = t;
    }

    for (int i = 0; i < nrelease; ++i) {
        task_release_unused(release[i]);
    }

    /*
     * A sibling may run the first syscall after an exiting thread has
     * published TASK_ZOMBIE but before the scheduler has retired its kernel
     * stack.  Keep the event armed until a later syscall observes the task as
     * reapable.  Otherwise the dead TID remains visible in /proc/self/task
     * indefinitely and pthread users can mistake the process for threaded.
     */
    if (retry)
        __atomic_store_n(&g_detached_zombie_reap_pending, 1u,
                         __ATOMIC_RELEASE);

    return nrelease;
}

int process_reap_detached_zombie_threads_periodic(const char *reason) {
    if (!g_tasks) return 0;
    if (!__atomic_exchange_n(&g_detached_zombie_reap_pending, 0u,
                             __ATOMIC_ACQ_REL))
        return 0;
    /*
     * Linux non-leader CLONE_THREAD exits and children covered by SIG_IGN or
     * SA_NOCLDWAIT are not persistent parent-visible zombies.  Reap completed
     * non-current slots after an exit publishes one instead of periodically
     * scanning every task slot.  task_t intentionally carries substantial
     * process and mm state, so a timer-driven full-table walk destroys cache
     * locality during dense X11, D-Bus, and browser syscall traffic.
     */
    return process_reap_detached_zombies(reason ? reason : "periodic");
}

static uint64_t task_kernel_stack_top_for_index(int idx) {
    uint64_t off;
    if (idx < 0 || idx >= PROC_MAX_TASKS) return 0;
    if (idx < USER_AS_MAX_TASKS) {
        return (uint64_t)(uintptr_t)&g_kstack_fixed[idx][EDGE_TASK_KSTACK_SIZE - 16];
    }
    /*
     * Task-only slots are valid Linux CLONE_VM/pthread targets, but they do not
     * own the large fixed userspace backing below.  Their kernel stacks are
     * carved from boot-reported usable memory after the sparse mmap backing list
     * is sorted.  Never hand the scheduler a task-only slot until that runtime
     * stack pool exists; returning EAGAIN is better than resuming through a null
     * or non-contiguous stack.
     */
    if (!g_kstack_task_only_ready || !g_kstack_task_only) return 0;
    off = (uint64_t)(idx - USER_AS_MAX_TASKS) * (uint64_t)EDGE_TASK_KSTACK_SIZE;
    if (off + (uint64_t)EDGE_TASK_KSTACK_SIZE >
        (uint64_t)g_kstack_task_only_pages * USER_PAGE_SIZE) {
        return 0;
    }
    return (uint64_t)(uintptr_t)(g_kstack_task_only + off + EDGE_TASK_KSTACK_SIZE - 16);
}

static void task_release_dynamic_vma_storage(task_t *task) {
    if (!task || !task->user_vma_dynamic_pages) return;
    kernel_mm_vma_storage_release(task->user_vmas,
                                  task->user_vma_dynamic_pages);
    task->user_vmas = 0;
    task->user_vma_dynamic_pages = 0;
    task->user_vma_capacity = 0;
}

static void task_reset_slot(task_t *task, int index) {
    uint64_t *x86_ldt_entries;
    uint32_t x86_ldt_capacity;

    if (!task) return;
    x86_ldt_entries = task->x86_ldt_entries;
    x86_ldt_capacity = task->x86_ldt_capacity;
    task_release_dynamic_vma_storage(task);
    memset(task, 0, sizeof(*task));
    task->x86_ldt_entries = x86_ldt_entries;
    task->x86_ldt_capacity = x86_ldt_capacity;
    if (x86_ldt_entries && x86_ldt_capacity)
        memset(x86_ldt_entries, 0,
               (uint64_t)x86_ldt_capacity * sizeof(uint64_t));
    spinlock_init(&task->x86_ldt_lock);
    task->user_vmas = index >= 0 && index < USER_AS_MAX_TASKS ?
        kernel_mm_vma_space((uint32_t)index) : 0;
    task->user_vma_capacity = task->user_vmas ?
        KERNEL_MM_VMA_INITIAL_AREAS : 0u;
    task->exec_record = index >= 0 && index < USER_AS_MAX_TASKS ?
        kernel_exec_record_space((uint32_t)index) : 0;
    task->scratch = index >= 0 ?
        kernel_task_scratch_space((uint32_t)index) : 0;
    kernel_exec_record_reset(task->exec_record);
}

static task_t *task_alloc(void) {
    if (!g_tasks) return 0;
    for (int i = 0; i < USER_AS_MAX_TASKS; ++i) {
        if (g_tasks[i].state == TASK_UNUSED) return &g_tasks[i];
    }
    for (int i = 0; i < USER_AS_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (task_is_detached_zombie_raw(t)) return t;
    }
    for (int i = 0; i < USER_AS_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (t->state != TASK_ZOMBIE) continue;
        /*
         * The first USER_AS_MAX_TASKS slots own fixed userspace backing.  They
         * are expensive and cannot remain pinned by unreaped zombies when a
         * Linux userspace is doing fork-heavy package triggers.  Recycle only
         * after every truly unused slot has been consumed, and only for a
         * TASK_ZOMBIE, so a live task is never stolen.  This is a pressure
         * valve for imperfect init/shell reaping compatibility until process
         * address spaces are allocated dynamically instead of from this fixed
         * pool.
         *
         * Red flag: do not recycle a zombie VM owner while CLONE_VM threads still
         * reference its pid.  Linux keeps the mm alive independently of the
         * thread-group leader task lifetime; recycling this slot destroys the
         * sparse mmap page tables under GLib/XFCE worker threads and later faults
         * show up as bogus sparse OOM or killed desktop helpers.
         */
        if (process_vm_live_users_raw(process_vm_owner_pid_of_task_raw(t), t) > 0) continue;
        task_child_unlink(t);
        return t;
    }
    return 0;
}

static task_t *task_alloc_any(void) {
    if (!g_tasks) return 0;
    for (int i = USER_AS_MAX_TASKS; i < PROC_MAX_TASKS; ++i) {
        if (!task_kernel_stack_top_for_index(i)) continue;
        if (g_tasks[i].state == TASK_UNUSED) return &g_tasks[i];
    }
    for (int i = USER_AS_MAX_TASKS; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (!task_kernel_stack_top_for_index(i)) continue;
        if (task_is_detached_zombie_raw(t)) return t;
    }
    for (int i = 0; i < USER_AS_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (task_is_detached_zombie_raw(t)) return t;
    }
    /*
     * Shared-mm tasks and pthreads must not silently consume the fixed
     * independent-mm slots once the task-only range is exhausted.  Returning
     * EAGAIN here is Linux-compatible resource pressure; stealing a process
     * slot makes later fork()/execve() fail and wedges desktop launchers.
     */
    return 0;
}

static task_t *task_alloc_reserved(int any_slot, int *slot_idx) {
    uint64_t flags;
    task_t *t = 0;

    /*
     * Linux non-leader pthread exits are not persistent parent-visible zombie
     * processes.  Reap those internal EdgeOS task slots before deciding that
     * fork/clone has hit EAGAIN, or a burst of GLib/Pango helper threads can
     * make later real processes fail even though the Linux-visible workload is
     * idle.
     */
    process_reap_detached_zombies(any_slot ? "alloc-task" : "alloc-mm");

    flags = spin_lock_irqsave(&g_task_lock);
    if (any_slot) {
        t = task_alloc_any();
    } else {
        t = task_alloc();
    }
    if (t) {
        int idx = task_index(t);
        uint64_t stack_top = task_kernel_stack_top_for_index(idx);
        if (idx >= 0)
            edge_pid_index_remove(&g_task_pid_index, t->pid,
                                  (uint32_t)idx);
        task_child_unlink(t);
        task_save_user_region_watermarks(t);
        if (t->state != TASK_UNUSED || t->on_runqueue || t->assigned_cpu >= 0) {
            scheduler_task_set_unused(t);
        }
        if (!stack_top) {
            task_reset_slot(t, idx);
            t = 0;
            if (slot_idx) *slot_idx = -1;
            goto out_unlock;
        }
        task_reset_slot(t, idx);
        task_init_resource_limits(t);
        /*
         * A task created before secondary CPUs finish starting must still be
         * eligible for CPUs that become online later.  Linux initializes a
         * normal task with the system's possible CPU mask and intersects it
         * with the online mask when selecting or reporting affinity.  Using
         * the instantaneous online mask here permanently pinned init and all
         * descendants to CPU0.
         */
        edge_linux_scheduler_state_init(&t->scheduler, UINT64_MAX);
        edge_linux_scheduler_entity_init(
            &t->scheduler_entity, &t->scheduler,
            boottime_monotonic_us());
        t->pid = g_next_pid++;
        if (edge_pid_index_insert(&g_task_pid_index, t->pid,
                                  (uint32_t)idx) < 0) {
            task_reset_slot(t, idx);
            t = 0;
            if (slot_idx) *slot_idx = -1;
            goto out_unlock;
        }
        t->tgid = t->pid;
        t->vm_owner_pid = t->pid;
        t->fd_owner_pid = t->pid;
        t->fs_context_id = g_next_fs_context_id++;
        if (!t->fs_context_id) t->fs_context_id = g_next_fs_context_id++;
        t->sighand_context_id = task_sighand_context_alloc();
        t->state = TASK_BLOCKED;
        t->kernel_stack_top = stack_top;
        t->assigned_cpu = -1;
        t->rusage_start_us = boottime_monotonic_us();
        if (slot_idx) *slot_idx = idx;
    } else if (slot_idx) {
        *slot_idx = -1;
    }

out_unlock:
    spin_unlock_irqrestore(&g_task_lock, flags);
    return t;
}

static void task_release_unused(task_t *t) {
    uint32_t cgroup_id;
    uint32_t expected;
    int was_counted;
    uint64_t flags;
    if (!t) return;
    if (t->state == TASK_ZOMBIE && !scheduler_task_reap_ready(t)) {
        /*
         * Another CPU may reap a waitable task after exit state is published
         * but before the dying task performs its final context switch.  Keep
         * the task slot and live kernel stack intact until the destination
         * task proves that switch completed, while detaching it from
         * parent-visible wait bookkeeping.
         */
        task_child_unlink(t);
        t->parent = 0;
        t->ppid = 0;
        __atomic_store_n(&g_detached_zombie_reap_pending, 1u,
                         __ATOMIC_RELEASE);
        return;
    }
    expected = 0u;
    if (!__atomic_compare_exchange_n(&t->reap_claimed, &expected, 1u, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    if (t->state == TASK_ZOMBIE &&
        t->pid == process_vm_owner_pid_of_task_raw(t) &&
        process_vm_live_users_raw(t->pid, t) > 0) {
        /*
         * The parent has reaped the zombie leader, but live CLONE_VM siblings
         * still run on the leader's address-space slot.  Detach it from wait
         * bookkeeping and keep the slot as a zombie mm container until the last
         * user exits; process_finish_task_exit() releases it then.
         */
        task_child_unlink(t);
        t->parent = 0;
        t->ppid = 0;
        __atomic_store_n(&t->reap_claimed, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&g_detached_zombie_reap_pending, 1u,
                         __ATOMIC_RELEASE);
        return;
    }
    cgroup_id = t->cgroup_id;
    was_counted = t->cgroup_accounted != 0;
    t->cgroup_accounted = 0;
    task_child_unlink(t);
    /*
     * Task slots are recycled aggressively for Linux pthread churn.  Wait state
     * belongs to the dying task, not to the storage slot; clear it before the
     * slot can be reused so the next task cannot inherit a stale blocked-wait
     * deadline or fd-wait marker.  External wait queues store pids and validate
     * liveness before waking, so clearing these per-task flags is the durable
     * slot hygiene required here.
     */
    t->sleep_wait_active = 0;
    t->fd_wait_active = 0;
    t->child_wait_active = 0;
    t->sleep_deadline_us = 0;
    t->need_resched = 0;
    kernel_exec_file_release(t->exec_file_handle);
    t->exec_file_handle = KERNEL_EXEC_FILE_HANDLE_NONE;
    if (t->pid_namespace_attached) {
        edge_pid_namespace_task_detach(t->pid);
        t->pid_namespace_attached = 0;
    }
    linux_group_list_release(&t->supplementary_groups);
    edge_seccomp_state_release(&t->seccomp);
    edge_namespaces_release(&t->namespaces);
    task_save_user_region_watermarks(t);
    if (task_index(t) >= 0 && task_index(t) < USER_AS_MAX_TASKS &&
        process_vm_owner_pid_of_task_raw(t) == t->pid &&
        process_vm_live_users_raw(t->pid, t) == 0) {
        process_user_mmap_reset(t);
        task_clear_user_regions(t);
    }
    task_clear_user_vmas(t);
    flags = spin_lock_irqsave(&g_task_lock);
    {
        int idx = task_index(t);
        if (idx >= 0)
            edge_pid_index_remove(&g_task_pid_index, t->pid,
                                  (uint32_t)idx);
    }
    scheduler_task_set_unused(t);
    task_reset_slot(t, task_index(t));
    spin_unlock_irqrestore(&g_task_lock, flags);
    if (was_counted) cgroupfs_task_leave(cgroup_id);
}

int process_cgroup_account_publish(int pid) {
    task_t *task = task_find_by_pid(pid);

    if (!task || task->state == TASK_UNUSED ||
        task->state == TASK_ZOMBIE)
        return -1;
    if (!task->cgroup_accounted) {
        cgroupfs_task_join(task->cgroup_id);
        task->cgroup_accounted = 1;
    }
    return 0;
}

int process_cgroup_account_rebuilt(int pid) {
    task_t *task = task_find_by_pid(pid);

    if (!task || task->state == TASK_UNUSED ||
        task->state == TASK_ZOMBIE)
        return -1;
    task->cgroup_accounted = 1;
    return 0;
}

static int count_used_tasks_local(void) {
    int used = 0;
    if (!g_tasks) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        if (g_tasks[i].state != TASK_UNUSED) used++;
    }
    return used;
}

static int count_used_user_as_tasks_local(void) {
    int used = 0;
    if (!g_tasks) return 0;
    for (int i = 0; i < USER_AS_MAX_TASKS; ++i) {
        if (g_tasks[i].state != TASK_UNUSED) used++;
    }
    return used;
}

static int count_used_task_only_tasks_local(void) {
    int used = 0;
    if (!g_tasks) return 0;
    for (int i = USER_AS_MAX_TASKS; i < PROC_MAX_TASKS; ++i) {
        if (g_tasks[i].state != TASK_UNUSED) used++;
    }
    return used;
}

static uint32_t sparse_bitmap_count_used_local(const uint64_t *bits, uint32_t nbits) {
    uint32_t used = 0;
    uint32_t words = (nbits + 63u) / 64u;

    if (!bits) return 0;
    for (uint32_t word = 0; word < words; ++word) {
        uint64_t value = __atomic_load_n(&bits[word], __ATOMIC_ACQUIRE);
        if (word + 1u == words && (nbits & 63u))
            value &= (UINT64_C(1) << (nbits & 63u)) - 1u;
        used += (uint32_t)__builtin_popcountll(value);
    }
    return used;
}

static void sparse_mmap_log_oom_local(task_t *t, const char *what, uint64_t va) {
    if (g_sparse_mmap_oom_log_budget <= 0) return;
    printf("[sparse-oom] pid=%d task=%s what=%s va=0x%x backing=%u/%u pt=%u/%u tasks=%d/%d as=%d/%d taskonly=%d/%d\n",
           t ? t->pid : -1,
           (t && t->name[0]) ? t->name : "?",
           what ? what : "?",
           (uint32_t)va,
           sparse_bitmap_count_used_local(g_user_mmap_backing_used, g_user_mmap_backing_ready_pages),
           g_user_mmap_backing_ready_pages,
           sparse_bitmap_count_used_local(g_user_mmap_pt_used,
                                          g_user_mmap_backing_ready_pages),
           g_user_mmap_backing_ready_pages,
           count_used_tasks_local(),
           PROC_MAX_TASKS,
           count_used_user_as_tasks_local(),
           USER_AS_MAX_TASKS,
           count_used_task_only_tasks_local(),
           EDGE_TASK_ONLY_SLOTS);
    g_sparse_mmap_oom_log_budget--;
}

static const char *task_state_name_local(task_state_t state) {
    switch (state) {
        case TASK_UNUSED: return "unused";
        case TASK_RUNNABLE: return "run";
        case TASK_RUNNING: return "cpu";
        case TASK_BLOCKED: return "block";
        case TASK_STOPPED: return "stop";
        case TASK_ZOMBIE: return "zombie";
        default: return "?";
    }
}

static void task_dump_slots_local(const char *reason) {
    static int budget = 8;
    if (budget <= 0) return;
    budget--;
    printf("[task-slots] %s used=%d/%d as=%d/%d taskonly=%d/%d\n",
           reason ? reason : "?",
           count_used_tasks_local(), PROC_MAX_TASKS,
           count_used_user_as_tasks_local(), USER_AS_MAX_TASKS,
           count_used_task_only_tasks_local(), EDGE_TASK_ONLY_SLOTS);
    if (!g_tasks) return;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (t->state == TASK_UNUSED) continue;
        printf("[task-slot] idx=%d pid=%d ppid=%d tgid=%d vm=%d fd=%d state=%s name=%s syscall=%u in=%u wait=%u/%u/%u/%u\n",
               i, t->pid, t->ppid, t->tgid, t->vm_owner_pid, t->fd_owner_pid,
               task_state_name_local(t->state), t->name[0] ? t->name : "?",
               (uint32_t)t->last_syscall_nr, (unsigned)t->in_syscall,
               (unsigned)t->sleep_wait_active,
               (unsigned)t->fd_wait_active,
               (unsigned)t->child_wait_active,
               (unsigned)t->file_lock_wait_active);
    }
}

void process_debug_dump_tasks(const char *reason) {
    task_dump_slots_local(reason);
}

static task_t *task_vm_owner_local(task_t *t) {
    task_t *owner;
    if (!t) return 0;
    if (t->vm_owner_pid <= 0 || t->vm_owner_pid == t->pid) return t;
    owner = task_find_by_pid(t->vm_owner_pid);
    return owner ? owner : t;
}

void process_user_mm_cpu_enter(task_t *task, uint32_t cpu_id) {
    static volatile int32_t active_mm_pid[64];
    task_t *memory = task && !task->is_idle ?
        task_vm_owner_local(task) : 0;
    int32_t new_pid = memory && memory->cr3 ? memory->pid : 0;
    int32_t old_pid;

    if (cpu_id >= 64u) return;
    old_pid = __atomic_exchange_n(&active_mm_pid[cpu_id], new_pid,
                                  __ATOMIC_ACQ_REL);
    if (old_pid > 0 && old_pid != new_pid) {
        task_t *old_memory = task_find_by_pid(old_pid);

        if (old_memory)
            __atomic_fetch_and(&old_memory->user_mm_cpu_mask,
                               ~(UINT64_C(1) << cpu_id),
                               __ATOMIC_RELEASE);
    }
    if (!memory || !memory->cr3) return;
    __atomic_fetch_or(&memory->user_mm_cpu_mask,
                      UINT64_C(1) << cpu_id, __ATOMIC_RELEASE);
}

void process_user_vma_mutation_lock(task_t *task) {
    task_t *memory = task_vm_owner_local(task);
    task_t *current = process_current_task();
    int owner_pid = current ? current->pid : -1;
    uint32_t spins = 0u;

    if (!memory) return;
    if (memory->user_vma_mutation_lock &&
        memory->user_vma_mutation_owner_pid == owner_pid) {
        if (memory->user_vma_mutation_depth != UINT16_MAX)
            ++memory->user_vma_mutation_depth;
        return;
    }
    while (__sync_lock_test_and_set(
               &memory->user_vma_mutation_lock, 1u)) {
        __asm__ __volatile__("pause");
        if ((++spins & 0x3fffu) == 0u) {
            current = process_current_task();
            if (current && !current->is_idle && current->pid > 0 &&
                current->state == TASK_RUNNING)
                scheduler_yield();
        }
    }
    memory->user_vma_mutation_owner_pid = owner_pid;
    memory->user_vma_mutation_depth = 1u;
}

void process_user_vma_mutation_unlock(task_t *task) {
    task_t *memory = task_vm_owner_local(task);
    task_t *current = process_current_task();
    int owner_pid = current ? current->pid : -1;

    if (!memory || !memory->user_vma_mutation_lock ||
        memory->user_vma_mutation_owner_pid != owner_pid)
        return;
    if (memory->user_vma_mutation_depth > 1u) {
        --memory->user_vma_mutation_depth;
        return;
    }
    memory->user_vma_mutation_depth = 0;
    memory->user_vma_mutation_owner_pid = 0;
    __sync_lock_release(&memory->user_vma_mutation_lock);
}

static void process_user_page_table_lock(task_t *task) {
    task_t *memory = task_vm_owner_local(task);
    task_t *current = process_current_task();
    int owner_pid = current ? current->pid : -1;
    uint32_t spins = 0;
    static volatile int contention_log_budget = 16;

    if (!memory) return;
    if (memory->user_page_table_lock &&
        memory->user_page_table_owner_pid == owner_pid) {
        if (memory->user_page_table_lock_depth != UINT16_MAX)
            ++memory->user_page_table_lock_depth;
        return;
    }
    while (__sync_lock_test_and_set(&memory->user_page_table_lock, 1u)) {
        if (++spins == 100000u &&
            __sync_fetch_and_sub(&contention_log_budget, 1) > 0) {
            task_t *owner = task_find_by_pid(
                memory->user_page_table_owner_pid);
            printf("[page-table-lock] waiter=%d:%s mm=%d owner=%d:%s state=%d syscall=%u oncpu=%u\n",
                   current ? current->pid : -1,
                   (current && current->name[0]) ? current->name : "?",
                   memory->pid, memory->user_page_table_owner_pid,
                   (owner && owner->name[0]) ? owner->name : "?",
                   owner ? owner->state : -1,
                   owner ? (uint32_t)owner->last_syscall_nr : UINT32_MAX,
                   owner ? (unsigned)owner->on_cpu : 0u);
        }
        __asm__ __volatile__("pause");
        if ((spins & 0x3fffu) == 0u) {
            current = process_current_task();
            if (current && !current->is_idle && current->pid > 0 &&
                current->state == TASK_RUNNING)
                scheduler_yield();
        }
    }
    memory->user_page_table_owner_pid = owner_pid;
    memory->user_page_table_lock_depth = 1u;
}

static void process_user_page_table_unlock(task_t *task) {
    task_t *memory = task_vm_owner_local(task);
    task_t *current = process_current_task();
    int owner_pid = current ? current->pid : -1;

    if (!memory || !memory->user_page_table_lock ||
        memory->user_page_table_owner_pid != owner_pid)
        return;
    if (memory->user_page_table_lock_depth > 1u) {
        --memory->user_page_table_lock_depth;
        return;
    }
    memory->user_page_table_lock_depth = 0;
    memory->user_page_table_owner_pid = 0;
    __sync_lock_release(&memory->user_page_table_lock);
}

static void task_clear_user_regions(task_t *t) {
    int idx = task_index(t);
    uint64_t old_cr3;
    uint64_t rflags;
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    old_cr3 = backing_access_enter(&rflags);
    /*
     * Fixed userspace windows are demand-backed by refcounted 4 KiB pages.
     * Releasing those PTE references is the Linux-style exec/exit operation;
     * bulk-zeroing multi-megabyte per-slot arrays made every short-lived
     * process pay for address space it never touched.
     */
    fixed_user_release_data_for_idx(idx);
    fixed_user_pt_release_for_idx(idx);
    backing_access_leave(old_cr3, rflags);
    g_user_bigpie_dirty_bytes[idx] = 0;
}

static int process_user_vma_live_count(const task_t *t) {
    int live;

    if (!t || !t->user_vmas) return 0;
    live = t->user_vma_count;
    if ((uint32_t)live > t->user_vma_capacity)
        live = (int)t->user_vma_capacity;
    return live;
}

static uint64_t task_bigpie_used_bytes(task_t *t) {
    uint64_t hi = USER_BIGPIE_BASE;
    int live;
    if (!t) return 0;
    if (t->start_at_entry >= USER_BIGPIE_BASE && t->start_at_entry < USER_BIGPIE_BASE + USER_BIGPIE_SIZE) {
        uint64_t end = t->start_at_entry + USER_PAGE_SIZE;
        if (end > hi) hi = end;
    }
    if (t->start_at_phdr >= USER_BIGPIE_BASE && t->start_at_phdr < USER_BIGPIE_BASE + USER_BIGPIE_SIZE) {
        uint64_t end = t->start_at_phdr + USER_PAGE_SIZE;
        if (end > hi) hi = end;
    }
    live = process_user_vma_live_count(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        uint64_t end;
        if (v->end <= v->start) continue;
        if (v->start >= USER_BIGPIE_BASE + USER_BIGPIE_SIZE) continue;
        if (v->end <= USER_BIGPIE_BASE) continue;
        end = v->end;
        if (end > USER_BIGPIE_BASE + USER_BIGPIE_SIZE) end = USER_BIGPIE_BASE + USER_BIGPIE_SIZE;
        if (end > hi) hi = end;
    }
    if (hi <= USER_BIGPIE_BASE) return 0;
    return (hi - USER_BIGPIE_BASE + USER_PAGE_SIZE - 1ULL) & ~(USER_PAGE_SIZE - 1ULL);
}

static uint64_t task_heap_used_bytes(task_t *t, uint64_t *heap_ext_out) {
    uint64_t hi = USER_HEAP_BASE;
    uint64_t total;
    uint64_t heap_bytes;
    uint64_t heap_ext_bytes = 0;
    int live;
    if (heap_ext_out) *heap_ext_out = 0;
    if (!t) return 0;
    if (t->user_brk > hi) hi = t->user_brk;
    live = process_user_vma_live_count(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        uint64_t end;
        if (v->end <= v->start) continue;
        if (v->start >= USER_HEAP_EXT_BASE + USER_HEAP_EXT_SIZE) continue;
        if (v->end <= USER_HEAP_BASE) continue;
        end = v->end;
        if (end > USER_HEAP_EXT_BASE + USER_HEAP_EXT_SIZE) end = USER_HEAP_EXT_BASE + USER_HEAP_EXT_SIZE;
        if (end > hi) hi = end;
    }
    if (hi <= USER_HEAP_BASE) return 0;
    total = (hi - USER_HEAP_BASE + USER_PAGE_SIZE - 1ULL) & ~(USER_PAGE_SIZE - 1ULL);
    heap_bytes = total;
    if (heap_bytes > USER_HEAP_SIZE) {
        heap_ext_bytes = heap_bytes - USER_HEAP_SIZE;
        heap_bytes = USER_HEAP_SIZE;
        if (heap_ext_bytes > USER_HEAP_EXT_SIZE) heap_ext_bytes = USER_HEAP_EXT_SIZE;
    }
    if (heap_ext_out) *heap_ext_out = heap_ext_bytes;
    return heap_bytes;
}

static void task_save_user_region_watermarks(task_t *t) {
    uint64_t heap_ext_bytes = 0;
    uint64_t heap_bytes;
    uint64_t bigpie_bytes;
    int idx = task_index(t);
    if (!t || idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    heap_bytes = task_heap_used_bytes(t, &heap_ext_bytes);
    bigpie_bytes = task_bigpie_used_bytes(t);
    (void)heap_bytes;
    (void)heap_ext_bytes;
    if (bigpie_bytes > g_user_bigpie_dirty_bytes[idx]) g_user_bigpie_dirty_bytes[idx] = bigpie_bytes;
}

static void task_clear_user_vmas(task_t *t) {
    int task_slot;
    int live;
    int had_fbdev_mapping = 0;

    if (!t) return;
    task_slot = task_index(t);
    live = process_user_vma_live_count(t);
    if (t->user_vma_refs_owned) {
        for (int i = 0; i < live; ++i) {
            edge_user_vma_t *v = &t->user_vmas[i];
            if (process_user_vma_is_fbdev(v)) had_fbdev_mapping = 1;
            if (v->end > v->start) process_user_vma_release_backing(v);
        }
    }
    t->user_vma_count = 0;
    t->user_vma_refs_owned = 0;
    /*
     * The VMA array is compact and user_vma_count is its authoritative live
     * length. Scrub only entries that were live; dynamic capacity beyond the
     * count is neither traversed nor exposed and is overwritten before reuse.
     */
    if (live > 0)
        memset(t->user_vmas, 0,
               (uint32_t)live * (uint32_t)sizeof(t->user_vmas[0]));
    if (task_slot >= 0 && task_slot < USER_AS_MAX_TASKS) {
        g_user_fbdev_owner_active[task_slot] = 0;
        memset(g_user_vma_lookup_cache[task_slot], 0xFF,
               sizeof(g_user_vma_lookup_cache[task_slot]));
        g_user_vma_lookup_cache_next[task_slot] = 0;
    }
    /*
     * Address-space reset detaches sparse file PTEs before this function drops
     * their VMA references.  Complete the shared orphan-lifetime phase only
     * after the metadata is gone, so the cache may write back and retire a
     * zero-link inode without racing a still-reachable user alias.
     */
    vfs_inode_lifetime_finish_alias_release();
    if (had_fbdev_mapping && !process_user_any_fbdev_mapping()) {
        fb_release_user_mmap();
        if (!syscall_console_active_vt_in_graphics())
            fb_console_set_present_enabled(1);
    }
}

static int task_retain_user_vmas(task_t *t) {
    int live;
    if (!t) return -1;
    live = process_user_vma_live_count(t);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &t->user_vmas[i];
        if (v->end <= v->start) continue;
        if (process_user_vma_retain_backing(v) < 0) {
            for (int j = 0; j < i; ++j) {
                edge_user_vma_t *old = &t->user_vmas[j];
                if (old->end > old->start)
                    process_user_vma_release_backing(old);
            }
            return -1;
        }
    }
    t->user_vma_refs_owned = 1;
    return 0;
}

static inline void invlpg_local(uint64_t va) {
    __asm__ __volatile__("invlpg (%0)" :: "r"((void *)(uintptr_t)va) : "memory");
}

static int bitmap_test_idx(const uint64_t *bitmap, uint32_t bits, uint32_t idx) {
    if (!bitmap || idx >= bits) return 0;
    return (bitmap[idx / 64u] & (1ull << (idx % 64u))) != 0;
}

static void bitmap_set_idx(uint64_t *bitmap, uint32_t bits, uint32_t idx) {
    if (!bitmap || idx >= bits) return;
    bitmap[idx / 64u] |= 1ull << (idx % 64u);
}

static void bitmap_clear_idx(uint64_t *bitmap, uint32_t bits, uint32_t idx) {
    if (!bitmap || idx >= bits) return;
    bitmap[idx / 64u] &= ~(1ull << (idx % 64u));
}

static int bitmap_find_next_clear_range(const uint64_t *bitmap, uint32_t bits,
                                        uint32_t begin, uint32_t end) {
    uint32_t first_word;
    uint32_t last_word;

    if (!bitmap || begin >= end || end > bits) return -1;
    first_word = begin / 64u;
    last_word = (end - 1u) / 64u;
    for (uint32_t word = first_word; word <= last_word; ++word) {
        uint64_t free_mask = ~bitmap[word];
        uint32_t first_bit = begin % 64u;
        uint32_t tail_bits = end % 64u;

        if (word == first_word && first_bit != 0)
            free_mask &= ~0ULL << first_bit;
        if (word == last_word && tail_bits != 0)
            free_mask &= (1ULL << tail_bits) - 1ULL;
        if (free_mask != 0) {
            uint32_t index =
                word * 64u + (uint32_t)__builtin_ctzll(free_mask);
            return index < end ? (int)index : -1;
        }
    }
    return -1;
}

static int fixed_user_pt_pool_index_from_ptr(const uint64_t *pt) {
    uintptr_t address = (uintptr_t)pt;
    uint64_t physical;

    if (!address || (address & (USER_PAGE_SIZE - 1ULL)) != 0) return -1;
    if (address >= EDGE_MMIO_LOW_ALIAS_BASE &&
        address < EDGE_MMIO_LOW_ALIAS_BASE + EDGE_MMIO_LOW_ALIAS_SIZE) {
        physical = address - EDGE_MMIO_LOW_ALIAS_BASE;
    } else {
        physical = address;
    }
    return sparse_mmap_backing_index_from_phys(physical);
}

static uint64_t fixed_user_pt_phys_from_ptr(const uint64_t *pt) {
    uintptr_t address = (uintptr_t)pt;
    if (!address || (address & (USER_PAGE_SIZE - 1ULL)) != 0) return 0;
    if (address >= EDGE_MMIO_LOW_ALIAS_BASE &&
        address < EDGE_MMIO_LOW_ALIAS_BASE + EDGE_MMIO_LOW_ALIAS_SIZE) {
        return address - EDGE_MMIO_LOW_ALIAS_BASE;
    }
    return address;
}

static uint64_t *fixed_user_pt_ptr_from_phys(uint64_t physical) {
    int pt_idx = sparse_mmap_backing_index_from_phys(
        physical & ~(USER_PAGE_SIZE - 1ULL));
    if (pt_idx < 0 ||
        !bitmap_test_idx(g_user_mmap_backing_used,
                         g_user_mmap_backing_ready_pages,
                         (uint32_t)pt_idx) ||
        !bitmap_test_idx(g_user_mmap_pt_used,
                         g_user_mmap_backing_ready_pages,
                         (uint32_t)pt_idx)) {
        return 0;
    }
    return (uint64_t *)sparse_mmap_backing_ptr(pt_idx);
}

static void process_user_heap_release_for_idx(int idx);
static int process_user_heap_clone(task_t *dst, const task_t *src);
static uint8_t *process_user_heap_byte_ptr(task_t *t, uint64_t addr, int write);
static int process_user_heap_handle_fault(task_t *t, uint64_t addr, int write);
static int process_user_heap_unmap_range(task_t *t, uint64_t start, uint64_t len);
static edge_user_vma_t *process_user_vma_for_addr(task_t *mm, uint64_t addr);

static uint64_t *fixed_user_pt_alloc(int idx, const char *name, uint32_t slot) {
    int pt_idx = sparse_mmap_alloc_backing_index_local();
    uint64_t *pt;
    if (pt_idx < 0) {
        printf("[fixed-pt] OOM idx=%d window=%s slot=%u pt=%u backing=%u/%u\n",
               idx, name ? name : "?", slot,
               sparse_bitmap_count_used_local(
                   g_user_mmap_pt_used,
                   g_user_mmap_backing_ready_pages),
               sparse_bitmap_count_used_local(
                   g_user_mmap_backing_used,
                   g_user_mmap_backing_ready_pages),
               g_user_mmap_backing_ready_pages);
        return 0;
    }
    pt = (uint64_t *)sparse_mmap_backing_ptr(pt_idx);
    if (!pt) {
        sparse_mmap_release_backing_index_local(pt_idx);
        return 0;
    }
    bitmap_set_idx(g_user_mmap_pt_used,
                   g_user_mmap_backing_ready_pages,
                   (uint32_t)pt_idx);
    return pt;
}

static void fixed_user_pt_release_ptr(uint64_t **ptp) {
    int pt_idx;
    if (!ptp || !*ptp) return;
    pt_idx = fixed_user_pt_pool_index_from_ptr(*ptp);
    if (pt_idx >= 0 &&
        (uint32_t)pt_idx < g_user_mmap_backing_ready_pages &&
        bitmap_test_idx(g_user_mmap_pt_used,
                        g_user_mmap_backing_ready_pages,
                        (uint32_t)pt_idx)) {
        memset(*ptp, 0, USER_PAGE_SIZE);
        bitmap_clear_idx(g_user_mmap_pt_used,
                         g_user_mmap_backing_ready_pages,
                         (uint32_t)pt_idx);
        sparse_mmap_release_backing_index_local(pt_idx);
    }
    *ptp = 0;
}

static void fixed_user_pt_release_for_idx(int idx) {
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    for (uint32_t p = 0; p < USER_LOW_PDE_CNT; ++p)
        fixed_user_pt_release_ptr(&g_user_low_pt[idx][p]);
    fixed_user_pt_release_ptr(&g_user_text_pt[idx]);
    fixed_user_pt_release_ptr(&g_user_stack_pt[idx]);
    process_user_heap_release_for_idx(idx);
    for (uint32_t p = 0; p < USER_BIGPIE_PDE_CNT; ++p) {
        fixed_user_pt_release_ptr(&g_user_bigpie_pt[idx][p]);
    }
}

static int fixed_user_pt_ensure_for_idx(int idx) {
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    if (!g_user_text_pt[idx]) {
        g_user_text_pt[idx] = fixed_user_pt_alloc(idx, "text", 0);
        if (!g_user_text_pt[idx]) return -1;
    }
    if (!g_user_stack_pt[idx]) {
        g_user_stack_pt[idx] = fixed_user_pt_alloc(idx, "stack", 0);
        if (!g_user_stack_pt[idx]) return -1;
    }
    return 0;
}

static uint64_t page_align_down_local(uint64_t v) {
    return v & ~(USER_PAGE_SIZE - 1ULL);
}

static uint64_t page_align_up_local(uint64_t v) {
    return (v + USER_PAGE_SIZE - 1ULL) & ~(USER_PAGE_SIZE - 1ULL);
}

static uint64_t *fixed_user_pd_for_va(int idx, uint64_t va) {
    uint32_t pdpt_idx;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    pdpt_idx = (uint32_t)((va >> 30) & 0x1FFu);
    if (pdpt_idx >= USER_LOW_PDPT_COUNT) return 0;
    return &g_pd[idx][pdpt_idx][0];
}

static uint64_t fixed_user_zero_phys(void) {
    return (uint64_t)(uintptr_t)&g_user_fixed_zero_page[0];
}

static uint64_t fixed_user_zero_entry(void) {
    /* PAGE_COW means logically writable but physically shared with zero-page. */
    return fixed_user_zero_phys() | PAGE_PRESENT | PAGE_USER | PAGE_COW;
}

static void fixed_user_fill_zero_entries(uint64_t *pt) {
    uint64_t zero_entry;
    if (!pt) return;
    zero_entry = fixed_user_zero_entry();
    for (uint32_t i = 0; i < 512; ++i) {
        if ((pt[i] & PAGE_PRESENT) == 0) pt[i] = zero_entry;
    }
}

static uint64_t *fixed_user_low_pt_ensure(int idx, uint32_t page) {
    uint64_t *pt;
    uint64_t *pd;
    uint64_t va;
    uint32_t pde;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS || page >= USER_LOW_PDE_CNT)
        return 0;
    pt = g_user_low_pt[idx][page];
    if (pt) return pt;
    pt = fixed_user_pt_alloc(idx, "low-exec", page);
    if (!pt) return 0;
    va = USER_LOW_BASE + ((uint64_t)page << 21);
    pd = fixed_user_pd_for_va(idx, va);
    if (!pd) {
        fixed_user_pt_release_ptr(&pt);
        return 0;
    }
    g_user_low_pt[idx][page] = pt;
    pde = (uint32_t)((va >> 21) & 0x1ffu);
    pd[pde] = fixed_user_pt_phys_from_ptr(pt) |
              PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    invlpg_local(va);
    return pt;
}

static uint64_t *fixed_user_bigpie_pt_ensure(int idx, uint32_t page) {
    uint64_t *pt;
    uint64_t *pd;
    uint64_t va;
    uint32_t pde;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS || page >= USER_BIGPIE_PDE_CNT)
        return 0;
    pt = g_user_bigpie_pt[idx][page];
    if (pt) return pt;
    pt = fixed_user_pt_alloc(idx, "bigpie", page);
    if (!pt) return 0;
    va = USER_BIGPIE_BASE + ((uint64_t)page << 21);
    pd = fixed_user_pd_for_va(idx, va);
    if (!pd) {
        fixed_user_pt_release_ptr(&pt);
        return 0;
    }
    g_user_bigpie_pt[idx][page] = pt;
    pde = (uint32_t)((va >> 21) & 0x1ffu);
    pd[pde] = fixed_user_pt_phys_from_ptr(pt) |
              PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    invlpg_local(va);
    return pt;
}

static void map_user_low_window_pte(int idx) {
    uint64_t pde_flags = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    for (uint32_t p = 0; p < USER_LOW_PDE_CNT; ++p) {
        uint64_t va = USER_LOW_BASE + ((uint64_t)p << 21);
        uint64_t *pd = fixed_user_pd_for_va(idx, va);
        uint32_t pde = (uint32_t)((va >> 21) & 0x1FF);
        uint64_t *pt = g_user_low_pt[idx][p];
        if (!pt) continue;
        if (!pd) return;
        pd[pde] = fixed_user_pt_phys_from_ptr(pt) | pde_flags;
    }
}

static void map_user_text_window_pte(int idx) {
    uint64_t pde_flags = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    uint64_t *pd;
    uint32_t pde;
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    if (!g_user_text_pt[idx]) return;
    pd = fixed_user_pd_for_va(idx, USER_TEXT_BASE);
    if (!pd) return;
    pde = (uint32_t)((USER_TEXT_BASE >> 21) & 0x1FF);
    pd[pde] = fixed_user_pt_phys_from_ptr(g_user_text_pt[idx]) |
              pde_flags;
}

static void map_user_stack_window_pte(int idx) {
    uint64_t pde_flags = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    uint64_t *pd;
    uint32_t pde;
    if (idx < 0 || idx >= USER_AS_MAX_TASKS || !g_user_stack_pt[idx]) return;
    pd = fixed_user_pd_for_va(idx, USER_STACK_BASE);
    if (!pd) return;
    pde = (uint32_t)((USER_STACK_BASE >> 21) & 0x1FF);
    pd[pde] = fixed_user_pt_phys_from_ptr(g_user_stack_pt[idx]) |
              pde_flags;
    fixed_user_fill_zero_entries(g_user_stack_pt[idx]);
}

static void map_user_bigpie_window_pte(int idx) {
    uint64_t pde_flags = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    for (uint32_t p = 0; p < USER_BIGPIE_PDE_CNT; ++p) {
        uint64_t va = USER_BIGPIE_BASE + ((uint64_t)p << 21);
        uint64_t *pd = fixed_user_pd_for_va(idx, va);
        uint32_t pde = (uint32_t)((va >> 21) & 0x1FF);
        if (!pd) return;
        if (!g_user_bigpie_pt[idx][p]) continue;
        pd[pde] = fixed_user_pt_phys_from_ptr(g_user_bigpie_pt[idx][p]) |
                  pde_flags;
    }
}

static int restore_user_low_window_roots(int idx) {
    uint64_t pde_flags = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    int changed = 0;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    for (uint32_t p = 0; p < USER_LOW_PDE_CNT; ++p) {
        uint64_t va = USER_LOW_BASE + ((uint64_t)p << 21);
        uint64_t *pd = fixed_user_pd_for_va(idx, va);
        uint32_t pde = (uint32_t)((va >> 21) & 0x1FF);
        uint64_t expected;
        uint64_t *pt = g_user_low_pt[idx][p];

        if (!pt) continue;
        if (!pd) continue;
        expected = fixed_user_pt_phys_from_ptr(pt) | pde_flags;
        if (pd[pde] == expected) continue;
        pd[pde] = expected;
        changed = 1;
    }
    return changed;
}

static int restore_user_text_window_root(int idx) {
    uint64_t *pd;
    uint32_t pde;
    uint64_t expected;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS || !g_user_text_pt[idx])
        return 0;
    pd = fixed_user_pd_for_va(idx, USER_TEXT_BASE);
    if (!pd) return 0;
    pde = (uint32_t)((USER_TEXT_BASE >> 21) & 0x1FF);
    expected = fixed_user_pt_phys_from_ptr(g_user_text_pt[idx]) |
               PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    if (pd[pde] == expected) return 0;
    pd[pde] = expected;
    return 1;
}

static int restore_user_stack_window_root(int idx) {
    uint64_t *pd;
    uint32_t pde;
    uint64_t expected;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS || !g_user_stack_pt[idx])
        return 0;
    pd = fixed_user_pd_for_va(idx, USER_STACK_BASE);
    if (!pd) return 0;
    pde = (uint32_t)((USER_STACK_BASE >> 21) & 0x1FF);
    expected = fixed_user_pt_phys_from_ptr(g_user_stack_pt[idx]) |
               PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    if (pd[pde] == expected) return 0;
    pd[pde] = expected;
    return 1;
}

static int restore_user_bigpie_window_roots(int idx) {
    uint64_t pde_flags = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    int changed = 0;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    for (uint32_t p = 0; p < USER_BIGPIE_PDE_CNT; ++p) {
        uint64_t va;
        uint64_t *pd;
        uint32_t pde;
        uint64_t expected;

        if (!g_user_bigpie_pt[idx][p]) continue;
        va = USER_BIGPIE_BASE + ((uint64_t)p << 21);
        pd = fixed_user_pd_for_va(idx, va);
        if (!pd) continue;
        pde = (uint32_t)((va >> 21) & 0x1FF);
        expected = fixed_user_pt_phys_from_ptr(g_user_bigpie_pt[idx][p]) |
                   pde_flags;
        if (pd[pde] == expected) continue;
        pd[pde] = expected;
        changed = 1;
    }
    return changed;
}

static uint64_t *fixed_user_pte_for_addr_idx(int idx, uint64_t addr) {
    uint32_t pte = (uint32_t)((addr >> 12) & 0x1FFu);

    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    if (addr < USER_LOW_LIMIT) {
        uint32_t page = (uint32_t)((addr - USER_LOW_BASE) >> 21);
        uint64_t *pt;
        if (page >= USER_LOW_PDE_CNT) return 0;
        pt = g_user_low_pt[idx][page];
        return pt ? &pt[pte] : 0;
    }
    if (addr >= USER_TEXT_BASE && addr < USER_TEXT_BASE + USER_REGION_SIZE) {
        return g_user_text_pt[idx] ? &g_user_text_pt[idx][pte] : 0;
    }
    if (addr >= USER_STACK_BASE && addr < USER_STACK_BASE + USER_REGION_SIZE) {
        return g_user_stack_pt[idx] ? &g_user_stack_pt[idx][pte] : 0;
    }
    if (addr >= USER_BIGPIE_BASE && addr < USER_BIGPIE_BASE + USER_BIGPIE_SIZE) {
        uint32_t page = (uint32_t)((addr - USER_BIGPIE_BASE) >> 21);
        if (page >= USER_BIGPIE_PDE_CNT || !g_user_bigpie_pt[idx][page]) return 0;
        return &g_user_bigpie_pt[idx][page][pte];
    }
    return 0;
}

static int fixed_user_addr(uint64_t addr) {
    return (addr < USER_LOW_LIMIT) ||
           (addr >= USER_TEXT_BASE && addr < USER_TEXT_BASE + USER_REGION_SIZE) ||
           (addr >= USER_STACK_BASE && addr < USER_STACK_BASE + USER_REGION_SIZE) ||
           (addr >= USER_BIGPIE_BASE && addr < USER_BIGPIE_BASE + USER_BIGPIE_SIZE);
}

static void fixed_user_release_pt_data(uint64_t *pt) {
    if (!pt) return;
    for (uint32_t i = 0; i < 512; ++i) {
        uint64_t entry = pt[i];
        int backing_idx;
        if ((entry & PAGE_PRESENT) == 0) continue;
        backing_idx = sparse_mmap_backing_index_from_phys(entry & ~0xFFFULL);
        pt[i] = 0;
        if (backing_idx >= 0) {
            sparse_mmap_user_alias_release(backing_idx);
            sparse_mmap_release_backing_index_local(backing_idx);
        }
    }
}

static void fixed_user_release_data_for_idx(int idx) {
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    for (uint32_t page = 0; page < USER_LOW_PDE_CNT; ++page)
        fixed_user_release_pt_data(g_user_low_pt[idx][page]);
    fixed_user_release_pt_data(g_user_text_pt[idx]);
    fixed_user_release_pt_data(g_user_stack_pt[idx]);
    for (uint32_t page = 0; page < USER_BIGPIE_PDE_CNT; ++page)
        fixed_user_release_pt_data(g_user_bigpie_pt[idx][page]);
}

static int private_pte_resolve_cow(task_t *mm, uint64_t addr,
                                   uint64_t *entryp) {
    uint64_t entry;
    uint64_t old_phys;
    int old_backing_idx;

    if (!mm || !entryp) return 0;
    entry = *entryp;
    if ((entry & (PAGE_PRESENT | PAGE_USER | PAGE_COW)) !=
        (PAGE_PRESENT | PAGE_USER | PAGE_COW)) {
        return 0;
    }
    old_phys = entry & ~0xFFFULL;
    old_backing_idx = sparse_mmap_backing_index_from_phys(old_phys);

    if (old_backing_idx >= 0 &&
        sparse_mmap_backing_refcnt_local(old_backing_idx) == 1) {
        *entryp = (entry & ~PAGE_COW) | PAGE_WRITE;
    } else {
        int new_backing_idx = sparse_mmap_alloc_backing_index_mode_local(0);
        uint8_t *new_page;
        if (new_backing_idx < 0) return 0;
        new_page = sparse_mmap_backing_ptr(new_backing_idx);
        if (!new_page) {
            sparse_mmap_release_backing_index_local(new_backing_idx);
            return 0;
        }
        if (old_phys == fixed_user_zero_phys()) {
            memset(new_page, 0, USER_PAGE_SIZE);
        } else {
            uint8_t *old_page = old_backing_idx >= 0
                ? sparse_mmap_backing_ptr(old_backing_idx)
                : (uint8_t *)edge_mmio_low_alias(old_phys);
            if (!old_page) {
                sparse_mmap_release_backing_index_local(new_backing_idx);
                return 0;
            }
            memcpy(new_page, old_page, USER_PAGE_SIZE);
        }
        if (sparse_mmap_user_alias_acquire(mm, new_backing_idx) < 0) {
            sparse_mmap_release_backing_index_local(new_backing_idx);
            return 0;
        }
        *entryp = sparse_mmap_backing_phys(new_backing_idx) |
                  ((entry & 0xFFFULL) &
                   ~(PAGE_COW | PAGE_FILE_CACHE | PAGE_ACCESSED | PAGE_DIRTY)) |
                  PAGE_WRITE;
    }
    invlpg_local(page_align_down_local(addr));
    sparse_mmap_flush_task(mm);
    if (old_backing_idx >= 0 &&
        sparse_mmap_backing_phys(old_backing_idx) !=
            ((*entryp) & ~0xFFFULL)) {
        sparse_mmap_user_alias_release(old_backing_idx);
        sparse_mmap_release_backing_index_local(old_backing_idx);
    }
    return 1;
}

static int fixed_user_clone_pt_cow(task_t *dst, const task_t *src,
                                   uint64_t *dst_pt, uint64_t *src_pt) {
    if (!dst || !src || !dst_pt || !src_pt) return -1;
    for (uint32_t i = 0; i < 512; ++i) {
        uint64_t entry = src_pt[i];
        uint64_t shared;
        uint64_t phys;
        int backing_idx;
        if ((entry & PAGE_PRESENT) == 0) {
            dst_pt[i] = entry == PAGE_POISONED ? PAGE_POISONED : 0;
            continue;
        }
        if ((entry & PAGE_DEVICE) != 0) {
            dst_pt[i] = entry;
            continue;
        }
        phys = entry & ~0xFFFULL;
        backing_idx = sparse_mmap_backing_index_from_phys(phys);
        if (phys != fixed_user_zero_phys() && backing_idx < 0) return -1;
        if (backing_idx >= 0) {
            if (sparse_mmap_user_alias_acquire(dst, backing_idx) < 0)
                return -1;
            sparse_mmap_retain_backing_index_local(backing_idx);
        }
        shared = entry;
        if ((entry & PAGE_WRITE) != 0) {
            shared = (entry & ~PAGE_WRITE) | PAGE_COW;
            src_pt[i] = shared;
        }
        dst_pt[i] = shared;
    }
    return 0;
}

static int fixed_user_clone_cow(task_t *dst, task_t *src) {
    int dst_idx = task_index(dst);
    int src_idx = task_index(src);
    if (!dst || !src || dst_idx < 0 || src_idx < 0 ||
        dst_idx >= USER_AS_MAX_TASKS || src_idx >= USER_AS_MAX_TASKS) {
        return -1;
    }
    for (uint32_t page = 0; page < USER_LOW_PDE_CNT; ++page) {
        uint64_t *src_pt = g_user_low_pt[src_idx][page];
        uint64_t *dst_pt;
        if (!src_pt) continue;
        dst_pt = fixed_user_low_pt_ensure(dst_idx, page);
        if (!dst_pt) goto fail;
        if (fixed_user_clone_pt_cow(dst, src, dst_pt, src_pt) < 0)
            goto fail;
    }
    if (fixed_user_clone_pt_cow(dst, src, g_user_text_pt[dst_idx],
                               g_user_text_pt[src_idx]) < 0)
        goto fail;
    if (fixed_user_clone_pt_cow(dst, src, g_user_stack_pt[dst_idx],
                               g_user_stack_pt[src_idx]) < 0)
        goto fail;
    for (uint32_t page = 0; page < USER_BIGPIE_PDE_CNT; ++page) {
        uint64_t *src_pt = g_user_bigpie_pt[src_idx][page];
        uint64_t *dst_pt;
        if (!src_pt) continue;
        dst_pt = fixed_user_bigpie_pt_ensure(dst_idx, page);
        if (!dst_pt ||
            fixed_user_clone_pt_cow(dst, src, dst_pt, src_pt) < 0)
            goto fail;
    }
    return 0;

fail:
    return -1;
}

static uint64_t *fixed_user_pte_recover_idx(int idx, uint64_t addr) {
    uint64_t *pd;
    uint64_t *pt;
    uint32_t page;
    uint32_t pde;
    uint32_t pte;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS || !fixed_user_addr(addr)) {
        return 0;
    }
    pd = fixed_user_pd_for_va(idx, addr);
    if (!pd) return 0;
    pde = (uint32_t)((addr >> 21) & 0x1FFu);
    if ((pd[pde] & (PAGE_PRESENT | PAGE_USER)) !=
            (PAGE_PRESENT | PAGE_USER) ||
        (pd[pde] & PAGE_PS) != 0) {
        return 0;
    }
    pt = fixed_user_pt_ptr_from_phys(pd[pde]);
    if (!pt) return 0;

    if (addr < USER_LOW_LIMIT) {
        page = (uint32_t)((addr - USER_LOW_BASE) >> 21);
        if (page >= USER_LOW_PDE_CNT) return 0;
        g_user_low_pt[idx][page] = pt;
    } else if (addr >= USER_TEXT_BASE &&
               addr < USER_TEXT_BASE + USER_REGION_SIZE) {
        g_user_text_pt[idx] = pt;
    } else if (addr >= USER_STACK_BASE &&
               addr < USER_STACK_BASE + USER_REGION_SIZE) {
        g_user_stack_pt[idx] = pt;
    } else if (addr >= USER_BIGPIE_BASE &&
               addr < USER_BIGPIE_BASE + USER_BIGPIE_SIZE) {
        page = (uint32_t)((addr - USER_BIGPIE_BASE) >> 21);
        if (page >= USER_BIGPIE_PDE_CNT) return 0;
        g_user_bigpie_pt[idx][page] = pt;
    } else {
        return 0;
    }

    /*
     * The hardware root is authoritative while this mm is live.  Reattach
     * bookkeeping if a reused task slot temporarily lost a fixed-window
     * pointer; allocating a replacement table here would discard live pages
     * that are still reachable through the process CR3.
     */
    pte = (uint32_t)((addr >> 12) & 0x1FFu);
    return &pt[pte];
}

static int process_user_fixed_handle_fault(task_t *t, uint64_t addr, int write) {
    task_t *mm;
    edge_user_vma_t *v;
    uint64_t *entryp;
    uint64_t entry;
    int idx;
    if (!t || !fixed_user_addr(addr)) return 0;
    mm = task_vm_owner_local(t);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    entryp = fixed_user_pte_for_addr_idx(idx, addr);
    if (!entryp)
        entryp = fixed_user_pte_recover_idx(idx, addr);
    if (!entryp) return 0;
    entry = *entryp;
    if ((entry & (PAGE_PRESENT | PAGE_USER)) != (PAGE_PRESENT | PAGE_USER)) {
        /*
         * The fixed main-stack window is an implicit VMA.  A fork child can
         * legitimately fault an untouched stack page after its page tables
         * have been cloned, so recover the page with the same demand-zero COW
         * entry used when the address space is created.  Requiring an explicit
         * VMA here incorrectly turns a valid stack access into SIGSEGV.
         */
        if (addr >= USER_STACK_BASE &&
            addr < USER_STACK_BASE + USER_REGION_SIZE) {
            *entryp = fixed_user_zero_entry();
            if (write)
                return private_pte_resolve_cow(mm, addr, entryp);
            invlpg_local(page_align_down_local(addr));
            return 1;
        }
        v = process_user_vma_for_addr(mm, addr);
        if (!v || !v->file_backed) return 0;
        return user_mmap_populate_file_page(
                   mm, v, page_align_down_local(addr), write) == 0;
    }
    if (write) {
        if ((entry & PAGE_COW) != 0)
            return private_pte_resolve_cow(mm, addr, entryp);
        if ((entry & PAGE_WRITE) == 0) return 0;
    }
    invlpg_local(page_align_down_local(addr));
    return 1;
}

static void clear_user_fbdev_window_pte(int idx) {
    if (idx >= 0 && idx < USER_AS_MAX_TASKS) {
        memset(g_user_fbdev_pt[idx], 0, sizeof(g_user_fbdev_pt[idx]));
    }
}

static void map_user_fbdev_window_pte(int idx) {
    /*
     * Linux exposes framebuffer memory only through an mmap VMA on /dev/fb0.
     * Do not preinstall a fixed user alias in every address space: that creates
     * writable device memory outside any VMA and can collide with ordinary
     * Linux mappings.  /dev/fb0 faults are installed lazily in
     * process_user_fbdev_handle_fault().
     *
     * Red flag: the syscall return policy uses this hook after operations that
     * can change Linux ABI mappings.  It must not clear g_user_fbdev_pt[] here;
     * doing so tears down live fbdev PTEs while Xorg is drawing and turns
     * otherwise-valid framebuffer stores into stale/black scanout.  New address
     * spaces clear the table explicitly through clear_user_fbdev_window_pte().
     */
    (void)idx;
}

static int process_user_idx_has_fbdev_mapping(int idx) {
    task_t *t;
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    t = &g_tasks[idx];
    if (t->state == TASK_UNUSED || t->state == TASK_ZOMBIE || t->vm_owner_pid != t->pid) return 0;
    return g_user_fbdev_owner_active[idx] != 0;
}

static int process_user_any_fbdev_mapping(void) {
    for (int idx = 0; idx < USER_AS_MAX_TASKS; ++idx) {
        if (process_user_idx_has_fbdev_mapping(idx)) return 1;
    }
    return 0;
}

static int process_user_vma_is_fbdev(const edge_user_vma_t *v) {
    const char *path;
    if (!v || v->end <= v->start || !v->file_backed) return 0;
    path = process_user_mmap_file_path_for_slot(v->file_slot);
    return path && strcmp(path, "/dev/fb0") == 0;
}

void process_user_fbdev_owner_set(task_t *t, int active) {
    task_t *mm;
    int idx;
    if (!t) return;
    mm = task_vm_owner_local(t);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    g_user_fbdev_owner_active[idx] = active ? 1u : 0u;
}

void process_user_fbdev_owner_refresh(task_t *t) {
    task_t *mm;
    int idx;
    int active = 0;
    int live;
    static int fbdev_owner_log_budget =
        EDGE_GUI_DEEP_TRACE ? 12 : 0;

    if (!t) return;
    mm = task_vm_owner_local(t);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    live = process_user_vma_live_count(mm);
    for (int i = 0; i < live; ++i) {
        if (process_user_vma_is_fbdev(&mm->user_vmas[i])) {
            active = 1;
            break;
        }
    }
    if ((g_user_fbdev_owner_active[idx] != 0) != active && fbdev_owner_log_budget > 0) {
        printf("[fb-owner] idx=%d pid=%d cmd=%s active=%d vmas=%d budget=%d\n",
               idx, mm->pid, mm->name[0] ? mm->name : "?",
               active, live, fbdev_owner_log_budget - 1);
        fbdev_owner_log_budget--;
    }
    g_user_fbdev_owner_active[idx] = active ? 1u : 0u;
}

static edge_user_vma_t *process_user_vma_for_addr(task_t *mm, uint64_t addr);
static int sparse_mmap_indices(uint64_t va, uint32_t *pdpt_idx_out, uint32_t *pde_idx_out, uint32_t *pte_idx_out);
static int sparse_mmap_ensure_pt(task_t *t, uint64_t va, uint64_t **pt_out);
static void sparse_mmap_flush_task(task_t *t);

static int process_user_fbdev_visible_range(const edge_user_vma_t *v,
                                            uint64_t page, uint64_t *off_out,
                                            uint64_t *len_out,
                                            uint64_t *phys_page_off_out) {
    uint64_t fb_phys = 0;
    uint64_t fb_off = 0;
    uint32_t fb_pages = 0;
    uint64_t fb_bytes;
    uint64_t fb_page_off;
    uint64_t map_off;
    uint64_t phys_window_off;
    uint64_t visible_start;
    uint64_t visible_len = USER_PAGE_SIZE;

    if (!v || page < v->start || page >= v->end) return 0;
    if (!fb.addr || fb.pitch == 0 || fb.height == 0) return 0;
    if (!fb_get_2m_phys_window(&fb_phys, &fb_pages, &fb_off)) return 0;
    (void)fb_phys;
    if (fb_pages == 0) return 0;
    fb_bytes = (uint64_t)fb.pitch * (uint64_t)fb.height;
    fb_page_off = fb_off & ~(USER_PAGE_SIZE - 1ULL);
    if (page - v->start > UINT64_MAX - v->file_off) return 0;
    map_off = v->file_off + (page - v->start);
    if (fb_page_off > UINT64_MAX - map_off) return 0;
    phys_window_off = fb_page_off + map_off;
    if (phys_window_off >= ((uint64_t)fb_pages << 21)) return 0;
    if (phys_page_off_out) *phys_page_off_out = phys_window_off;
    if (phys_window_off + visible_len <= fb_off) return 0;
    if (phys_window_off < fb_off) {
        uint64_t prefix = fb_off - phys_window_off;
        if (prefix >= visible_len) return 0;
        visible_len -= prefix;
        visible_start = 0;
    } else {
        visible_start = phys_window_off - fb_off;
    }
    if (visible_start >= fb_bytes) return 0;
    if (visible_len > fb_bytes - visible_start) visible_len = fb_bytes - visible_start;
    if (visible_len == 0) return 0;
    if (off_out) *off_out = visible_start;
    if (len_out) *len_out = visible_len;
    return 1;
}

int process_user_fbdev_install_vma(task_t *t, uint64_t start, uint64_t len) {
    task_t *mm;
    int idx;
    uint64_t end;
    uint64_t fb_phys = 0;
    uint64_t fb_off = 0;
    uint32_t fb_pages = 0;
    uint64_t pte_flags = PAGE_PRESENT | PAGE_USER;
    uint32_t mapped = 0;
    static int fbdev_install_log_budget =
        EDGE_GUI_DEEP_TRACE ? 16 : 0;

    if (!t || len == 0) return -1;
    mm = task_vm_owner_local(t);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    if (!fb_get_2m_phys_window(&fb_phys, &fb_pages, &fb_off)) return -1;
    if (fb_pages > USER_FBDEV_MAX_PAGES) fb_pages = USER_FBDEV_MAX_PAGES;
    if (fb_pages == 0) return -1;

    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end <= start) return -1;

    /*
     * Linux fbdev drivers normally install the whole device VMA during mmap
     * with remap_pfn_range-style PTEs.  Xorg's ShadowFB then writes the full
     * screen as normal memory.  Faulting each 4 KiB framebuffer page one by
     * one is observably non-Linux: a desktop-size repaint can spend thousands
     * of synchronous kernel faults before xfdesktop/panel have enough CPU to
     * start.  Install every visible fbdev page up front, but leave leaf PTEs
     * read-only until the first store.  That first write fault is EdgeOS'
     * equivalent of Linux fb_deferred_io page_mkwrite: it records framebuffer
     * damage and then grants write access until the next present re-arms the
     * mapping.
     *
     * Red flag: keep this generic to /dev/fb0 VMAs.  Do not key it on Xorg,
     * XFCE, Alpine, DISPLAY, or helper scripts.
     */
    for (uint64_t va = start; va < end; va += USER_PAGE_SIZE) {
        const edge_user_vma_t *v = process_user_vma_for_addr(mm, va);
        uint64_t window_off = 0;
        uint64_t visible_rel = 0;
        uint64_t visible_len = 0;
        uint64_t pte;

        if (!process_user_vma_is_fbdev(v)) continue;
        if (!process_user_fbdev_visible_range(v, va, &visible_rel, &visible_len, &window_off)) continue;
        (void)visible_rel;
        (void)visible_len;
        pte = (fb_phys + window_off) | pte_flags;

        if (va >= USER_FBDEV_BASE &&
            va < USER_FBDEV_BASE + ((uint64_t)fb_pages << 21)) {
            uint64_t rel = va - USER_FBDEV_BASE;
            uint32_t pde_page = (uint32_t)(rel >> 21);
            uint32_t pdpt_idx = (uint32_t)((va >> 30) & 0x1FFu);
            uint32_t pde_idx = (uint32_t)((va >> 21) & 0x1FFu);
            uint32_t pte_idx = (uint32_t)((va >> 12) & 0x1FFu);
            if (pde_page >= fb_pages || pde_page >= USER_FBDEV_MAX_PAGES ||
                pdpt_idx >= USER_LOW_PDPT_COUNT || pde_idx >= 512) {
                return -1;
            }
            g_pd[idx][pdpt_idx][pde_idx] =
                ((uint64_t)(uintptr_t)&g_user_fbdev_pt[idx][pde_page][0]) |
                PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
            g_user_fbdev_pt[idx][pde_page][pte_idx] = pte;
        } else {
            uint64_t *pt = 0;
            uint32_t pte_idx = 0;
            if (sparse_mmap_ensure_pt(mm, va, &pt) < 0 ||
                sparse_mmap_indices(va, 0, 0, &pte_idx) < 0) {
                return -1;
            }
            pt[pte_idx] = pte;
        }
        mapped++;
    }

    process_user_fbdev_owner_set(mm, mapped != 0);
    if (mapped != 0) sparse_mmap_flush_task(mm);
    if (mapped != 0 && fbdev_install_log_budget > 0) {
        printf("[fb-install] pid=%d cmd=%s start=0x%x len=0x%x pages=%u fb_pages=%u budget=%d\n",
               mm->pid, mm->name[0] ? mm->name : "?",
               (uint32_t)start, (uint32_t)(end - start), mapped, fb_pages,
               fbdev_install_log_budget - 1);
        fbdev_install_log_budget--;
    }
    return mapped != 0 ? 0 : -1;
}

#ifndef MULTIBOOT2_BOOTLOADER_MAGIC
#define MULTIBOOT2_BOOTLOADER_MAGIC 0x36d76289u
#endif

struct edge_mb2_tag {
    uint32_t type;
    uint32_t size;
};

struct edge_mb2_tag_mmap {
    struct edge_mb2_tag tag;
    uint32_t entry_size;
    uint32_t entry_version;
    uint8_t entries[];
};

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint64_t len;
    uint32_t type;
    uint32_t zero;
} edge_mb2_mmap_entry_t;

static int range_overlaps_local(uint64_t a_start, uint64_t a_len, uint64_t b_start, uint64_t b_len) {
    uint64_t a_end = a_start + a_len;
    uint64_t b_end = b_start + b_len;
    if (a_end < a_start || b_end < b_start) return 1;
    return a_start < b_end && b_start < a_end;
}

static uint64_t kernel_symbol_phys_local(const char *sym) {
    uint64_t addr = (uint64_t)(uintptr_t)sym;
    /*
     * EdgeOS is linked at a low multiboot physical address, but some boot/page
     * table arrangements can expose linker symbols through a high/direct
     * mapping while firmware memory maps are always physical.  Sparse mmap
     * backing pages must never overlap the loaded kernel image or static kernel
     * data; normalize symbols to the low physical address used by GRUB before
     * comparing against multiboot ranges.
     */
    if (addr > 0xFFFFFFFFULL) addr &= 0xFFFFFFFFULL;
    return addr;
}

static void mmap_backing_reserve_boot_range(uint64_t start, uint64_t len) {
    uint64_t end;
    if (len == 0 || g_mmap_boot_reserved_count >= EDGE_MMAP_BOOT_RESERVED_MAX) return;
    end = start + len;
    if (end < start) end = UINT64_MAX;
    start = page_align_down_local(start);
    end = page_align_up_local(end);
    if (end <= start) return;
    g_mmap_boot_reserved[g_mmap_boot_reserved_count].start = start;
    g_mmap_boot_reserved[g_mmap_boot_reserved_count].end = end;
    g_mmap_boot_reserved_count++;
}

static int mmap_backing_phys_conflicts_with_boot_reserved(uint64_t phys) {
    for (uint32_t i = 0; i < g_mmap_boot_reserved_count; ++i) {
        if (phys < g_mmap_boot_reserved[i].end &&
            phys + USER_PAGE_SIZE > g_mmap_boot_reserved[i].start) {
            return 1;
        }
    }
    return 0;
}

static int mmap_backing_phys_reserved(uint64_t phys) {
    uint64_t kstart = page_align_down_local(kernel_symbol_phys_local(&_kernel_start));
    uint64_t kend = page_align_up_local(kernel_symbol_phys_local(&_kernel_end));
    uint64_t fb_phys = 0;
    uint64_t fb_offset = 0;
    uint32_t fb_pages = 0;

    if (phys < 0x100000ULL) return 1;
    /*
     * Backing PTEs contain physical addresses, while every kernel-side access
     * goes through edge_mmio_low_alias().  Consequently a physical page may
     * have the same numeric address as a process VMA without aliasing that VMA.
     * Older code rejected those pages and discarded most RAM in a 4 GiB guest,
     * eventually killing a normal XFCE session with sparse-backing ENOMEM.
     *
     * Keep the real safety boundary explicit: pages admitted here must fit in
     * the supervisor-only direct-map aperture installed in every process CR3.
     * Never fall back to an identity pointer for runtime backing memory.
     */
    if (phys > EDGE_MMIO_LOW_ALIAS_SIZE - USER_PAGE_SIZE) return 1;
    /*
     * The current kernel image reserves a very large low physical span for
     * fixed per-address-space data.  Do not use "free" firmware pages below
     * _kernel_end as sparse mmap backing: on real boots those pages can still
     * alias the loaded kernel/static data layout, and any aliasing corrupts
     * executable user mappings with unrelated kernel/input bytes.
     */
    if (kend > kstart && phys < kend) return 1;
    if (mmap_backing_phys_conflicts_with_boot_reserved(phys)) return 1;

    /*
     * Multiboot memory maps normally exclude PCI/MMIO, but the virtio-gpu
     * framebuffer sits close enough to the old static .bss failure that keeping
     * an explicit guard here makes the allocator self-documenting.
     */
    if (fb_get_2m_phys_window(&fb_phys, &fb_pages, &fb_offset) && fb_pages > 0) {
        uint64_t fb_len = ((uint64_t)fb_pages << 21);
        if (range_overlaps_local(phys, USER_PAGE_SIZE, fb_phys, fb_len)) return 1;
    }
    return 0;
}

static void mmap_backing_swap_phys(uint32_t a, uint32_t b) {
    uint64_t tmp;
    if (a == b) return;
    tmp = g_user_mmap_backing_phys[a];
    g_user_mmap_backing_phys[a] = g_user_mmap_backing_phys[b];
    g_user_mmap_backing_phys[b] = tmp;
}

static void mmap_backing_sort_phys_range(int lo, int hi) {
    int i;
    int j;
    uint64_t pivot;
    if (lo >= hi) return;
    i = lo;
    j = hi;
    pivot = g_user_mmap_backing_phys[(lo + hi) / 2];
    while (i <= j) {
        while (g_user_mmap_backing_phys[i] < pivot) i++;
        while (g_user_mmap_backing_phys[j] > pivot) j--;
        if (i <= j) {
            mmap_backing_swap_phys((uint32_t)i, (uint32_t)j);
            i++;
            j--;
        }
    }
    if (lo < j) mmap_backing_sort_phys_range(lo, j);
    if (i < hi) mmap_backing_sort_phys_range(i, hi);
}

static void mmap_backing_sort_and_dedup(void) {
    uint32_t out = 0;
    uint32_t in;
    if (g_user_mmap_backing_ready_pages <= 1) return;
    mmap_backing_sort_phys_range(0, (int)g_user_mmap_backing_ready_pages - 1);
    for (in = 0; in < g_user_mmap_backing_ready_pages; ++in) {
        uint64_t phys = g_user_mmap_backing_phys[in];
        if (out > 0 && g_user_mmap_backing_phys[out - 1] == phys) continue;
        g_user_mmap_backing_phys[out++] = phys;
    }
    g_user_mmap_backing_ready_pages = out;
}

static void mmap_backing_validate_ready_list(const char *phase) {
    uint32_t unsorted = 0;
    uint32_t reserved = 0;
    uint32_t zero = 0;
    uint64_t first_bad = 0;
    uint64_t prev = 0;

    for (uint32_t i = 0; i < g_user_mmap_backing_ready_pages; ++i) {
        uint64_t phys = g_user_mmap_backing_phys[i];
        int bad = 0;
        if (phys == 0 || (phys & (USER_PAGE_SIZE - 1ULL)) != 0) {
            zero++;
            bad = 1;
        }
        if (i > 0 && phys <= prev) {
            unsorted++;
            bad = 1;
        }
        if (mmap_backing_phys_reserved(phys)) {
            reserved++;
            bad = 1;
        }
        if (bad && first_bad == 0) first_bad = phys;
        prev = phys;
    }

    if (unsorted || reserved || zero) {
        printf("[mmap-backing] ERROR validate phase=%s pages=%u unsorted=%u reserved=%u zero=%u first_bad=0x%llx first=0x%llx last=0x%llx\n",
               phase ? phase : "?",
               g_user_mmap_backing_ready_pages,
               unsorted,
               reserved,
               zero,
               (unsigned long long)first_bad,
               (unsigned long long)(g_user_mmap_backing_ready_pages ? g_user_mmap_backing_phys[0] : 0),
               (unsigned long long)(g_user_mmap_backing_ready_pages ? g_user_mmap_backing_phys[g_user_mmap_backing_ready_pages - 1] : 0));
    }
}

static int mmap_backing_carve_contiguous_tail_pages(uint32_t pages, uint64_t *base_out) {
    uint32_t end;
    if (base_out) *base_out = 0;
    if (pages == 0 || pages > g_user_mmap_backing_ready_pages) return -1;

    /*
     * Runtime mmap metadata must not live in .bss: desktop-sized process and
     * mapping tables already push the early kernel image near the bootstrap
     * relocation limit.  Carve a physically contiguous run from the sorted
     * backing list instead.  Removing the pages from g_user_mmap_backing_phys
     * is the reservation; userspace can never receive them as mmap backing.
     */
    end = g_user_mmap_backing_ready_pages;
    while (end > 0) {
        uint32_t start = end - 1;
        while (start > 0 &&
               g_user_mmap_backing_phys[start] == g_user_mmap_backing_phys[start - 1] + USER_PAGE_SIZE) {
            start--;
        }
        if (end - start >= pages) {
            uint32_t carve_start = end - pages;
            uint32_t tail_count = g_user_mmap_backing_ready_pages - end;
            uint64_t base = g_user_mmap_backing_phys[carve_start];
            if (tail_count > 0) {
                memmove(&g_user_mmap_backing_phys[carve_start],
                        &g_user_mmap_backing_phys[end],
                        tail_count * sizeof(g_user_mmap_backing_phys[0]));
            }
            g_user_mmap_backing_ready_pages -= pages;
            if (base_out) *base_out = base;
            return 0;
        }
        end = start;
    }
    return -1;
}

int process_kernel_runtime_reserve_pages(uint32_t pages, void **kva_out,
                                         uint64_t *phys_out) {
    uint64_t base = 0;
    void *kva;
    if (kva_out) *kva_out = 0;
    if (phys_out) *phys_out = 0;
    if (pages == 0) return -1;
    /*
     * Large kernel runtime tables must not live in .bss when their numeric
     * virtual addresses can overlap fixed Linux userspace ABI windows.  Reserve
     * them from boot-reported usable RAM before sparse mmap pages are handed to
     * userspace.
     */
    if (mmap_backing_carve_contiguous_tail_pages(pages, &base) < 0 || base == 0) return -1;
    kva = (void *)edge_mmio_low_alias(base);
    if (!kva) return -1;
    if (kva_out) *kva_out = kva;
    if (phys_out) *phys_out = base;
    return 0;
}

int process_kernel_runtime_alloc_pages(uint32_t pages, void **kva_out,
                                       uint64_t *phys_out) {
    void *kva = 0;
    uint64_t physical = 0;

    if (kva_out) *kva_out = 0;
    if (phys_out) *phys_out = 0;
    if (process_kernel_runtime_reserve_pages(
            pages, &kva, &physical) < 0) {
        return -1;
    }
    memset(kva, 0, pages * (uint32_t)USER_PAGE_SIZE);
    if (kva_out) *kva_out = kva;
    if (phys_out) *phys_out = physical;
    return 0;
}

static int exec_payload_runtime_init(void) {
    uint64_t bytes = kernel_exec_payload_pool_bytes();
    uint32_t pages = (uint32_t)((bytes + USER_PAGE_SIZE - 1u) /
                                USER_PAGE_SIZE);
    uint64_t physical = 0;
    void *memory = 0;

    if (process_kernel_runtime_alloc_pages(pages, &memory, &physical) < 0 ||
        kernel_exec_payload_pool_initialize(
            memory, (uint64_t)pages * USER_PAGE_SIZE) < 0) {
        printf("[exec-payload] ERROR runtime pool unavailable pages=%u\n",
               pages);
        return -1;
    }
    printf("[exec-payload] runtime slots=%u pages=%u bytes=%u KiB phys=0x%llx kva=%p\n",
           KERNEL_EXEC_PAYLOAD_SLOT_COUNT, pages,
           (uint32_t)(bytes / 1024u),
           (unsigned long long)physical, memory);
    return 0;
}

static int exec_record_runtime_init(void) {
    uint64_t bytes = kernel_exec_record_pool_bytes(USER_AS_MAX_TASKS);
    uint32_t pages = (uint32_t)((bytes + USER_PAGE_SIZE - 1u) /
                                USER_PAGE_SIZE);
    uint64_t physical = 0;
    void *memory = 0;

    if (!bytes ||
        process_kernel_runtime_alloc_pages(pages, &memory, &physical) < 0 ||
        kernel_exec_record_pool_initialize(
            memory, (uint64_t)pages * USER_PAGE_SIZE,
            USER_AS_MAX_TASKS) < 0) {
        printf("[exec-record] ERROR runtime pool unavailable spaces=%u pages=%u\n",
               (uint32_t)USER_AS_MAX_TASKS, pages);
        return -1;
    }
    printf("[exec-record] runtime spaces=%u pages=%u bytes=%u KiB phys=0x%llx kva=%p\n",
           (uint32_t)USER_AS_MAX_TASKS, pages,
           (uint32_t)(bytes / 1024u),
           (unsigned long long)physical, memory);
    return 0;
}

static int task_scratch_runtime_init(void) {
    uint64_t bytes = kernel_task_scratch_pool_bytes(PROC_MAX_TASKS);
    uint32_t pages = (uint32_t)((bytes + USER_PAGE_SIZE - 1u) /
                                USER_PAGE_SIZE);
    uint64_t physical = 0;
    void *memory = 0;

    if (!bytes ||
        process_kernel_runtime_alloc_pages(pages, &memory, &physical) < 0 ||
        kernel_task_scratch_pool_initialize(
            memory, (uint64_t)pages * USER_PAGE_SIZE,
            PROC_MAX_TASKS) < 0) {
        printf("[task-scratch] ERROR runtime pool unavailable tasks=%u pages=%u\n",
               (uint32_t)PROC_MAX_TASKS, pages);
        return -1;
    }
    printf("[task-scratch] runtime tasks=%u pages=%u bytes=%u KiB phys=0x%llx kva=%p\n",
           (uint32_t)PROC_MAX_TASKS, pages,
           (uint32_t)(bytes / 1024u),
           (unsigned long long)physical, memory);
    return 0;
}

void process_exec_storage_reset(task_t *task) {
    if (!task) return;
    kernel_exec_record_reset(task->exec_record);
}

int process_exec_storage_append(task_t *task, const char *string,
                                char **stored_out) {
    if (!task || !task->exec_record) return -1;
    return kernel_exec_record_append(task->exec_record, string, 0,
                                     stored_out);
}

int process_exec_storage_contains(const task_t *task, const char *string) {
    return task && kernel_exec_record_contains(task->exec_record, string);
}

int process_exec_storage_budget_ok(const task_t *task, int argc, int envc) {
    if (!task || !task->exec_record || argc < 0 || envc < 0 ||
        (uint32_t)argc != task->exec_record->argc ||
        (uint32_t)envc != task->exec_record->envc)
        return 0;
    return kernel_exec_record_budget_ok(task->exec_record);
}

static int task_table_runtime_init(void) {
    uint64_t bytes = (uint64_t)PROC_MAX_TASKS * sizeof(g_tasks[0]);
    uint32_t pages = (uint32_t)((bytes + USER_PAGE_SIZE - 1ULL) / USER_PAGE_SIZE);
    uint64_t base = 0;

    g_tasks = 0;
    g_tasks_phys = 0;
    g_tasks_pages = 0;
    g_tasks_ready = 0;

    /*
     * task_t carries Linux process ABI state: fd tables, signal state, mmap
     * tables, groups, exec buffers, and scheduler context.  A desktop-sized task
     * table is therefore real kernel state, but it cannot live in .bss without
     * pushing the image beyond x86-64 kernel relocation limits.  Reserve it from
     * boot-reported usable RAM before any userspace task can exist.
     */
    if (mmap_backing_carve_contiguous_tail_pages(pages, &base) < 0 || base == 0) {
        printf("[task-table] ERROR runtime carve failed tasks=%u pages=%u ready=%u bytes=%u KiB\n",
               (uint32_t)PROC_MAX_TASKS,
               pages,
               g_user_mmap_backing_ready_pages,
               (uint32_t)(bytes / 1024ULL));
        return -1;
    }

    g_tasks_phys = base;
    g_tasks_pages = pages;
    g_tasks = (task_t *)edge_mmio_low_alias(base);
    memset(g_tasks, 0, (uint32_t)bytes);
    g_tasks_ready = 1;
    printf("[task-table] runtime tasks=%u pages=%u bytes=%u KiB phys=0x%llx kva=%p task_size=%u\n",
           (uint32_t)PROC_MAX_TASKS,
           g_tasks_pages,
           (uint32_t)(bytes / 1024ULL),
           (unsigned long long)g_tasks_phys,
           g_tasks,
           (uint32_t)sizeof(g_tasks[0]));
    return 0;
}

static int user_vma_runtime_init(void) {
    uint64_t bytes = kernel_mm_vma_pool_bytes(
        USER_AS_MAX_TASKS, KERNEL_MM_VMA_INITIAL_AREAS);
    uint32_t pages = (uint32_t)((bytes + USER_PAGE_SIZE - 1ULL) /
                                USER_PAGE_SIZE);
    uint64_t physical = 0;
    void *memory = 0;
    uint64_t lock_bytes = kernel_mm_lock_space_pool_bytes(
        USER_AS_MAX_TASKS);
    uint32_t lock_pages = (uint32_t)(
        (lock_bytes + USER_PAGE_SIZE - 1ULL) / USER_PAGE_SIZE);
    uint64_t lock_physical = 0;
    void *lock_memory = 0;

    g_user_vma_pool_phys = 0;
    g_user_vma_pool_pages = 0;
    if (!bytes ||
        process_kernel_runtime_alloc_pages(pages, &memory, &physical) < 0 ||
        kernel_mm_vma_pool_initialize(
            memory, (uint64_t)pages * USER_PAGE_SIZE,
            USER_AS_MAX_TASKS, KERNEL_MM_VMA_INITIAL_AREAS) < 0) {
        printf("[vma-pool] ERROR runtime pool unavailable spaces=%u pages=%u\n",
               (uint32_t)USER_AS_MAX_TASKS, pages);
        return -1;
    }
    g_user_vma_pool_phys = physical;
    g_user_vma_pool_pages = pages;
    if (!lock_bytes ||
        process_kernel_runtime_alloc_pages(
            lock_pages, &lock_memory, &lock_physical) < 0 ||
        kernel_mm_lock_space_pool_initialize(
            lock_memory, (uint64_t)lock_pages * USER_PAGE_SIZE,
            USER_AS_MAX_TASKS) < 0) {
        printf("[vma-pool] ERROR resident-lock metadata unavailable spaces=%u pages=%u\n",
               (uint32_t)USER_AS_MAX_TASKS, lock_pages);
        return -1;
    }
    printf("[vma-pool] runtime spaces=%u areas=%u pages=%u bytes=%u KiB phys=0x%llx kva=%p\n",
           (uint32_t)USER_AS_MAX_TASKS,
           (uint32_t)KERNEL_MM_VMA_INITIAL_AREAS,
           pages,
           (uint32_t)(bytes / 1024ULL),
           (unsigned long long)physical,
           memory);
    printf("[vma-pool] resident-lock spaces=%u pages=%u bytes=%u KiB phys=0x%llx kva=%p\n",
           (uint32_t)USER_AS_MAX_TASKS,
           lock_pages,
           (uint32_t)(lock_bytes / 1024ULL),
           (unsigned long long)lock_physical,
           lock_memory);
    return 0;
}

static int task_kstack_runtime_init(void) {
    uint64_t base = 0;
    uint64_t bytes = (uint64_t)EDGE_TASK_ONLY_KSTACK_PAGES * USER_PAGE_SIZE;

    g_kstack_task_only = 0;
    g_kstack_task_only_phys = 0;
    g_kstack_task_only_pages = 0;
    g_kstack_task_only_ready = 0;

    if (EDGE_TASK_ONLY_KSTACK_PAGES == 0) {
        g_kstack_task_only_ready = 1;
        return 0;
    }

    /*
     * A kernel stack must be contiguous in the kernel virtual address space.
     * EdgeOS' low-MMIO alias is linear over physical memory, so a physically
     * contiguous carve gives every task-only slot a real stack without adding a
     * huge .bss array that breaks desktop-scale task tables at link time.
     */
    if (mmap_backing_carve_contiguous_tail_pages(EDGE_TASK_ONLY_KSTACK_PAGES, &base) < 0 || base == 0) {
        printf("[task-kstack] ERROR runtime carve failed task_slots=%u pages=%u ready=%u\n",
               (uint32_t)EDGE_TASK_ONLY_SLOTS,
               EDGE_TASK_ONLY_KSTACK_PAGES,
               g_user_mmap_backing_ready_pages);
        return -1;
    }

    g_kstack_task_only_phys = base;
    g_kstack_task_only = (uint8_t *)edge_mmio_low_alias(base);
    g_kstack_task_only_pages = EDGE_TASK_ONLY_KSTACK_PAGES;
    memset(g_kstack_task_only, 0, (uint32_t)bytes);
    g_kstack_task_only_ready = 1;
    printf("[task-kstack] runtime slots=%u pages=%u bytes=%u KiB phys=0x%llx kva=%p\n",
           (uint32_t)EDGE_TASK_ONLY_SLOTS,
           g_kstack_task_only_pages,
           (uint32_t)(bytes / 1024ULL),
           (unsigned long long)g_kstack_task_only_phys,
           g_kstack_task_only);
    return 0;
}

static int fixed_user_backing_runtime_init(void) {
    memset(g_user_fixed_zero_page, 0, sizeof(g_user_fixed_zero_page));
    memset(g_user_low_pt, 0, sizeof(g_user_low_pt));
    memset(g_user_text_pt, 0, sizeof(g_user_text_pt));
    memset(g_user_stack_pt, 0, sizeof(g_user_stack_pt));
    memset(g_user_heap_pt, 0, sizeof(g_user_heap_pt));
    memset(g_user_bigpie_pt, 0, sizeof(g_user_bigpie_pt));

    /*
     * Linux does not reserve and zero the maximum fixed virtual window for
     * every process.  Map untouched fixed pages to one read-only zero page and
     * allocate a refcounted backing page on the first write.  This preserves
     * zero-fill, fork COW, and page-granular mprotect semantics while avoiding
     * the former 14 MiB reservation and first-use scrub per process slot.
     */
    printf("[fixed-backing] demand-zero slots=%u zero_phys=0x%llx reserved=0 MiB\n",
           (uint32_t)USER_AS_MAX_TASKS,
           (unsigned long long)fixed_user_zero_phys());
    return 0;
}

static int fixed_user_backing_prepare_for_idx(int idx) {
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    return 0;
}

static int mmap_backing_init_generation_table(void) {
    uint64_t bytes = (uint64_t)USER_SPARSE_MMAP_BACKING_PAGES * sizeof(uint32_t);
    uint32_t pages = (uint32_t)((bytes + USER_PAGE_SIZE - 1ULL) / USER_PAGE_SIZE);
    uint64_t base = 0;

    g_user_mmap_backing_generation = 0;
    g_user_mmap_backing_generation_phys = 0;
    g_user_mmap_backing_generation_entries = 0;
    g_user_mmap_backing_generation_pages = 0;
    if (mmap_backing_carve_contiguous_tail_pages(pages, &base) < 0 || base == 0) {
        printf("[mmap-backing] ERROR generation-table carve failed pages=%u ready=%u\n",
               pages, g_user_mmap_backing_ready_pages);
        return -1;
    }
    g_user_mmap_backing_generation_phys = base;
    g_user_mmap_backing_generation = (uint32_t *)edge_mmio_low_alias(base);
    g_user_mmap_backing_generation_entries = (uint32_t)USER_SPARSE_MMAP_BACKING_PAGES;
    g_user_mmap_backing_generation_pages = pages;
    memset(g_user_mmap_backing_generation, 0, (uint32_t)bytes);
    return 0;
}

static void mmap_backing_add_available_range(uint64_t addr, uint64_t len) {
    uint64_t start = page_align_up_local(addr);
    uint64_t end = page_align_down_local(addr + len);
    if (addr + len < addr || end <= start) return;

    for (uint64_t phys = start;
         phys + USER_PAGE_SIZE > phys && phys + USER_PAGE_SIZE <= end;
         phys += USER_PAGE_SIZE) {
        if (g_user_mmap_backing_ready_pages >= (uint32_t)USER_SPARSE_MMAP_BACKING_PAGES) return;
        if (mmap_backing_phys_reserved(phys)) continue;
        g_user_mmap_backing_phys[g_user_mmap_backing_ready_pages++] = phys;
    }
}

static void mmap_backing_reserve_boot_memory(uint32_t magic, void *mb_info) {
    if (!mb_info) return;

    if (magic == MULTIBOOT_BOOTLOADER_MAGIC) {
        multiboot_info_t *mb = (multiboot_info_t *)mb_info;
        mmap_backing_reserve_boot_range((uint64_t)(uintptr_t)mb_info, sizeof(*mb));
        if (mb->flags & MULTIBOOT_INFO_MEM_MAP) {
            mmap_backing_reserve_boot_range((uint64_t)mb->mmap_addr, (uint64_t)mb->mmap_length);
        }
        if ((mb->flags & MULTIBOOT_INFO_MODS) && mb->mods_count > 0) {
            multiboot_module_t *mods = (multiboot_module_t *)(uintptr_t)mb->mods_addr;
            mmap_backing_reserve_boot_range((uint64_t)mb->mods_addr,
                                            (uint64_t)mb->mods_count * sizeof(multiboot_module_t));
            for (uint32_t i = 0; i < mb->mods_count; ++i) {
                if (mods[i].mod_end > mods[i].mod_start) {
                    mmap_backing_reserve_boot_range((uint64_t)mods[i].mod_start,
                                                    (uint64_t)(mods[i].mod_end - mods[i].mod_start));
                }
                if (mods[i].cmdline) {
                    const char *s = (const char *)(uintptr_t)mods[i].cmdline;
                    mmap_backing_reserve_boot_range((uint64_t)mods[i].cmdline,
                                                    (uint64_t)strlen(s) + 1ULL);
                }
            }
        }
        if ((mb->flags & MULTIBOOT_INFO_CMDLINE) && mb->cmdline) {
            const char *s = (const char *)(uintptr_t)mb->cmdline;
            mmap_backing_reserve_boot_range((uint64_t)mb->cmdline, (uint64_t)strlen(s) + 1ULL);
        }
        return;
    }

    if (magic == MULTIBOOT2_BOOTLOADER_MAGIC) {
        uint8_t *base = (uint8_t *)mb_info;
        uint32_t total_size = *(uint32_t *)base;
        uint8_t *p;
        uint8_t *end;
        if (total_size < 16 || total_size > (64u * 1024u * 1024u)) return;
        mmap_backing_reserve_boot_range((uint64_t)(uintptr_t)mb_info, (uint64_t)total_size);
        p = base + 8;
        end = base + total_size;
        while (p + sizeof(struct edge_mb2_tag) <= end) {
            struct edge_mb2_tag *tag = (struct edge_mb2_tag *)p;
            if (tag->type == 0) break;
            if (tag->size < sizeof(struct edge_mb2_tag)) break;
            if (tag->type == 3 && tag->size >= 16) {
                uint32_t mod_start = *(uint32_t *)(p + 8);
                uint32_t mod_end = *(uint32_t *)(p + 12);
                if (mod_end > mod_start) {
                    mmap_backing_reserve_boot_range((uint64_t)mod_start,
                                                    (uint64_t)(mod_end - mod_start));
                }
            }
            p += (tag->size + 7u) & ~7u;
        }
    }
}

void process_mmap_backing_init(uint32_t magic, void *mb_info) {
    uint64_t kstart_phys;
    uint64_t kend_phys;
    memset(g_user_mmap_backing_phys, 0, sizeof(g_user_mmap_backing_phys));
    memset(g_user_mmap_backing_used, 0, sizeof(g_user_mmap_backing_used));
    memset(g_user_mmap_backing_refcnt, 0, sizeof(g_user_mmap_backing_refcnt));
    memset(g_user_mmap_backing_cgroup_owner, 0,
           sizeof(g_user_mmap_backing_cgroup_owner));
    memset(g_user_mmap_backing_user_aliases, 0,
           sizeof(g_user_mmap_backing_user_aliases));
    memset(g_mmap_boot_reserved, 0, sizeof(g_mmap_boot_reserved));
    g_user_mmap_backing_generation = 0;
    g_user_mmap_backing_generation_phys = 0;
    g_user_mmap_backing_generation_entries = 0;
    g_user_mmap_backing_generation_pages = 0;
    g_user_mmap_backing_ready_pages = 0;
    g_user_mmap_backing_alloc_hint = 0;
    g_user_mmap_backing_allocations = 0;
    g_user_mmap_backing_frees = 0;
    g_user_mmap_backing_allocation_failures = 0;
    g_mmap_boot_reserved_count = 0;

    kstart_phys = page_align_down_local(kernel_symbol_phys_local(&_kernel_start));
    kend_phys = page_align_up_local(kernel_symbol_phys_local(&_kernel_end));
    if (kend_phys > kstart_phys) {
        mmap_backing_reserve_boot_range(kstart_phys, kend_phys - kstart_phys);
    }
    mmap_backing_reserve_boot_memory(magic, mb_info);

    if (magic == MULTIBOOT_BOOTLOADER_MAGIC && mb_info) {
        multiboot_info_t *mb = (multiboot_info_t *)mb_info;
        if (mb->flags & MULTIBOOT_INFO_MEM_MAP) {
            uint32_t end = mb->mmap_addr + mb->mmap_length;
            for (uint32_t p = mb->mmap_addr; p < end;) {
                multiboot_memory_map_t *e = (multiboot_memory_map_t *)(uintptr_t)p;
                if (e->type == MULTIBOOT_MEMORY_AVAILABLE) {
                    mmap_backing_add_available_range((uint64_t)e->addr, (uint64_t)e->len);
                }
                p += e->size + sizeof(e->size);
            }
        }
    } else if (magic == MULTIBOOT2_BOOTLOADER_MAGIC && mb_info) {
        uint8_t *base = (uint8_t *)mb_info;
        uint32_t total_size = *(uint32_t *)base;
        uint8_t *p = base + 8;
        uint8_t *end = base + total_size;
        while (p + sizeof(struct edge_mb2_tag) <= end) {
            struct edge_mb2_tag *tag = (struct edge_mb2_tag *)p;
            if (tag->type == 0) break;
            if (tag->type == 6 && tag->size >= sizeof(struct edge_mb2_tag_mmap)) {
                struct edge_mb2_tag_mmap *m = (struct edge_mb2_tag_mmap *)tag;
                uint8_t *mp = m->entries;
                uint8_t *me = ((uint8_t *)tag) + tag->size;
                while (mp + m->entry_size <= me && m->entry_size >= sizeof(edge_mb2_mmap_entry_t)) {
                    edge_mb2_mmap_entry_t *e = (edge_mb2_mmap_entry_t *)mp;
                    if (e->type == MULTIBOOT_MEMORY_AVAILABLE) {
                        mmap_backing_add_available_range(e->addr, e->len);
                    }
                    mp += m->entry_size;
                }
            }
            p += (tag->size + 7u) & ~7u;
        }
    }

    /*
     * sparse_mmap_backing_index_from_phys() uses binary search because unmap
     * and COW paths hit it frequently.  Firmware memory maps are usually
     * sorted, but the ABI does not require EdgeOS to trust that ordering.  Keep
     * this list sorted and unique before any userspace mapping can retain or
     * release pages; otherwise a wrong refcount entry can recycle live file
     * pages and corrupt unrelated executables such as Xorg.
     */
    mmap_backing_sort_and_dedup();
    mmap_backing_validate_ready_list("post-sort");
    if (fixed_user_backing_runtime_init() < 0) {
        printf("[mmap-backing] ERROR fixed process backing unavailable; userspace cannot start\n");
    }
    if (task_table_runtime_init() < 0) {
        printf("[mmap-backing] ERROR task table unavailable; userspace cannot start\n");
    }
    if (user_vma_runtime_init() < 0) {
        printf("[mmap-backing] ERROR VMA metadata unavailable; userspace cannot start\n");
    }
    if (exec_record_runtime_init() < 0) {
        printf("[mmap-backing] ERROR persistent exec records unavailable; userspace cannot start\n");
    }
    if (task_scratch_runtime_init() < 0) {
        printf("[mmap-backing] ERROR task scratch storage unavailable; userspace cannot start\n");
    }
    if (exec_payload_runtime_init() < 0) {
        printf("[mmap-backing] ERROR exec payload storage unavailable; userspace cannot start\n");
    }
    if (task_kstack_runtime_init() < 0) {
        printf("[mmap-backing] WARNING task-only kernel stacks unavailable; CLONE_VM capacity limited to fixed slots\n");
    }
    if (mmap_backing_init_generation_table() < 0) {
        g_user_mmap_backing_ready_pages = 0;
    }
    mmap_backing_validate_ready_list("post-generation");

    printf("[mmap-backing] pages=%u/%u bytes=%u MiB gen_pages=%u gen_phys=0x%llx gen_kva=%p kernel=0x%llx..0x%llx sym=%p..%p boot_reserved=%u first=0x%llx last=0x%llx\n",
           g_user_mmap_backing_ready_pages,
           (uint32_t)USER_SPARSE_MMAP_BACKING_PAGES,
           (uint32_t)((uint64_t)g_user_mmap_backing_ready_pages * USER_PAGE_SIZE / (1024ULL * 1024ULL)),
           g_user_mmap_backing_generation_pages,
           (unsigned long long)g_user_mmap_backing_generation_phys,
           g_user_mmap_backing_generation,
           (unsigned long long)kstart_phys,
           (unsigned long long)kend_phys,
           &_kernel_start,
           &_kernel_end,
           g_mmap_boot_reserved_count,
           (unsigned long long)(g_user_mmap_backing_ready_pages ? g_user_mmap_backing_phys[0] : 0),
           (unsigned long long)(g_user_mmap_backing_ready_pages ? g_user_mmap_backing_phys[g_user_mmap_backing_ready_pages - 1] : 0));
}

static int sparse_mmap_range_ok_local(uint64_t start, uint64_t len) {
    int in_high = (start >= USER_SPARSE_MMAP_BASE && start < USER_SPARSE_MMAP_LIMIT);
    int in_low = (start >= USER_LOW_SPARSE_MMAP_BASE && start < USER_LOW_SPARSE_MMAP_LIMIT);
    if (!in_high && !in_low) return 0;
    if (len == 0) return 1;
    if (start + len < start) return 0;
    if (in_high && start + len > USER_SPARSE_MMAP_LIMIT) return 0;
    if (in_low && start + len > USER_LOW_SPARSE_MMAP_LIMIT) return 0;
    return 1;
}

int process_user_mmap_range_ok(uint64_t start, uint64_t len) {
    return sparse_mmap_range_ok_local(start, len);
}

static int sparse_mmap_indices(uint64_t va, uint32_t *pdpt_idx_out, uint32_t *pde_idx_out, uint32_t *pte_idx_out) {
    uint32_t pml4_idx;
    uint32_t pdpt_idx;
    if (!sparse_mmap_range_ok_local(va, 1)) return -1;
    pml4_idx = (uint32_t)((va >> 39) & 0x1FF);
    if (va >= USER_LOW_SPARSE_MMAP_BASE && va < USER_LOW_SPARSE_MMAP_LIMIT) {
        if (pml4_idx != USER_LOW_SPARSE_MMAP_PML4_IDX) return -1;
    } else if (pml4_idx < USER_SPARSE_MMAP_PML4_FIRST ||
               pml4_idx >= USER_SPARSE_MMAP_PML4_LAST_EXCL) {
        return -1;
    }
    pdpt_idx = (uint32_t)((va >> 30) & 0x1FF);
    if (pdpt_idx >= USER_PDPT_COUNT) return -1;
    if (pdpt_idx_out) *pdpt_idx_out = pdpt_idx;
    if (pde_idx_out) *pde_idx_out = (uint32_t)((va >> 21) & 0x1FF);
    if (pte_idx_out) *pte_idx_out = (uint32_t)((va >> 12) & 0x1FF);
    return 0;
}

static int sparse_mmap_high_root_slot(uint32_t pml4_idx) {
    if (pml4_idx < USER_SPARSE_MMAP_PML4_FIRST ||
        pml4_idx >= USER_SPARSE_MMAP_PML4_LAST_EXCL)
        return -1;
    return (int)(pml4_idx - USER_SPARSE_MMAP_PML4_FIRST);
}

static uint64_t *sparse_mmap_alloc_table(int idx, const char *level,
                                         uint32_t slot) {
    return fixed_user_pt_alloc(idx, level, slot);
}

static void sparse_mmap_release_table(uint64_t *table) {
    int pool_idx;
    if (!table) return;
    pool_idx = fixed_user_pt_pool_index_from_ptr(table);
    if (pool_idx < 0 ||
        (uint32_t)pool_idx >= g_user_mmap_backing_ready_pages ||
        !bitmap_test_idx(g_user_mmap_pt_used,
                         g_user_mmap_backing_ready_pages,
                         (uint32_t)pool_idx))
        return;
    memset(table, 0, USER_PAGE_SIZE);
    bitmap_clear_idx(g_user_mmap_pt_used,
                     g_user_mmap_backing_ready_pages,
                     (uint32_t)pool_idx);
    sparse_mmap_release_backing_index_local(pool_idx);
}

static uint64_t *sparse_mmap_pdpt_root(int idx, uint32_t pml4_idx,
                                       int create) {
    uint64_t *root;
    uint64_t flags = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    int slot;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    if (pml4_idx == USER_LOW_SPARSE_MMAP_PML4_IDX)
        return &g_pdpt[idx][0];
    slot = sparse_mmap_high_root_slot(pml4_idx);
    if (slot < 0) return 0;
    root = g_pdpt_sparse[idx][slot];
    if (!root && create) {
        root = sparse_mmap_alloc_table(idx, "sparse-pdpt", pml4_idx);
        if (!root) return 0;
        g_pdpt_sparse[idx][slot] = root;
    }
    if (root && create)
        g_pml4[idx][pml4_idx] =
            fixed_user_pt_phys_from_ptr(root) | flags;
    return root;
}

static uint64_t *sparse_mmap_pd_root(int idx, uint32_t pml4_idx,
                                     uint32_t pdpt_idx, int create) {
    uint64_t *pdpt;
    uint64_t entry;
    uint64_t *pd;

    if (pdpt_idx >= USER_PDPT_COUNT) return 0;
    pdpt = sparse_mmap_pdpt_root(idx, pml4_idx, create);
    if (!pdpt) return 0;
    entry = pdpt[pdpt_idx];
    if ((entry & PAGE_PRESENT) != 0 && (entry & PAGE_PS) == 0)
        return fixed_user_pt_ptr_from_phys(entry);
    if (!create) return 0;
    pd = sparse_mmap_alloc_table(idx, "sparse-pd", pdpt_idx);
    if (!pd) return 0;
    pdpt[pdpt_idx] = fixed_user_pt_phys_from_ptr(pd) |
                     PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    return pd;
}

static uint64_t *sparse_mmap_pde_entry(int idx, uint64_t va, int create) {
    uint32_t pml4_idx;
    uint32_t pdpt_idx;
    uint32_t pde_idx;
    uint64_t *pd;

    if (sparse_mmap_indices(va, &pdpt_idx, &pde_idx, 0) < 0)
        return 0;
    pml4_idx = (uint32_t)((va >> 39) & 0x1FFu);
    pd = sparse_mmap_pd_root(idx, pml4_idx, pdpt_idx, create);
    return pd ? &pd[pde_idx] : 0;
}

static int sparse_mmap_backing_index_from_phys(uint64_t phys) {
    uint32_t lo = 0;
    uint32_t hi = g_user_mmap_backing_ready_pages;
    if ((phys & (USER_PAGE_SIZE - 1ULL)) != 0) return -1;
    /*
     * The sorted backing array is normally a long contiguous RAM run.  Page
     * table walking calls this helper for every level, so paying a binary
     * search for the common run makes ordinary user faults unnecessarily
     * expensive.  Derive the likely index from the first page and confirm the
     * exact physical value; memory-map holes safely fall back to binary search.
     */
    if (hi != 0 && phys >= g_user_mmap_backing_phys[0]) {
        uint64_t offset = phys - g_user_mmap_backing_phys[0];
        uint64_t candidate = offset / USER_PAGE_SIZE;
        if (candidate < hi &&
            g_user_mmap_backing_phys[candidate] == phys) {
            return (int)candidate;
        }
    }
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) / 2u);
        uint64_t cur = g_user_mmap_backing_phys[mid];
        if (cur == phys) return (int)mid;
        if (cur < phys) lo = mid + 1u;
        else hi = mid;
    }
    return -1;
}

static uint8_t *sparse_mmap_backing_ptr(int idx) {
    if (idx < 0 || (uint32_t)idx >= g_user_mmap_backing_ready_pages) return 0;
    return (uint8_t *)edge_mmio_low_alias(g_user_mmap_backing_phys[idx]);
}

static uint64_t sparse_mmap_backing_phys(int idx) {
    if (idx < 0 || (uint32_t)idx >= g_user_mmap_backing_ready_pages) return 0;
    return g_user_mmap_backing_phys[idx];
}

static int sparse_mmap_alloc_backing_index_mode_local(int clear_page) {
    int idx = -1;
    uint8_t *page_ptr;
    uint32_t start;
    uint64_t flags;
    static int reserved_late_log_budget = 8;
    if (g_user_mmap_backing_ready_pages == 0) {
        __atomic_add_fetch(&g_user_mmap_backing_allocation_failures, 1u,
                           __ATOMIC_RELAXED);
        return -1;
    }
    flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    start = g_user_mmap_backing_alloc_hint;
    if (start >= g_user_mmap_backing_ready_pages) start = 0;

    /*
     * A desktop faults tens of thousands of anonymous and shared-object pages.
     * Restarting a bit-by-bit first-fit search at zero for each 4 KiB page made
     * allocation quadratic and put sparse_mmap_alloc_backing_index_local() on
     * the x86 XFCE hot path.  A next-fit cursor preserves every ownership and
     * reservation check while making sequential faults amortized O(1).
     * Word-level clear-bit discovery also keeps fragmented and nearly full
     * pools bounded by the bitmap size rather than the number of pages.  The
     * second pass wraps once so released holes are still reused and ENOMEM is
     * reported only after the complete pool has been examined.
     */
    for (int pass = 0; pass < 2 && idx < 0; ++pass) {
        uint32_t begin = pass == 0 ? start : 0;
        uint32_t end = pass == 0 ? g_user_mmap_backing_ready_pages : start;
        uint32_t cursor = begin;
        while (cursor < end) {
            int candidate = bitmap_find_next_clear_range(
                g_user_mmap_backing_used,
                g_user_mmap_backing_ready_pages,
                cursor, end);
            uint64_t phys;
            uint32_t i;

            if (candidate < 0) break;
            i = (uint32_t)candidate;
            phys = g_user_mmap_backing_phys[i];
            if (mmap_backing_phys_reserved(phys)) {
                /*
                 * The boot memory map is not the only owner of physical pages.
                 * Drivers can install DMA/resource buffers such as virtio-gpu's
                 * framebuffer after sparse backing setup.  Permanently reserve
                 * such a page rather than aliasing device memory into userspace.
                 */
                bitmap_set_idx(g_user_mmap_backing_used,
                               g_user_mmap_backing_ready_pages, i);
                g_user_mmap_backing_refcnt[i] = 0xFFFFu;
                if (reserved_late_log_budget > 0) {
                    printf("[mmap-backing] late-reserve idx=%u phys=0x%x budget=%d\n",
                           i, (uint32_t)phys, reserved_late_log_budget - 1);
                    reserved_late_log_budget--;
                }
                cursor = i + 1u;
                continue;
            }
            idx = (int)i;
            bitmap_set_idx(g_user_mmap_backing_used,
                           g_user_mmap_backing_ready_pages, i);
            g_user_mmap_backing_alloc_hint = i + 1u;
            if (g_user_mmap_backing_alloc_hint >= g_user_mmap_backing_ready_pages) {
                g_user_mmap_backing_alloc_hint = 0;
            }
            break;
        }
    }
    if (idx < 0) {
        __atomic_add_fetch(&g_user_mmap_backing_allocation_failures, 1u,
                           __ATOMIC_RELAXED);
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return -1;
    }
    page_ptr = sparse_mmap_backing_ptr(idx);
    if (!page_ptr) {
        bitmap_clear_idx(g_user_mmap_backing_used, g_user_mmap_backing_ready_pages, (uint32_t)idx);
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        __atomic_add_fetch(&g_user_mmap_backing_allocation_failures, 1u,
                           __ATOMIC_RELAXED);
        return -1;
    }
    if (g_user_mmap_backing_generation &&
        (uint32_t)idx < g_user_mmap_backing_generation_entries) {
        g_user_mmap_backing_generation[idx]++;
        if (g_user_mmap_backing_generation[idx] == 0) g_user_mmap_backing_generation[idx] = 1;
    }
    g_user_mmap_backing_refcnt[idx] = 1;
    g_user_mmap_backing_cgroup_owner[idx] = 0;
    g_user_mmap_backing_user_aliases[idx] = 0;
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
    /* The used bit and initial owner reference reserve this page completely.
     * Zeroing 4 KiB while holding the global allocator lock serialized every
     * concurrent anonymous and COW fault and kept interrupts disabled for the
     * memory write.  No caller can publish the page before this function
     * returns, so initialize it after releasing the metadata lock. */
    if (clear_page) memset(page_ptr, 0, USER_PAGE_SIZE);
    __atomic_add_fetch(&g_user_mmap_backing_allocations, 1u,
                       __ATOMIC_RELAXED);
    return idx;
}

static int sparse_mmap_alloc_backing_index_local(void) {
    return sparse_mmap_alloc_backing_index_mode_local(1);
}

static void sparse_mmap_retain_backing_index_local(int idx) {
    static int ref_overflow_log_budget = 16;
    uint64_t flags;
    if (idx < 0 || (uint32_t)idx >= g_user_mmap_backing_ready_pages) return;
    flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    if ((g_user_mmap_backing_used[idx / 64u] & (1ull << (idx % 64u))) == 0) {
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return;
    }
    if (g_user_mmap_backing_refcnt[idx] == 0) g_user_mmap_backing_refcnt[idx] = 1;
    else if (g_user_mmap_backing_refcnt[idx] != 0xFFFFu) {
        g_user_mmap_backing_refcnt[idx]++;
        if (g_user_mmap_backing_refcnt[idx] == 0xFFFFu && ref_overflow_log_budget > 0) {
            printf("[mmap-ref] saturated idx=%d phys=0x%x budget=%d\n",
                   idx, (uint32_t)g_user_mmap_backing_phys[idx],
                   ref_overflow_log_budget - 1);
            ref_overflow_log_budget--;
        }
    }
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
}

static uint16_t sparse_mmap_backing_refcnt_local(int idx) {
    uint16_t count;
    uint64_t flags;
    if (idx < 0 || (uint32_t)idx >= g_user_mmap_backing_ready_pages)
        return 0;
    flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    count = (g_user_mmap_backing_used[idx / 64u] &
             (1ull << (idx % 64u))) != 0 ?
            g_user_mmap_backing_refcnt[idx] : 0;
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
    return count;
}

static int sparse_mmap_user_alias_acquire(task_t *t, int idx) {
    task_t *fault_task = t;
    uint32_t cgroup_id;
    uint32_t oom_cgroup_id = 0;
    uint64_t flags;
    int first_alias = 0;

    if (!t || idx < 0 ||
        (uint32_t)idx >= g_user_mmap_backing_ready_pages) {
        return -1;
    }
    t = task_vm_owner_local(t);
    if (!t) return -1;
    flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    if (
        !bitmap_test_idx(g_user_mmap_backing_used,
                         g_user_mmap_backing_ready_pages,
                         (uint32_t)idx) ||
        bitmap_test_idx(g_user_mmap_pt_used,
                        g_user_mmap_backing_ready_pages,
                        (uint32_t)idx) ||
        g_user_mmap_backing_user_aliases[idx] == UINT32_MAX) {
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return -1;
    }
    if (g_user_mmap_backing_user_aliases[idx] != 0) {
        g_user_mmap_backing_user_aliases[idx]++;
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);

    cgroup_id = t->cgroup_id;
    if (cgroup_id < UINT16_MAX)
        (void)kernel_mm_prepare_cgroup_charge(
            cgroup_id, USER_PAGE_SIZE);
    if (cgroup_id >= UINT16_MAX ||
        cgroupfs_memory_charge(cgroup_id, USER_PAGE_SIZE,
                               &oom_cgroup_id) < 0) {
        fault_task->cgroup_memory_oom_id = oom_cgroup_id;
        return -1;
    }

    flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    if (!bitmap_test_idx(g_user_mmap_backing_used,
                         g_user_mmap_backing_ready_pages,
                         (uint32_t)idx) ||
        bitmap_test_idx(g_user_mmap_pt_used,
                        g_user_mmap_backing_ready_pages,
                        (uint32_t)idx) ||
        g_user_mmap_backing_user_aliases[idx] == UINT32_MAX) {
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        cgroupfs_memory_uncharge(cgroup_id, USER_PAGE_SIZE);
        return -1;
    }
    if (g_user_mmap_backing_user_aliases[idx] == 0) {
        g_user_mmap_backing_cgroup_owner[idx] =
            (uint16_t)(cgroup_id + 1u);
        first_alias = 1;
    }
    g_user_mmap_backing_user_aliases[idx]++;
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
    if (!first_alias) {
        cgroupfs_memory_uncharge(cgroup_id, USER_PAGE_SIZE);
    } else {
        (void)kernel_mm_reclaim_cgroup_pressure(cgroup_id);
    }
    return 0;
}

int process_consume_cgroup_memory_oom(task_t *t) {
    uint32_t oom_cgroup_id;

    if (!t || !t->cgroup_memory_oom_id) return 0;
    oom_cgroup_id = t->cgroup_memory_oom_id;
    t->cgroup_memory_oom_id = 0;
    (void)cgroupfs_memory_oom_group_kill(
        oom_cgroup_id, process_tgid_of_task(t));
    cgroupfs_memory_note_oom_kill(t->cgroup_id);
    t->termination_signal = LINUX_SIGKILL;
    return 1;
}

static void sparse_mmap_user_alias_release(int idx) {
    uint16_t encoded_owner;
    uint64_t flags;

    if (idx < 0 || (uint32_t)idx >= g_user_mmap_backing_ready_pages) return;
    flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    if (g_user_mmap_backing_user_aliases[idx] == 0) {
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return;
    }
    if (--g_user_mmap_backing_user_aliases[idx] != 0) {
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return;
    }
    encoded_owner = g_user_mmap_backing_cgroup_owner[idx];
    g_user_mmap_backing_cgroup_owner[idx] = 0;
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
    if (encoded_owner != 0)
        cgroupfs_memory_uncharge((uint32_t)encoded_owner - 1u,
                                 USER_PAGE_SIZE);
}

static void sparse_mmap_release_backing_index_local(int idx) {
    static int ref_underflow_log_budget = 32;
    uint16_t encoded_owner = 0;
    uint64_t flags;
    if (idx < 0 || (uint32_t)idx >= g_user_mmap_backing_ready_pages) return;
    flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    if ((g_user_mmap_backing_used[idx / 64u] & (1ull << (idx % 64u))) == 0) {
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return;
    }
    /*
     * Sparse backing pages are directly installed in userspace PTEs.  Linux does
     * not scan every address space to free a page; the page-map refcount is the
     * ownership contract.  EdgeOS must keep the same invariant: every PTE install
     * or long-lived kernel owner retains exactly once, and every unmap/owner drop
     * releases exactly once.  The old drift guard walked all task page tables on
     * the last-reference edge, which made XFCE appear hung because munmap/exit
     * churn repeatedly performed a full desktop-wide sparse-PTE scan with
     * interrupts disabled.  Do not reintroduce global scans in this hot path.
     */
    if (g_user_mmap_backing_refcnt[idx] == 0xFFFFu) {
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return;
    }
    if (g_user_mmap_backing_refcnt[idx] == 0) {
        if (ref_underflow_log_budget > 0) {
            printf("[mmap-ref] release-underflow idx=%d phys=0x%x budget=%d\n",
                   idx, (uint32_t)g_user_mmap_backing_phys[idx],
                   ref_underflow_log_budget - 1);
            ref_underflow_log_budget--;
        }
        bitmap_clear_idx(g_user_mmap_backing_used, g_user_mmap_backing_ready_pages, (uint32_t)idx);
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return;
    }
    if (g_user_mmap_backing_refcnt[idx] > 1) {
        g_user_mmap_backing_refcnt[idx]--;
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return;
    }
    g_user_mmap_backing_refcnt[idx] = 0;
    if (g_user_mmap_backing_user_aliases[idx] != 0) {
        encoded_owner = g_user_mmap_backing_cgroup_owner[idx];
        g_user_mmap_backing_user_aliases[idx] = 0;
        g_user_mmap_backing_cgroup_owner[idx] = 0;
    }
    bitmap_clear_idx(g_user_mmap_backing_used, g_user_mmap_backing_ready_pages, (uint32_t)idx);
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
    __atomic_add_fetch(&g_user_mmap_backing_frees, 1u, __ATOMIC_RELAXED);
    if (encoded_owner != 0)
        cgroupfs_memory_uncharge((uint32_t)encoded_owner - 1u,
                                 USER_PAGE_SIZE);
}

int process_user_mmap_alloc_backing_page(void) {
    return sparse_mmap_alloc_backing_index_local();
}

int process_user_mmap_alloc_file_backing_page(void) {
    /*
     * File-fault callers initialize the entire page, including the zero-filled
     * tail after EOF, before publishing it in the shared file cache.  Keep a
     * dedicated interface so anonymous and shared-memory allocation can never
     * accidentally expose stale data while file reads avoid a duplicate clear.
     */
    return sparse_mmap_alloc_backing_index_mode_local(0);
}

void *process_user_mmap_alloc_contiguous_backing_pages(uint32_t page_count) {
    uint32_t run_start = 0;
    uint32_t run_length = 0;
    uint32_t start;
    uint64_t flags;
    void *result = 0;

    if (page_count == 0 ||
        page_count > g_user_mmap_backing_ready_pages ||
        page_count > UINT32_MAX / USER_PAGE_SIZE) {
        return 0;
    }

    flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    start = g_user_mmap_backing_alloc_hint;
    if (start >= g_user_mmap_backing_ready_pages) start = 0;

    /*
     * Runtime kernel objects may need physically contiguous storage after
     * userspace mappings already exist.  Boot-time table allocation removes
     * pages from the backing index, but doing that here would renumber live
     * page metadata underneath existing PTEs.  Reserve an unused contiguous
     * run in place instead, using the same ownership/refcount contract as an
     * ordinary mmap backing page.
     */
    for (int pass = 0; pass < 2; ++pass) {
        uint32_t begin = pass == 0 ? start : 0;
        uint32_t end = pass == 0 ? g_user_mmap_backing_ready_pages : start;

        run_length = 0;
        for (uint32_t i = begin; i < end; ++i) {
            uint64_t physical = g_user_mmap_backing_phys[i];
            int unavailable = bitmap_test_idx(
                g_user_mmap_backing_used,
                g_user_mmap_backing_ready_pages, i);

            if (!unavailable && mmap_backing_phys_reserved(physical)) {
                bitmap_set_idx(g_user_mmap_backing_used,
                               g_user_mmap_backing_ready_pages, i);
                g_user_mmap_backing_refcnt[i] = 0xFFFFu;
                unavailable = 1;
            }
            if (unavailable ||
                (run_length > 0 &&
                 physical != g_user_mmap_backing_phys[i - 1] +
                                 USER_PAGE_SIZE)) {
                run_length = 0;
            }
            if (unavailable) continue;
            if (run_length == 0) run_start = i;
            run_length++;
            if (run_length == page_count) {
                uint8_t *memory = sparse_mmap_backing_ptr((int)run_start);
                if (!memory) goto out;
                for (uint32_t page = 0; page < page_count; ++page) {
                    uint32_t index = run_start + page;
                    bitmap_set_idx(g_user_mmap_backing_used,
                                   g_user_mmap_backing_ready_pages, index);
                    g_user_mmap_backing_refcnt[index] = 1;
                    if (g_user_mmap_backing_generation &&
                        index < g_user_mmap_backing_generation_entries) {
                        g_user_mmap_backing_generation[index]++;
                        if (g_user_mmap_backing_generation[index] == 0)
                            g_user_mmap_backing_generation[index] = 1;
                    }
                }
                g_user_mmap_backing_alloc_hint = run_start + page_count;
                if (g_user_mmap_backing_alloc_hint >=
                    g_user_mmap_backing_ready_pages) {
                    g_user_mmap_backing_alloc_hint = 0;
                }
                memset(memory, 0, page_count * (uint32_t)USER_PAGE_SIZE);
                __atomic_add_fetch(&g_user_mmap_backing_allocations,
                                   page_count, __ATOMIC_RELAXED);
                result = memory;
                goto out;
            }
        }
    }
out:
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
    if (!result)
        __atomic_add_fetch(&g_user_mmap_backing_allocation_failures, 1u,
                           __ATOMIC_RELAXED);
    return result;
}

void *process_user_mmap_backing_page_ptr(int idx) {
    return sparse_mmap_backing_ptr(idx);
}

int process_user_mmap_backing_page_index(const void *page) {
    uintptr_t address = (uintptr_t)page;
    uint64_t physical;

    if (!address || (address & (USER_PAGE_SIZE - 1u))) return -1;
    if (address >= EDGE_MMIO_LOW_ALIAS_BASE &&
        address < EDGE_MMIO_LOW_ALIAS_BASE + EDGE_MMIO_LOW_ALIAS_SIZE)
        physical = address - EDGE_MMIO_LOW_ALIAS_BASE;
    else
        physical = address;
    return sparse_mmap_backing_index_from_phys(physical);
}

void process_user_mmap_retain_backing_page(int idx) {
    sparse_mmap_retain_backing_index_local(idx);
}

void process_user_mmap_release_backing_page(int idx) {
    sparse_mmap_release_backing_index_local(idx);
}

int edge_process_runtime_group_page_allocate(linux_group_page_t *page) {
    int index;
    index = process_user_mmap_alloc_backing_page();
    if (index < 0) return -1;
    page->values = process_user_mmap_backing_page_ptr(index);
    if (!page->values) {
        process_user_mmap_release_backing_page(index);
        return -1;
    }
    page->token = (uint32_t)index;
    return 0;
}

int edge_process_runtime_group_page_retain(
    const linux_group_page_t *page) {
    int index;
    if (!page || !page->values || page->token > INT32_MAX) return -1;
    index = (int)page->token;
    if (process_user_mmap_backing_page_ptr(index) != page->values ||
        !process_user_mmap_backing_page_active(index))
        return -1;
    process_user_mmap_retain_backing_page(index);
    return 0;
}

void edge_process_runtime_group_page_release(
    const linux_group_page_t *page) {
    int index;
    if (!page || !page->values || page->token > INT32_MAX) return;
    index = (int)page->token;
    if (process_user_mmap_backing_page_ptr(index) == page->values)
        process_user_mmap_release_backing_page(index);
}

int process_user_mmap_backing_page_active(int idx) {
    return sparse_mmap_backing_refcnt_local(idx) > 0;
}

uint16_t process_user_mmap_backing_page_refcount(int idx) {
    return sparse_mmap_backing_refcnt_local(idx);
}

uint32_t process_user_mmap_backing_page_generation(int idx) {
    if (idx < 0 || (uint32_t)idx >= g_user_mmap_backing_ready_pages) return 0;
    if ((g_user_mmap_backing_used[idx / 64u] & (1ull << (idx % 64u))) == 0) return 0;
    if (!g_user_mmap_backing_generation ||
        (uint32_t)idx >= g_user_mmap_backing_generation_entries) return 0;
    return g_user_mmap_backing_generation[idx];
}

int process_user_mmap_backing_page_cgroup(int idx,
                                          uint32_t *cgroup_id_out) {
    uint16_t encoded_owner;
    uint64_t flags;

    if (!cgroup_id_out || idx < 0 ||
        (uint32_t)idx >= g_user_mmap_backing_ready_pages)
        return -1;
    flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    if (!bitmap_test_idx(g_user_mmap_backing_used,
                         g_user_mmap_backing_ready_pages,
                         (uint32_t)idx)) {
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
        return -1;
    }
    encoded_owner = g_user_mmap_backing_cgroup_owner[idx];
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, flags);
    if (!encoded_owner) return -1;
    *cgroup_id_out = (uint32_t)encoded_owner - 1u;
    return 0;
}

uint32_t process_user_mmap_backing_used_pages(void) {
    return sparse_bitmap_count_used_local(g_user_mmap_backing_used, g_user_mmap_backing_ready_pages);
}

uint32_t process_user_mmap_backing_total_pages(void) {
    return g_user_mmap_backing_ready_pages;
}

uint64_t process_user_mmap_backing_free_bytes(void) {
    uint32_t total = __atomic_load_n(
        &g_user_mmap_backing_ready_pages, __ATOMIC_ACQUIRE);
    uint32_t used = sparse_bitmap_count_used_local(
        g_user_mmap_backing_used, total);

    return (uint64_t)(used <= total ? total - used : 0u) * USER_PAGE_SIZE;
}

static edge_page_zone_t process_page_zone(uint64_t physical) {
    if (physical < UINT64_C(0x01000000)) return EDGE_PAGE_ZONE_DMA;
    if (physical < UINT64_C(0x100000000)) return EDGE_PAGE_ZONE_DMA32;
    return EDGE_PAGE_ZONE_NORMAL;
}

static int process_page_snapshot_used(uint32_t index) {
    uint64_t value = __atomic_load_n(
        &g_user_mmap_backing_used[index / 64u], __ATOMIC_ACQUIRE);
    return (value & (UINT64_C(1) << (index % 64u))) != 0;
}

static void process_page_snapshot_watermarks(
        edge_page_allocator_snapshot_t *snapshot, uint32_t zone) {
    uint32_t managed = snapshot->managed_pages[zone];
    uint32_t minimum;

    if (!managed) return;
    minimum = managed / 100u;
    if (minimum < 16u) minimum = managed < 16u ? managed : 16u;
    if (minimum > 4096u) minimum = 4096u;
    snapshot->watermark_min[zone] = minimum;
    snapshot->watermark_low[zone] = minimum * 2u > managed ?
        managed : minimum * 2u;
    snapshot->watermark_high[zone] = minimum * 3u > managed ?
        managed : minimum * 3u;
}

int process_page_allocator_snapshot(edge_page_allocator_snapshot_t *snapshot) {
    uint32_t total = __atomic_load_n(
        &g_user_mmap_backing_ready_pages, __ATOMIC_ACQUIRE);
    uint32_t index = 0;

    if (!snapshot || !total) return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    while (index < total) {
        uint64_t physical = g_user_mmap_backing_phys[index];
        edge_page_zone_t zone = process_page_zone(physical);

        ++snapshot->managed_pages[zone];
        if (process_page_snapshot_used(index)) {
            ++index;
            continue;
        }
        {
            uint32_t run_start = index;
            uint32_t run_end = index + 1u;

            ++snapshot->free_pages[zone];
            while (run_end < total &&
                   !process_page_snapshot_used(run_end) &&
                   process_page_zone(g_user_mmap_backing_phys[run_end]) ==
                       zone &&
                   g_user_mmap_backing_phys[run_end] ==
                       g_user_mmap_backing_phys[run_end - 1u] +
                           USER_PAGE_SIZE) {
                ++snapshot->managed_pages[zone];
                ++snapshot->free_pages[zone];
                ++run_end;
            }
            while (run_start < run_end) {
                uint64_t pfn =
                    g_user_mmap_backing_phys[run_start] / USER_PAGE_SIZE;
                uint32_t remaining = run_end - run_start;
                uint32_t order = 0;

                while (order < EDGE_PAGE_ALLOCATOR_ORDER_MAX &&
                       (UINT32_C(1) << (order + 1u)) <= remaining &&
                       !(pfn & ((UINT64_C(1) << (order + 1u)) - 1u)))
                    ++order;
                ++snapshot->free_blocks[zone]
                    [EDGE_PAGE_MIGRATE_UNMOVABLE][order];
                run_start += UINT32_C(1) << order;
            }
            index = run_end;
        }
    }
    for (uint32_t zone = 0; zone < EDGE_PAGE_ZONE_COUNT; ++zone)
        process_page_snapshot_watermarks(snapshot, zone);
    snapshot->allocated_pages = __atomic_load_n(
        &g_user_mmap_backing_allocations, __ATOMIC_RELAXED);
    snapshot->freed_pages = __atomic_load_n(
        &g_user_mmap_backing_frees, __ATOMIC_RELAXED);
    snapshot->allocation_failures = __atomic_load_n(
        &g_user_mmap_backing_allocation_failures, __ATOMIC_RELAXED);
    snapshot->buddy_exact = 1u;
    return 0;
}

uint32_t process_user_mmap_pt_used_pages(void) {
    return sparse_bitmap_count_used_local(
        g_user_mmap_pt_used, g_user_mmap_backing_ready_pages);
}

uint32_t process_user_mmap_pt_total_pages(void) {
    return g_user_mmap_backing_ready_pages;
}

static edge_user_vma_t *process_user_vma_for_addr(task_t *mm, uint64_t addr);
static uint64_t *sparse_mmap_lookup_pt(task_t *t, uint64_t va, uint32_t *pde_slot_out);
static void sparse_mmap_flush_task(task_t *t);

static int user_heap_slot_for_addr(uint64_t addr, uint32_t *slot_out, uint32_t *pte_out) {
    uint64_t rel;
    if (addr < USER_HEAP_BASE || addr >= USER_HEAP_BASE + USER_HEAP_TOTAL_SIZE) return -1;
    rel = addr - USER_HEAP_BASE;
    if (slot_out) *slot_out = (uint32_t)(rel >> 21);
    if (pte_out) *pte_out = (uint32_t)((addr >> 12) & 0x1FFu);
    return 0;
}

static int process_user_heap_install_roots(int idx) {
    uint64_t pde_flags = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    int changed = 0;
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    for (uint32_t slot = 0; slot < USER_HEAP_TOTAL_PDE_CNT; ++slot) {
        uint64_t va = USER_HEAP_BASE + ((uint64_t)slot << 21);
        uint64_t *pd = fixed_user_pd_for_va(idx, va);
        uint32_t pde = (uint32_t)((va >> 21) & 0x1FFu);
        uint64_t expected;
        if (!pd || !g_user_heap_pt[idx][slot]) continue;
        expected = fixed_user_pt_phys_from_ptr(
                       g_user_heap_pt[idx][slot]) |
                   pde_flags;
        if (pd[pde] == expected) continue;
        pd[pde] = expected;
        changed = 1;
    }
    return changed;
}

static int process_user_heap_ensure_pt(task_t *mm, uint64_t addr, uint64_t **pt_out) {
    int idx;
    uint32_t slot;
    uint32_t pde;
    uint64_t *pd;
    if (!pt_out) return -1;
    *pt_out = 0;
    mm = task_vm_owner_local(mm);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    if (user_heap_slot_for_addr(addr, &slot, 0) < 0 || slot >= USER_HEAP_TOTAL_PDE_CNT) return -1;
    if (!g_user_heap_pt[idx][slot]) {
        g_user_heap_pt[idx][slot] = fixed_user_pt_alloc(idx, "heap", slot);
        if (!g_user_heap_pt[idx][slot]) return -1;
    }
    pd = fixed_user_pd_for_va(idx, addr);
    if (!pd) return -1;
    pde = (uint32_t)((addr >> 21) & 0x1FFu);
    pd[pde] = fixed_user_pt_phys_from_ptr(g_user_heap_pt[idx][slot]) |
              PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    *pt_out = g_user_heap_pt[idx][slot];
    return 0;
}

static edge_user_vma_t *process_user_heap_vma_for_addr(task_t *mm, uint64_t addr) {
    edge_user_vma_t *v;
    if (!mm) return 0;
    v = process_user_vma_for_addr(mm, addr);
    if (!v) return 0;
    if (addr < USER_HEAP_BASE || addr >= USER_HEAP_BASE + USER_HEAP_TOTAL_SIZE) return 0;
    return v;
}

static int process_user_heap_addr_valid(task_t *mm, uint64_t addr, int write) {
    edge_user_vma_t *v;
    if (!mm) return 0;
    /*
     * Linux MAP_FIXED mappings replace the old range even when that range used
     * to be part of brk(2).  Check VMA metadata before the legacy brk window so
     * anonymous PROT_NONE reservations installed by musl's loader/allocator stay
     * inaccessible until mprotect(2), instead of silently behaving as writable
     * heap and corrupting adjacent shared-object mappings.
     */
    v = process_user_heap_vma_for_addr(mm, addr);
    if (v) {
        if (v->prot == 0) return 0;
        if (write && (v->prot & 0x2u) == 0) return 0;
        return 1;
    }
    if (addr >= mm->user_heap_base && addr < mm->user_brk) return 1;
    return 0;
}

static int process_user_heap_commit_page(task_t *mm, uint64_t addr, int write) {
    uint64_t page = page_align_down_local(addr);
    uint64_t *pt = 0;
    uint64_t new_pte;
    uint64_t expected;
    uint32_t slot = 0;
    uint32_t pte_idx = 0;
    int backing_idx;
    uint8_t *page_ptr;
    edge_user_vma_t *v;
    uint64_t pte_flags = PAGE_PRESENT | PAGE_USER;
    if (!process_user_heap_addr_valid(mm, page, write)) return -1;
    v = process_user_heap_vma_for_addr(mm, page);
    if (!v || (v->prot & 0x2u) != 0) {
        pte_flags |= PAGE_WRITE;
    }
    if (user_heap_slot_for_addr(page, &slot, &pte_idx) < 0 ||
        slot >= USER_HEAP_TOTAL_PDE_CNT)
        return -1;
    {
        int idx = task_index(mm);
        if (idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
        pt = g_user_heap_pt[idx][slot];
    }
    if (!pt) {
        /* Only hierarchy construction needs the per-mm lock.  The stable leaf
         * table is published once and individual first touches use an atomic
         * compare-exchange below, avoiding a contended lock on every heap
         * page in a multi-threaded browser. */
        process_user_page_table_lock(mm);
        if (process_user_heap_ensure_pt(mm, page, &pt) < 0) {
            process_user_page_table_unlock(mm);
            return -1;
        }
        process_user_page_table_unlock(mm);
    }
    if ((__atomic_load_n(&pt[pte_idx], __ATOMIC_ACQUIRE) & PAGE_PRESENT) != 0)
        return 0;
    backing_idx = sparse_mmap_alloc_backing_index_local();
    if (backing_idx < 0) {
        sparse_mmap_log_oom_local(mm, "heap-backing", page);
        return -1;
    }
    page_ptr = sparse_mmap_backing_ptr(backing_idx);
    if (!page_ptr) {
        sparse_mmap_release_backing_index_local(backing_idx);
        return -1;
    }
    /* The backing allocator returns a fully zeroed page, preserving Linux
     * demand-zero semantics without clearing the same 4 KiB twice here. */
    if (sparse_mmap_user_alias_acquire(mm, backing_idx) < 0) {
        sparse_mmap_release_backing_index_local(backing_idx);
        return -1;
    }
    new_pte = sparse_mmap_backing_phys(backing_idx) | pte_flags;
    expected = 0;
    if (!__atomic_compare_exchange_n(
            &pt[pte_idx], &expected, new_pte, 0,
            __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
        sparse_mmap_user_alias_release(backing_idx);
        sparse_mmap_release_backing_index_local(backing_idx);
        return (expected & PAGE_PRESENT) != 0 ? 0 : -1;
    }
    invlpg_local(page);
    return 0;
}

static void process_user_heap_release_for_idx(int idx) {
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    for (uint32_t slot = 0; slot < USER_HEAP_TOTAL_PDE_CNT; ++slot) {
        uint64_t *pt = g_user_heap_pt[idx][slot];
        if (!pt) continue;
        for (uint32_t pte = 0; pte < 512; ++pte) {
            uint64_t entry = pt[pte];
            int backing_idx;
            if ((entry & PAGE_PRESENT) == 0) continue;
            backing_idx = sparse_mmap_backing_index_from_phys(entry & ~0xFFFULL);
            pt[pte] = 0;
            if (backing_idx >= 0) {
                sparse_mmap_user_alias_release(backing_idx);
                sparse_mmap_release_backing_index_local(backing_idx);
            }
        }
        fixed_user_pt_release_ptr(&g_user_heap_pt[idx][slot]);
    }
}

static int process_user_heap_unmap_range(task_t *t, uint64_t start, uint64_t len) {
    enum { HEAP_UNMAP_RELEASE_BATCH = 256 };
    task_t *mm;
    int release_backings[HEAP_UNMAP_RELEASE_BATCH];
    uint32_t release_count = 0;
    int idx;
    uint64_t end;
    int touched = 0;
    if (!t || len == 0) return 0;
    mm = task_vm_owner_local(t);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start) return -1;
    if (start < USER_HEAP_BASE) start = USER_HEAP_BASE;
    if (end > USER_HEAP_BASE + USER_HEAP_TOTAL_SIZE) end = USER_HEAP_BASE + USER_HEAP_TOTAL_SIZE;
    if (end <= start) return 0;
    process_user_page_table_lock(mm);
    for (uint64_t va = start; va < end; va += USER_PAGE_SIZE) {
        uint32_t slot;
        uint32_t pte_idx;
        uint64_t *pt;
        uint64_t entry;
        int backing_idx;
        if (user_heap_slot_for_addr(va, &slot, &pte_idx) < 0 || slot >= USER_HEAP_TOTAL_PDE_CNT) continue;
        pt = g_user_heap_pt[idx][slot];
        if (!pt) continue;
        entry = pt[pte_idx];
        if ((entry & PAGE_PRESENT) == 0) {
            if (entry == PAGE_POISONED) {
                pt[pte_idx] = 0;
                touched = 1;
            }
            continue;
        }
        backing_idx = sparse_mmap_backing_index_from_phys(entry & ~0xFFFULL);
        pt[pte_idx] = 0;
        invlpg_local(va);
        if (backing_idx >= 0) {
            release_backings[release_count++] = backing_idx;
        }
        if (release_count == HEAP_UNMAP_RELEASE_BATCH) {
            process_user_page_table_unlock(mm);
            sparse_mmap_flush_task(mm);
            for (uint32_t release = 0; release < release_count;
                 ++release) {
                sparse_mmap_user_alias_release(release_backings[release]);
                sparse_mmap_release_backing_index_local(
                    release_backings[release]);
            }
            release_count = 0;
            touched = 0;
            process_user_page_table_lock(mm);
        }
        touched = 1;
    }
    process_user_page_table_unlock(mm);
    if (touched) sparse_mmap_flush_task(mm);
    for (uint32_t release = 0; release < release_count; ++release) {
        sparse_mmap_user_alias_release(release_backings[release]);
        sparse_mmap_release_backing_index_local(release_backings[release]);
    }
    return 0;
}

int process_user_heap_unmap(task_t *t, uint64_t start, uint64_t len) {
    return process_user_heap_unmap_range(t, start, len);
}

static int process_user_heap_clone(task_t *dst, const task_t *src) {
    int dst_idx;
    int src_idx;
    dst = task_vm_owner_local(dst);
    src = task_vm_owner_local((task_t *)src);
    dst_idx = task_index(dst);
    src_idx = task_index((task_t *)src);
    if (!dst || !src || dst_idx < 0 || src_idx < 0 ||
        dst_idx >= USER_AS_MAX_TASKS || src_idx >= USER_AS_MAX_TASKS) {
        return -1;
    }
    for (uint32_t slot = 0; slot < USER_HEAP_TOTAL_PDE_CNT; ++slot) {
        uint64_t *src_pt = g_user_heap_pt[src_idx][slot];
        uint64_t base = USER_HEAP_BASE + ((uint64_t)slot << 21);
        if (!src_pt) continue;
        for (uint32_t pte = 0; pte < 512; ++pte) {
            uint64_t src_entry = src_pt[pte];
            uint64_t *dst_pt = 0;
            int src_backing_idx;
            uint64_t va;
            uint64_t shared;
            if ((src_entry & PAGE_PRESENT) == 0 &&
                src_entry != PAGE_POISONED)
                continue;
            va = base + ((uint64_t)pte << 12);
            if (process_user_heap_ensure_pt(dst, va, &dst_pt) < 0)
                goto fail;
            if ((src_entry & PAGE_PRESENT) == 0) {
                if (src_entry == PAGE_POISONED)
                    dst_pt[pte] = PAGE_POISONED;
                continue;
            }
            src_backing_idx = sparse_mmap_backing_index_from_phys(src_entry & ~0xFFFULL);
            if (!sparse_mmap_backing_ptr(src_backing_idx))
                goto fail;
            if (sparse_mmap_user_alias_acquire(dst, src_backing_idx) < 0)
                goto fail;
            sparse_mmap_retain_backing_index_local(src_backing_idx);
            shared = src_entry;
            if ((src_entry & PAGE_WRITE) != 0) {
                shared = (src_entry & ~PAGE_WRITE) | PAGE_COW;
                src_pt[pte] = shared;
            }
            dst_pt[pte] = shared;
        }
    }
    return 0;

fail:
    return -1;
}

static uint8_t *process_user_heap_byte_ptr(task_t *t, uint64_t addr, int write) {
    task_t *mm;
    int idx;
    uint32_t slot;
    uint32_t pte_idx;
    uint64_t *pt;
    uint64_t entry;
    uint8_t *page;
    if (!t) return 0;
    mm = task_vm_owner_local(t);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    if (user_heap_slot_for_addr(addr, &slot, &pte_idx) < 0 || slot >= USER_HEAP_TOTAL_PDE_CNT) return 0;
    if (!process_user_heap_addr_valid(mm, addr, write)) return 0;
    pt = g_user_heap_pt[idx][slot];
    if (!pt || (pt[pte_idx] & PAGE_PRESENT) == 0) {
        if (process_user_heap_commit_page(mm, addr, write) < 0) return 0;
        pt = g_user_heap_pt[idx][slot];
    }
    if (!pt) return 0;
    entry = pt[pte_idx];
    if ((entry & (PAGE_PRESENT | PAGE_USER)) != (PAGE_PRESENT | PAGE_USER)) return 0;
    if (write && (entry & PAGE_WRITE) == 0) {
        if ((entry & PAGE_COW) == 0 ||
            !private_pte_resolve_cow(mm, addr, &pt[pte_idx])) return 0;
        entry = pt[pte_idx];
    }
    page = (uint8_t *)edge_mmio_low_alias(entry & ~0xFFFULL);
    return page + (addr & (USER_PAGE_SIZE - 1ULL));
}

static int process_user_heap_handle_fault(task_t *t, uint64_t addr, int write) {
    task_t *mm;
    if (!t || addr < USER_HEAP_BASE || addr >= USER_HEAP_BASE + USER_HEAP_TOTAL_SIZE) return 0;
    mm = task_vm_owner_local(t);
    if (!mm) return 0;
    if (!process_user_heap_addr_valid(mm, addr, write)) return 0;
    if (write) {
        int idx = task_index(mm);
        uint32_t slot;
        uint32_t pte_idx;
        if (idx >= 0 && idx < USER_AS_MAX_TASKS &&
            user_heap_slot_for_addr(addr, &slot, &pte_idx) == 0 &&
            slot < USER_HEAP_TOTAL_PDE_CNT && g_user_heap_pt[idx][slot] &&
            (g_user_heap_pt[idx][slot][pte_idx] & PAGE_COW) != 0) {
            return private_pte_resolve_cow(
                mm, addr, &g_user_heap_pt[idx][slot][pte_idx]);
        }
    }
    if (process_user_heap_commit_page(mm, addr, write) < 0) return 0;
    /* A non-present-to-present leaf install does not invalidate a usable
     * translation on another CPU.  A sibling that already faulted the same
     * address performs its own local retry, so a synchronous remote shootdown
     * here only serializes every brk/heap first touch. */
    return 1;
}

void process_user_mmap_debug_dump_addr(const char *tag, task_t *t, uint64_t addr) {
    task_t *mm = task_vm_owner_local(t);
    int mm_idx = task_index(mm);
    uint64_t page = page_align_down_local(addr);
    edge_user_vma_t *v;
    const char *path = 0;
    uint64_t *pt;
    uint32_t pte_idx = 0;
    uint64_t pte = 0;
    int backing_idx = -1;
    uint8_t *page_ptr = 0;

    if (!tag) tag = "MMAPDBG";
    if (!mm) {
        printf("[%s] addr=0x%x%08x no-mm\n", tag, (uint32_t)(addr >> 32), (uint32_t)addr);
        return;
    }

    v = process_user_vma_for_addr(mm, addr);
    if (v && v->file_backed) path = process_user_mmap_file_path_for_slot(v->file_slot);
    printf("[%s] pid=%d mm=%d addr=0x%x%08x page=0x%x%08x vma=%s start=0x%x%08x end=0x%x%08x prot=0x%x flags=0x%x off=0x%x file=%s\n",
           tag,
           t ? t->pid : -1,
           mm->pid,
           (uint32_t)(addr >> 32), (uint32_t)addr,
           (uint32_t)(page >> 32), (uint32_t)page,
           v ? "yes" : "no",
           v ? (uint32_t)(v->start >> 32) : 0, v ? (uint32_t)v->start : 0,
           v ? (uint32_t)(v->end >> 32) : 0, v ? (uint32_t)v->end : 0,
           v ? v->prot : 0,
           v ? v->flags : 0,
           v ? (uint32_t)v->file_off : 0,
           path && path[0] ? path : "-");

    if (mm_idx >= 0 && mm_idx < USER_AS_MAX_TASKS &&
        addr < USER_LOW_LIMIT) {
        uint32_t low_page = (uint32_t)((addr - USER_LOW_BASE) >> 21);
        uint32_t pte_slot = (uint32_t)((addr >> 12) & 0x1ffu);
        uint64_t *low_pt = g_user_low_pt[mm_idx][low_page];
        uint64_t pte_entry = low_pt ? low_pt[pte_slot] : 0;
        uint64_t mapped_phys = pte_entry & ~0xfffULL;
        uint64_t hw_cr3 = cr3_read_local_process();
        int backing_idx = sparse_mmap_backing_index_from_phys(mapped_phys);
        printf("[%s] fixed-low idx=%d task_cr3=0x%x%08x hw_cr3=0x%x%08x "
               "pte=0x%x%08x mapped_phys=0x%x%08x backing=%d ref=%u zero=%u\n",
               tag, mm_idx,
               (uint32_t)(mm->cr3 >> 32), (uint32_t)mm->cr3,
               (uint32_t)(hw_cr3 >> 32), (uint32_t)hw_cr3,
               (uint32_t)(pte_entry >> 32), (uint32_t)pte_entry,
               (uint32_t)(mapped_phys >> 32), (uint32_t)mapped_phys,
               backing_idx,
               sparse_mmap_backing_refcnt_local(backing_idx),
               mapped_phys == fixed_user_zero_phys());
        return;
    }

    if (!sparse_mmap_range_ok_local(page, USER_PAGE_SIZE)) {
        printf("[%s] page is outside sparse mmap ranges\n", tag);
        return;
    }
    pt = sparse_mmap_lookup_pt(mm, page, 0);
    if (!pt || sparse_mmap_indices(page, 0, 0, &pte_idx) < 0) {
        printf("[%s] no sparse PTE page\n", tag);
        return;
    }
    pte = pt[pte_idx];
    backing_idx = sparse_mmap_backing_index_from_phys(pte & ~0xFFFULL);
    page_ptr = sparse_mmap_backing_ptr(backing_idx);
    printf("[%s] pte=0x%x%08x present=%u write=%u cow=%u filecache=%u backing=%d ref=%u phys=0x%x%08x ptr=0x%x\n",
           tag,
           (uint32_t)(pte >> 32), (uint32_t)pte,
           (unsigned)((pte & PAGE_PRESENT) != 0),
           (unsigned)((pte & PAGE_WRITE) != 0),
           (unsigned)((pte & PAGE_COW) != 0),
           (unsigned)((pte & PAGE_FILE_CACHE) != 0),
           backing_idx,
           sparse_mmap_backing_refcnt_local(backing_idx),
           (uint32_t)((pte & ~0xFFFULL) >> 32), (uint32_t)(pte & ~0xFFFULL),
           (uint32_t)(uintptr_t)page_ptr);
    if (page_ptr) {
        uint32_t rel = (uint32_t)(addr & (USER_PAGE_SIZE - 1ULL));
        uint32_t base = rel >= 16 ? rel - 16 : 0;
        printf("[%s] page-bytes off=0x%x:", tag, base);
        for (uint32_t i = 0; i < 48 && base + i < USER_PAGE_SIZE; ++i) {
            printf(" %x", (uint32_t)page_ptr[base + i]);
        }
        printf("\n");
    }
}

static void sparse_mmap_flush_task(task_t *t) {
    task_t *cur = process_current_task();
    edge_cpumask_t targets;
    uint32_t current_cpu = scheduler_cpu_id();
    int local_active;
    if (!t || !cur || !t->cr3) return;
    /*
     * Sparse mmap PTEs live in the mm owner slot.  Linux CLONE_VM threads may
     * fault through that owner's VMAs even when per-thread CR3 bookkeeping is
     * stale during exec/clone/exit churn.  Reload the real owner CR3 for any
     * current thread that belongs to this mm; otherwise a freshly populated
     * page can remain invisible in hardware and later be misdiagnosed as a
     * fatal userspace page fault.
     */
    local_active = cr3_read_local_process() == t->cr3 || cur == t ||
                   task_vm_owner_local(cur) == t || cur->cr3 == t->cr3;
    if (local_active) {
        cr3_write(t->cr3);
    }
    /*
     * CLONE_VM threads can fault the same address space concurrently on
     * different CPUs.  A leaf changed from non-present to present, or from
     * read-only to writable, may otherwise remain cached on a sibling CPU and
     * produce a second protection fault after the shared PTE is already valid.
     * Target only CPUs currently executing this mm; a task scheduled later
     * reloads CR3 as part of its normal context switch and observes the update.
     */
    /* The scheduler records the active mm before loading its CR3 and removes
     * the previous mm at the same transition.  CPUs that switch into this mm
     * after the mask snapshot load CR3 after the PTE publication and therefore
     * already observe the update. */
    if (local_active) process_user_mm_cpu_enter(t, current_cpu);
    edge_cpumask_init(&targets, edge_smp_nr_cpu_ids());
    {
        uint64_t mm_mask = __atomic_load_n(&t->user_mm_cpu_mask,
                                           __ATOMIC_ACQUIRE);
        uint64_t online_mask = edge_smp_online_mask64();

        mm_mask &= online_mask;
        for (uint32_t cpu = 0; cpu < targets.nbits && cpu < 64u; ++cpu) {
            if (cpu != current_cpu && (mm_mask & (UINT64_C(1) << cpu)))
                (void)edge_cpumask_set_cpu(&targets, cpu);
        }
    }
    if (edge_cpumask_weight(&targets))
        (void)edge_smp_call(&targets, EDGE_SMP_CALL_TLB_FLUSH);
}

static void sparse_mmap_activate_task(task_t *t) {
    task_t *cur = process_current_task();
    uint64_t hardware_cr3;

    if (!t || !cur || !t->cr3) return;
    hardware_cr3 = cr3_read_local_process();
    if (hardware_cr3 == t->cr3) return;
    /*
     * INVLPG is sufficient after a leaf-PTE change when this mm is already
     * active.  A CLONE_VM thread can temporarily carry stale per-thread CR3
     * bookkeeping, however, so install the owner CR3 once before a range walk.
     * The x86 scheduler is currently uniprocessor-only; SMP will require an mm
     * lock plus remote invalidation rather than this local activation rule.
     */
    if (cur == t || task_vm_owner_local(cur) == t || cur->cr3 == t->cr3)
        cr3_write(t->cr3);
}

static uint64_t *sparse_mmap_lookup_pt(task_t *t, uint64_t va, uint32_t *pde_slot_out) {
    int idx = task_index(t);
    uint32_t pde_idx = 0;
    uint64_t *pde_entry;
    uint64_t pde;
    if (!t || idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    if (sparse_mmap_indices(va, 0, &pde_idx, 0) < 0) return 0;
    pde_entry = sparse_mmap_pde_entry(idx, va, 0);
    if (!pde_entry) return 0;
    pde = *pde_entry;
    if ((pde & PAGE_PRESENT) == 0 || (pde & PAGE_PS) != 0) return 0;
    if (pde_slot_out) *pde_slot_out = pde_idx;
    return fixed_user_pt_ptr_from_phys(pde);
}

typedef struct sparse_mmap_pt_span {
    uint64_t *pt;
    uint64_t start;
    uint64_t end;
} sparse_mmap_pt_span_t;

static uint64_t sparse_mmap_next_level_boundary(uint64_t va,
                                                uint32_t shift,
                                                uint64_t limit) {
    uint64_t span = 1ULL << shift;
    uint64_t next = (va & ~(span - 1ULL)) + span;

    if (next <= va || next > limit) return limit;
    return next;
}

static int sparse_mmap_next_present_pt(task_t *t, uint64_t *cursor,
                                       uint64_t end,
                                       sparse_mmap_pt_span_t *span_out) {
    uint64_t va;
    int idx;

    if (!t || !cursor || !span_out) return -1;
    idx = task_index(t);
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    va = page_align_down_local(*cursor);
    while (va < end) {
        uint32_t pml4_idx = (uint32_t)((va >> 39) & 0x1ffu);
        uint32_t pdpt_idx = (uint32_t)((va >> 30) & 0x1ffu);
        uint32_t pde_idx = (uint32_t)((va >> 21) & 0x1ffu);
        uint64_t pml4_end =
            sparse_mmap_next_level_boundary(va, 39, end);
        uint64_t pdpt_end =
            sparse_mmap_next_level_boundary(va, 30, pml4_end);
        uint64_t pde_end =
            sparse_mmap_next_level_boundary(va, 21, pdpt_end);
        uint64_t *pdpt = sparse_mmap_pdpt_root(idx, pml4_idx, 0);
        uint64_t pdpte;
        uint64_t *pd;
        uint64_t pde;
        uint64_t *pt;

        /*
         * Walk by hardware hierarchy rather than by virtual page.  A browser
         * commonly reserves hundreds of gigabytes while touching only a few
         * megabytes.  Missing PML4, PDPT, and PD entries therefore skip 512 GiB,
         * 1 GiB, and 2 MiB respectively instead of paying one lookup per 4 KiB.
         */
        if (!pdpt) {
            va = pml4_end;
            continue;
        }
        pdpte = pdpt[pdpt_idx];
        if ((pdpte & PAGE_PRESENT) == 0 || (pdpte & PAGE_PS) != 0) {
            va = pdpt_end;
            continue;
        }
        pd = fixed_user_pt_ptr_from_phys(pdpte);
        if (!pd) return -1;
        pde = pd[pde_idx];
        if ((pde & PAGE_PRESENT) == 0 || (pde & PAGE_PS) != 0) {
            va = pde_end;
            continue;
        }
        pt = fixed_user_pt_ptr_from_phys(pde);
        if (!pt) return -1;
        span_out->pt = pt;
        span_out->start = va;
        span_out->end = pde_end;
        *cursor = pde_end;
        return 1;
    }
    *cursor = end;
    return 0;
}

static int process_user_mmap_present_pte_allows_fault(task_t *mm, const edge_user_vma_t *v,
                                                       uint64_t page, int write) {
    uint64_t *pt;
    uint32_t pte_idx = 0;
    uint64_t pte;
    static int present_retry_log_budget = 0;

    if (!mm || !v) return 0;
    if (write && (v->prot & 0x2u) == 0) return 0;
    if (!write && (v->prot & 0x5u) == 0) return 0;
    pt = sparse_mmap_lookup_pt(mm, page, 0);
    if (!pt || sparse_mmap_indices(page, 0, 0, &pte_idx) < 0) return 0;
    pte = pt[pte_idx];
    if ((pte & (PAGE_PRESENT | PAGE_USER)) != (PAGE_PRESENT | PAGE_USER)) return 0;
    if (write && (pte & PAGE_WRITE) == 0) {
        if (v->file_backed &&
            (v->flags & USER_MAP_SHARED_FLAG) != 0 &&
            (pte & PAGE_FILE_CACHE) != 0) {
            uint64_t expected = pte;

            if (__atomic_compare_exchange_n(
                    &pt[pte_idx], &expected, pte | PAGE_WRITE, 0,
                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                process_user_mmap_file_page_write_notify(
                    v->file_slot, v->file_off + page - v->start);
            }
            sparse_mmap_activate_task(mm);
            invlpg_local(page);
            return 1;
        }
        return 0;
    }

    /*
     * A valid sparse mmap PTE means the Linux-visible access is already backed.
     * This can still arrive here after a lazy file-mmap install or CR3/TLB
     * repair in another CLONE_VM thread.  Linux retries these faults after the
     * page table is made present; EdgeOS must do the same instead of calling the
     * file-population path again, where "already mapped" looks like an error
     * and incorrectly kills GTK/XFCE processes.
     */
    sparse_mmap_activate_task(mm);
    invlpg_local(page);
    if (present_retry_log_budget > 0) {
        task_t *cur = process_current_task();
        printf("[mmap-fault] present-retry pid=%d mm=%d addr=0x%x write=%d prot=0x%x pte=0x%x hwcr3=0x%x mmcr3=0x%x budget=%d\n",
               cur ? cur->pid : -1, mm->pid, (uint32_t)page, write, v->prot,
               (uint32_t)pte, (uint32_t)cr3_read_local_process(),
               (uint32_t)mm->cr3, present_retry_log_budget - 1);
        present_retry_log_budget--;
    }
    return 1;
}

static edge_user_vma_t *process_user_vma_for_addr(task_t *mm, uint64_t addr) {
    int task_slot;
    int live;

    if (!mm) return 0;
    live = process_user_vma_live_count(mm);
    task_slot = task_index(mm);
    if (task_slot >= 0 && task_slot < USER_AS_MAX_TASKS) {
        for (uint32_t cache_slot = 0;
             cache_slot < USER_VMA_LOOKUP_CACHE_SLOTS; ++cache_slot) {
            int vma_slot = g_user_vma_lookup_cache[task_slot][cache_slot];
            edge_user_vma_t *v;

            if (vma_slot < 0 || vma_slot >= live) continue;
            v = &mm->user_vmas[vma_slot];
            if (v->end > v->start &&
                addr >= v->start && addr < v->end) {
                return v;
            }
        }
    }
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &mm->user_vmas[i];
        if (v->end <= v->start) continue;
        if (addr >= v->start && addr < v->end) {
            if (task_slot >= 0 && task_slot < USER_AS_MAX_TASKS) {
                uint32_t cache_slot =
                    g_user_vma_lookup_cache_next[task_slot] %
                    USER_VMA_LOOKUP_CACHE_SLOTS;
                g_user_vma_lookup_cache[task_slot][cache_slot] =
                    (int16_t)i;
                g_user_vma_lookup_cache_next[task_slot] =
                    (uint8_t)((cache_slot + 1u) %
                              USER_VMA_LOOKUP_CACHE_SLOTS);
            }
            return v;
        }
    }
    return 0;
}

static int process_user_vma_sort_key_after(const edge_user_vma_t *left,
                                           const edge_user_vma_t *right) {
    uint64_t left_start =
        left->end > left->start ? left->start : UINT64_MAX;
    uint64_t right_start =
        right->end > right->start ? right->start : UINT64_MAX;

    if (left_start != right_start) return left_start > right_start;
    return left->end > right->end;
}

static int process_user_vma_sort_by_start(task_t *mm) {
    int live = process_user_vma_live_count(mm);

    /*
     * Clone walks populated PTEs in ascending virtual-address order. Keep the
     * compact VMA array ordered for that walk so COW policy does not perform a
     * full VMA scan for every resident page of a large browser process.
     */
    for (int gap = live / 2; gap > 0; gap /= 2) {
        for (int index = gap; index < live; ++index) {
            edge_user_vma_t value = mm->user_vmas[index];
            int position = index;

            while (position >= gap &&
                   process_user_vma_sort_key_after(
                       &mm->user_vmas[position - gap], &value)) {
                mm->user_vmas[position] =
                    mm->user_vmas[position - gap];
                position -= gap;
            }
            mm->user_vmas[position] = value;
        }
    }
    return live;
}

static edge_user_vma_t *process_user_vma_for_addr_sorted(
    task_t *mm, int live, uint64_t addr) {
    int low = 0;
    int high = live;

    while (low < high) {
        int middle = low + (high - low) / 2;
        if (mm->user_vmas[middle].start <= addr)
            low = middle + 1;
        else
            high = middle;
    }
    if (low <= 0) return 0;
    if (addr >= mm->user_vmas[low - 1].start &&
        addr < mm->user_vmas[low - 1].end)
        return &mm->user_vmas[low - 1];
    return 0;
}

static edge_user_vma_t *process_user_vma_grow_down_for_fault(task_t *mm, uint64_t page, int write) {
    edge_user_vma_t *best = 0;
    uint64_t best_delta = ~0ULL;
    int live;
    if (!mm || !write) return 0;
    live = process_user_vma_live_count(mm);
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &mm->user_vmas[i];
        uint64_t delta;
        if (v->end <= v->start) continue;
        if (v->file_backed) continue;
        if ((v->prot & 0x2u) == 0) continue;
        if (page >= v->start) continue;
        delta = v->start - page;
        /*
         * Linux grows VM_GROWSDOWN stack-like VMAs on a near-below write fault.
         * EdgeOS does not yet preserve a dedicated grow-down VMA bit for every
         * libc stack mapping, so keep this recovery narrow: only anonymous,
         * writable sparse VMAs, only within a small guard-style gap, and never
         * across an existing VMA.  Red flag: do not make this a broad "any
         * sparse no-vma write is OK" rule; that would hide real use-after-unmap
         * bugs and diverge from Linux SIGSEGV behavior.
         */
        if (delta > (1024ULL * 1024ULL)) continue;
        if (delta < best_delta) {
            best = v;
            best_delta = delta;
        }
    }
    if (!best) return 0;
    for (int i = 0; i < live; ++i) {
        edge_user_vma_t *v = &mm->user_vmas[i];
        if (v == best || v->end <= v->start) continue;
        if (page + USER_PAGE_SIZE <= v->start || page >= v->end) continue;
        return 0;
    }
    best->start = page;
    return best;
}

static int process_user_mmap_resolve_cow(task_t *mm, uint64_t addr) {
    int idx;
    uint64_t page;
    uint64_t *pt;
    uint32_t pte_idx = 0;
    uint64_t pte;
    int old_backing_idx;
    uint8_t *old_page;
    edge_user_vma_t *v;
    int new_backing_idx = -1;
    uint8_t *new_page;

    if (!mm) return 0;
    mm = task_vm_owner_local(mm);
    process_user_page_table_lock(mm);
    idx = task_index(mm);
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) goto out;
    page = page_align_down_local(addr);
    v = process_user_vma_for_addr(mm, page);
    if (!v || (v->prot & 0x2u) == 0) goto out;
    pt = sparse_mmap_lookup_pt(mm, page, 0);
    if (!pt) goto out;
    if (sparse_mmap_indices(page, 0, 0, &pte_idx) < 0) goto out;
    pte = pt[pte_idx];
    if ((pte & PAGE_PRESENT) == 0 || (pte & PAGE_COW) == 0) goto out;
    old_backing_idx = sparse_mmap_backing_index_from_phys(pte & ~0xFFFULL);
    old_page = (pte & ~0xFFFULL) == fixed_user_zero_phys() ? 0 :
        sparse_mmap_backing_ptr(old_backing_idx);
    if ((pte & ~0xFFFULL) != fixed_user_zero_phys() && !old_page) goto out;

    if (old_backing_idx >= 0 &&
        sparse_mmap_backing_refcnt_local(old_backing_idx) <= 1) {
        pt[pte_idx] = (pte | PAGE_WRITE | PAGE_USER) &
                      ~(PAGE_COW | PAGE_FILE_CACHE);
        sparse_mmap_activate_task(mm);
        invlpg_local(page);
        process_user_page_table_unlock(mm);
        sparse_mmap_flush_task(mm);
        return 1;
    }

    if (old_backing_idx >= 0)
        sparse_mmap_retain_backing_index_local(old_backing_idx);
    process_user_page_table_unlock(mm);

    new_backing_idx = old_page ?
        sparse_mmap_alloc_backing_index_mode_local(0) :
        sparse_mmap_alloc_backing_index_local();
    if (new_backing_idx < 0) goto release_source;
    new_page = sparse_mmap_backing_ptr(new_backing_idx);
    if (!new_page) goto release_new;
    if (old_page) memcpy(new_page, old_page, USER_PAGE_SIZE);
    if (sparse_mmap_user_alias_acquire(mm, new_backing_idx) < 0)
        goto release_new;

    process_user_page_table_lock(mm);
    pt = sparse_mmap_lookup_pt(mm, page, 0);
    if (!pt || sparse_mmap_indices(page, 0, 0, &pte_idx) < 0 ||
        pt[pte_idx] != pte) {
        int resolved = pt &&
            (pt[pte_idx] & (PAGE_PRESENT | PAGE_WRITE | PAGE_USER)) ==
            (PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
        process_user_page_table_unlock(mm);
        sparse_mmap_user_alias_release(new_backing_idx);
        sparse_mmap_release_backing_index_local(new_backing_idx);
        if (old_backing_idx >= 0)
            sparse_mmap_release_backing_index_local(old_backing_idx);
        return resolved;
    }
    pt[pte_idx] = sparse_mmap_backing_phys(new_backing_idx) |
                  PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    sparse_mmap_activate_task(mm);
    invlpg_local(page);
    process_user_page_table_unlock(mm);
    sparse_mmap_flush_task(mm);
    if (old_backing_idx >= 0) {
        sparse_mmap_user_alias_release(old_backing_idx);
        sparse_mmap_release_backing_index_local(old_backing_idx);
        sparse_mmap_release_backing_index_local(old_backing_idx);
    }
    return 1;

release_new:
    if (new_backing_idx >= 0)
        sparse_mmap_release_backing_index_local(new_backing_idx);
release_source:
    if (old_backing_idx >= 0)
        sparse_mmap_release_backing_index_local(old_backing_idx);
    return 0;

out:
    process_user_page_table_unlock(mm);
    return 0;
}

static int sparse_mmap_pt_empty(const uint64_t *pt) {
    if (!pt) return 1;
    for (int i = 0; i < 512; ++i) {
        if (pt[i] != 0) return 0;
    }
    return 1;
}

static int sparse_mmap_prune_boundary(uint64_t va, uint64_t end) {
    uint64_t next = va + USER_PAGE_SIZE;
    if (next < va) return 1;
    return next >= end || (next & (USER_REGION_SIZE - 1ULL)) == 0;
}

static void sparse_mmap_defer_table_release(uint64_t **release_list,
                                            uint64_t *table) {
    if (!release_list || !table) return;
    table[0] = (uint64_t)(uintptr_t)*release_list;
    *release_list = table;
}

static void sparse_mmap_release_deferred_tables(uint64_t *release_list) {
    while (release_list) {
        uint64_t *table = release_list;
        release_list = (uint64_t *)(uintptr_t)table[0];
        sparse_mmap_release_table(table);
    }
}

static int sparse_mmap_prune_empty_tables_deferred(
    int idx, uint64_t va, uint64_t **release_list) {
    uint32_t pml4_idx;
    uint32_t pdpt_idx;
    uint32_t pde_idx;
    uint64_t *pdpt;
    uint64_t *pd;
    uint64_t *pt;
    uint64_t *release_pt = 0;
    uint64_t *release_pd = 0;
    uint64_t *release_pdpt = 0;
    int root_slot;
    int changed = 0;

    if (idx < 0 || idx >= USER_AS_MAX_TASKS ||
        sparse_mmap_indices(va, &pdpt_idx, &pde_idx, 0) < 0) {
        return 0;
    }
    pml4_idx = (uint32_t)((va >> 39) & 0x1ffu);
    pdpt = sparse_mmap_pdpt_root(idx, pml4_idx, 0);
    if (!pdpt) return 0;
    if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0) {
        if (pml4_idx == USER_LOW_SPARSE_MMAP_PML4_IDX ||
            !sparse_mmap_pt_empty(pdpt)) {
            return 0;
        }
        root_slot = sparse_mmap_high_root_slot(pml4_idx);
        if (root_slot < 0 || g_pdpt_sparse[idx][root_slot] != pdpt)
            return 0;
        g_pdpt_sparse[idx][root_slot] = 0;
        g_pml4[idx][pml4_idx] = 0;
        release_pdpt = pdpt;
        changed = 1;
        goto flush_and_release;
    }
    if ((pdpt[pdpt_idx] & PAGE_PS) != 0) return 0;
    pd = fixed_user_pt_ptr_from_phys(pdpt[pdpt_idx]);
    if (!pd) return 0;
    if ((pd[pde_idx] & PAGE_PRESENT) != 0) {
        if ((pd[pde_idx] & PAGE_PS) != 0) return 0;
        pt = fixed_user_pt_ptr_from_phys(pd[pde_idx]);
        if (!pt || !sparse_mmap_pt_empty(pt)) return 0;
        pd[pde_idx] = 0;
        release_pt = pt;
        changed = 1;
    }
    if (!sparse_mmap_pt_empty(pd)) goto flush_and_release;

    pdpt[pdpt_idx] = 0;
    release_pd = pd;
    changed = 1;
    if (pml4_idx == USER_LOW_SPARSE_MMAP_PML4_IDX ||
        !sparse_mmap_pt_empty(pdpt)) {
        goto flush_and_release;
    }

    root_slot = sparse_mmap_high_root_slot(pml4_idx);
    if (root_slot < 0 || g_pdpt_sparse[idx][root_slot] != pdpt)
        goto flush_and_release;
    g_pdpt_sparse[idx][root_slot] = 0;
    g_pml4[idx][pml4_idx] = 0;
    release_pdpt = pdpt;

flush_and_release:
    /*
     * Empty page-table pages form an intrusive deferred-release list after
     * their parent entries have been detached.  This lets a large munmap or
     * mremap perform one address-space flush before recycling every detached
     * table, rather than reloading CR3 once per 2 MiB region.
     */
    sparse_mmap_defer_table_release(release_list, release_pt);
    sparse_mmap_defer_table_release(release_list, release_pd);
    sparse_mmap_defer_table_release(release_list, release_pdpt);
    return changed;
}

static int sparse_mmap_prune_empty_tables(int idx, uint64_t va) {
    uint64_t *release_list = 0;
    int changed =
        sparse_mmap_prune_empty_tables_deferred(idx, va, &release_list);

    /*
     * Callers that cannot batch pruning still detach the complete hierarchy
     * before recycling it.  Reloading an active mm is sufficient on the current
     * UP x86 scheduler; an SMP implementation must add remote shootdowns.
     */
    if (changed) sparse_mmap_flush_task(&g_tasks[idx]);
    sparse_mmap_release_deferred_tables(release_list);
    return changed;
}

static int sparse_mmap_install_roots(int idx) {
    uint64_t uflags = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    int changed = 0;
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;
    for (uint32_t slot = 0; slot < USER_SPARSE_MMAP_PML4_COUNT;
         ++slot) {
        uint64_t *root = g_pdpt_sparse[idx][slot];
        uint32_t pml4_idx = USER_SPARSE_MMAP_PML4_FIRST + slot;
        uint64_t expected;
        if (!root) continue;
        expected = fixed_user_pt_phys_from_ptr(root) | uflags;
        if (g_pml4[idx][pml4_idx] == expected) continue;
        g_pml4[idx][pml4_idx] = expected;
        changed = 1;
    }
    return changed;
}

static int sparse_mmap_ensure_pt(task_t *t, uint64_t va, uint64_t **pt_out) {
    int idx = task_index(t);
    if (!t || idx < 0 || idx >= USER_AS_MAX_TASKS || !pt_out) return -1;
    *pt_out = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        uint64_t *pde_entry = sparse_mmap_pde_entry(idx, va, 1);
        uint64_t *pt;
        uint64_t pde;

        if (!pde_entry) {
            if (!sparse_mmap_prune_empty_tables(idx, va)) break;
            continue;
        }
        pde = *pde_entry;
        if ((pde & PAGE_PRESENT) != 0 && (pde & PAGE_PS) == 0) {
            *pt_out = fixed_user_pt_ptr_from_phys(pde);
            return *pt_out ? 0 : -1;
        }
        pt = fixed_user_pt_alloc(
            idx, "sparse-pt",
            (uint32_t)((va >> 21) & 0x1ffu));
        if (pt) {
            *pde_entry = fixed_user_pt_phys_from_ptr(pt) |
                         PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
            *pt_out = pt;
            return 0;
        }
        if (!sparse_mmap_prune_empty_tables(idx, va)) break;
    }
    sparse_mmap_log_oom_local(t, "pt", va);
    return -1;
}

static void process_user_mmap_unmap_resident(task_t *t, uint64_t start,
                                             uint64_t len) {
    enum { UNMAP_RELEASE_BATCH = 256 };
    sparse_mmap_pt_span_t span;
    uint64_t *release_list = 0;
    uint64_t cursor;
    uint64_t end;
    int release_backings[UNMAP_RELEASE_BATCH];
    uint32_t release_count = 0;
    int idx;
    int hierarchy_changed = 0;
    int leaves_changed = 0;
    int walk_result;

    if (!t || len == 0) return;
    t = task_vm_owner_local(t);
    idx = task_index(t);
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start) return;
    if (!sparse_mmap_range_ok_local(start, end - start)) return;
    process_user_page_table_lock(t);
#ifdef CONFIG_FS_SWAP
    (void)edge_swap_map_drop_range(t->cr3, start, end - start);
#endif
    sparse_mmap_activate_task(t);
    cursor = start;
    while ((walk_result =
                sparse_mmap_next_present_pt(t, &cursor, end, &span)) > 0) {
        for (uint64_t va = span.start; va < span.end;
             va += USER_PAGE_SIZE) {
            uint32_t pte_idx = (uint32_t)((va >> 12) & 0x1ffu);
            uint64_t pte = span.pt[pte_idx];
            int backing_idx;

            if ((pte & PAGE_PRESENT) == 0) {
                if (pte == PAGE_POISONED) {
                    span.pt[pte_idx] = 0;
                    leaves_changed = 1;
                }
                continue;
            }
            backing_idx =
                sparse_mmap_backing_index_from_phys(pte & ~0xFFFULL);
            span.pt[pte_idx] = 0;
            invlpg_local(va);
            if (backing_idx >= 0) {
                release_backings[release_count++] = backing_idx;
            }
            leaves_changed = 1;
            if (release_count == UNMAP_RELEASE_BATCH) {
                process_user_page_table_unlock(t);
                sparse_mmap_flush_task(t);
                for (uint32_t release = 0; release < release_count;
                     ++release) {
                    sparse_mmap_user_alias_release(
                        release_backings[release]);
                    sparse_mmap_release_backing_index_local(
                        release_backings[release]);
                }
                release_count = 0;
                leaves_changed = 0;
                process_user_page_table_lock(t);
            }
        }
        if (sparse_mmap_pt_empty(span.pt) &&
            sparse_mmap_prune_empty_tables_deferred(
                idx, span.start, &release_list)) {
            hierarchy_changed = 1;
        }
    }
    if (walk_result < 0) {
        printf("[mmap-unmap] invalid page-table hierarchy pid=%d range=0x%x-0x%x\n",
               t->pid, (uint32_t)start, (uint32_t)end);
    }
    process_user_page_table_unlock(t);
    if (leaves_changed || hierarchy_changed) sparse_mmap_flush_task(t);
    for (uint32_t release = 0; release < release_count; ++release) {
        sparse_mmap_user_alias_release(release_backings[release]);
        sparse_mmap_release_backing_index_local(release_backings[release]);
    }
    sparse_mmap_release_deferred_tables(release_list);
}

void process_user_mmap_unmap(task_t *t, uint64_t start, uint64_t len) {
    process_user_mmap_unmap_resident(t, start, len);
}

void process_user_mmap_unmap_fast(task_t *t, uint64_t start, uint64_t len) {
    process_user_mmap_unmap_resident(t, start, len);
}

int process_user_mmap_unmap_page_if_backing(task_t *t, uint64_t address,
                                            int backing_index) {
    uint64_t *page_table;
    uint64_t page;
    uint32_t pte_index;
    uint64_t pte;

    if (!t || backing_index < 0) return -1;
    t = task_vm_owner_local(t);
    page = page_align_down_local(address);
    page_table = sparse_mmap_lookup_pt(t, page, 0);
    if (!page_table || sparse_mmap_indices(
            page, 0, 0, &pte_index) < 0)
        return 0;
    pte = __atomic_load_n(&page_table[pte_index], __ATOMIC_ACQUIRE);
    if ((pte & PAGE_PRESENT) == 0 ||
        sparse_mmap_backing_index_from_phys(
            pte & ~0xFFFULL) != backing_index)
        return 0;
    process_user_mmap_unmap_resident(t, page, USER_PAGE_SIZE);
    return 1;
}

int process_user_mmap_move_present(task_t *t, uint64_t old_start, uint64_t new_start, uint64_t len) {
    sparse_mmap_pt_span_t span;
    uint64_t cursor;
    uint64_t old_end;
    int idx;
    int result = 0;
    int walk_result;

    if (!t || len == 0 || old_start == new_start) return 0;
    t = task_vm_owner_local(t);
    idx = task_index(t);
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    old_start = page_align_down_local(old_start);
    new_start = page_align_down_local(new_start);
    len = page_align_up_local(len);
    old_end = old_start + len;
    if (old_end < old_start || new_start + len < new_start) return -1;
    if (!sparse_mmap_range_ok_local(old_start, len) ||
        !sparse_mmap_range_ok_local(new_start, len)) {
        return -1;
    }
    if (new_start < old_end && new_start + len > old_start) return -1;
    sparse_mmap_activate_task(t);

    /*
     * Linux mremap(2) moves PTEs; it does not read every byte through
     * userspace and rematerialize lazy file mappings as anonymous memory.
     * Pre-create destination PTE pages before touching the old PTEs so ENOMEM
     * cannot leave a half-moved VMA behind.
     */
    cursor = old_start;
    while ((walk_result =
                sparse_mmap_next_present_pt(t, &cursor, old_end, &span)) > 0) {
        uint64_t cached_destination_base = UINT64_MAX;
        uint64_t *cached_destination_pt = 0;

        for (uint64_t old_va = span.start; old_va < span.end;
             old_va += USER_PAGE_SIZE) {
            uint32_t old_pte_idx =
                (uint32_t)((old_va >> 12) & 0x1ffu);
            uint64_t new_va;
            uint64_t destination_base;
            uint32_t new_pte_idx;

            if ((span.pt[old_pte_idx] & PAGE_PRESENT) == 0) continue;
            new_va = new_start + (old_va - old_start);
            destination_base = new_va & ~(USER_REGION_SIZE - 1ULL);
            if (destination_base != cached_destination_base) {
                if (sparse_mmap_ensure_pt(
                        t, new_va, &cached_destination_pt) < 0) {
                    process_user_mmap_unmap(t, new_start, len);
                    return -1;
                }
                cached_destination_base = destination_base;
            }
            new_pte_idx = (uint32_t)((new_va >> 12) & 0x1ffu);
            if ((cached_destination_pt[new_pte_idx] & PAGE_PRESENT) != 0) {
                process_user_mmap_unmap(t, new_start, len);
                return -1;
            }
        }
    }
    if (walk_result < 0) {
        process_user_mmap_unmap(t, new_start, len);
        return -1;
    }

    cursor = old_start;
    while ((walk_result =
                sparse_mmap_next_present_pt(t, &cursor, old_end, &span)) > 0) {
        uint64_t cached_destination_base = UINT64_MAX;
        uint64_t *cached_destination_pt = 0;

        for (uint64_t old_va = span.start; old_va < span.end;
             old_va += USER_PAGE_SIZE) {
            uint32_t old_pte_idx =
                (uint32_t)((old_va >> 12) & 0x1ffu);
            uint64_t pte = span.pt[old_pte_idx];
            uint64_t new_va;
            uint64_t destination_base;
            uint32_t new_pte_idx;

            if ((pte & PAGE_PRESENT) == 0) continue;
            new_va = new_start + (old_va - old_start);
            destination_base = new_va & ~(USER_REGION_SIZE - 1ULL);
            if (destination_base != cached_destination_base) {
                cached_destination_pt =
                    sparse_mmap_lookup_pt(t, new_va, 0);
                if (!cached_destination_pt) {
                    result = -1;
                    goto move_finish;
                }
                cached_destination_base = destination_base;
            }
            new_pte_idx = (uint32_t)((new_va >> 12) & 0x1ffu);
            if ((cached_destination_pt[new_pte_idx] & PAGE_PRESENT) != 0) {
                result = -1;
                goto move_finish;
            }
            cached_destination_pt[new_pte_idx] = pte;
            span.pt[old_pte_idx] = 0;
            invlpg_local(old_va);
            invlpg_local(new_va);
        }
    }
    if (walk_result < 0) result = -1;

move_finish:
#ifdef CONFIG_FS_SWAP
    if (result == 0 && edge_swap_map_move_range(
            t->cr3, old_start, new_start, len) < 0)
        result = -1;
#endif
    /*
     * Keep the source page-table hierarchy attached until the complete move
     * succeeds.  Source and destination may occupy different leaves below the
     * same upper-level table.  Pruning an emptied source leaf while the walk is
     * still active can invalidate a later lookup and leave a failed mremap with
     * some source pages already moved.  The caller unmaps the old range after
     * success and performs the normal batched pruning there.
     *
     * If an invariant still fails after movement starts, restore every moved
     * page before returning an error.  The destination was verified empty
     * above, so each present destination PTE in this range belongs to this
     * transaction.  Source page-table leaves are still attached by design.
     */
    if (result < 0) {
        uint64_t destination_end = new_start + len;

        cursor = new_start;
        while ((walk_result = sparse_mmap_next_present_pt(
                    t, &cursor, destination_end, &span)) > 0) {
            for (uint64_t new_va = span.start; new_va < span.end;
                 new_va += USER_PAGE_SIZE) {
                uint32_t new_pte_idx =
                    (uint32_t)((new_va >> 12) & 0x1ffu);
                uint64_t pte = span.pt[new_pte_idx];
                uint64_t old_va;
                uint64_t *source_pt;
                uint32_t old_pte_idx;

                if ((pte & PAGE_PRESENT) == 0) continue;
                old_va = old_start + (new_va - new_start);
                source_pt = sparse_mmap_lookup_pt(t, old_va, 0);
                if (!source_pt) continue;
                old_pte_idx = (uint32_t)((old_va >> 12) & 0x1ffu);
                if ((source_pt[old_pte_idx] & PAGE_PRESENT) != 0)
                    continue;
                source_pt[old_pte_idx] = pte;
                span.pt[new_pte_idx] = 0;
                invlpg_local(old_va);
                invlpg_local(new_va);
            }
        }
    }
    return result;
}

static int process_user_mmap_consume_prepared_alias(
        task_t *t, int backing_idx, int *prepared_alias) {
    if (prepared_alias && *prepared_alias) {
        *prepared_alias = 0;
        return 0;
    }
    if (sparse_mmap_user_alias_acquire(t, backing_idx) < 0)
        return -1;
    sparse_mmap_retain_backing_index_local(backing_idx);
    return 0;
}

static int process_user_mmap_map_backing_page_ex_locked(
        task_t *t, uint64_t va, int backing_idx, int writable,
        int file_cache, int private_cow, int invalidate,
        int replace_present, int *prepared_alias) {
    uint64_t *pt = 0;
    uint32_t pte_idx = 0;
    uint8_t *page_ptr;
    static int stale_present_log_budget = 32;

    if (!t) return -1;
    t = task_vm_owner_local(t);
    sparse_mmap_activate_task(t);
    page_ptr = sparse_mmap_backing_ptr(backing_idx);
    if (!page_ptr) return -1;
    if (fixed_user_addr(va)) {
        uint64_t *entryp;
        uint64_t entry;
        int idx = task_index(t);

        if (idx < 0 || idx >= USER_AS_MAX_TASKS ||
            (va & (USER_PAGE_SIZE - 1ULL)) != 0)
            return -1;
        entryp = fixed_user_pte_for_addr_idx(idx, va);
        if (!entryp)
            entryp = fixed_user_pte_recover_idx(idx, va);
        if (!entryp) return -1;
        entry = *entryp;
        if ((entry & PAGE_PRESENT) != 0) {
            int old_backing_idx =
                sparse_mmap_backing_index_from_phys(entry & ~0xFFFULL);
            if (!replace_present) return 1;
            if (old_backing_idx == backing_idx &&
                (entry & PAGE_USER) != 0) {
                if (invalidate) invlpg_local(va);
                return 0;
            }
            return -1;
        }
        if (process_user_mmap_consume_prepared_alias(
                t, backing_idx, prepared_alias) < 0)
            return -1;
        *entryp = sparse_mmap_backing_phys(backing_idx) |
                  PAGE_PRESENT | PAGE_USER |
                  (writable ? PAGE_WRITE : 0) |
                  (file_cache ? PAGE_FILE_CACHE : 0) |
                  (private_cow ? PAGE_COW : 0);
        if (invalidate) invlpg_local(va);
        return 0;
    }
    if (!sparse_mmap_range_ok_local(va, USER_PAGE_SIZE)) return -1;
    if ((va & (USER_PAGE_SIZE - 1ULL)) != 0) return -1;
    if (sparse_mmap_ensure_pt(t, va, &pt) < 0) return -1;
    if (sparse_mmap_indices(va, 0, 0, &pte_idx) < 0) return -1;
    if ((pt[pte_idx] & PAGE_PRESENT) != 0) {
        uint64_t pte = pt[pte_idx];
        int old_backing_idx =
            sparse_mmap_backing_index_from_phys(pte & ~0xFFFULL);

        if (!replace_present) return 1;
        if (kernel_mm_file_install_race_satisfied(
                (uint64_t)(uint32_t)old_backing_idx,
                (uint64_t)(uint32_t)backing_idx,
                (pte & PAGE_PRESENT) != 0,
                (pte & PAGE_USER) != 0,
                (pte & PAGE_FILE_CACHE) != 0,
                (pte & PAGE_WRITE) != 0,
                writable, private_cow)) {
            if (invalidate) invlpg_local(va);
            return 0;
        }
        /*
         * Linux's fault path tolerates another thread completing the same
         * shared-mm fault first.  GTK/XFCE can fault the same GLib/GDK text
         * page from cooperating helper threads; by the time file I/O finishes,
         * the PTE may already be valid.  Do not blindly trust that PTE,
         * though: a stale anonymous zero page inside a file VMA makes the
         * process execute zeros from library text and later fault with a bogus
         * write-to-code page fault.  Compare against the freshly read page; an
         * identical page is the normal race, while different contents are a
         * stale mapping that must be replaced with the file-backed page Linux
         * userspace actually asked for.
         */
        if ((pte & PAGE_USER) != 0 &&
            (!writable || (pte & PAGE_WRITE) != 0) &&
            (!private_cow ||
             (pte & (PAGE_COW | PAGE_WRITE)) != 0)) {
            uint8_t *old_page = sparse_mmap_backing_ptr(old_backing_idx);
            /*
             * Another thread may already have resolved this MAP_PRIVATE fault
             * through COW while the current thread was reading the file page.
             * That writable page can contain relocations, so comparing it with
             * the immutable cache page and replacing it would discard valid
             * process-private writes.
             */
            if (private_cow && (pte & PAGE_WRITE) != 0) {
                if (invalidate) invlpg_local(va);
                return 0;
            }
            if (old_page && memcmp(old_page, page_ptr, USER_PAGE_SIZE) == 0) {
                if (invalidate) invlpg_local(va);
                return 0;
            }
            if (process_user_mmap_consume_prepared_alias(
                    t, backing_idx, prepared_alias) < 0)
                return -1;
            pt[pte_idx] = sparse_mmap_backing_phys(backing_idx) | PAGE_PRESENT | PAGE_USER |
                          (writable ? PAGE_WRITE : 0) |
                          (file_cache ? PAGE_FILE_CACHE : 0) |
                          (private_cow ? PAGE_COW : 0);
            if (invalidate) invlpg_local(va);
            if (old_page) {
                sparse_mmap_user_alias_release(old_backing_idx);
                sparse_mmap_release_backing_index_local(old_backing_idx);
            }
            if (stale_present_log_budget > 0) {
                task_t *cur = process_current_task();
                printf("[mmap-map] replaced-stale-present pid=%d mm=%d va=0x%x old=0x%x new=0x%x writable=%d filecache=%d cow=%d budget=%d\n",
                       cur ? cur->pid : -1, t ? t->pid : -1, (uint32_t)va,
                       (uint32_t)pte, (uint32_t)(uintptr_t)page_ptr,
                       writable, file_cache, private_cow,
                       stale_present_log_budget - 1);
                stale_present_log_budget--;
            }
            return 0;
        }
        return -1;
    }

    if (process_user_mmap_consume_prepared_alias(
            t, backing_idx, prepared_alias) < 0)
        return -1;
    pt[pte_idx] = sparse_mmap_backing_phys(backing_idx) | PAGE_PRESENT | PAGE_USER |
                  (writable ? PAGE_WRITE : 0) |
                  (file_cache ? PAGE_FILE_CACHE : 0) |
                  (private_cow ? PAGE_COW : 0);
    if (invalidate) invlpg_local(va);
    return 0;
}

static int process_user_mmap_map_backing_page_ex(
        task_t *t, uint64_t va, int backing_idx, int writable,
        int file_cache, int private_cow, int invalidate,
        int replace_present) {
    task_t *memory;
    int result;
    int prepared_alias = 0;

    if (!t) return -1;
    memory = task_vm_owner_local(t);
    if (!memory) return -1;
    /*
     * The first alias charge can reclaim memory.  Prepare it before taking the
     * page-table lock; if another thread wins publication, undo the unused
     * reference after the locked recheck.
     */
    if (sparse_mmap_user_alias_acquire(memory, backing_idx) == 0) {
        sparse_mmap_retain_backing_index_local(backing_idx);
        prepared_alias = 1;
    }
    /*
     * File data can be read concurrently, but page-table construction and the
     * final leaf install are one per-mm transaction.  Without this boundary,
     * two CLONE_VM threads can publish different intermediate tables for the
     * same 2 MiB region and retain incompatible translations on separate CPUs.
     */
    process_user_page_table_lock(memory);
    result = process_user_mmap_map_backing_page_ex_locked(
        memory, va, backing_idx, writable, file_cache, private_cow,
        invalidate, replace_present, &prepared_alias);
    process_user_page_table_unlock(memory);
    if (prepared_alias) {
        sparse_mmap_user_alias_release(backing_idx);
        sparse_mmap_release_backing_index_local(backing_idx);
    }
    return result;
}

int process_user_mmap_map_backing_page(task_t *t, uint64_t va, int backing_idx, int writable) {
    return process_user_mmap_map_backing_page_ex(t, va, backing_idx,
                                                 writable, 0, 0, 1, 1);
}

int process_user_device_install_page(task_t *t, uint64_t va,
                                     uint64_t physical, uint32_t protection,
                                     int32_t memory_attribute) {
    task_t *owner;
    uint64_t *entry;
    uint64_t flags = PAGE_PRESENT | PAGE_DEVICE;
    uint32_t pte_idx = 0;
    int idx;
    int result = -1;

    if (!t || (va & (USER_PAGE_SIZE - 1ULL)) != 0 ||
        (physical & (USER_PAGE_SIZE - 1ULL)) != 0)
        return -1;
    owner = task_vm_owner_local(t);
    idx = task_index(owner);
    if (!owner || idx < 0 || idx >= USER_AS_MAX_TASKS)
        return -1;
    if (protection != 0)
        flags |= PAGE_USER;
    if ((protection & 0x2u) != 0 &&
        memory_attribute != DEVICE_MEMORY_WRITE_PROTECTED)
        flags |= PAGE_WRITE;
    switch (memory_attribute) {
    case DEVICE_MEMORY_UNCACHEABLE:
    case DEVICE_MEMORY_DEVICE:
    case DEVICE_MEMORY_DEVICE_NP:
        flags |= PAGE_PWT | PAGE_PCD;
        break;
    case DEVICE_MEMORY_WRITE_COMBINING:
    case DEVICE_MEMORY_WEAK_UNCACHEABLE:
        flags |= PAGE_PCD;
        break;
    case DEVICE_MEMORY_WRITE_THROUGH:
        flags |= PAGE_PWT;
        break;
    default:
        break;
    }

    process_user_page_table_lock(owner);
    sparse_mmap_activate_task(owner);
    if (fixed_user_addr(va)) {
        entry = fixed_user_pte_for_addr_idx(idx, va);
        if (!entry || (*entry & PAGE_PRESENT) != 0)
            goto out;
    } else {
        uint64_t *pt = 0;

        if (!sparse_mmap_range_ok_local(va, USER_PAGE_SIZE) ||
            sparse_mmap_ensure_pt(owner, va, &pt) < 0 ||
            sparse_mmap_indices(va, 0, 0, &pte_idx) < 0 ||
            (pt[pte_idx] & PAGE_PRESENT) != 0)
            goto out;
        entry = &pt[pte_idx];
    }
    *entry = physical | flags;
    invlpg_local(va);
    result = 0;
out:
    process_user_page_table_unlock(owner);
    return result;
}

int process_user_mmap_map_file_cache_page(task_t *t, uint64_t va,
                                          int backing_idx, int writable,
                                          int private_cow) {
    if (writable && private_cow) return -1;
    return process_user_mmap_map_backing_page_ex(t, va, backing_idx,
                                                 writable, 1, private_cow,
                                                 1, 1);
}

int process_user_mmap_map_file_cache_pages(
    task_t *t, uint64_t start, const int *backing_indices,
    uint32_t page_count, uint32_t required_index, int writable,
    int private_cow) {
    uint64_t required_va;

    if (!t || !backing_indices || page_count == 0 ||
        required_index >= page_count || (writable && private_cow) ||
        (start & (USER_PAGE_SIZE - 1ULL)) != 0 ||
        backing_indices[required_index] < 0)
        return -1;
    if ((uint64_t)(page_count - 1u) >
        (UINT64_MAX - start) / USER_PAGE_SIZE)
        return -1;

    required_va = start + (uint64_t)required_index * USER_PAGE_SIZE;
    /*
     * The faulting address can race another thread or replace a stale leaf, so
     * preserve the normal validation and invalidate it immediately.  Neighbor
     * entries are best-effort non-present-to-present installs only.  x86 does
     * not retain a valid TLB translation for a non-present leaf, so those PTEs
     * need no individual INVLPG.  This turns one cache window into one required
     * invalidation without flushing unrelated translations from the mm.
     */
    if (process_user_mmap_map_backing_page_ex(
            t, required_va, backing_indices[required_index], writable, 1,
            private_cow, 1, 1) < 0)
        return -1;

    /*
     * Each neighbor performs its potentially reclaiming cgroup charge before
     * entering the short publication section.  Keeping one page-table lock
     * across the whole fault-around window would make a cache hit capable of
     * blocking every sibling fault in the address space.
     */
    for (uint32_t index = 0; index < page_count; ++index) {
        uint64_t va;
        if (index == required_index || backing_indices[index] < 0) continue;
        va = start + (uint64_t)index * USER_PAGE_SIZE;
        (void)process_user_mmap_map_backing_page_ex(
            t, va, backing_indices[index], writable, 1,
            private_cow, 0, 0);
    }
    return 0;
}

void process_user_mmap_writeprotect_all_file_cache(void) {
    for (int task_index_value = 0;
         task_index_value < USER_AS_MAX_TASKS; ++task_index_value) {
        task_t *memory = &g_tasks[task_index_value];
        int touched = 0;
        int live;

        if (memory->state == TASK_UNUSED ||
            memory->state == TASK_ZOMBIE ||
            memory->vm_owner_pid != memory->pid)
            continue;
        live = process_user_vma_live_count(memory);
        for (int vma_index = 0; vma_index < live; ++vma_index) {
            edge_user_vma_t *vma = &memory->user_vmas[vma_index];

            if (vma->end <= vma->start || !vma->file_backed ||
                (vma->flags & USER_MAP_SHARED_FLAG) == 0)
                continue;
            for (uint64_t address = vma->start;
                 address < vma->end; address += USER_PAGE_SIZE) {
                uint64_t *page_table =
                    sparse_mmap_lookup_pt(memory, address, 0);
                uint32_t pte_index = 0;
                uint64_t pte;

                if (!page_table || sparse_mmap_indices(
                        address, 0, 0, &pte_index) < 0)
                    continue;
                pte = __atomic_load_n(
                    &page_table[pte_index], __ATOMIC_ACQUIRE);
                if ((pte & (PAGE_PRESENT | PAGE_USER |
                            PAGE_FILE_CACHE | PAGE_WRITE)) !=
                        (PAGE_PRESENT | PAGE_USER |
                         PAGE_FILE_CACHE | PAGE_WRITE))
                    continue;
                __atomic_fetch_and(
                    &page_table[pte_index], ~PAGE_WRITE,
                    __ATOMIC_ACQ_REL);
                touched = 1;
            }
        }
        if (touched) sparse_mmap_flush_task(memory);
    }
}

static int process_user_mmap_copy_cached_private_page(task_t *mm, uint64_t page, uint32_t prot) {
    uint64_t *pt;
    uint32_t pte_idx = 0;
    uint64_t pte;
    int old_backing_idx;
    int new_backing_idx;
    uint8_t *old_page;
    uint8_t *new_page;

    if (!mm) return -1;
    mm = task_vm_owner_local(mm);
    sparse_mmap_activate_task(mm);
    pt = sparse_mmap_lookup_pt(mm, page, 0);
    if (!pt || sparse_mmap_indices(page, 0, 0, &pte_idx) < 0) return -1;
    pte = pt[pte_idx];
    if ((pte & PAGE_PRESENT) == 0 || (pte & PAGE_FILE_CACHE) == 0) return -1;
    old_backing_idx = sparse_mmap_backing_index_from_phys(pte & ~0xFFFULL);
    old_page = sparse_mmap_backing_ptr(old_backing_idx);
    if (!old_page) return -1;
    new_backing_idx = sparse_mmap_alloc_backing_index_mode_local(0);
    if (new_backing_idx < 0) return -1;
    new_page = sparse_mmap_backing_ptr(new_backing_idx);
    if (!new_page) {
        sparse_mmap_release_backing_index_local(new_backing_idx);
        return -1;
    }
    memcpy(new_page, old_page, USER_PAGE_SIZE);
    if (sparse_mmap_user_alias_acquire(mm, new_backing_idx) < 0) {
        sparse_mmap_release_backing_index_local(new_backing_idx);
        return -1;
    }
    pte = sparse_mmap_backing_phys(new_backing_idx) | PAGE_PRESENT | PAGE_USER;
    if (prot & 0x2u) pte |= PAGE_WRITE;
    pt[pte_idx] = pte;
    invlpg_local(page);
    sparse_mmap_user_alias_release(old_backing_idx);
    sparse_mmap_release_backing_index_local(old_backing_idx);
    return 0;
}

static int process_user_mmap_commit_prot(task_t *t, uint64_t start,
                                         uint64_t len, uint32_t prot) {
    uint64_t end;

    if (!t || len == 0) return 0;
    t = task_vm_owner_local(t);
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start) return -1;
    if (!sparse_mmap_range_ok_local(start, end - start)) return -1;
    sparse_mmap_activate_task(t);
    for (uint64_t va = start; va < end; va += USER_PAGE_SIZE) {
        uint64_t *page_table = sparse_mmap_lookup_pt(t, va, 0);
        uint32_t pte_idx = (uint32_t)((va >> 12) & 0x1ffu);
        int backing_idx;
        uint8_t *page_ptr;

        if (page_table &&
            (__atomic_load_n(&page_table[pte_idx], __ATOMIC_ACQUIRE) &
             PAGE_PRESENT) != 0)
            continue;

        /*
         * Physical allocation, zeroing, and cgroup charging may reclaim or
         * yield.  Keep all three outside the page-table publication lock so a
         * fault cannot block sibling threads while holding the mm hierarchy.
         * The final present check below resolves simultaneous first touches.
         */
        backing_idx = sparse_mmap_alloc_backing_index_local();
        if (backing_idx < 0) {
            sparse_mmap_log_oom_local(t, "backing", va);
            return -1;
        }
        page_ptr = sparse_mmap_backing_ptr(backing_idx);
        if (!page_ptr) {
            sparse_mmap_log_oom_local(t, "backing-ptr", va);
            sparse_mmap_release_backing_index_local(backing_idx);
            return -1;
        }
        /* The backing allocator already guarantees a zero-filled page. */
        if (sparse_mmap_user_alias_acquire(t, backing_idx) < 0) {
            sparse_mmap_release_backing_index_local(backing_idx);
            return -1;
        }
        process_user_page_table_lock(t);
        if (sparse_mmap_ensure_pt(t, va, &page_table) < 0 || !page_table) {
            process_user_page_table_unlock(t);
            sparse_mmap_user_alias_release(backing_idx);
            sparse_mmap_release_backing_index_local(backing_idx);
            sparse_mmap_log_oom_local(t, "pt-ensure", va);
            return -1;
        }
        if ((page_table[pte_idx] & PAGE_PRESENT) != 0) {
            process_user_page_table_unlock(t);
            sparse_mmap_user_alias_release(backing_idx);
            sparse_mmap_release_backing_index_local(backing_idx);
            continue;
        }
        page_table[pte_idx] = sparse_mmap_backing_phys(backing_idx) |
                              PAGE_PRESENT |
                              (prot != 0 ? PAGE_USER : 0) |
                              ((prot & 0x2u) != 0 ? PAGE_WRITE : 0);
        invlpg_local(va);
        process_user_page_table_unlock(t);
    }
    return 0;
}

#ifdef CONFIG_FS_SWAP
static int process_user_mmap_restore_swapped_page(
        task_t *t, uint64_t address, uint32_t protection) {
    uint64_t swap_entry;
    uint64_t *pt = 0;
    uint32_t pte_index = 0;
    uint32_t stored_cgroup = 0;
    int backing_index;
    uint8_t *page;

    if (!t || edge_swap_map_take(
            t->cr3, address, &swap_entry) < 0)
        return 0;
    backing_index = sparse_mmap_alloc_backing_index_local();
    page = backing_index >= 0 ?
        sparse_mmap_backing_ptr(backing_index) : 0;
    if (!page || swap_load_page(
            swap_entry, page, &stored_cgroup) < 0 ||
        stored_cgroup != t->cgroup_id) {
        if (backing_index >= 0)
            sparse_mmap_release_backing_index_local(backing_index);
        if (edge_swap_map_insert(t->cr3, address, swap_entry) < 0)
            swap_release_entry(swap_entry);
        return -1;
    }
    process_user_page_table_lock(t);
    if (sparse_mmap_ensure_pt(t, address, &pt) < 0 || !pt ||
        sparse_mmap_indices(address, 0, 0, &pte_index) < 0 ||
        (pt[pte_index] & PAGE_PRESENT) != 0 ||
        sparse_mmap_user_alias_acquire(t, backing_index) < 0) {
        process_user_page_table_unlock(t);
        if (backing_index >= 0)
            sparse_mmap_release_backing_index_local(backing_index);
        if (edge_swap_map_insert(t->cr3, address, swap_entry) < 0)
            swap_release_entry(swap_entry);
        return -1;
    }
    pt[pte_index] = sparse_mmap_backing_phys(backing_index) |
                    PAGE_PRESENT |
                    (protection != 0 ? PAGE_USER : 0) |
                    ((protection & KERNEL_MM_PROT_WRITE) != 0 ?
                     PAGE_WRITE : 0);
    invlpg_local(address);
    process_user_page_table_unlock(t);
    swap_release_entry(swap_entry);
    return 1;
}

static int process_user_mmap_restore_swap_mapping(
        uint64_t address_space, uint64_t address, uint64_t swap_entry) {
    task_t *memory = 0;
    uint64_t mapped_entry = 0;
    uint32_t protection = 0;

    if (!address_space || !swap_entry ||
        edge_swap_map_acquire(
            address_space, address, &mapped_entry) < 0)
        return -1;
    swap_release_entry(mapped_entry);
    if (mapped_entry != swap_entry) return -1;
    for (uint32_t index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *candidate = &g_tasks[index];
        if (candidate->state == TASK_UNUSED ||
            task_vm_owner_local(candidate) != candidate ||
            candidate->cr3 != address_space)
            continue;
        memory = candidate;
        break;
    }
    if (!memory) return -1;
    process_user_vma_mutation_lock(memory);
    {
        edge_user_vma_t *vma =
            process_user_vma_for_addr(memory, address);
        if (vma && (vma->flags & USER_MAP_SHARED_FLAG) == 0)
            protection = vma->prot;
    }
    process_user_vma_mutation_unlock(memory);
    if (!protection) return -1;
    return process_user_mmap_restore_swapped_page(
        memory, page_align_down_local(address), protection) > 0 ? 0 : -1;
}
#endif

int process_user_mmap_commit(task_t *t, uint64_t start, uint64_t len) {
    return process_user_mmap_commit_prot(t, start, len, 0x3u);
}

static int process_user_mmap_protect_locked(task_t *t, uint64_t start,
                                            uint64_t len, uint32_t prot) {
    sparse_mmap_pt_span_t span;
    uint64_t cursor;
    uint64_t end;
    int walk_result;

    if (!t || len == 0) return 0;
    t = task_vm_owner_local(t);
    if (task_index(t) < 0 || task_index(t) >= USER_AS_MAX_TASKS)
        return -1;
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start) return -1;
    if (!sparse_mmap_range_ok_local(start, end - start)) return -1;
    sparse_mmap_activate_task(t);
    cursor = start;
    while ((walk_result =
                sparse_mmap_next_present_pt(t, &cursor, end, &span)) > 0) {
        for (uint64_t va = span.start; va < span.end;
             va += USER_PAGE_SIZE) {
            uint32_t pte_idx = (uint32_t)((va >> 12) & 0x1ffu);
            uint64_t pte = span.pt[pte_idx];

            if ((pte & PAGE_PRESENT) == 0) continue;
            if ((prot & 0x2u) != 0) {
                edge_user_vma_t *v = process_user_vma_for_addr(t, va);
                if (v && v->file_backed &&
                    (v->flags & USER_MAP_SHARED_FLAG) == 0 &&
                    (pte & PAGE_FILE_CACHE) != 0) {
                    /*
                     * A writable MAP_PRIVATE VMA does not make the shared
                     * page-cache leaf writable.  Keep the immutable page in
                     * place and resolve it on the first store fault.  Besides
                     * matching Linux's lazy COW behavior, this avoids copying
                     * every relocation page during mprotect(2) and guarantees
                     * that no CPU can retain a writable cache alias.
                     */
                    pte |= PAGE_COW;
                }
            }
            if (prot != 0) pte |= PAGE_USER;
            else pte &= ~PAGE_USER;
            if (prot & 0x2u) pte |= PAGE_WRITE;
            else pte &= ~PAGE_WRITE;
            if ((pte & PAGE_COW) != 0) pte &= ~PAGE_WRITE;
            span.pt[pte_idx] = pte;
            invlpg_local(va);
        }
    }
    return walk_result < 0 ? -1 : 0;
}

int process_user_mmap_protect(task_t *t, uint64_t start, uint64_t len,
                              uint32_t prot) {
    task_t *memory;
    int result;

    if (!t) return -1;
    memory = task_vm_owner_local(t);
    if (!memory) return -1;
    process_user_page_table_lock(memory);
    result = process_user_mmap_protect_locked(memory, start, len, prot);
    process_user_page_table_unlock(memory);
    if (result == 0 && len != 0)
        sparse_mmap_flush_task(memory);
    return result;
}

int process_user_mmap_write_protect(task_t *t, uint64_t start,
                                    uint64_t len, int enable) {
    task_t *memory;
    uint64_t end;
    uint64_t cursor;
    int result = 0;

    if (!t || !len || len > UINT64_MAX - start) return -1;
    memory = task_vm_owner_local(t);
    if (!memory) return -1;
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start) return -1;

    process_user_page_table_lock(memory);
    cursor = start;
    while (cursor < end) {
        edge_user_vma_t *vma = process_user_vma_for_addr(memory, cursor);
        uint64_t run_end;
        uint32_t protection;

        if (!vma) {
            result = -1;
            break;
        }
        run_end = vma->end < end ? vma->end : end;
        protection = vma->prot;
        if (enable) protection &= ~KERNEL_MM_PROT_WRITE;
        if (process_user_mmap_protect_locked(
                memory, cursor, run_end - cursor, protection) < 0) {
            result = -1;
            break;
        }
        cursor = run_end;
    }
    process_user_page_table_unlock(memory);
    if (result == 0) sparse_mmap_flush_task(memory);
    return result;
}

static uint64_t *process_user_poison_pte_locked(task_t *memory,
                                                uint64_t page,
                                                int create) {
    int index;
    uint64_t *table = 0;

    if (!memory) return 0;
    memory = task_vm_owner_local(memory);
    index = task_index(memory);
    if (!memory || index < 0 || index >= USER_AS_MAX_TASKS) return 0;

    if (page >= USER_HEAP_BASE &&
        page < USER_HEAP_BASE + USER_HEAP_TOTAL_SIZE) {
        uint32_t slot;
        uint32_t pte;
        if (user_heap_slot_for_addr(page, &slot, &pte) < 0) return 0;
        if (create) {
            if (process_user_heap_ensure_pt(memory, page, &table) < 0)
                return 0;
        } else {
            table = g_user_heap_pt[index][slot];
        }
        return table ? &table[pte] : 0;
    }

    if (fixed_user_addr(page)) {
        if (create && !fixed_user_pte_for_addr_idx(index, page)) {
            if (page < USER_LOW_LIMIT) {
                uint32_t low_page =
                    (uint32_t)((page - USER_LOW_BASE) >> 21);
                if (!fixed_user_low_pt_ensure(index, low_page)) return 0;
            } else if (page >= USER_BIGPIE_BASE &&
                       page < USER_BIGPIE_BASE + USER_BIGPIE_SIZE) {
                uint32_t bigpie_page =
                    (uint32_t)((page - USER_BIGPIE_BASE) >> 21);
                if (!fixed_user_bigpie_pt_ensure(index, bigpie_page))
                    return 0;
            } else if (fixed_user_pt_ensure_for_idx(index) < 0) {
                return 0;
            }
        }
        return fixed_user_pte_for_addr_idx(index, page);
    }

    if (!sparse_mmap_range_ok_local(page, USER_PAGE_SIZE)) return 0;
    if (create) {
        if (sparse_mmap_ensure_pt(memory, page, &table) < 0) return 0;
    } else {
        table = sparse_mmap_lookup_pt(memory, page, 0);
    }
    return table ? &table[(page >> 12) & 0x1ffu] : 0;
}

int process_user_mmap_poison_page(task_t *t, uint64_t address) {
    task_t *memory;
    uint64_t page;
    uint64_t *entry;
    int result;

    if (!t || (address & (USER_PAGE_SIZE - 1u))) return -1;
    memory = task_vm_owner_local(t);
    if (!memory) return -1;
    page = page_align_down_local(address);
    process_user_page_table_lock(memory);
    entry = process_user_poison_pte_locked(memory, page, 1);
    if (!entry) {
        result = -1;
    } else if (__atomic_load_n(entry, __ATOMIC_ACQUIRE) != 0) {
        result = 1;
    } else {
        __atomic_store_n(entry, PAGE_POISONED, __ATOMIC_RELEASE);
        result = 0;
    }
    process_user_page_table_unlock(memory);
    if (result == 0) sparse_mmap_flush_task(memory);
    return result;
}

int process_user_mmap_page_poisoned(task_t *t, uint64_t address) {
    task_t *memory;
    uint64_t *entry;
    uint64_t value = 0;

    if (!t) return -1;
    memory = task_vm_owner_local(t);
    if (!memory) return -1;
    process_user_page_table_lock(memory);
    entry = process_user_poison_pte_locked(
        memory, page_align_down_local(address), 0);
    if (entry) value = __atomic_load_n(entry, __ATOMIC_ACQUIRE);
    process_user_page_table_unlock(memory);
    return value == PAGE_POISONED ? 1 : 0;
}

static int process_user_fbdev_handle_fault(task_t *t, uint64_t addr, int write) {
    task_t *mm;
    const edge_user_vma_t *v;
    const char *path = 0;
    int idx;
    uint64_t page;
    uint64_t rel;
    uint64_t visible_rel;
    uint64_t visible_len = USER_PAGE_SIZE;
    uint64_t window_off;
    uint64_t fb_phys = 0;
    uint64_t fb_off = 0;
    uint32_t fb_pages = 0;
    uint32_t pde_page;
    uint32_t pdpt_idx;
    uint32_t pde_idx;
    uint32_t pte_idx;
    uint64_t pte;
    uint64_t pte_flags = PAGE_PRESENT | PAGE_USER;
    uint64_t *sparse_pt = 0;
    int installed = 0;
    static int fbdev_fault_log_budget = EDGE_GUI_DEEP_TRACE ? 64 : 0;
    static int fbdev_reject_log_budget = EDGE_GUI_DEEP_TRACE ? 32 : 4;

    if (!t) return 0;
    mm = task_vm_owner_local(t);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) {
        if (fbdev_reject_log_budget > 0) {
            printf("[fb-fault] reject idx pid=%d task=%s owner=%d idx=%d addr=0x%x write=%d budget=%d\n",
                   t ? t->pid : -1, (t && t->name[0]) ? t->name : "?",
                   mm ? mm->pid : -1, idx, (uint32_t)addr, write,
                   fbdev_reject_log_budget - 1);
            fbdev_reject_log_budget--;
        }
        return 0;
    }
    v = process_user_vma_for_addr(mm, addr);
    if (!v || !v->file_backed) {
        if (fbdev_reject_log_budget > 0 && addr >= USER_FBDEV_BASE &&
            addr < USER_FBDEV_BASE + ((uint64_t)USER_FBDEV_MAX_PAGES << 21)) {
            printf("[fb-fault] reject vma pid=%d task=%s owner=%d idx=%d addr=0x%x v=%d file=%d budget=%d\n",
                   t->pid, t->name[0] ? t->name : "?", mm->pid, idx,
                   (uint32_t)addr, v ? 1 : 0, v ? v->file_backed : 0,
                   fbdev_reject_log_budget - 1);
            fbdev_reject_log_budget--;
        }
        return 0;
    }
    path = process_user_mmap_file_path_for_slot(v->file_slot);
    if (!path || strcmp(path, "/dev/fb0") != 0) {
        if (fbdev_reject_log_budget > 0 && addr >= USER_FBDEV_BASE &&
            addr < USER_FBDEV_BASE + ((uint64_t)USER_FBDEV_MAX_PAGES << 21)) {
            printf("[fb-fault] reject path pid=%d task=%s owner=%d idx=%d addr=0x%x slot=%u path=%s budget=%d\n",
                   t->pid, t->name[0] ? t->name : "?", mm->pid, idx,
                   (uint32_t)addr, v->file_slot, path ? path : "(null)",
                   fbdev_reject_log_budget - 1);
            fbdev_reject_log_budget--;
        }
        return 0;
    }
    if (write && (v->prot & 0x2u) == 0) {
        if (fbdev_reject_log_budget > 0) {
            printf("[fb-fault] reject prot pid=%d task=%s owner=%d idx=%d addr=0x%x prot=0x%x budget=%d\n",
                   t->pid, t->name[0] ? t->name : "?", mm->pid, idx,
                   (uint32_t)addr, v->prot, fbdev_reject_log_budget - 1);
            fbdev_reject_log_budget--;
        }
        return 0;
    }
    if (!fb_get_2m_phys_window(&fb_phys, &fb_pages, &fb_off)) {
        if (fbdev_fault_log_budget > 0) {
            printf("[fb-fault] reject no-window pid=%d task=%s addr=0x%x vma=0x%x..0x%x budget=%d\n",
                   t->pid, t->name[0] ? t->name : "?",
                   (uint32_t)addr, (uint32_t)v->start, (uint32_t)v->end,
                   fbdev_fault_log_budget - 1);
            fbdev_fault_log_budget--;
        }
        return 0;
    }
    if (fb_pages > USER_FBDEV_MAX_PAGES) fb_pages = USER_FBDEV_MAX_PAGES;

    page = page_align_down_local(addr);
    if (page >= USER_FBDEV_BASE && page < USER_FBDEV_BASE + ((uint64_t)fb_pages << 21)) {
        window_off = page - USER_FBDEV_BASE;
        rel = window_off;
        visible_rel = (rel >= fb_off) ? (rel - fb_off) : 0;
        pde_page = (uint32_t)(rel >> 21);
        pdpt_idx = (uint32_t)((page >> 30) & 0x1FFu);
        pde_idx = (uint32_t)((page >> 21) & 0x1FFu);
        pte_idx = (uint32_t)((page >> 12) & 0x1FFu);
        if (pde_page >= fb_pages || pde_page >= USER_FBDEV_MAX_PAGES ||
            pdpt_idx >= USER_LOW_PDPT_COUNT || pde_idx >= 512) {
            if (fbdev_reject_log_budget > 0) {
                printf("[fb-fault] reject index pid=%d task=%s owner=%d idx=%d addr=0x%x rel=0x%x pdpt=%u pde=%u page=%u pages=%u budget=%d\n",
                       t->pid, t->name[0] ? t->name : "?", mm->pid, idx,
                       (uint32_t)addr, (uint32_t)rel, pdpt_idx, pde_idx,
                       pde_page, fb_pages, fbdev_reject_log_budget - 1);
                fbdev_reject_log_budget--;
            }
            return 0;
        }
        g_pd[idx][pdpt_idx][pde_idx] =
            ((uint64_t)(uintptr_t)&g_user_fbdev_pt[idx][pde_page][0]) |
            PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        pte = g_user_fbdev_pt[idx][pde_page][pte_idx];
    } else {
        /*
         * Linux device VMAs fault by VMA, not by a single hard-coded return
         * address.  The file offset plus byte position inside the VMA selects
         * the framebuffer page, including the sub-page bias from smem_start.
         */
        if (!process_user_fbdev_visible_range(v, page, &visible_rel, &visible_len, &window_off)) {
            if (fbdev_reject_log_budget > 0) {
                printf("[fb-fault] reject bounds pid=%d task=%s owner=%d idx=%d addr=0x%x page=0x%x vma=0x%x..0x%x budget=%d\n",
                       t->pid, t->name[0] ? t->name : "?", mm->pid, idx,
                       (uint32_t)addr, (uint32_t)page, (uint32_t)v->start,
                       (uint32_t)v->end, fbdev_reject_log_budget - 1);
                fbdev_reject_log_budget--;
            }
            return 0;
        }
        rel = window_off;
        pde_page = (uint32_t)(rel >> 21);
        pdpt_idx = (uint32_t)((page >> 30) & 0x1FFu);
        pde_idx = (uint32_t)((page >> 21) & 0x1FFu);
        if (pde_page >= fb_pages) return 0;
        if (sparse_mmap_ensure_pt(mm, page, &sparse_pt) < 0 ||
            sparse_mmap_indices(page, 0, 0, &pte_idx) < 0) {
            return 0;
        }
        pte = sparse_pt[pte_idx];
    }
    if ((pte & PAGE_PRESENT) == 0 || (pte & PAGE_USER) == 0) {
        /*
         * Device mappings are VMAs and Linux permits demand faults inside them.
         * Xorg's fbdev shadow code writes well beyond the first few pages during
         * full-screen presents; a missing PTE inside the valid /dev/fb0 VMA must
         * install the corresponding framebuffer page, not turn into SIGSEGV.
         */
        pte = (fb_phys + rel) | pte_flags;
        installed = 1;
    }
    if (!write) {
        if (sparse_pt) sparse_pt[pte_idx] = pte;
        else g_user_fbdev_pt[idx][pde_page][pte_idx] = pte;
        invlpg_local(page);
        if (process_current_task() == mm || (process_current_task() && process_current_task()->cr3 == mm->cr3)) {
            cr3_write(mm->cr3);
        }
        return 1;
    }
    if ((pte & PAGE_WRITE) != 0 && !installed) {
        /*
         * A write fault on an already-writable fbdev PTE means the active CR3
         * had a stale/non-present translation even though the per-mm table is
         * current.  Reload and report the fault handled instead of delivering
         * SIGSEGV to Xorg; the instruction will retry against the restored PTE.
         */
        invlpg_local(page);
        if (process_current_task() == mm || (process_current_task() && process_current_task()->cr3 == mm->cr3)) {
            cr3_write(mm->cr3);
        }
        if (fbdev_fault_log_budget > 0) {
            printf("[fb-fault] stale-tlb pid=%d task=%s addr=0x%x rel=0x%x pte=0x%x budget=%d\n",
                   t->pid, t->name[0] ? t->name : "?", (uint32_t)addr,
                   (uint32_t)rel, (uint32_t)pte, fbdev_fault_log_budget - 1);
            fbdev_fault_log_budget--;
        }
        return 1;
    }

    /*
     * Linux fbdev mmap writes are immediately visible to scanout hardware.  On
     * virtio-gpu, EdgeOS must submit an explicit transfer, so use write faults
     * as a generic dirty signal for the fbdev aperture.  Red flag: this is not
     * Xorg/XFCE-specific; any process writing a shared /dev/fb0 mapping needs
     * the same visibility semantics.
     */
    fb_note_user_mmap_dirty(visible_rel, visible_len);
    if (sparse_pt) sparse_pt[pte_idx] = pte | PAGE_WRITE;
    else g_user_fbdev_pt[idx][pde_page][pte_idx] = pte | PAGE_WRITE;
    invlpg_local(page);
    if (process_current_task() == mm || (process_current_task() && process_current_task()->cr3 == mm->cr3)) {
        cr3_write(mm->cr3);
    }
    if (fbdev_fault_log_budget > 0) {
        printf("[fb-fault] %s pid=%d task=%s addr=0x%x rel=0x%x pdpt=%u pde=%u page=%u pte=%u budget=%d\n",
               installed ? "install-dirty" : "dirty",
               t->pid, t->name[0] ? t->name : "?",
               (uint32_t)addr, (uint32_t)visible_rel, pdpt_idx, pde_idx, pde_page, pte_idx,
               fbdev_fault_log_budget - 1);
        fbdev_fault_log_budget--;
    }
    /*
     * Xorg's fbdev ShadowFB can repaint for long stretches under ITIMER_REAL
     * without reaching an ordinary syscall/yield point.  The timer IRQ only
     * records that a virtio-gpu transfer is needed; consume that request here
     * only when the fbdev deferred-I/O batch is due.  Running the synchronous
     * virtio transfer on every 4 KiB write fault fragments one Linux-visible
     * repaint into hundreds of tiny scanouts and starves the desktop.
     */
    if (fb_user_mmap_deferred_due()) fb_user_mmap_pump_deferred();
    return 1;
}

void process_user_fbdev_writeprotect_all(void) {
    uint64_t fb_phys = 0;
    uint64_t fb_off = 0;
    uint32_t fb_pages = 0;
    task_t *cur;

    if (!fb_get_2m_phys_window(&fb_phys, &fb_pages, &fb_off)) return;
    (void)fb_phys;
    (void)fb_off;
    if (fb_pages > USER_FBDEV_MAX_PAGES) fb_pages = USER_FBDEV_MAX_PAGES;
    if (fb_pages == 0) return;
    cur = process_current_task();
    for (int idx = 0; idx < USER_AS_MAX_TASKS; ++idx) {
        int touched = 0;
        task_t *owner = &g_tasks[idx];
        if (!process_user_idx_has_fbdev_mapping(idx)) continue;
        if (owner->state != TASK_UNUSED && owner->state != TASK_ZOMBIE &&
            owner->vm_owner_pid == owner->pid) {
            int live = process_user_vma_live_count(owner);
            for (int vi = 0; vi < live; ++vi) {
                edge_user_vma_t *v = &owner->user_vmas[vi];
                if (!process_user_vma_is_fbdev(v)) continue;
                for (uint64_t va = v->start; va < v->end; va += USER_PAGE_SIZE) {
                    uint64_t *pt = sparse_mmap_lookup_pt(owner, va, 0);
                    uint32_t pte_idx = 0;
                    uint64_t pte;
                    if (!pt || sparse_mmap_indices(va, 0, 0, &pte_idx) < 0) continue;
                    pte = pt[pte_idx];
                    if ((pte & PAGE_PRESENT) == 0) continue;
                    pt[pte_idx] = pte & ~(PAGE_WRITE | PAGE_DIRTY | PAGE_ACCESSED);
                    touched = 1;
                }
            }
        }
        for (uint32_t p = 0; p < fb_pages; ++p) {
            for (uint32_t i = 0; i < 512; ++i) {
                uint64_t pte = g_user_fbdev_pt[idx][p][i];
                if ((pte & PAGE_PRESENT) != 0) {
                    g_user_fbdev_pt[idx][p][i] =
                        pte & ~(PAGE_WRITE | PAGE_DIRTY | PAGE_ACCESSED);
                    touched = 1;
                }
            }
        }
        /*
         * Linux fbdev deferred I/O uses the mmap write-fault path as the
         * durable dirty signal, then write-protects the mapping again after
         * the driver consumes the dirty page list.  EdgeOS has the same
         * userspace-visible contract: /dev/fb0 remains a writable MAP_SHARED
         * mapping, but each repaint must become visible to the virtio-gpu
         * scanout without relying on fragile cross-CPU PTE dirty polling.
         *
         * Red flag: do not replace this with Xorg/XFCE-specific repaint hooks.
         * If a repaint is missed, fix the generic fbdev mmap fault/flush path.
         */
        if (touched && cur) {
            task_t *mm = task_vm_owner_local(cur);
            if (mm && task_index(mm) == idx) cr3_write(mm->cr3);
        }
    }
}

void process_user_fbdev_collect_dirty_all(void) {
    uint64_t fb_phys = 0;
    uint64_t fb_off = 0;
    uint32_t fb_pages = 0;
    task_t *cur;
    uint32_t total_dirty = 0;
    static int fbdev_dirty_collect_log_budget = EDGE_GUI_DEEP_TRACE ? 48 : 0;

    if (!fb_get_2m_phys_window(&fb_phys, &fb_pages, &fb_off)) return;
    (void)fb_off;
    if (fb_pages > USER_FBDEV_MAX_PAGES) fb_pages = USER_FBDEV_MAX_PAGES;
    if (fb_pages == 0) return;
    cur = process_current_task();

    /*
     * Linux fbdev mmap is scanout memory.  Userspace can dirty a writable page
     * many times after the first write fault and before EdgeOS' virtio-gpu
     * bridge submits a transfer.  Use the x86 dirty bit as the generic damage
     * source, then clear it and invalidate the local TLB entry so the next
     * store sets it again.  This preserves Linux-visible mmap semantics without
     * a full-screen polling transfer or Xorg/XFCE-specific hooks.
     */
    for (int idx = 0; idx < USER_AS_MAX_TASKS; ++idx) {
        int touched = 0;
        task_t *owner = &g_tasks[idx];
        if (!process_user_idx_has_fbdev_mapping(idx)) continue;
        if (owner->state != TASK_UNUSED && owner->state != TASK_ZOMBIE &&
            owner->vm_owner_pid == owner->pid) {
            int live = process_user_vma_live_count(owner);
            for (int vi = 0; vi < live; ++vi) {
                edge_user_vma_t *v = &owner->user_vmas[vi];
                if (!process_user_vma_is_fbdev(v)) continue;
                for (uint64_t va = v->start; va < v->end; va += USER_PAGE_SIZE) {
                    uint64_t *pt = sparse_mmap_lookup_pt(owner, va, 0);
                    uint32_t pte_idx = 0;
                    uint64_t pte;
                    uint64_t dirty_off = 0;
                    uint64_t dirty_len = 0;
                    if (!pt || sparse_mmap_indices(va, 0, 0, &pte_idx) < 0) continue;
                    pte = pt[pte_idx];
                    if ((pte & (PAGE_PRESENT | PAGE_DIRTY)) != (PAGE_PRESENT | PAGE_DIRTY)) continue;
                    if (process_user_fbdev_visible_range(v, va, &dirty_off, &dirty_len, 0)) {
                        fb_note_user_mmap_dirty(dirty_off, dirty_len);
                    }
                    pt[pte_idx] = pte & ~PAGE_DIRTY;
                    touched = 1;
                    total_dirty++;
                }
            }
        }
        for (uint32_t p = 0; p < fb_pages; ++p) {
            uint64_t page_base = ((uint64_t)p << 21);
            for (uint32_t i = 0; i < 512; ++i) {
                uint64_t pte = g_user_fbdev_pt[idx][p][i];
                if ((pte & (PAGE_PRESENT | PAGE_DIRTY)) != (PAGE_PRESENT | PAGE_DIRTY)) continue;
                uint64_t phys_window_off = page_base + ((uint64_t)i << 12);
                if (phys_window_off + USER_PAGE_SIZE <= fb_off) continue;
                fb_note_user_mmap_dirty(phys_window_off > fb_off ? phys_window_off - fb_off : 0,
                                        USER_PAGE_SIZE);
                g_user_fbdev_pt[idx][p][i] = pte & ~PAGE_DIRTY;
                touched = 1;
                total_dirty++;
            }
        }
        if (touched && cur) {
            task_t *mm = task_vm_owner_local(cur);
            if (mm && task_index(mm) == idx) cr3_write(mm->cr3);
        }
    }
    if (total_dirty && fbdev_dirty_collect_log_budget > 0) {
        task_t *ct = cur ? task_vm_owner_local(cur) : 0;
        printf("[fb-dirty] pages=%u current=%d:%s owner=%d budget=%d\n",
               total_dirty,
               cur ? cur->pid : -1,
               (cur && cur->name[0]) ? cur->name : "?",
               ct ? ct->pid : -1,
               fbdev_dirty_collect_log_budget - 1);
        fbdev_dirty_collect_log_budget--;
    }

    /*
     * Linux exposes smem_start as framebuffer metadata, not as an implicit
     * user mapping at the same numeric address.  EdgeOS used to map those raw
     * low-physical PDEs PAGE_USER in every mm so legacy fbdev probes could
     * dereference smem_start directly.  That is not Linux ABI and it is unsafe:
     * desktop workloads then had a writable alias to kernel-owned framebuffer
     * storage in every process, and corruption signatures showed framebuffer
     * pixel values inside ordinary TLS pages.  The real Linux-visible access
     * path is the /dev/fb0 VMA installed by mmap(2), handled above.
     */
}

int process_user_mmap_handle_fault(task_t *t, uint64_t addr, int write) {
    task_t *mm;
    uint64_t page;
    uint32_t prot = 0;
    uint64_t hw_cr3;
    static int mmap_fb_dispatch_log_budget = 0;

    if (!t) return 0;
    mm = task_vm_owner_local(t);
    if (!mm) return 0;
    if (addr >= USER_FBDEV_BASE && addr < USER_FBDEV_BASE + ((uint64_t)USER_FBDEV_MAX_PAGES << 21) &&
        mmap_fb_dispatch_log_budget > 0) {
        int idx = task_index(mm);
        const edge_user_vma_t *v = process_user_vma_for_addr(mm, addr);
        const char *path = (v && v->file_backed) ? process_user_mmap_file_path_for_slot(v->file_slot) : 0;
        printf("[mmap-fault] fb-range pid=%d task=%s owner=%d idx=%d addr=0x%x write=%d v=%d file=%d slot=%u path=%s budget=%d\n",
               t->pid, t->name[0] ? t->name : "?", mm->pid, idx,
               (uint32_t)addr, write, v ? 1 : 0, v ? v->file_backed : 0,
               v ? v->file_slot : 0, path ? path : "(null)",
               mmap_fb_dispatch_log_budget - 1);
        mmap_fb_dispatch_log_budget--;
    }
    if (process_user_fixed_handle_fault(t, addr, write)) {
        return 1;
    }
    if (process_user_heap_handle_fault(t, addr, write)) {
        return 1;
    }
    if (process_user_fbdev_handle_fault(t, addr, write)) {
        return 1;
    }
    if (!sparse_mmap_range_ok_local(addr, 1)) return 0;
    hw_cr3 = cr3_read_local_process();
    if (t != mm && t->vm_owner_pid == mm->pid &&
        (t->cr3 != mm->cr3 || hw_cr3 != mm->cr3)) {
        /*
         * Linux CLONE_VM threads share one mm.  EdgeOS stores sparse mmap page
         * tables in the VM owner's slot, so a thread running with a stale CR3
         * can fault inside a valid shared VMA and still see a missing PTE.  Do
         * not paper over arbitrary address-space corruption; only repair tasks
         * whose vm_owner_pid points at this owner.  Red flag: if this triggers
         * often, audit clone/exec/exit CR3 propagation rather than adding rootfs
         * workarounds.
         */
        if (g_sparse_mmap_fault_log_budget > 0) {
            printf("[mmap-fault] repair-cr3 pid=%d task=%s owner=%d addr=0x%x old=0x%x new=0x%x\n",
                   t->pid, t->name, mm->pid, (uint32_t)addr,
                   (uint32_t)hw_cr3, (uint32_t)mm->cr3);
            g_sparse_mmap_fault_log_budget--;
        }
        t->cr3 = mm->cr3;
        cr3_write(mm->cr3);
    }
    {
        const edge_user_vma_t *v;
        edge_user_vma_t fault_vma;
        int have_vma = 0;

        page = page_align_down_local(addr);
        /*
         * mmap, munmap, mprotect, mremap, fork, and a grow-down fault all
         * inspect or change the same compact VMA array.  Take a short read-side
         * snapshot under the per-mm mutation lock, then release it before file
         * I/O can yield.  This prevents a torn descriptor without serializing
         * independent page-cache reads from sibling threads.
         */
        process_user_vma_mutation_lock(mm);
        if (write && process_user_mmap_resolve_cow(mm, addr)) {
            process_user_vma_mutation_unlock(mm);
            return 1;
        }
        v = process_user_vma_for_addr(mm, addr);
        if (!v && write)
            v = process_user_vma_grow_down_for_fault(mm, page, write);
        if (v) {
            fault_vma = *v;
            have_vma = 1;
        }
        process_user_vma_mutation_unlock(mm);

        if (process_user_mmap_present_pte_allows_fault(
                mm, have_vma ? &fault_vma : 0, page, write)) {
            return 1;
        }
        if (have_vma && fault_vma.file_backed) {
            int populate_result = -1;

#ifdef CONFIG_FS_SWAP
            if ((fault_vma.flags & USER_MAP_SHARED_FLAG) == 0) {
                int restored = process_user_mmap_restore_swapped_page(
                    mm, page, fault_vma.prot);
                if (restored != 0) return restored > 0 ? 2 : 0;
            }
#endif

            if (write &&
                (fault_vma.flags & USER_MAP_SHARED_FLAG) == 0) {
                uint64_t *pt = sparse_mmap_lookup_pt(mm, page, 0);
                uint32_t pte_idx = 0;
                if (pt && sparse_mmap_indices(page, 0, 0, &pte_idx) == 0 &&
                    (pt[pte_idx] & (PAGE_PRESENT | PAGE_FILE_CACHE)) ==
                    (PAGE_PRESENT | PAGE_FILE_CACHE)) {
                    int copy_result;
                    process_user_page_table_lock(mm);
                    copy_result = process_user_mmap_copy_cached_private_page(
                        mm, page, fault_vma.prot);
                    process_user_page_table_unlock(mm);
                    return copy_result == 0;
                }
            }
            /*
             * Linux keeps the faulting VMA stable while a file page is read.
             * EdgeOS file I/O may yield, allowing a sibling CLONE_VM thread to
             * sort or split the shared VMA array.  Pass a value snapshot so
             * the fault cannot continue through a descriptor slot that now
             * describes an unrelated mapping.  The live VMA already owns the
             * backing reference; adding another inode reference for every
             * major fault would make desktop startup I/O-bound.
             */
            /*
             * Linux file-backed mmap is demand populated.  EdgeOS previously
             * preloaded every mapped library page in mmap(2), which made real
             * desktop sessions spend minutes inside one syscall and starved
             * timer/input/fbdev work.  Keep the actual file I/O helper outside
             * process.c so VMA metadata remains generic, but fault the page in
             * here where Linux would.  Red flag: if storage fault reentrancy is
             * changed later, keep this path demand-backed rather than returning
             * to eager file population in mmap(2).
             */
            populate_result = user_mmap_populate_file_page(
                mm, &fault_vma, page, write);
            if (populate_result == 0) {
                if (kernel_userfaultfd_apply_writeprotect(
                        mm->cr3, page) < 0)
                    return 0;
                return 1;
            }
            proc_emerg_puts("[mmap-fault-emerg] file-populate-fail pid=");
            proc_emerg_dec(t->pid);
            proc_emerg_puts(" task=");
            proc_emerg_task_name(t);
            proc_emerg_puts(" owner=");
            proc_emerg_dec(mm->pid);
            proc_emerg_puts(" addr=");
            proc_emerg_hex(addr);
            proc_emerg_puts(" page=");
            proc_emerg_hex(page);
            proc_emerg_puts(" vma=");
            proc_emerg_hex(fault_vma.start);
            proc_emerg_puts("-");
            proc_emerg_hex(fault_vma.end);
            proc_emerg_puts(" prot=");
            proc_emerg_hex(fault_vma.prot);
            proc_emerg_puts(" flags=");
            proc_emerg_hex(fault_vma.flags);
            proc_emerg_puts(" off=");
            proc_emerg_hex(fault_vma.file_off);
            proc_emerg_puts(" len=");
            proc_emerg_hex(fault_vma.file_len);
            proc_emerg_puts(" path=");
            proc_emerg_puts(process_user_mmap_file_path_for_slot(
                fault_vma.file_slot));
            proc_emerg_puts("\n");
            return 0;
        }
        if (have_vma) {
            prot = fault_vma.prot;
        }
    }
    if (prot == 0) {
        proc_emerg_puts("[mmap-fault-emerg] no-vma pid=");
        proc_emerg_dec(t->pid);
        proc_emerg_puts(" task=");
        proc_emerg_task_name(t);
        proc_emerg_puts(" owner=");
        proc_emerg_dec(mm->pid);
        proc_emerg_puts(" addr=");
        proc_emerg_hex(addr);
        proc_emerg_puts(" write=");
        proc_emerg_dec(write);
        proc_emerg_puts("\n");
        if (g_sparse_mmap_fault_log_budget > 0) {
            printf("[mmap-fault] no-vma pid=%d task=%s owner=%d addr=0x%x write=%d\n",
                   t->pid, t->name, mm->pid, (uint32_t)addr, write);
            int live = process_user_vma_live_count(mm);
            for (int i = 0; i < live; ++i) {
                const edge_user_vma_t *v = &mm->user_vmas[i];
                const char *path = 0;
                if (v->end <= v->start) continue;
                if (addr + (16ULL * 1024ULL * 1024ULL) < v->start ||
                    addr > v->end + (16ULL * 1024ULL * 1024ULL)) {
                    continue;
                }
                if (v->file_backed) path = process_user_mmap_file_path_for_slot(v->file_slot);
                printf("[mmap-fault-vma] pid=%d slot=%d range=0x%x-0x%x prot=0x%x flags=0x%x file_off=0x%x file_len=0x%x path=%s\n",
                       t->pid, i, (uint32_t)v->start, (uint32_t)v->end,
                       v->prot, v->flags, (uint32_t)v->file_off,
                       (uint32_t)v->file_len, path ? path : "-");
            }
            g_sparse_mmap_fault_log_budget--;
        }
        return 0;
    }
    if (write && (prot & 0x2u) == 0) {
        if (g_sparse_mmap_fault_log_budget > 0) {
            printf("[mmap-fault] write-deny pid=%d task=%s owner=%d addr=0x%x prot=0x%x\n",
                   t->pid, t->name, mm->pid, (uint32_t)addr, prot);
            g_sparse_mmap_fault_log_budget--;
        }
        return 0;
    }
    page = page_align_down_local(addr);
#ifdef CONFIG_FS_SWAP
    {
        int restored = process_user_mmap_restore_swapped_page(
            mm, page, prot);
        if (restored != 0) return restored > 0 ? 2 : 0;
    }
#endif
    /*
     * Install an anonymous first-touch PTE with its final VMA permissions.
     * The old commit-then-protect sequence invalidated the same page twice and
     * reloaded CR3 twice on every anonymous browser fault.
     */
    if (process_user_mmap_commit_prot(
            mm, page, USER_PAGE_SIZE, prot) < 0) {
        if (g_sparse_mmap_fault_log_budget > 0) {
            printf("[mmap-fault] commit-fail pid=%d task=%s owner=%d addr=0x%x page=0x%x prot=0x%x backing=%u/%u pt=%u/%u\n",
                   t->pid, t->name, mm->pid, (uint32_t)addr, (uint32_t)page, prot,
                   process_user_mmap_backing_used_pages(), process_user_mmap_backing_total_pages(),
                   process_user_mmap_pt_used_pages(), process_user_mmap_pt_total_pages());
            g_sparse_mmap_fault_log_budget--;
        }
        return 0;
    }
    if (kernel_userfaultfd_apply_writeprotect(mm->cr3, page) < 0)
        return 0;
    return 1;
}

void process_user_mmap_discard_private(task_t *t, uint64_t start,
                                       uint64_t len) {
    enum { DISCARD_RELEASE_BATCH = 256 };
    uint64_t end;
    int release_backings[DISCARD_RELEASE_BATCH];
    uint32_t release_count = 0;
    int leaves_changed = 0;
    int idx;
    if (!t || len == 0) return;
    t = task_vm_owner_local(t);
    idx = task_index(t);
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start) return;
    if (!sparse_mmap_range_ok_local(start, end - start)) return;
    process_user_page_table_lock(t);
#ifdef CONFIG_FS_SWAP
    (void)edge_swap_map_drop_range(t->cr3, start, end - start);
#endif
    for (uint64_t va = start; va < end; va += USER_PAGE_SIZE) {
        uint32_t pml4_idx;
        uint32_t pdpt_idx = 0;
        uint32_t pde_idx = 0;
        uint32_t pte_idx = 0;
        uint64_t *pdpt;
        uint64_t pdpte;
        uint64_t *pd;
        uint64_t pde;
        uint64_t pte;
        uint64_t *pt;
        int backing_idx;
        edge_user_vma_t *v;
        if (sparse_mmap_indices(va, &pdpt_idx, &pde_idx, &pte_idx) < 0)
            continue;

        /*
         * MADV_DONTNEED is commonly issued over very large sparse allocator
         * reservations.  Walking every absent 4 KiB leaf can hold the shared
         * mm lock for seconds even though only a few page-table branches
         * exist.  Skip holes at the highest missing level; populated leaf
         * pages retain the same per-page discard and ownership checks below.
         */
        pml4_idx = (uint32_t)((va >> 39) & 0x1ffu);
        pdpt = sparse_mmap_pdpt_root(idx, pml4_idx, 0);
        if (!pdpt) {
            uint64_t next = (va | ((UINT64_C(1) << 39) - 1u)) + 1u;
            if (next == 0 || next >= end) break;
            va = next - USER_PAGE_SIZE;
            continue;
        }
        pdpte = pdpt[pdpt_idx];
        if ((pdpte & PAGE_PRESENT) == 0 || (pdpte & PAGE_PS) != 0) {
            uint64_t next = (va | ((UINT64_C(1) << 30) - 1u)) + 1u;
            if (next == 0 || next >= end) break;
            va = next - USER_PAGE_SIZE;
            continue;
        }
        pd = fixed_user_pt_ptr_from_phys(pdpte);
        if (!pd) continue;
        pde = pd[pde_idx];
        if ((pde & PAGE_PRESENT) == 0 || (pde & PAGE_PS) != 0) {
            uint64_t next = (va | ((UINT64_C(1) << 21) - 1u)) + 1u;
            if (next == 0 || next >= end) break;
            va = next - USER_PAGE_SIZE;
            continue;
        }
        pt = fixed_user_pt_ptr_from_phys(pde);
        if (!pt) continue;
        pte = pt[pte_idx];
        if ((pte & PAGE_PRESENT) == 0) {
            if (sparse_mmap_prune_boundary(va, end) &&
                sparse_mmap_pt_empty(pt))
                (void)sparse_mmap_prune_empty_tables(idx, va);
            continue;
        }
        v = process_user_vma_for_addr(t, va);
        /*
         * MADV_DONTNEED removes private anonymous pages from the calling
         * address space.  It must not zero a backing page in place: after
         * fork, that page can still be referenced through COW by another
         * process, and MAP_SHARED pages are the storage object itself.
         * Chromium exercises both cases while trimming renderer processes;
         * modifying the shared physical page corrupts allocator metadata in
         * otherwise unrelated processes.
         *
         * EdgeOS can fault private anonymous pages back as zero-filled pages,
         * so discard their PTE and release only this address-space reference.
         * Shared anonymous mappings need a separate shmem object before an
         * individual PTE can be discarded and later reattached to the same
         * page, so Linux permits the advice to remain non-destructive here.
         * File mappings also remain intact; dropping them requires preserving
         * fault-safe inode access and writeback ordering.
         */
        if (!v || v->file_backed ||
            (v->flags & USER_MAP_SHARED_FLAG) != 0)
            continue;
        backing_idx = sparse_mmap_backing_index_from_phys(pte & ~0xFFFULL);
        if (!sparse_mmap_backing_ptr(backing_idx)) continue;
        pt[pte_idx] = 0;
        invlpg_local(va);
        release_backings[release_count++] = backing_idx;
        leaves_changed = 1;
        if (release_count == DISCARD_RELEASE_BATCH) {
            process_user_page_table_unlock(t);
            sparse_mmap_flush_task(t);
            for (uint32_t release = 0; release < release_count;
                 ++release) {
                sparse_mmap_user_alias_release(release_backings[release]);
                sparse_mmap_release_backing_index_local(
                    release_backings[release]);
            }
            release_count = 0;
            leaves_changed = 0;
            process_user_page_table_lock(t);
        }
    }
    process_user_page_table_unlock(t);
    if (leaves_changed) sparse_mmap_flush_task(t);
    for (uint32_t release = 0; release < release_count; ++release) {
        sparse_mmap_user_alias_release(release_backings[release]);
        sparse_mmap_release_backing_index_local(release_backings[release]);
    }
}

uint32_t process_user_mmap_deactivate_range(task_t *t, uint64_t start,
                                            uint64_t len) {
    uint64_t end;
    uint32_t deactivated = 0;

    if (!t || !len) return 0;
    t = task_vm_owner_local(t);
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start ||
        !sparse_mmap_range_ok_local(start, end - start))
        return 0;
    for (uint64_t address = start; address < end;
         address += USER_PAGE_SIZE) {
        uint64_t *page_table;
        uint32_t pte_index;
        uint64_t old_entry;

        page_table = sparse_mmap_lookup_pt(t, address, 0);
        if (!page_table || sparse_mmap_indices(
                address, 0, 0, &pte_index) < 0)
            continue;
        old_entry = __atomic_load_n(
            &page_table[pte_index], __ATOMIC_ACQUIRE);
        while ((old_entry & (PAGE_PRESENT | PAGE_ACCESSED)) ==
               (PAGE_PRESENT | PAGE_ACCESSED)) {
            uint64_t new_entry = old_entry & ~PAGE_ACCESSED;
            if (__atomic_compare_exchange_n(
                    &page_table[pte_index], &old_entry, new_entry, 0,
                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                if (cr3_read_local_process() == t->cr3)
                    invlpg_local(address);
                ++deactivated;
                break;
            }
        }
    }
    return deactivated;
}

static int process_user_mmap_pageout_one(task_t *memory, uint64_t address,
                                         uint32_t cgroup_id) {
#ifdef CONFIG_FS_SWAP
    edge_user_vma_t *vma;
    uint64_t *page_table;
    uint32_t pte_index;
    uint64_t pte;
    int backing_index;
    uint16_t encoded_owner;
    uint32_t aliases;
    uint16_t references;
    uint64_t irq_flags;
    uint64_t swap_entry;
    uint64_t frozen_pte;
    int frozen = 0;

    if (!memory || cgroup_id >= UINT16_MAX || !swap_total_bytes())
        return 0;
    vma = process_user_vma_for_addr(memory, address);
    if (!vma || (vma->flags & USER_MAP_SHARED_FLAG) != 0 ||
        kernel_mm_lock_space_contains(memory->cr3, address))
        return 0;
    page_table = sparse_mmap_lookup_pt(memory, address, 0);
    if (!page_table || sparse_mmap_indices(
            address, 0, 0, &pte_index) < 0)
        return 0;
    pte = page_table[pte_index];
    if ((pte & (PAGE_PRESENT | PAGE_USER)) !=
            (PAGE_PRESENT | PAGE_USER) ||
        (pte & (PAGE_FILE_CACHE | PAGE_DEVICE)) != 0)
        return 0;
    backing_index = sparse_mmap_backing_index_from_phys(
        pte & ~0xFFFULL);
    if (backing_index < 0) return 0;
    irq_flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
    encoded_owner = g_user_mmap_backing_cgroup_owner[backing_index];
    aliases = g_user_mmap_backing_user_aliases[backing_index];
    references = g_user_mmap_backing_refcnt[backing_index];
    spin_unlock_irqrestore(&g_user_mmap_backing_lock, irq_flags);
    if (encoded_owner != (uint16_t)(cgroup_id + 1u) ||
        aliases != 1u || references != 1u)
        return 0;

    frozen_pte = pte;
    if (pte & PAGE_WRITE) {
        uint64_t expected = pte;

        sparse_mmap_retain_backing_index_local(backing_index);
        frozen_pte = (pte & ~PAGE_WRITE) | PAGE_COW;
        if (!__atomic_compare_exchange_n(
                &page_table[pte_index], &expected, frozen_pte, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            sparse_mmap_release_backing_index_local(backing_index);
            return 0;
        }
        sparse_mmap_flush_task(memory);
        frozen = 1;
    }
    if (swap_store_page(
            cgroup_id, sparse_mmap_backing_ptr(backing_index),
            &swap_entry) < 0) {
        if (frozen) {
            uint64_t expected = frozen_pte;
            uint64_t restored = (frozen_pte | PAGE_WRITE) & ~PAGE_COW;
            (void)__atomic_compare_exchange_n(
                &page_table[pte_index], &expected, restored, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            sparse_mmap_flush_task(memory);
            sparse_mmap_release_backing_index_local(backing_index);
        }
        return -1;
    }
    if (edge_swap_map_insert(
            memory->cr3, address, swap_entry) < 0) {
        swap_release_entry(swap_entry);
        if (frozen) {
            uint64_t expected = frozen_pte;
            uint64_t restored = (frozen_pte | PAGE_WRITE) & ~PAGE_COW;
            (void)__atomic_compare_exchange_n(
                &page_table[pte_index], &expected, restored, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            sparse_mmap_flush_task(memory);
            sparse_mmap_release_backing_index_local(backing_index);
        }
        return 0;
    }
    {
        uint64_t expected = frozen_pte;
        if (!__atomic_compare_exchange_n(
                &page_table[pte_index], &expected, 0, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            uint64_t rollback_entry;
            if (edge_swap_map_take(
                    memory->cr3, address, &rollback_entry) == 0)
                swap_release_entry(rollback_entry);
            if (frozen) {
                uint64_t restore_expected = frozen_pte;
                uint64_t restored =
                    (frozen_pte | PAGE_WRITE) & ~PAGE_COW;
                (void)__atomic_compare_exchange_n(
                    &page_table[pte_index], &restore_expected,
                    restored, 0, __ATOMIC_ACQ_REL,
                    __ATOMIC_ACQUIRE);
                sparse_mmap_flush_task(memory);
                sparse_mmap_release_backing_index_local(backing_index);
            }
            return 0;
        }
    }
    if (cr3_read_local_process() == memory->cr3)
        invlpg_local(address);
    sparse_mmap_user_alias_release(backing_index);
    sparse_mmap_release_backing_index_local(backing_index);
    if (frozen)
        sparse_mmap_release_backing_index_local(backing_index);
    return 1;
#else
    (void)memory;
    (void)address;
    (void)cgroup_id;
    return 0;
#endif
}

uint32_t process_user_mmap_pageout_range(task_t *t, uint64_t start,
                                         uint64_t len,
                                         uint64_t *scanned_pages_out) {
    uint64_t end;
    uint64_t scanned = 0;
    uint32_t reclaimed = 0;

    if (scanned_pages_out) *scanned_pages_out = 0;
    if (!t || !len) return 0;
    t = task_vm_owner_local(t);
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start ||
        !sparse_mmap_range_ok_local(start, end - start))
        return 0;
    for (uint64_t address = start; address < end;
         address += USER_PAGE_SIZE) {
        int result;
        ++scanned;
        result = process_user_mmap_pageout_one(
            t, address, t->cgroup_id);
        if (result < 0) break;
        reclaimed += (uint32_t)result;
    }
    if (reclaimed) sparse_mmap_flush_task(t);
    if (scanned_pages_out) *scanned_pages_out = scanned;
    edge_mm_statistics_note_reclaim(scanned, reclaimed);
    return reclaimed;
}

uint32_t process_user_mmap_drop_file_cache_range(task_t *t, uint64_t start,
                                                 uint64_t len) {
    uint64_t end;
    uint32_t unmapped = 0;

    if (!t || !len) return 0;
    t = task_vm_owner_local(t);
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start ||
        !sparse_mmap_range_ok_local(start, end - start))
        return 0;
    for (uint64_t address = start; address < end;
         address += USER_PAGE_SIZE) {
        uint64_t *page_table;
        uint32_t pte_index;
        uint64_t pte;
        int backing_index;

        page_table = sparse_mmap_lookup_pt(t, address, 0);
        if (!page_table || sparse_mmap_indices(
                address, 0, 0, &pte_index) < 0)
            continue;
        pte = __atomic_load_n(&page_table[pte_index], __ATOMIC_ACQUIRE);
        if ((pte & (PAGE_PRESENT | PAGE_USER | PAGE_FILE_CACHE)) !=
            (PAGE_PRESENT | PAGE_USER | PAGE_FILE_CACHE))
            continue;
        backing_index = sparse_mmap_backing_index_from_phys(
            pte & ~0xFFFULL);
        if (backing_index < 0) continue;

        /*
         * Keep the backing alive until stale translations are invalidated.
         * Cache pressure can otherwise release the final cache reference as
         * soon as the PTE disappears while another CPU still uses its TLB.
         */
        sparse_mmap_retain_backing_index_local(backing_index);
        if (!__atomic_compare_exchange_n(
                &page_table[pte_index], &pte, 0, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            sparse_mmap_release_backing_index_local(backing_index);
            continue;
        }
        sparse_mmap_flush_task(t);
        sparse_mmap_user_alias_release(backing_index);
        sparse_mmap_release_backing_index_local(backing_index);
        sparse_mmap_release_backing_index_local(backing_index);
        ++unmapped;
    }
    return unmapped;
}

/*
 * Writable anonymous pages are frozen as COW while storage I/O is in flight.
 * A concurrent writer therefore receives a private copy and the saved page
 * remains an exact snapshot.  The final PTE exchange is atomic so it cannot
 * evict a replacement installed by a racing fault.
 */
uint32_t process_user_mmap_swap_reclaim(uint32_t cgroup_id,
                                        uint32_t target_pages,
                                        uint64_t *scanned_pages_out) {
#ifdef CONFIG_FS_SWAP
    static uint32_t task_cursor;
    static uint32_t vma_cursor;
    static uint64_t address_cursor;
    uint32_t reclaimed = 0;
    uint32_t scanned = 0;
    uint32_t scan_budget;

    if (scanned_pages_out) *scanned_pages_out = 0;
    if (!target_pages || cgroup_id >= UINT16_MAX || !swap_total_bytes())
        return 0;
    scan_budget = target_pages > 64u ? 4096u : target_pages * 64u;
    if (scan_budget < 128u) scan_budget = 128u;
    while (reclaimed < target_pages && scanned < scan_budget) {
        task_t *memory;
        edge_user_vma_t *vma;
        uint64_t address;
        uint64_t *pt;
        uint32_t pte_index;
        uint64_t pte;
        int backing_index;
        uint16_t encoded_owner;
        uint32_t aliases;
        uint16_t references;
        uint64_t irq_flags;
        uint64_t swap_entry;
        uint64_t frozen_pte;
        int frozen = 0;

        if (task_cursor >= PROC_MAX_TASKS) {
            task_cursor = 0;
            vma_cursor = 0;
            address_cursor = 0;
        }
        memory = &g_tasks[task_cursor];
        if (memory->state == TASK_UNUSED ||
            task_vm_owner_local(memory) != memory) {
            ++task_cursor;
            vma_cursor = 0;
            address_cursor = 0;
            continue;
        }
        if (vma_cursor >= (uint32_t)process_user_vma_live_count(memory)) {
            ++task_cursor;
            vma_cursor = 0;
            address_cursor = 0;
            continue;
        }
        vma = &memory->user_vmas[vma_cursor];
        if (vma->end <= vma->start || vma->file_backed ||
            (vma->flags & USER_MAP_SHARED_FLAG) != 0) {
            ++vma_cursor;
            address_cursor = 0;
            continue;
        }
        if (address_cursor < vma->start || address_cursor >= vma->end)
            address_cursor = page_align_down_local(vma->start);
        address = address_cursor;
        address_cursor += USER_PAGE_SIZE;
        if (address_cursor >= vma->end) {
            ++vma_cursor;
            address_cursor = 0;
        }
        ++scanned;
        if (kernel_mm_lock_space_contains(memory->cr3, address))
            continue;
        pt = sparse_mmap_lookup_pt(memory, address, 0);
        if (!pt || sparse_mmap_indices(
                address, 0, 0, &pte_index) < 0)
            continue;
        pte = pt[pte_index];
        if ((pte & (PAGE_PRESENT | PAGE_USER)) !=
                (PAGE_PRESENT | PAGE_USER) ||
            (pte & (PAGE_FILE_CACHE | PAGE_DEVICE)) != 0)
            continue;
        backing_index = sparse_mmap_backing_index_from_phys(
            pte & ~0xFFFULL);
        if (backing_index < 0) continue;
        irq_flags = spin_lock_irqsave(&g_user_mmap_backing_lock);
        encoded_owner =
            g_user_mmap_backing_cgroup_owner[backing_index];
        aliases = g_user_mmap_backing_user_aliases[backing_index];
        references = g_user_mmap_backing_refcnt[backing_index];
        spin_unlock_irqrestore(&g_user_mmap_backing_lock, irq_flags);
        if (encoded_owner != (uint16_t)(cgroup_id + 1u) ||
            aliases != 1u || references != 1u)
            continue;
        if (pte & PAGE_ACCESSED) {
            pt[pte_index] = pte & ~PAGE_ACCESSED;
            if (cr3_read_local_process() == memory->cr3)
                invlpg_local(address);
            continue;
        }
        frozen_pte = pte;
        if (pte & PAGE_WRITE) {
            uint64_t expected = pte;

            sparse_mmap_retain_backing_index_local(backing_index);
            frozen_pte = (pte & ~PAGE_WRITE) | PAGE_COW;
            if (!__atomic_compare_exchange_n(
                    &pt[pte_index], &expected, frozen_pte, 0,
                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                sparse_mmap_release_backing_index_local(backing_index);
                continue;
            }
            sparse_mmap_flush_task(memory);
            frozen = 1;
        }
        if (swap_store_page(
                cgroup_id, sparse_mmap_backing_ptr(backing_index),
                &swap_entry) < 0) {
            if (frozen) {
                uint64_t expected = frozen_pte;
                uint64_t restored = (frozen_pte | PAGE_WRITE) & ~PAGE_COW;
                (void)__atomic_compare_exchange_n(
                    &pt[pte_index], &expected, restored, 0,
                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
                sparse_mmap_flush_task(memory);
                sparse_mmap_release_backing_index_local(backing_index);
            }
            break;
        }
        if (edge_swap_map_insert(
                memory->cr3, address, swap_entry) < 0) {
            swap_release_entry(swap_entry);
            if (frozen) {
                uint64_t expected = frozen_pte;
                uint64_t restored = (frozen_pte | PAGE_WRITE) & ~PAGE_COW;
                (void)__atomic_compare_exchange_n(
                    &pt[pte_index], &expected, restored, 0,
                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
                sparse_mmap_flush_task(memory);
                sparse_mmap_release_backing_index_local(backing_index);
            }
            continue;
        }
        {
            uint64_t expected = frozen_pte;
            if (!__atomic_compare_exchange_n(
                    &pt[pte_index], &expected, 0, 0,
                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                uint64_t rollback_entry;
                if (edge_swap_map_take(
                        memory->cr3, address, &rollback_entry) == 0)
                    swap_release_entry(rollback_entry);
                if (frozen) {
                    uint64_t restore_expected = frozen_pte;
                    uint64_t restored =
                        (frozen_pte | PAGE_WRITE) & ~PAGE_COW;
                    (void)__atomic_compare_exchange_n(
                        &pt[pte_index], &restore_expected, restored, 0,
                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
                    sparse_mmap_flush_task(memory);
                    sparse_mmap_release_backing_index_local(backing_index);
                }
                continue;
            }
        }
        if (cr3_read_local_process() == memory->cr3)
            invlpg_local(address);
        sparse_mmap_user_alias_release(backing_index);
        sparse_mmap_release_backing_index_local(backing_index);
        if (frozen)
            sparse_mmap_release_backing_index_local(backing_index);
        ++reclaimed;
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

static void sparse_mmap_release_detached_pd(uint64_t *pd) {
    if (!pd) return;
    for (uint32_t pde_idx = 0; pde_idx < 512; ++pde_idx) {
        uint64_t pde = pd[pde_idx];
        uint64_t *pt;
        pd[pde_idx] = 0;
        if ((pde & PAGE_PRESENT) == 0 || (pde & PAGE_PS) != 0) {
            continue;
        }
        pt = fixed_user_pt_ptr_from_phys(pde);
        if (!pt) continue;
        for (uint32_t pte_idx = 0; pte_idx < 512; ++pte_idx) {
            uint64_t pte = pt[pte_idx];
            int backing_idx;
            if ((pte & PAGE_PRESENT) == 0) continue;
            backing_idx =
                sparse_mmap_backing_index_from_phys(pte & ~0xFFFULL);
            pt[pte_idx] = 0;
            if (backing_idx >= 0) {
                sparse_mmap_user_alias_release(backing_idx);
                sparse_mmap_release_backing_index_local(backing_idx);
            }
        }
        sparse_mmap_release_table(pt);
    }
    sparse_mmap_release_table(pd);
}

static void sparse_mmap_release_detached_pdpt(uint64_t *pdpt) {
    if (!pdpt) return;
    for (uint32_t pdpt_idx = 0; pdpt_idx < USER_PDPT_COUNT; ++pdpt_idx) {
        uint64_t entry = pdpt[pdpt_idx];
        pdpt[pdpt_idx] = 0;
        if ((entry & PAGE_PRESENT) == 0 || (entry & PAGE_PS) != 0)
            continue;
        sparse_mmap_release_detached_pd(
            fixed_user_pt_ptr_from_phys(entry));
    }
    sparse_mmap_release_table(pdpt);
}

static void process_user_mmap_reset_internal(task_t *t) {
    uint64_t *detached_low_pd[USER_LOW_SPARSE_MMAP_PDPT_COUNT] = {0};
    uint64_t *detached_high_pdpt[USER_SPARSE_MMAP_PML4_COUNT] = {0};
    uint64_t rflags;
    uint64_t hardware_cr3;
    int idx;
    int had_fbdev_mapping;

    t = task_vm_owner_local(t);
    idx = task_index(t);
    if (!t || idx < 0 || idx >= USER_AS_MAX_TASKS) return;
    kernel_userfaultfd_address_space_release(t->cr3);
    kernel_mm_lock_space_release(t->cr3);
#ifdef CONFIG_FS_SWAP
    edge_swap_map_release_space(t->cr3);
#endif
    had_fbdev_mapping = g_user_fbdev_owner_active[idx] != 0;
    g_user_fbdev_owner_active[idx] = 0;

    /*
     * A page-table destroy is a three-phase operation: detach every reachable
     * root, invalidate/deactivate the hardware address space, then recycle the
     * detached hierarchy.  Page-table pages share the ordinary backing
     * allocator, so releasing a table while a parent entry or TLB can still
     * reach it would let that physical page be reused as user data.
     *
     * Keep interrupts disabled across the local teardown.  The x86 scheduler is
     * currently uniprocessor-only; an SMP backend must replace this section with
     * the architecture's mm lock and remote TLB-shootdown primitive.
     */
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(rflags) :: "memory");
    for (uint32_t pdpt_idx = USER_LOW_SPARSE_MMAP_PDPT_FIRST;
         pdpt_idx < USER_LOW_SPARSE_MMAP_PDPT_LAST_EXCL; ++pdpt_idx) {
        uint64_t entry = g_pdpt[idx][pdpt_idx];
        g_pdpt[idx][pdpt_idx] = 0;
        if ((entry & PAGE_PRESENT) != 0 && (entry & PAGE_PS) == 0) {
            detached_low_pd[pdpt_idx -
                            USER_LOW_SPARSE_MMAP_PDPT_FIRST] =
                fixed_user_pt_ptr_from_phys(entry);
        }
    }
    for (uint32_t slot = 0; slot < USER_SPARSE_MMAP_PML4_COUNT;
         ++slot) {
        uint64_t *pdpt = g_pdpt_sparse[idx][slot];
        uint32_t pml4_idx = USER_SPARSE_MMAP_PML4_FIRST + slot;
        g_pml4[idx][pml4_idx] = 0;
        g_pdpt_sparse[idx][slot] = 0;
        detached_high_pdpt[slot] = pdpt;
    }

    /*
     * A reset destroys this mm.  Never use sparse_mmap_flush_task() here: that
     * helper intentionally loads a live owner CR3 for CLONE_VM updates and can
     * undo an exit/exec path's switch to the kernel CR3.  If the target CR3 is
     * still active, leave it permanently before any detached page is released.
     */
    hardware_cr3 = cr3_read_local_process();
    if (t->cr3 && hardware_cr3 == t->cr3 &&
        g_kernel_cr3 && g_kernel_cr3 != t->cr3) {
        cr3_write(g_kernel_cr3);
    }

    for (uint32_t slot = 0; slot < USER_LOW_SPARSE_MMAP_PDPT_COUNT;
         ++slot) {
        sparse_mmap_release_detached_pd(detached_low_pd[slot]);
    }
    for (uint32_t slot = 0; slot < USER_SPARSE_MMAP_PML4_COUNT;
         ++slot) {
        sparse_mmap_release_detached_pdpt(detached_high_pdpt[slot]);
    }
    if (rflags & (1ULL << 9)) __asm__ __volatile__("sti");
    if (had_fbdev_mapping && !process_user_any_fbdev_mapping()) {
        fb_release_user_mmap();
        if (!syscall_console_active_vt_in_graphics())
            fb_console_set_present_enabled(1);
    }
}

void process_user_mmap_reset(task_t *t) {
    process_user_mmap_reset_internal(t);
}

static int process_mrelease_group_will_free(const task_t *task) {
    const uint64_t kill_bit =
        UINT64_C(1) << (LINUX_SIGKILL - 1u);
    int group;

    if (!task || task->state == TASK_UNUSED ||
        task->state == TASK_ZOMBIE)
        return 0;
    group = process_tgid_of_task(task);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        const task_t *peer = &g_tasks[index];
        if (peer->state == TASK_UNUSED || peer->state == TASK_ZOMBIE ||
            process_tgid_of_task(peer) != group)
            continue;
        if (peer->group_exit_pending ||
            ((peer->signal_pending | peer->signal_shared_pending) &
             kill_bit))
            return 1;
    }
    return 0;
}

int arch_mm_process_mrelease(int32_t pid) {
    task_t *target = task_find_by_pid(pid);
    task_t *memory;
    task_t *current = process_current_task();
    int memory_owner_pid;

    if (!target || target->state == TASK_UNUSED ||
        target->state == TASK_ZOMBIE)
        return -EDGE_LINUX_ESRCH;
    memory = task_vm_owner_local(target);
    if (!memory || !memory->cr3)
        return -EDGE_LINUX_ESRCH;
    if (!process_mrelease_group_will_free(target))
        return -EDGE_LINUX_EINVAL;

    memory_owner_pid = process_vm_owner_pid_of_task_raw(memory);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *peer = &g_tasks[index];
        if (peer->state == TASK_UNUSED || peer->state == TASK_ZOMBIE ||
            process_vm_owner_pid_of_task_raw(peer) != memory_owner_pid)
            continue;
        if (!process_mrelease_group_will_free(peer))
            return -EDGE_LINUX_EINVAL;
        if (peer == current ||
            __atomic_load_n(&peer->on_cpu, __ATOMIC_ACQUIRE))
            return -EDGE_LINUX_EAGAIN;
    }
    if (__atomic_load_n(&memory->user_vma_mutation_lock,
                        __ATOMIC_ACQUIRE))
        return -EDGE_LINUX_EAGAIN;

    process_user_vma_mutation_lock(memory);
    if (!process_mrelease_group_will_free(target)) {
        process_user_vma_mutation_unlock(memory);
        return -EDGE_LINUX_EINVAL;
    }
    process_user_mmap_reset(memory);
    task_clear_user_regions(memory);
    process_user_vma_mutation_unlock(memory);
    return 0;
}

int process_user_mmap_clone(task_t *dst, const task_t *src) {
    int src_vma_live;
    dst = task_vm_owner_local(dst);
    src = task_vm_owner_local((task_t *)src);
    int dst_idx = task_index(dst);
    int src_idx = task_index((task_t *)src);
    if (!dst || !src || dst_idx < 0 || src_idx < 0 || dst_idx >= USER_AS_MAX_TASKS || src_idx >= USER_AS_MAX_TASKS) return -1;
    src_vma_live = process_user_vma_sort_by_start((task_t *)src);
    for (uint32_t root = 0; root <= USER_SPARSE_MMAP_PML4_COUNT;
         ++root) {
        uint32_t pml4_idx;
        uint32_t pdpt_first;
        uint32_t pdpt_last;
        uint64_t *src_pdpt;
        if (root == 0) {
            pml4_idx = USER_LOW_SPARSE_MMAP_PML4_IDX;
            pdpt_first = USER_LOW_SPARSE_MMAP_PDPT_FIRST;
            pdpt_last = USER_LOW_SPARSE_MMAP_PDPT_LAST_EXCL;
            src_pdpt = &g_pdpt[src_idx][0];
        } else {
            pml4_idx = USER_SPARSE_MMAP_PML4_FIRST + root - 1u;
            pdpt_first = 0;
            pdpt_last = USER_PDPT_COUNT;
            src_pdpt = g_pdpt_sparse[src_idx][root - 1u];
            if (!src_pdpt) continue;
        }
        for (uint32_t pdpt_idx = pdpt_first;
             pdpt_idx < pdpt_last; ++pdpt_idx) {
            uint64_t pdpte = src_pdpt[pdpt_idx];
            uint64_t *src_pd;
            if ((pdpte & PAGE_PRESENT) == 0 ||
                (pdpte & PAGE_PS) != 0)
                continue;
            src_pd = fixed_user_pt_ptr_from_phys(pdpte);
            if (!src_pd) return -1;
            for (uint32_t pde_idx = 0; pde_idx < 512; ++pde_idx) {
                uint64_t src_pde = src_pd[pde_idx];
                uint64_t *src_pt;
                uint64_t *dst_pt = 0;
                uint64_t pde_base;
                if ((src_pde & PAGE_PRESENT) == 0 ||
                    (src_pde & PAGE_PS) != 0)
                    continue;
                src_pt = fixed_user_pt_ptr_from_phys(src_pde);
                if (!src_pt) return -1;
                pde_base = ((uint64_t)pml4_idx << 39) |
                           ((uint64_t)pdpt_idx << 30) |
                           ((uint64_t)pde_idx << 21);
                if (sparse_mmap_ensure_pt(dst, pde_base, &dst_pt) < 0)
                    return -1;
                for (uint32_t pte_idx = 0; pte_idx < 512;
                     ++pte_idx) {
                    uint64_t src_pte = src_pt[pte_idx];
                    uint64_t va =
                        pde_base | ((uint64_t)pte_idx << 12);
                    int src_backing_idx;
                    edge_user_vma_t *v;
                    uint64_t shared_pte;
                    v = process_user_vma_for_addr_sorted(
                        (task_t *)src, src_vma_live, va);
                    if (v &&
                        (v->fork_policy & KERNEL_MM_VMA_FORK_WIPE) != 0)
                        continue;
                    if ((src_pte & PAGE_PRESENT) == 0) {
                        if (src_pte == PAGE_POISONED)
                            dst_pt[pte_idx] = PAGE_POISONED;
                        continue;
                    }
                    if ((src_pte & PAGE_DEVICE) != 0) {
                        dst_pt[pte_idx] =
                            src_pte & ~(PAGE_COW | PAGE_FILE_CACHE);
                        continue;
                    }
                    if (process_user_vma_is_fbdev(v)) {
                        dst_pt[pte_idx] =
                            src_pte & ~(PAGE_COW | PAGE_FILE_CACHE);
                        continue;
                    }
                    if ((src_pte & ~0xFFFULL) == fixed_user_zero_phys()) {
                        /* The global zero page has no sparse-backing reference
                         * to retain.  Its read-only/COW leaf can be shared by
                         * the child exactly as-is. */
                        dst_pt[pte_idx] = src_pte;
                        continue;
                    }
                    src_backing_idx =
                        sparse_mmap_backing_index_from_phys(
                            src_pte & ~0xFFFULL);
                    if (!sparse_mmap_backing_ptr(src_backing_idx))
                        return -1;
                    if (sparse_mmap_user_alias_acquire(
                            dst, src_backing_idx) < 0)
                        return -1;
                    sparse_mmap_retain_backing_index_local(
                        src_backing_idx);
                    shared_pte = src_pte;
                    if ((src_pte & PAGE_WRITE) != 0 &&
                        (!v ||
                         (v->flags & USER_MAP_SHARED_FLAG) == 0)) {
                        shared_pte =
                            (src_pte & ~PAGE_WRITE) | PAGE_COW;
                        src_pt[pte_idx] = shared_pte;
                    }
                    dst_pt[pte_idx] = shared_pte;
                }
            }
        }
    }
    process_user_fbdev_owner_refresh(dst);
    return 0;
}

static uint8_t *process_user_byte_ptr(task_t *t, uint64_t addr, int write) {
    task_t *mm;
    int idx;

    if (!t || addr < EDGE_USER_MIN_ADDR || addr >= EDGE_USER_MAX_ADDR) return 0;
    mm = task_vm_owner_local(t);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return 0;

    if (fixed_user_addr(addr)) {
        uint64_t *entryp = fixed_user_pte_for_addr_idx(idx, addr);
        uint64_t entry;
        uint8_t *page;
        if (!entryp) return 0;
        entry = *entryp;
        if ((entry & (PAGE_PRESENT | PAGE_USER)) !=
                (PAGE_PRESENT | PAGE_USER) &&
            process_user_fixed_handle_fault(mm, addr, write)) {
            entry = *entryp;
        }
        if ((entry & (PAGE_PRESENT | PAGE_USER)) !=
            (PAGE_PRESENT | PAGE_USER)) return 0;
        if (write && (entry & PAGE_WRITE) == 0) {
            if ((entry & PAGE_COW) == 0 ||
                !private_pte_resolve_cow(mm, addr, entryp)) return 0;
            entry = *entryp;
        }
        entry |= PAGE_ACCESSED;
        if (write) entry |= PAGE_DIRTY;
        *entryp = entry;
        page = (uint8_t *)edge_mmio_low_alias(entry & ~0xFFFULL);
        return page ? page + (addr & (USER_PAGE_SIZE - 1ULL)) : 0;
    }
    if (addr >= USER_HEAP_BASE && addr < USER_HEAP_BASE + USER_HEAP_TOTAL_SIZE) {
        return process_user_heap_byte_ptr(t, addr, write);
    }
    if (sparse_mmap_range_ok_local(addr, 1)) {
        uint32_t pte_idx;
        uint64_t *pde_entry;
        uint64_t pde;
        uint64_t *pt;
        uint64_t pte;
        uint8_t *page;
        if (write && process_user_mmap_resolve_cow(mm, addr) < 0) return 0;
        if (sparse_mmap_indices(addr, 0, 0, &pte_idx) < 0) return 0;
        pde_entry = sparse_mmap_pde_entry(idx, addr, 0);
        if (!pde_entry) return 0;
        pde = *pde_entry;
        if ((pde & PAGE_PRESENT) == 0 || (pde & PAGE_PS) != 0) return 0;
        pt = fixed_user_pt_ptr_from_phys(pde);
        if (!pt) return 0;
        pte = pt[pte_idx];
        if ((pte & PAGE_PRESENT) == 0 || (pte & PAGE_USER) == 0) return 0;
        if (write && (pte & PAGE_WRITE) == 0) {
            if (!process_user_mmap_handle_fault(mm, addr, 1)) return 0;
            pte = pt[pte_idx];
            if ((pte & PAGE_WRITE) == 0) return 0;
        }
        page = (uint8_t *)edge_mmio_low_alias(pte & ~0xFFFULL);
        return page + (addr & (USER_PAGE_SIZE - 1ULL));
    }
    return 0;
}

int process_read_user_memory(int pid, uint64_t src_u, void *dst, uint64_t len) {
    task_t *target;
    uint8_t *out = (uint8_t *)dst;
    uint64_t off = 0;

    if (!dst && len) return -1;
    if (len == 0) return 0;
    if (src_u + len < src_u) return -1;
    target = task_find_by_pid(pid);
    if (!target) return -1;
    while (off < len) {
        uint64_t addr = src_u + off;
        uint64_t chunk = USER_PAGE_SIZE - (addr & (USER_PAGE_SIZE - 1ULL));
        uint8_t *p = process_user_byte_ptr(target, addr, 0);
        if (!p) return -1;
        if (chunk > len - off) chunk = len - off;
        memcpy(out + off, p, (uint32_t)chunk);
        off += chunk;
    }
    return 0;
}

int process_write_user_memory(int pid, uint64_t dst_u, const void *src, uint64_t len) {
    task_t *target;
    const uint8_t *in = (const uint8_t *)src;
    uint64_t off = 0;

    if (!src && len) return -1;
    if (len == 0) return 0;
    if (dst_u + len < dst_u) return -1;
    target = task_find_by_pid(pid);
    if (!target) return -1;
    while (off < len) {
        uint64_t addr = dst_u + off;
        uint64_t chunk = USER_PAGE_SIZE - (addr & (USER_PAGE_SIZE - 1ULL));
        uint8_t *p = process_user_byte_ptr(target, addr, 1);
        if (!p) return -1;
        if (chunk > len - off) chunk = len - off;
        memcpy(p, in + off, (uint32_t)chunk);
        off += chunk;
    }
    /*
     * Do not reload CR3 after ordinary user copies.  The sparse mmap paths
     * that actually change PTEs, such as copy-on-write resolution and lazy
     * page population, already invalidate/reload the active address space at
     * the point of mutation.  Linux getdents/read/ioctl style syscalls can
     * copy thousands of small records; forcing a CR3 reload after every record
     * makes desktop directory scans and D-Bus/X11 traffic dramatically slower
     * without adding correctness.
     */
    return 0;
}

static int task_name_from_path(const char *path, char *out, int out_sz) {
    if (!path || !out || out_sz <= 0) return -1;
    const char *name = path;
    for (const char *p = path; *p; ++p) {
        if (*p == '/') name = p + 1;
    }
    int i = 0;
    while (name[i] && i < out_sz - 1) {
        out[i] = name[i];
        ++i;
    }
    out[i] = '\0';
    return 0;
}

static void process_canonicalize_syscall_frame(edge_trap_frame_t *tf) {
    if (!tf) return;
    /*
     * Fork/clone children resume through an iret frame copied from the parent.
     * The Linux-visible continuation is always userspace; never let a stale or
     * partially constructed kernel selector survive into the child frame.
     */
    tf->cs = USER_CS;
    tf->ss = USER_DS;
    if (tf->int_no == 6 && tf->rcx >= EDGE_USER_MIN_ADDR && tf->rcx < EDGE_USER_MAX_ADDR) {
        tf->rip = tf->rcx;
    }
    tf->rflags = (tf->r11 | 0x2ull) & ~(1ull << 8);
}

static int task_build_address_space(task_t *t, int user_mode) {
    int idx = task_index(t);
    const int trace_as_build = 0;
    if (!t || idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    if (user_mode && fixed_user_backing_prepare_for_idx(idx) < 0) {
        printf("[fixed-backing] cannot prepare user address space idx=%d pid=%d name=%s\n",
               idx, t->pid, t->name[0] ? t->name : "?");
        return -1;
    }
    if (trace_as_build && t && t->pid > 0 && t->pid <= 2) {
        proc_trace_puts("[as-build] enter pid=");
        proc_trace_dec(t->pid);
        proc_trace_puts(" idx=");
        proc_trace_dec(idx);
        proc_trace_puts(" user=");
        proc_trace_dec(user_mode);
        proc_trace_puts("\n");
    }
    if (user_mode) process_user_mmap_reset_internal(t);
    if (trace_as_build && t && t->pid > 0 && t->pid <= 2) proc_trace_puts("[as-build] mmap-reset\n");
    memset(g_pml4[idx], 0, sizeof(g_pml4[idx]));
    memset(g_pdpt[idx], 0, sizeof(g_pdpt[idx]));
    memset(g_pdpt_pci_mmio[idx], 0, sizeof(g_pdpt_pci_mmio[idx]));
    memset(g_pdpt_mmio_low_alias[idx], 0, sizeof(g_pdpt_mmio_low_alias[idx]));
    memset(g_pd[idx], 0, sizeof(g_pd[idx]));
    if (trace_as_build && t && t->pid > 0 && t->pid <= 2) proc_trace_puts("[as-build] roots-cleared\n");
    if (idx >= 0 && idx < USER_AS_MAX_TASKS) {
        memset(g_pdpt_sparse[idx], 0, sizeof(g_pdpt_sparse[idx]));
        if (user_mode && fixed_user_pt_ensure_for_idx(idx) < 0) {
            printf("[fixed-pt] cannot build user address space idx=%d pid=%d name=%s\n",
                   idx, t ? t->pid : -1, (t && t->name[0]) ? t->name : "?");
            fixed_user_pt_release_for_idx(idx);
            t->cr3 = 0;
            return -1;
        }
    }
    if (trace_as_build && t && t->pid > 0 && t->pid <= 2) proc_trace_puts("[as-build] sparse-cleared\n");

    uint64_t upper_flags = PAGE_PRESENT | PAGE_WRITE;
    if (user_mode) upper_flags |= PAGE_USER;

    g_pml4[idx][0] = ((uint64_t)&g_pdpt[idx][0]) | upper_flags;
    g_pml4[idx][USER_PCI_MMIO_PML4_IDX] = ((uint64_t)&g_pdpt_pci_mmio[idx][0]) |
                                          PAGE_PRESENT | PAGE_WRITE;
    for (uint32_t slot = 0; slot < EDGE_MMIO_LOW_ALIAS_PML4_COUNT; ++slot) {
        g_pml4[idx][EDGE_MMIO_LOW_ALIAS_PML4_INDEX + slot] =
            ((uint64_t)&g_pdpt_mmio_low_alias[idx][slot][0]) | PAGE_PRESENT | PAGE_WRITE;
    }
    for (int pdi = 0; pdi < 512; ++pdi) {
        uint64_t base = USER_PCI_MMIO_PML4_BASE + ((uint64_t)pdi << 30);
        g_pdpt_pci_mmio[idx][pdi] = base | PAGE_PRESENT | PAGE_WRITE | PAGE_PS;
    }

    for (uint32_t slot = 0; slot < EDGE_MMIO_LOW_ALIAS_PML4_COUNT; ++slot) {
        for (uint32_t pdi = 0; pdi < 512; ++pdi) {
            uint64_t phys = ((uint64_t)slot << 39) | ((uint64_t)pdi << 30);
            g_pdpt_mmio_low_alias[idx][slot][pdi] =
                phys | PAGE_PRESENT | PAGE_WRITE | PAGE_PS;
        }
    }

    for (int pdi = 0; pdi < USER_PDPT_COUNT; ++pdi) {
        if (pdi >= USER_LOW_PDPT_COUNT && pdi < USER_KERNEL_IDENTITY_PDPT_COUNT) {
            g_pdpt[idx][pdi] = ((uint64_t)pdi << 30) | PAGE_PRESENT | PAGE_WRITE | PAGE_PS;
            continue;
        }
        if (pdi >= USER_LOW_PDPT_COUNT) {
            g_pdpt[idx][pdi] = 0;
            continue;
        }
        if (user_mode &&
            (uint32_t)pdi >= USER_LOW_SPARSE_MMAP_PDPT_FIRST &&
            (uint32_t)pdi < USER_LOW_SPARSE_MMAP_PDPT_LAST_EXCL) {
            g_pdpt[idx][pdi] = 0;
            continue;
        }
        /*
         * Keep the low physical identity map supervisor-only in user address
         * spaces.  Earlier builds marked non-kernel identity PDEs PAGE_USER and
         * then overlaid a few Linux ABI windows on top.  That let normal Linux
         * processes reach sparse-mmap backing pages through their raw physical
         * addresses; X11/fbdev traffic could then overwrite shared library
         * backing and later processes executed framebuffer-looking bytes.
         *
         * Linux exposes user memory through VMAs, not through a writable low
         * physical map.  The real user mappings are installed below by the
         * fixed windows, sparse mmap roots, and the explicit fbdev aperture.
         */
        g_pdpt[idx][pdi] = ((uint64_t)&g_pd[idx][pdi][0]) | upper_flags;
        for (int i = 0; i < 512; ++i) {
            uint64_t base = ((uint64_t)pdi << 30) + ((uint64_t)i << 21);
            uint64_t flags = PAGE_PRESENT | PAGE_WRITE | PAGE_PS;
            if (pdi >= USER_KERNEL_IDENTITY_PDPT_COUNT) {
                g_pd[idx][pdi][i] = 0;
                continue;
            }
            g_pd[idx][pdi][i] = base | flags;
        }
    }
    if (user_mode && idx < USER_AS_MAX_TASKS) {
        map_user_low_window_pte(idx);
        map_user_text_window_pte(idx);
        map_user_stack_window_pte(idx);
        process_user_heap_install_roots(idx);
        map_user_bigpie_window_pte(idx);
        clear_user_fbdev_window_pte(idx);
        map_user_fbdev_window_pte(idx);
    }

    {
        uint64_t fb_phys = 0, fb_virt = 0;
        uint32_t fb_pages = 0;
        if (fb_get_2m_remap(&fb_phys, &fb_pages, &fb_virt)) {
            uint64_t kflags = PAGE_PRESENT | PAGE_WRITE | PAGE_PS;
            uint32_t pde_start = (uint32_t)((fb_virt - 0xC0000000ULL) >> 21);
            for (uint32_t i = 0; i < fb_pages && (pde_start + i) < 512; ++i) {
                g_pd[idx][3][pde_start + i] = (fb_phys + ((uint64_t)i << 21)) | kflags;
            }
        }
    }

    t->cr3 = (uint64_t)&g_pml4[idx][0];
    if (trace_as_build && t && t->pid > 0 && t->pid <= 2) {
        proc_trace_puts("[as-build] done pid=");
        proc_trace_dec(t->pid);
        proc_trace_puts(" cr3=");
        proc_trace_hex(t->cr3);
        proc_trace_puts("\n");
    }
    return 0;
}

void process_refresh_fixed_user_mappings(task_t *t) {
    task_t *mm;
    int idx;
    task_t *cur;
    int roots_changed = 0;
    if (!t) return;
    mm = task_vm_owner_local(t);
    if (!mm) return;
    idx = task_index(mm);
    if (idx < 0 || idx >= USER_AS_MAX_TASKS) return;

    /*
     * Linux mmaps are independent from the fixed text/heap/stack windows.
     * EdgeOS currently keeps those mmap PTEs under per-task sparse roots that
     * occupy the same low canonical PDPT slots as the boot-time supervisor
     * identity map.  Any path that refreshes fixed userspace mappings must
     * also restore the sparse roots; otherwise a valid low mmap VMA can fault
     * through the stale kernel identity entry instead of the user page tables.
     *
     * CLONE_VM threads share the leader's mm but still have their own task_t.
     * Refresh the mm owner, not the current thread's spare task slot; otherwise
     * GTK/XFCE helper threads can keep running with an old low identity PDPT
     * entry in the real CR3 while the refreshed roots live in an unused slot.
     *
     * The fixed-window leaf PTEs are persistent and are updated by mmap,
     * mprotect, fault, and exec paths at the point of mutation.  Rebuilding all
     * of them after every syscall rewrote thousands of cache lines and flushed
     * CR3 even when no mapping changed.  That turned every pthread futex
     * handoff into desktop-visible latency.  This exit hook only repairs root
     * entries that another mapping path could have displaced, and flushes the
     * active address space only when such a repair was actually necessary.
    */
    roots_changed |= sparse_mmap_install_roots(idx);
    roots_changed |= restore_user_low_window_roots(idx);
    roots_changed |= restore_user_text_window_root(idx);
    roots_changed |= restore_user_stack_window_root(idx);
    roots_changed |= process_user_heap_install_roots(idx);
    roots_changed |= restore_user_bigpie_window_roots(idx);
    map_user_fbdev_window_pte(idx);

    cur = process_current_task();
    if (roots_changed &&
        (cur == mm || (cur && cur->cr3 == mm->cr3)))
        cr3_write(mm->cr3);
}

int process_user_fixed_map_pid(int pid, uint64_t start, uint64_t len) {
    task_t *target;
    task_t *mm;
    uint64_t end;
    int idx;

    if (len == 0) return 0;
    if (start + len < start) return -1;
    end = start + len;
    target = task_find_by_pid(pid);
    if (!target) return -1;
    mm = task_vm_owner_local(target);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    start = page_align_down_local(start);
    end = page_align_up_local(end);
    if (end <= start) return -1;

    for (uint64_t va = start; va < end; va += USER_PAGE_SIZE) {
        uint64_t *entryp;
        if (va < USER_LOW_LIMIT) {
            uint32_t page = (uint32_t)((va - USER_LOW_BASE) >> 21);
            uint64_t *pt = fixed_user_low_pt_ensure(idx, page);
            if (!pt) return -1;
            entryp = &pt[(va >> 12) & 0x1ffu];
        } else if (va >= USER_BIGPIE_BASE &&
                   va < USER_BIGPIE_BASE + USER_BIGPIE_SIZE) {
            uint32_t page =
                (uint32_t)((va - USER_BIGPIE_BASE) >> 21);
            uint64_t *pt = fixed_user_bigpie_pt_ensure(idx, page);
            if (!pt) return -1;
            entryp = &pt[(va >> 12) & 0x1ffu];
        } else {
            entryp = fixed_user_pte_for_addr_idx(idx, va);
        }
        if (!entryp) return -1;
        if ((*entryp & PAGE_PRESENT) == 0)
            *entryp = fixed_user_zero_entry();
        invlpg_local(va);
    }
    return 0;
}

int process_user_fixed_reserve_pid(int pid, uint64_t start, uint64_t len) {
    task_t *target;
    task_t *mm;
    uint64_t end;
    int idx;

    if (len == 0) return 0;
    if (start + len < start) return -1;
    end = page_align_up_local(start + len);
    start = page_align_down_local(start);
    if (end <= start) return -1;
    target = task_find_by_pid(pid);
    if (!target) return -1;
    mm = task_vm_owner_local(target);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;

    for (uint64_t va = start; va < end; va += USER_PAGE_SIZE) {
        if (va < USER_LOW_LIMIT) {
            uint32_t page = (uint32_t)((va - USER_LOW_BASE) >> 21);
            if (!fixed_user_low_pt_ensure(idx, page)) return -1;
        } else if (va >= USER_BIGPIE_BASE &&
                   va < USER_BIGPIE_BASE + USER_BIGPIE_SIZE) {
            uint32_t page =
                (uint32_t)((va - USER_BIGPIE_BASE) >> 21);
            if (!fixed_user_bigpie_pt_ensure(idx, page)) return -1;
        } else if (!fixed_user_pte_for_addr_idx(idx, va)) {
            return -1;
        }
    }
    return 0;
}

int process_user_fixed_mprotect(task_t *t, uint64_t start, uint64_t len, uint32_t prot) {
    task_t *mm;
    int idx;
    uint64_t end;
    int touched = 0;

    if (!t || len == 0) return 0;
    mm = task_vm_owner_local(t);
    idx = task_index(mm);
    if (!mm || idx < 0 || idx >= USER_AS_MAX_TASKS) return -1;
    start = page_align_down_local(start);
    end = page_align_up_local(start + len);
    if (end < start) return -1;

    for (uint64_t va = start; va < end; va += USER_PAGE_SIZE) {
        uint64_t *pd = fixed_user_pd_for_va(idx, va);
        uint32_t page;
        uint32_t pde;
        uint32_t pte;
        uint64_t *entryp = 0;
        uint64_t entry;

        pte = (uint32_t)((va >> 12) & 0x1FF);
        if (va < USER_LOW_LIMIT) {
            page = (uint32_t)((va - USER_LOW_BASE) >> 21);
            pde = (uint32_t)((va >> 21) & 0x1FF);
            if (page >= USER_LOW_PDE_CNT) return -1;
            if (!pd || (pd[pde] & PAGE_PRESENT) == 0 ||
                (pd[pde] & PAGE_PS) != 0) {
                return -1;
            }
            if (!g_user_low_pt[idx][page]) return -1;
            entryp = &g_user_low_pt[idx][page][pte];
        } else if (va >= USER_TEXT_BASE && va < USER_TEXT_BASE + USER_REGION_SIZE) {
            pde = (uint32_t)((va >> 21) & 0x1FF);
            if (!g_user_text_pt[idx]) return -1;
            if (!pd || (pd[pde] & PAGE_PRESENT) == 0 ||
                (pd[pde] & PAGE_PS) != 0) {
                return -1;
            }
            entryp = &g_user_text_pt[idx][pte];
        } else if (va >= USER_STACK_BASE && va < USER_STACK_BASE + USER_REGION_SIZE) {
            pde = (uint32_t)((va >> 21) & 0x1FF);
            if (!g_user_stack_pt[idx]) return -1;
            if (!pd || (pd[pde] & PAGE_PRESENT) == 0 ||
                (pd[pde] & PAGE_PS) != 0) {
                return -1;
            }
            entryp = &g_user_stack_pt[idx][pte];
        } else if (va >= USER_HEAP_BASE && va < USER_HEAP_BASE + USER_HEAP_TOTAL_SIZE) {
            uint32_t slot;
            if (user_heap_slot_for_addr(va, &slot, &pte) < 0 || slot >= USER_HEAP_TOTAL_PDE_CNT) return -1;
            if (!g_user_heap_pt[idx][slot]) continue;
            pde = (uint32_t)((va >> 21) & 0x1FF);
            if (!pd || (pd[pde] & PAGE_PRESENT) == 0 ||
                (pd[pde] & PAGE_PS) != 0) {
                return -1;
            }
            entryp = &g_user_heap_pt[idx][slot][pte];
            if ((*entryp & PAGE_PRESENT) == 0) continue;
        } else if (va >= USER_BIGPIE_BASE && va < USER_BIGPIE_BASE + USER_BIGPIE_SIZE) {
            page = (uint32_t)((va - USER_BIGPIE_BASE) >> 21);
            pde = (uint32_t)((va >> 21) & 0x1FF);
            if (page >= USER_BIGPIE_PDE_CNT) return -1;
            if (!g_user_bigpie_pt[idx][page]) return -1;
            if (!pd || (pd[pde] & PAGE_PRESENT) == 0 ||
                (pd[pde] & PAGE_PS) != 0) {
                return -1;
            }
            entryp = &g_user_bigpie_pt[idx][page][pte];
        } else {
            continue;
        }
        entry = *entryp;
        if ((entry & PAGE_PRESENT) == 0) {
            edge_user_vma_t *v = process_user_vma_for_addr(mm, va);
            if (!v) return -1;
            touched = 1;
            continue;
        }
        if (prot & 0x2u) {
            uint64_t phys = entry & ~0xFFFULL;
            int backing_idx = sparse_mmap_backing_index_from_phys(phys);
            if (phys == fixed_user_zero_phys() ||
                sparse_mmap_backing_refcnt_local(backing_idx) > 1) {
                entry = (entry & ~PAGE_WRITE) | PAGE_COW;
            } else {
                entry = (entry & ~PAGE_COW) | PAGE_WRITE;
            }
        } else {
            entry &= ~(PAGE_WRITE | PAGE_COW);
        }
        *entryp = entry;
        invlpg_local(va);
        touched = 1;
    }
    if (touched) {
        task_t *cur = process_current_task();
        if (cur == mm || (cur && cur->cr3 == mm->cr3)) cr3_write(mm->cr3);
    }
    return touched;
}

int process_user_fixed_mprotect_pid(int pid, uint64_t start, uint64_t len,
                                    uint32_t prot) {
    task_t *target = task_find_by_pid(pid);

    if (!target) return -1;
    return process_user_fixed_mprotect(target, start, len, prot);
}

void process_init(void) {
#ifdef CONFIG_FS_SWAP
    uint32_t swap_map_capacity;
    uint64_t swap_map_bytes;
    uint64_t swap_map_pages;
    void *swap_map_memory;
#endif

    if (!g_tasks_ready || !g_tasks) {
        printf("[process-init] ERROR no runtime task table tasks=%u\n", (uint32_t)PROC_MAX_TASKS);
        return;
    }
#ifdef CONFIG_FS_SWAP
    swap_map_capacity = edge_swap_map_capacity_for_memory(
        arch_vm_memory_total_bytes() / USER_PAGE_SIZE);
    swap_map_bytes = edge_swap_map_pool_bytes(swap_map_capacity);
    swap_map_pages = (swap_map_bytes + USER_PAGE_SIZE - 1u) /
                     USER_PAGE_SIZE;
    swap_map_memory = arch_vm_alloc_pages(swap_map_pages);
    if (!swap_map_memory || edge_swap_map_initialize(
            swap_map_memory, swap_map_pages * USER_PAGE_SIZE,
            swap_map_capacity) < 0) {
        printf("[swap] ERROR swapped-page metadata unavailable\n");
        return;
    }
    swap_register_pager(process_user_mmap_restore_swap_mapping);
#endif
    /* task_table_runtime_init() zeroes the entire runtime allocation once. */
    memset(g_user_mmap_pt_used, 0, sizeof(g_user_mmap_pt_used));
    spinlock_init(&g_task_lock);
    spinlock_init(&g_user_mmap_backing_lock);
    edge_pid_index_init(&g_task_pid_index);
    g_next_pid = 1;
    g_next_fs_context_id = 1u;
    g_next_sighand_context_id = 1u;
    g_kernel_cr3 = cr3_read();
    scheduler_init();
    scheduler_set_cpu_id(0);

    task_t *init = task_alloc_reserved(0, 0);
    if (!init) return;

    edge_pid_index_remove(&g_task_pid_index, init->pid,
                          (uint32_t)task_index(init));
    init->pid = 0;
    init->ppid = 0;
    init->tgid = init->pid;
    init->vm_owner_pid = init->pid;
    init->fd_owner_pid = init->pid;
    init->fs_context_id = g_next_fs_context_id++;
    init->state = TASK_UNUSED;
    init->exit_code = 0;
    strcpy(init->name, "init");
    init->kernel_stack_top = task_kernel_stack_top_for_index(0);
    init->user_stack_top = USER_STACK_TOP;
    init->user_heap_base = USER_HEAP_BASE;
    init->user_brk = USER_HEAP_BASE;
    init->user_heap_limit = USER_HEAP_BASE + USER_HEAP_DEFAULT_DELTA;
    init->user_mmap_next = USER_MMAP_BASE;
    task_clear_user_vmas(init);
    init->user_vma_refs_owned = 1;
    init->fs_base = 0;
    init->gs_base = 0;
    init->uid = init->gid = 0;
    init->euid = init->egid = 0;
    init->suid = init->sgid = 0;
    init->fsuid = init->fsgid = 0;
    init->dumpable = 1;
    init->no_new_privs = 0;
    init->timer_slack_ns = EDGE_LINUX_DEFAULT_TIMER_SLACK_NS;
    init->default_timer_slack_ns = EDGE_LINUX_DEFAULT_TIMER_SLACK_NS;
    init->thp_disabled = 0;
    edge_seccomp_state_init(&init->seccomp);
    task_set_root_caps(init);
    task_clear_groups(init);
    init->umask = 022;
    init->pgid = 0;
    init->sid = 0;
    init->execed_since_fork = 1;
    init->ctty_kind = PROCESS_CTTY_NONE;
    init->ctty_id = -1;
    init->cgroup_id = 0;
    task_signal_actions_reset(init);
    task_sigsys_action_reset(init);
    init->sigaltstack_flags = EDGE_LINUX_SS_DISABLE;
    strcpy(init->cwd, "/");
    strcpy(init->root, "/");
    edge_namespaces_bootstrap(&init->namespaces,
                              lwip_stack_get_hostname());
    (void)vfs_mount_namespace_activate(init->namespaces.mount);
    init->assigned_cpu = -1;
    init->cr3 = cr3_read();
    init_default_fxsave_region();
    task_init_default_fx(init);
    fxrstor_region(init->fxsave_region);
    scheduler_set_boot_current(init);
    g_next_pid = 1;
}

void process_register_task_exit_hook(process_task_exit_hook_t hook) {
    g_task_exit_hook = hook;
}

void process_register_task_prestart_hook(process_task_prestart_hook_t hook) {
    g_task_prestart_hook = hook;
}

void process_register_task_zombie_hook(process_task_exit_hook_t hook) {
    g_task_zombie_hook = hook;
}

void process_register_user_vma_backing_hooks(
    process_user_vma_retain_hook_t retain_hook,
    process_user_vma_release_hook_t release_hook) {
    g_user_vma_retain_hook = retain_hook;
    g_user_vma_release_hook = release_hook;
}

int process_user_vma_retain_backing(const edge_user_vma_t *vma) {
    if (!vma || vma->end <= vma->start) return -1;
    return g_user_vma_retain_hook ? g_user_vma_retain_hook(vma) : 0;
}

void process_user_vma_release_backing(const edge_user_vma_t *vma) {
    if (!vma || vma->end <= vma->start) return;
    if (g_user_vma_release_hook) g_user_vma_release_hook(vma);
}

int process_user_vma_reserve(task_t *task, uint32_t required_count) {
    task_t *owner = task_vm_owner_local(task);

    if (!owner || required_count > PROCESS_USER_VMA_MAX) return -1;
    if (kernel_mm_vma_storage_grow(
            &owner->user_vmas, &owner->user_vma_capacity,
            owner->user_vma_count, required_count,
            &owner->user_vma_dynamic_pages) < 0)
        return -1;
    return 0;
}

int process_fork(const edge_trap_frame_t *parent_tf,
                 uint64_t namespace_flags) {
    static int slow_fork_trace_budget = 32;
    task_t *parent = process_current_task();
    task_t *vm_parent;
    task_t *parent_leader;
    task_t *child;
    int child_idx;
    int parent_idx;
    uint64_t trace_started_us;
    uint64_t trace_allocated_us = 0;
    uint64_t trace_metadata_us = 0;
    uint64_t trace_fixed_us = 0;
    uint64_t trace_mmap_us = 0;
    if (!parent || !parent_tf) return -1;
    trace_started_us = boottime_monotonic_us();
    if (EDGE_GUI_DEEP_TRACE && parent->pid == 1) {
        proc_trace_puts("[fork-stage] enter pid=1 name=");
        proc_trace_puts(parent->name);
        proc_trace_puts(" rip=");
        proc_trace_hex(parent_tf->rip);
        proc_trace_puts("\n");
    }

    vm_parent = task_vm_owner_local(parent);
    parent_leader = parent;
    if (parent->tgid > 0) {
        task_t *leader = task_find_by_pid(parent->tgid);
        if (leader) parent_leader = leader;
    }
    if (!vm_parent) vm_parent = parent;

    child = task_alloc_reserved(0, &child_idx);
    if (!child) {
        printf("[fork-fail] no user address-space slot used=%d user_as=%d max=%d\n",
               count_used_tasks_local(), USER_AS_MAX_TASKS, PROC_MAX_TASKS);
        task_dump_slots_local("fork-no-user-as-slot");
        return -1;
    }
    trace_allocated_us = boottime_monotonic_us();
    if (edge_namespaces_clone(&child->namespaces, &parent->namespaces,
                              namespace_flags, parent->euid,
                              parent->egid) < 0) {
        task_release_unused(child);
        return -1;
    }
    if (task_seccomp_inherit(child, parent) < 0) {
        task_release_unused(child);
        return -1;
    }
    if (EDGE_GUI_DEEP_TRACE && parent->pid == 1) {
        proc_trace_puts("[fork-stage] allocated child=");
        proc_trace_dec(child->pid);
        proc_trace_puts(" idx=");
        proc_trace_dec(child_idx);
        proc_trace_puts("\n");
    }

    child_idx = task_index(child);
    parent_idx = task_index(vm_parent);
    if (child_idx >= USER_AS_MAX_TASKS || parent_idx >= USER_AS_MAX_TASKS) {
        printf("[fork-fail] bad as child=%d parent=%d\n", child_idx, parent_idx);
        task_dump_slots_local("fork-bad-user-as-index");
        task_release_unused(child);
        return -1;
    }

    // 1. Metadata
    child->ppid = parent_leader ? parent_leader->pid : parent->pid;
    child->parent_tid = parent->pid;
    child->exit_code = 0;
    child->exit_signal = LINUX_SIGCHLD;
    child->termination_signal = 0;
    if (task_copy_exec_identity(child, parent) < 0) {
        task_release_unused(child);
        return -1;
    }
    if (kernel_exec_record_copy(child->exec_record,
                                parent->exec_record) < 0) {
        task_release_unused(child);
        return -1;
    }
    if (edge_pid_namespace_task_attach(&child->namespaces,
                                       child->pid) < 0) {
        task_release_unused(child);
        return -1;
    }
    child->pid_namespace_attached = 1;

    // 2. Address Space
    if (task_build_address_space(child, 1) < 0) {
        printf("[fork-fail] address-space build child=%d parent=%d\n",
               child_idx, parent_idx);
        task_release_unused(child);
        return -1;
    }
    if (EDGE_GUI_DEEP_TRACE && parent->pid == 1) {
        proc_trace_puts("[fork-stage] address-space child=");
        proc_trace_dec(child->pid);
        proc_trace_puts(" cr3=");
        proc_trace_hex(child->cr3);
        proc_trace_puts("\n");
    }

    // 3. Stack Setup
    child->kernel_stack_top = task_kernel_stack_top_for_index(child_idx);
    if (!child->kernel_stack_top) {
        printf("[fork-fail] no kernel stack child=%d\n", child_idx);
        task_release_unused(child);
        return -1;
    }
    /*
     * fork duplicates one coherent mm snapshot.  A sibling CLONE_VM thread may
     * otherwise split or remove a VMA while this path copies metadata and COW
     * page tables, leaving the child with resident pages that do not match its
     * VMA table.  Linux holds the mmap lock across the equivalent operation.
     */
    process_user_vma_mutation_lock(vm_parent);
    child->user_stack_top = vm_parent->user_stack_top;
    child->user_heap_base = vm_parent->user_heap_base;
    child->user_brk = vm_parent->user_brk;
    child->user_heap_limit = vm_parent->user_heap_limit;
    child->user_mmap_next = vm_parent->user_mmap_next;
    if (process_user_vma_reserve(child, vm_parent->user_vma_count) < 0) {
        process_user_vma_mutation_unlock(vm_parent);
        task_release_unused(child);
        return -1;
    }
    child->user_vma_count = vm_parent->user_vma_count;
    if (child->user_vma_count > 0) {
        memcpy(child->user_vmas, vm_parent->user_vmas,
               (uint32_t)child->user_vma_count *
                   (uint32_t)sizeof(child->user_vmas[0]));
    }
    if (task_retain_user_vmas(child) < 0) {
        process_user_vma_mutation_unlock(vm_parent);
        task_release_unused(child);
        return -1;
    }
    child->fs_base = parent->fs_base;
    child->gs_base = parent->gs_base;
    task_copy_credentials(child, parent);
    task_copy_caps(child, parent);
    if (task_copy_groups(child, parent) < 0) {
        process_user_vma_mutation_unlock(vm_parent);
        task_release_unused(child);
        return -1;
    }
    task_copy_resource_limits(child, parent);
    child->umask = parent->umask;
    task_copy_process_control(child, parent);
    child->pgid = parent->pgid;
    child->sid = parent->sid;
    child->execed_since_fork = 0;
    child->ctty_kind = parent->ctty_kind;
    child->ctty_id = parent->ctty_id;
    child->cgroup_id = parent->cgroup_id;
    strcpy(child->cwd, parent->cwd[0] ? parent->cwd : "/");
    strcpy(child->root, parent->root[0] ? parent->root : "/");
    task_signal_actions_copy(child, parent);
    task_sigsys_action_copy(child, parent);
    child->sigmask = parent->sigmask;
    child->signal_saved_mask = 0;
    child->signal_restore_mask_pending = 0;
    child->sigaltstack_sp = parent->sigaltstack_sp;
    child->sigaltstack_size = parent->sigaltstack_size;
    child->sigaltstack_flags = parent->sigaltstack_flags;
    fxsave_region(parent->fxsave_region);
    memcpy(child->fxsave_region, parent->fxsave_region, sizeof(child->fxsave_region));
    task_child_link(parent_leader ? parent_leader : parent, child);
    trace_metadata_us = boottime_monotonic_us();

    // 4. Clone private user memory with page-granular COW.
    process_user_page_table_lock(vm_parent);
    {
        uint64_t backing_rflags;
        uint64_t backing_cr3 = backing_access_enter(&backing_rflags);
        if (EDGE_GUI_DEEP_TRACE && parent->pid == 1) {
            proc_trace_puts("[fork-stage] cow-fixed begin child=");
            proc_trace_dec(child->pid);
            proc_trace_puts(" parent_idx=");
            proc_trace_dec(parent_idx);
            proc_trace_puts(" child_idx=");
            proc_trace_dec(child_idx);
            proc_trace_puts("\n");
        }
        if (fixed_user_clone_cow(child, vm_parent) < 0) {
            backing_access_leave(backing_cr3, backing_rflags);
            printf("[fork-fail] fixed COW clone child=%d parent=%d\n",
                   child_idx, parent_idx);
            task_clear_user_regions(child);
            process_user_page_table_unlock(vm_parent);
            process_user_vma_mutation_unlock(vm_parent);
            sparse_mmap_flush_task(vm_parent);
            task_release_unused(child);
            return -1;
        }
        if (process_user_heap_clone(child, vm_parent) < 0) {
            backing_access_leave(backing_cr3, backing_rflags);
            printf("[fork-fail] heap clone child=%d parent=%d\n", child_idx, parent_idx);
            process_user_mmap_reset(child);
            task_clear_user_regions(child);
            task_child_unlink(child);
            process_user_page_table_unlock(vm_parent);
            process_user_vma_mutation_unlock(vm_parent);
            sparse_mmap_flush_task(vm_parent);
            task_release_unused(child);
            return -1;
        }
        backing_access_leave(backing_cr3, backing_rflags);
    }
    trace_fixed_us = boottime_monotonic_us();
    if (EDGE_GUI_DEEP_TRACE && parent->pid == 1) {
        proc_trace_puts("[fork-stage] cow-fixed done child=");
        proc_trace_dec(child->pid);
        proc_trace_puts("\n");
    }
    if (process_user_mmap_clone(child, vm_parent) < 0) {
        printf("[fork-fail] mmap clone child=%d parent=%d vmas=%u\n",
               child_idx, parent_idx, (unsigned)vm_parent->user_vma_count);
        task_dump_slots_local("fork-mmap-clone");
        process_user_mmap_reset(child);
        task_child_unlink(child);
        process_user_page_table_unlock(vm_parent);
        process_user_vma_mutation_unlock(vm_parent);
        sparse_mmap_flush_task(vm_parent);
        task_release_unused(child);
        return -1;
    }
#ifdef CONFIG_FS_SWAP
    if (edge_swap_map_clone_space(vm_parent->cr3, child->cr3) < 0) {
        printf("[fork-fail] swap-map clone child=%d parent=%d\n",
               child_idx, parent_idx);
        process_user_mmap_reset(child);
        task_child_unlink(child);
        process_user_page_table_unlock(vm_parent);
        process_user_vma_mutation_unlock(vm_parent);
        sparse_mmap_flush_task(vm_parent);
        task_release_unused(child);
        return -1;
    }
    for (uint32_t index = 0; index < child->user_vma_count; ++index) {
        edge_user_vma_t *vma = &child->user_vmas[index];
        if (vma->end <= vma->start ||
            (vma->fork_policy & KERNEL_MM_VMA_FORK_WIPE) == 0)
            continue;
        (void)edge_swap_map_drop_range(
            child->cr3, vma->start, vma->end - vma->start);
    }
#endif
    process_user_page_table_unlock(vm_parent);
    process_user_vma_mutation_unlock(vm_parent);
    /* All three clone domains convert source leaves while holding the per-mm
     * lock.  Invalidate after dropping it so a sibling fault handler cannot
     * block an inter-processor flush while waiting for the same lock. */
    sparse_mmap_flush_task(vm_parent);
    sparse_mmap_flush_task(child);
    trace_mmap_us = boottime_monotonic_us();
    if (kernel_sysv_shm_address_space_clone(
            (uintptr_t)vm_parent, (uintptr_t)child, child->pid) < 0) {
        process_user_mmap_reset(child);
        task_child_unlink(child);
        task_release_unused(child);
        return -1;
    }
    if (kernel_mm_seal_space_clone(vm_parent->cr3, child->cr3) < 0) {
        kernel_mm_lock_space_release(child->cr3);
        process_user_mmap_reset(child);
        task_child_unlink(child);
        task_release_unused(child);
        return -1;
    }
    if (kernel_mm_mempolicy_clone(vm_parent->cr3, child->cr3) < 0) {
        kernel_mm_lock_space_release(child->cr3);
        process_user_mmap_reset(child);
        task_child_unlink(child);
        task_release_unused(child);
        return -1;
    }
    if (process_x86_ldt_clone(child, vm_parent) < 0) {
        kernel_mm_lock_space_release(child->cr3);
        process_user_mmap_reset(child);
        task_child_unlink(child);
        task_release_unused(child);
        return -1;
    }
    if (EDGE_GUI_DEEP_TRACE && parent->pid == 1) {
        proc_trace_puts("[fork-stage] mmap-clone done child=");
        proc_trace_dec(child->pid);
        proc_trace_puts(" vmas=");
        proc_trace_dec((int)child->user_vma_count);
        proc_trace_puts("\n");
    }
    /*
     * Trap-frame driven fork:
     * child resumes through normal syscall/interrupt return path, with
     * registers copied from parent except rax=0.
     */
    child->fork_tf = *parent_tf;
    child->fork_tf.rax = 0;
    process_canonicalize_syscall_frame(&child->fork_tf);
    /* Never propagate single-step into a fork child. */
    child->fork_tf.rflags &= ~(1ull << 8);

    memset(&child->context, 0, sizeof(child->context));
    child->context.r12 = (uint64_t)(uintptr_t)&child->fork_tf;
    child->context.rip = (uint64_t)ret_from_fork;
    child->context.rsp = child->kernel_stack_top;
    child->context.rbp = child->kernel_stack_top;
    scheduler_task_context_ready(child);
    scheduler_task_set_blocked(child);
    if (slow_fork_trace_budget > 0 &&
        boottime_monotonic_us() - trace_started_us >= 10000u) {
        uint64_t trace_done_us = boottime_monotonic_us();
        --slow_fork_trace_budget;
        printf("[fork-latency] parent=%d child=%d alloc=%u metadata=%u fixed=%u mmap=%u tail=%u total=%u budget=%d\n",
               parent->pid, child->pid,
               (uint32_t)(trace_allocated_us - trace_started_us),
               (uint32_t)(trace_metadata_us - trace_allocated_us),
               (uint32_t)(trace_fixed_us - trace_metadata_us),
               (uint32_t)(trace_mmap_us - trace_fixed_us),
               (uint32_t)(trace_done_us - trace_mmap_us),
               (uint32_t)(trace_done_us - trace_started_us),
               slow_fork_trace_budget);
    }
    if (EDGE_GUI_DEEP_TRACE && parent->pid == 1) {
        proc_trace_puts("[fork-stage] ready child=");
        proc_trace_dec(child->pid);
        proc_trace_puts(" child_rip=");
        proc_trace_hex(child->fork_tf.rip);
        proc_trace_puts("\n");
    }

    return child->pid;
}

static int process_fork_shared_vm_impl(const edge_trap_frame_t *parent_tf,
                                       uint64_t namespace_flags,
                                       int reserve_exec_mm) {
    task_t *parent = process_current_task();
    task_t *vm_parent;
    task_t *parent_leader;
    task_t *child;
    int child_idx;

    if (!parent || !parent_tf) return -1;

    vm_parent = task_vm_owner_local(parent);
    if (!vm_parent) vm_parent = parent;
    parent_leader = parent;
    if (parent->tgid > 0) {
        task_t *leader = task_find_by_pid(parent->tgid);
        if (leader) parent_leader = leader;
    }

    /*
     * Linux CLONE_VM creates a task that shares the caller's mm.  It must not
     * consume one of EdgeOS' fixed independent user address-space slots; GLib,
     * GTK, and helper launchers create enough shared-mm workers that charging
     * them as full fork() children exhausts USER_AS_MAX_TASKS and makes normal
     * desktop subprocesses fail with EAGAIN.
     */
    child = task_alloc_reserved(reserve_exec_mm ? 0 : 1, &child_idx);
    if (!child) {
        printf("[fork-fail] no task slot used=%d\n", count_used_tasks_local());
        task_dump_slots_local("shared-vm-no-user-as-slot");
        return -1;
    }
    if (edge_namespaces_clone(&child->namespaces, &parent->namespaces,
                              namespace_flags, parent->euid,
                              parent->egid) < 0) {
        task_release_unused(child);
        return -1;
    }
    if (task_seccomp_inherit(child, parent) < 0) {
        task_release_unused(child);
        return -1;
    }
    child_idx = task_index(child);
    if (child_idx < 0 || child_idx >= PROC_MAX_TASKS ||
        (reserve_exec_mm && child_idx >= USER_AS_MAX_TASKS)) {
        task_release_unused(child);
        return -1;
    }

    child->ppid = parent_leader ? parent_leader->pid : parent->pid;
    child->parent_tid = parent->pid;
    child->vm_owner_pid = vm_parent->pid;
    child->exit_code = 0;
    child->exit_signal = LINUX_SIGCHLD;
    child->termination_signal = 0;
    if (task_copy_exec_identity(child, parent) < 0) {
        task_release_unused(child);
        return -1;
    }
    if (edge_pid_namespace_task_attach(&child->namespaces,
                                       child->pid) < 0) {
        task_release_unused(child);
        return -1;
    }
    child->pid_namespace_attached = 1;
    child->cr3 = vm_parent->cr3;
    child->kernel_stack_top = task_kernel_stack_top_for_index(child_idx);
    if (!child->kernel_stack_top) {
        printf("[fork-fail] no shared-vm kernel stack child=%d\n", child_idx);
        task_release_unused(child);
        return -1;
    }
    child->user_stack_top = vm_parent->user_stack_top;
    child->user_heap_base = vm_parent->user_heap_base;
    child->user_brk = vm_parent->user_brk;
    child->user_heap_limit = vm_parent->user_heap_limit;
    child->user_mmap_next = vm_parent->user_mmap_next;
    /*
     * CLONE_VM tasks operate on the mm owner's VMA table. Duplicating VMA
     * metadata into each pthread/vfork task is redundant and observably
     * expensive. A vfork child reserved in an mm-capable slot
     * starts using this shared owner and builds its own empty table only when
     * execve commits a new address space.
     */
    child->user_vma_count = 0;
    child->user_vma_refs_owned = 0;
    if (child_idx >= USER_AS_MAX_TASKS) {
        child->exec_record = vm_parent->exec_record;
    } else if (kernel_exec_record_copy(child->exec_record,
                                       parent->exec_record) < 0) {
        task_release_unused(child);
        return -1;
    }
    child->fs_base = parent->fs_base;
    child->gs_base = parent->gs_base;
    task_copy_credentials(child, parent);
    task_copy_caps(child, parent);
    if (task_copy_groups(child, parent) < 0) {
        task_release_unused(child);
        return -1;
    }
    task_copy_resource_limits(child, parent);
    child->umask = parent->umask;
    task_copy_process_control(child, parent);
    child->pgid = parent->pgid;
    child->sid = parent->sid;
    child->execed_since_fork = 0;
    child->ctty_kind = parent->ctty_kind;
    child->ctty_id = parent->ctty_id;
    child->cgroup_id = parent->cgroup_id;
    strcpy(child->cwd, parent->cwd[0] ? parent->cwd : "/");
    strcpy(child->root, parent->root[0] ? parent->root : "/");
    task_signal_actions_copy(child, parent);
    task_sigsys_action_copy(child, parent);
    child->sigmask = parent->sigmask;
    child->signal_saved_mask = 0;
    child->signal_restore_mask_pending = 0;
    /*
     * Linux clears the alternate signal stack for normal CLONE_VM thread
     * creation.  A pthread starts with no altstack of its own; inheriting the
     * parent thread's stack would make multiple threads build signal frames on
     * the same user memory and can corrupt GLib/Pango realtime-signal wakeups.
     */
    child->sigaltstack_sp = 0;
    child->sigaltstack_size = 0;
    child->sigaltstack_flags = EDGE_LINUX_SS_DISABLE;
    fxsave_region(parent->fxsave_region);
    memcpy(child->fxsave_region, parent->fxsave_region, sizeof(child->fxsave_region));
    task_child_link(parent_leader ? parent_leader : parent, child);

    child->fork_tf = *parent_tf;
    child->fork_tf.rax = 0;
    process_canonicalize_syscall_frame(&child->fork_tf);
    child->fork_tf.rflags &= ~(1ull << 8);

    memset(&child->context, 0, sizeof(child->context));
    child->context.r12 = (uint64_t)(uintptr_t)&child->fork_tf;
    child->context.rip = (uint64_t)ret_from_fork;
    child->context.rsp = child->kernel_stack_top;
    child->context.rbp = child->kernel_stack_top;
    scheduler_task_context_ready(child);
    scheduler_task_set_blocked(child);

    return child->pid;
}

int process_fork_shared_vm(const edge_trap_frame_t *parent_tf,
                           uint64_t namespace_flags) {
    return process_fork_shared_vm_impl(parent_tf, namespace_flags, 0);
}

int process_vfork_shared_vm(const edge_trap_frame_t *parent_tf,
                            uint64_t namespace_flags) {
    /*
     * Linux vfork shares the caller's mm while the parent is suspended, then
     * execve installs a new mm for the child.  Reserve an address-space slot
     * now so process_prepare_exec_current() can perform that split without a
     * late allocation or any copy of the parent's fixed/sparse memory.
     */
    return process_fork_shared_vm_impl(parent_tf, namespace_flags, 1);
}

int process_clone_clear_signal_handlers(int pid) {
    task_t *child = task_find_by_pid(pid);

    if (!child || child->state == TASK_UNUSED || child->state == TASK_ZOMBIE)
        return -1;

    /*
     * CLONE_CLEAR_SIGHAND resets caught dispositions in the new process while
     * preserving SIG_IGN.  The child is still blocked when clone calls this,
     * so its private signal-action table can be updated without racing user
     * execution.
     */
    for (uint32_t signal = 1; signal <= EDGE_LINUX_SIGNAL_MAX; ++signal) {
        edge_linux_signal_action_t *action =
            &child->signal_actions[signal - 1u];
        if (action->handler != LINUX_SIG_IGN)
            memset(action, 0, sizeof(*action));
    }
    return 0;
}

int process_clone_share_signal_handlers(int pid) {
    task_t *current = process_current_task();
    task_t *child = task_find_by_pid(pid);

    if (!current || !child || child->state == TASK_UNUSED ||
        child->state == TASK_ZOMBIE)
        return -1;

    /*
     * Linux CLONE_SIGHAND shares one signal-disposition object, including
     * between separate thread groups.  EdgeOS keeps a local table in each
     * task for fast delivery, so the context ID is the ownership identity and
     * updates are mirrored to every task carrying that identity.
     */
    child->sighand_context_id = current->sighand_context_id;
    task_signal_actions_copy(child, current);
    return 0;
}

int process_clone_set_parent(int pid, int parent_pid) {
    task_t *child = task_find_by_pid(pid);
    task_t *parent = parent_pid > 0 ? task_find_by_pid(parent_pid) : 0;

    if (!child || child->state == TASK_UNUSED || child->state == TASK_ZOMBIE)
        return -1;
    if (parent_pid > 0 && (!parent || parent->state == TASK_UNUSED ||
                           parent->state == TASK_ZOMBIE))
        return -1;

    task_child_link(parent, child);
    child->parent_tid = parent ? parent->pid : 0;
    return 0;
}

int process_clone_thread(const edge_trap_frame_t *parent_tf) {
    task_t *parent = process_current_task();
    task_t *leader;
    task_t *vm_parent;
    task_t *child;
    int child_idx;
    static int clone_no_slot_budget = 16;

    if (!parent || !parent_tf ||
        __atomic_load_n(&parent->group_exit_pending, __ATOMIC_ACQUIRE))
        return -1;
    child = task_alloc_reserved(1, &child_idx);
    if (!child) {
        if (clone_no_slot_budget > 0) {
            clone_no_slot_budget--;
            printf("[clone-thread-fail] parent=%d cmd=%s used=%d user_as=%d max=%d budget=%d\n",
                   parent ? parent->pid : -1,
                   (parent && parent->name[0]) ? parent->name : "?",
                   count_used_tasks_local(), USER_AS_MAX_TASKS, PROC_MAX_TASKS,
                   clone_no_slot_budget);
            task_dump_slots_local("clone-thread-no-slot");
        }
        return -1;
    }
    if (edge_namespaces_inherit(&child->namespaces,
                                &parent->namespaces) < 0) {
        task_release_unused(child);
        return -1;
    }
    if (task_seccomp_inherit(child, parent) < 0) {
        task_release_unused(child);
        return -1;
    }
    vm_parent = task_vm_owner_local(parent);
    if (!vm_parent) vm_parent = parent;

    child_idx = task_index(child);
    if (child_idx < 0 || child_idx >= PROC_MAX_TASKS) {
        task_release_unused(child);
        return -1;
    }

    child->ppid = parent->ppid;
    child->parent_tid = parent->parent_tid;
    child->tgid = parent->tgid > 0 ? parent->tgid : parent->pid;
    leader = task_find_by_pid(child->tgid);
    if (__atomic_load_n(&parent->group_exit_pending, __ATOMIC_ACQUIRE) ||
        (leader && __atomic_load_n(&leader->group_exit_pending,
                                    __ATOMIC_ACQUIRE))) {
        task_release_unused(child);
        return -1;
    }
    if (edge_pid_namespace_task_attach(&child->namespaces,
                                       child->pid) < 0) {
        task_release_unused(child);
        return -1;
    }
    child->pid_namespace_attached = 1;
    child->child_subreaper = parent->child_subreaper;
    child->vm_owner_pid = parent->vm_owner_pid > 0 ? parent->vm_owner_pid : parent->pid;
    child->fd_owner_pid = child->pid;
    child->exit_code = 0;
    child->exit_signal = 0;
    child->termination_signal = 0;
    if (task_copy_exec_identity(child, parent) < 0) {
        task_release_unused(child);
        return -1;
    }
    child->cr3 = parent->cr3;
    child->kernel_stack_top = task_kernel_stack_top_for_index(child_idx);
    if (!child->kernel_stack_top) {
        printf("[clone-thread-fail] no kernel stack child=%d used=%d user_as=%d max=%d\n",
               child_idx, count_used_tasks_local(), USER_AS_MAX_TASKS, PROC_MAX_TASKS);
        task_release_unused(child);
        return -1;
    }
    child->user_stack_top = vm_parent->user_stack_top;
    child->user_heap_base = vm_parent->user_heap_base;
    child->user_brk = vm_parent->user_brk;
    child->user_heap_limit = vm_parent->user_heap_limit;
    child->user_mmap_next = vm_parent->user_mmap_next;
    child->user_vma_count = 0;
    child->user_vma_refs_owned = 0;
    child->exec_record = vm_parent->exec_record;
    if (child_idx >= USER_AS_MAX_TASKS)
        child->user_vmas = vm_parent->user_vmas;
    child->fs_base = parent->fs_base;
    child->gs_base = parent->gs_base;
    task_copy_credentials(child, parent);
    task_copy_caps(child, parent);
    if (task_copy_groups(child, parent) < 0) {
        task_release_unused(child);
        return -1;
    }
    task_copy_resource_limits(child, parent);
    child->umask = parent->umask;
    task_copy_process_control(child, parent);
    child->pgid = parent->pgid;
    child->sid = parent->sid;
    child->execed_since_fork = parent->execed_since_fork;
    child->ctty_kind = parent->ctty_kind;
    child->ctty_id = parent->ctty_id;
    child->cgroup_id = parent->cgroup_id;
    strcpy(child->cwd, parent->cwd[0] ? parent->cwd : "/");
    strcpy(child->root, parent->root[0] ? parent->root : "/");
    task_signal_actions_copy(child, parent);
    task_sigsys_action_copy(child, parent);
    child->sigmask = parent->sigmask;
    child->signal_saved_mask = 0;
    child->signal_restore_mask_pending = 0;
    /*
     * Linux clears a CLONE_VM thread's alternate signal stack unless the clone
     * is the special vfork case.  pthread stacks are independent; sharing the
     * creator's altstack would let async signal frames from GLib/Pango helper
     * threads overwrite each other.
     */
    child->sigaltstack_sp = 0;
    child->sigaltstack_size = 0;
    child->sigaltstack_flags = EDGE_LINUX_SS_DISABLE;
    child->sig_stub_installed = parent->sig_stub_installed;
    child->assigned_cpu = -1;
    fxsave_region(parent->fxsave_region);
    memcpy(child->fxsave_region, parent->fxsave_region, sizeof(child->fxsave_region));

    child->fork_tf = *parent_tf;
    child->fork_tf.rax = 0;
    process_canonicalize_syscall_frame(&child->fork_tf);
    child->fork_tf.rflags &= ~(1ull << 8);

    memset(&child->context, 0, sizeof(child->context));
    child->context.r12 = (uint64_t)(uintptr_t)&child->fork_tf;
    child->context.rip = (uint64_t)ret_from_fork;
    child->context.rsp = child->kernel_stack_top;
    child->context.rbp = child->kernel_stack_top;
    scheduler_task_context_ready(child);
    scheduler_task_set_blocked(child);
    return child->pid;
}

int process_abort_clone(int pid) {
    task_t *task = task_find_by_pid(pid);

    if (!task || task == process_current_task() || task->pid == 1 ||
        (task->state != TASK_BLOCKED && task->state != TASK_STOPPED))
        return -1;
    task_release_unused(task);
    return 0;
}

int process_set_current(int pid) {
    task_t *cur = process_current_task();
    if (cur && cur->pid == pid) return 0;
    return -1;
}

static void process_rebase_one_path(char path[TASK_CWD_MAX],
                                    const char *new_root,
                                    const char *put_old,
                                    int fs_location) {
    char replacement[TASK_CWD_MAX];
    int result;

    if (!path[0]) return;
    result = fs_location ?
        kernel_vfs_rebase_pivot_fs_location(
            new_root, put_old, path, replacement, sizeof(replacement)) :
        kernel_vfs_rebase_pivot_path(
            new_root, put_old, path, replacement, sizeof(replacement));
    if (result < 0) return;
    strncpy(path, replacement, TASK_CWD_MAX - 1u);
    path[TASK_CWD_MAX - 1u] = 0;
}

void process_rebase_mount_namespace_paths(uint32_t namespace_id,
                                          const char *new_root,
                                          const char *put_old) {
    uint64_t flags;

    if (!g_tasks || !new_root || !put_old || new_root[0] != '/' ||
        put_old[0] != '/') return;

    flags = spin_lock_irqsave(&g_task_lock);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *task = &g_tasks[index];
        if (task->state == TASK_UNUSED || !task->namespaces.owned ||
            task->namespaces.mount != namespace_id)
            continue;
        process_rebase_one_path(task->cwd, new_root, put_old, 1);
        process_rebase_one_path(task->root, new_root, put_old, 1);
        process_rebase_one_path(task->exec_path, new_root, put_old, 0);
    }
    spin_unlock_irqrestore(&g_task_lock, flags);
}

void process_rebase_mount_move_paths(uint32_t namespace_id,
                                     const char *source,
                                     const char *target) {
    char replacement[TASK_CWD_MAX];
    uint64_t flags;

    if (!g_tasks || !source || !target || source[0] != '/' ||
        target[0] != '/') return;
    flags = spin_lock_irqsave(&g_task_lock);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *task = &g_tasks[index];
        if (task->state == TASK_UNUSED || !task->namespaces.owned ||
            task->namespaces.mount != namespace_id)
            continue;
        if (kernel_vfs_rebase_move_path(
                source, target, task->cwd, replacement,
                sizeof(replacement)) == 0)
            strncpy(task->cwd, replacement, sizeof(task->cwd) - 1u);
        task->cwd[sizeof(task->cwd) - 1u] = 0;
        if (kernel_vfs_rebase_move_path(
                source, target, task->root, replacement,
                sizeof(replacement)) == 0)
            strncpy(task->root, replacement, sizeof(task->root) - 1u);
        task->root[sizeof(task->root) - 1u] = 0;
        if (kernel_vfs_rebase_move_path(
                source, target, task->exec_path, replacement,
                sizeof(replacement)) == 0)
            strncpy(task->exec_path, replacement,
                    sizeof(task->exec_path) - 1u);
        task->exec_path[sizeof(task->exec_path) - 1u] = 0;
    }
    spin_unlock_irqrestore(&g_task_lock, flags);
}

int process_fd_owner_uses_mount_namespace(int owner_pid,
                                          uint32_t namespace_id) {
    uint64_t flags;
    int found = 0;

    if (!g_tasks || owner_pid <= 0) return 0;
    flags = spin_lock_irqsave(&g_task_lock);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        const task_t *task = &g_tasks[index];
        int task_owner;

        if (task->state == TASK_UNUSED || task->state == TASK_ZOMBIE ||
            !task->namespaces.owned ||
            task->namespaces.mount != namespace_id)
            continue;
        task_owner = task->fd_owner_pid > 0 ?
            task->fd_owner_pid : task->pid;
        if (task_owner == owner_pid) {
            found = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&g_task_lock, flags);
    return found;
}

int process_getpid(void) {
    task_t *t = process_current_task();
    return t ? t->pid : 0;
}

int process_gettid(void) {
    task_t *t = process_current_task();
    return t ? t->pid : 0;
}

int process_gettgid(void) {
    task_t *t = process_current_task();
    if (!t) return 0;
    return t->tgid > 0 ? t->tgid : t->pid;
}

int process_getfdpid(void) {
    task_t *t = process_current_task();
    if (!t) return 0;
    return t->fd_owner_pid > 0 ? t->fd_owner_pid : t->pid;
}

int process_set_fd_owner(int pid, int owner_pid) {
    task_t *t = task_find_by_pid(pid);
    if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) return -1;
    t->fd_owner_pid = owner_pid > 0 ? owner_pid : t->pid;
    return 0;
}

int process_getppid(void) {
    task_t *t = process_current_task();
    return t ? t->ppid : 0;
}

int process_thread_group_size(int tgid) {
    int count = 0;
    if (tgid <= 0) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        int task_tgid;
        if (t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) continue;
        task_tgid = t->tgid > 0 ? t->tgid : t->pid;
        if (task_tgid == tgid) count++;
    }
    return count;
}

static int process_fd_owner_of_task(const task_t *t) {
    if (!t) return 0;
    return t->fd_owner_pid > 0 ? t->fd_owner_pid : t->pid;
}

static int process_tgid_of_task(const task_t *t) {
    if (!t) return 0;
    return t->tgid > 0 ? t->tgid : t->pid;
}

static int process_task_live(const task_t *t) {
    return t && t->state != TASK_UNUSED && t->state != TASK_ZOMBIE;
}

static int process_fd_owner_live_users(int owner_pid, const task_t *exclude) {
    int count = 0;
    if (owner_pid <= 0) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *t = &g_tasks[i];
        if (!t || t == exclude) continue;
        if (t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) continue;
        if (process_fd_owner_of_task(t) == owner_pid) count++;
    }
    return count;
}

#if EDGE_FD_LIFETIME_TRACE
static int process_fd_lifetime_trace_task(const task_t *t) {
    if (!t) return 0;
    return strcmp(t->name, "Xorg") == 0 || strcmp(t->name, "InputThread") == 0 ||
           strcmp(t->name, "xsetroot") == 0 || strcmp(t->name, "twm") == 0 ||
           strcmp(t->name, "xterm") == 0 || strcmp(t->name, "xclock") == 0;
}
#endif

static void process_release_fds_if_last_user(task_t *t, const char *reason) {
    int owner_pid;
    int live_others;
#if !EDGE_FD_LIFETIME_TRACE
    (void)reason;
#endif
    if (!t) return;
    owner_pid = process_fd_owner_of_task(t);
    if (owner_pid <= 0) return;
    live_others = process_fd_owner_live_users(owner_pid, t);
    /*
     * Linux threads share a files_struct when CLONE_FILES is used.  A helper
     * thread exiting must not close the process-wide descriptor table, because
     * listeners such as Xorg's /tmp/.X11-unix sockets are owned by that shared
     * table and must remain open until the last live user is gone.
     */
    if (live_others > 0) {
#if EDGE_FD_LIFETIME_TRACE
        if (g_fd_lifetime_trace_budget > 0 && process_fd_lifetime_trace_task(t)) {
            g_fd_lifetime_trace_budget--;
            printf("[fdlife] keep owner=%d pid=%d tgid=%d cmd=%s reason=%s live_others=%d\n",
                   owner_pid, t->pid, t->tgid, t->name, reason ? reason : "?", live_others);
        }
#endif
        return;
    }
#if EDGE_FD_LIFETIME_TRACE
    if (g_fd_lifetime_trace_budget > 0 && process_fd_lifetime_trace_task(t)) {
        g_fd_lifetime_trace_budget--;
        printf("[fdlife] release owner=%d pid=%d tgid=%d cmd=%s reason=%s\n",
               owner_pid, t->pid, t->tgid, t->name, reason ? reason : "?");
    }
#endif
    syscall_release_process_fds(owner_pid);
}

static int process_parent_auto_reaps_child(const task_t *parent,
                                           const task_t *child) {
    if (!parent || !child || child->exit_signal != LINUX_SIGCHLD ||
        edge_linux_ptrace_exit_is_deferred(&child->ptrace))
        return 0;
    return kernel_signal_action_auto_reaps_child(
        EDGE_LINUX_SIGCHLD,
        &parent->signal_actions[LINUX_SIGCHLD - 1]);
}

static void process_ptrace_tracer_exit(task_t *tracer) {
    int kill_pids[PROC_MAX_TASKS];
    int kill_count = 0;
    if (!tracer || tracer->pid <= 0) return;

    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *tracee = &g_tasks[index];
        edge_linux_ptrace_tracer_exit_action_t action;
        edge_trap_frame_t *live;
        if (tracee->state == TASK_UNUSED ||
            tracee->ptrace.tracer_pid != tracer->pid)
            continue;
        action = edge_linux_ptrace_tracer_exit_action(
            &tracee->ptrace, tracee->state == TASK_ZOMBIE);
        if (action == EDGE_LINUX_PTRACE_TRACER_EXIT_RELEASE_ZOMBIE) {
            edge_linux_ptrace_state_reset(&tracee->ptrace);
            tracee->stop_signal = 0;
            tracee->stop_reported = 0;
            tracee->continued_pending = 0;
            process_notify_parent_exit(
                tracee->parent, tracee, tracee->exit_signal);
            continue;
        }

        edge_linux_ptrace_state_reset(&tracee->ptrace);
        tracee->stop_signal = 0;
        tracee->stop_reported = 0;
        tracee->continued_pending = 0;
        tracee->ptrace_frame.rflags &= ~(1ULL << 8);
        live = tracee->ptrace_live_frame ?
            (edge_trap_frame_t *)(uintptr_t)tracee->ptrace_live_frame : 0;
        if (live) live->rflags &= ~(1ULL << 8);
        if (action == EDGE_LINUX_PTRACE_TRACER_EXIT_KILL) {
            tracee->termination_signal = EDGE_LINUX_PTRACE_SIGKILL;
            if (kill_count < PROC_MAX_TASKS)
                kill_pids[kill_count++] = tracee->pid;
            continue;
        }
        if (tracee->state == TASK_STOPPED)
            scheduler_task_make_runnable(
                tracee, tracee->assigned_cpu >= 0 ?
                    (uint32_t)tracee->assigned_cpu : scheduler_cpu_id());
    }

    for (int index = 0; index < kill_count; ++index)
        (void)process_kill_pid(
            kill_pids[index], 128 + EDGE_LINUX_PTRACE_SIGKILL);
}

static int process_desktop_trace_task(const task_t *t) {
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "xinit") == 0 ||
           strcmp(t->name, "startxfce4") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "xfconfd") == 0 ||
           strcmp(t->name, "iceauth") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0 ||
           strcmp(t->name, "dbus-daemon-la") == 0 ||
           strcmp(t->name, "dbus-run-sessio") == 0 ||
           strcmp(t->name, "dbus-run-session") == 0 ||
           strcmp(t->name, "gdbus") == 0 ||
           strcmp(t->name, "gmain") == 0;
}

static int g_desktop_child_trace_budget = EDGE_GUI_DEEP_TRACE ? 512 : 0;

static int process_wait_status_for_task(const task_t *t) {
    if (!t) return 0;
    return (int)kernel_process_wait_exit_status(
        t->exit_code, t->termination_signal);
}

static void process_rusage_snapshot_task(const task_t *t, process_rusage_snapshot_t *out) {
    uint64_t now;
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!t) return;
    out->user_time_us = t->rusage_user_time_us;
    out->sys_time_us = t->rusage_sys_time_us;
    if (t == process_current_task() && t->state == TASK_RUNNING && t->rusage_run_start_us) {
        now = boottime_monotonic_us();
        if (now > t->rusage_run_start_us) {
            if (t->in_syscall)
                out->sys_time_us += now - t->rusage_run_start_us;
            else
                out->user_time_us += now - t->rusage_run_start_us;
        }
    }
    out->minor_faults = t->rusage_minor_faults;
    out->major_faults = t->rusage_major_faults;
    out->voluntary_ctxt_switches = t->rusage_voluntary_ctxt_switches;
    out->involuntary_ctxt_switches = t->rusage_involuntary_ctxt_switches;
}

static void process_rusage_snapshot_children(const task_t *t, process_rusage_snapshot_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!t) return;
    out->user_time_us = t->rusage_child_user_time_us;
    out->sys_time_us = t->rusage_child_sys_time_us;
    out->minor_faults = t->rusage_child_minor_faults;
    out->major_faults = t->rusage_child_major_faults;
    out->voluntary_ctxt_switches = t->rusage_child_voluntary_ctxt_switches;
    out->involuntary_ctxt_switches = t->rusage_child_involuntary_ctxt_switches;
}

static void process_rusage_accumulate_reaped_child(task_t *parent, const task_t *child) {
    if (!parent || !child) return;
    parent->rusage_child_user_time_us += child->rusage_user_time_us + child->rusage_child_user_time_us;
    parent->rusage_child_sys_time_us += child->rusage_sys_time_us + child->rusage_child_sys_time_us;
    parent->rusage_child_minor_faults += child->rusage_minor_faults + child->rusage_child_minor_faults;
    parent->rusage_child_major_faults += child->rusage_major_faults + child->rusage_child_major_faults;
    parent->rusage_child_voluntary_ctxt_switches += child->rusage_voluntary_ctxt_switches +
                                                    child->rusage_child_voluntary_ctxt_switches;
    parent->rusage_child_involuntary_ctxt_switches += child->rusage_involuntary_ctxt_switches +
                                                      child->rusage_child_involuntary_ctxt_switches;
}

static void process_rusage_charge_current_run(task_t *t) {
    uint64_t now;
    if (!t || !t->rusage_run_start_us) return;
    now = boottime_monotonic_us();
    if (now > t->rusage_run_start_us) {
        if (t->in_syscall)
            t->rusage_sys_time_us += now - t->rusage_run_start_us;
        else
            t->rusage_user_time_us += now - t->rusage_run_start_us;
    }
    /*
     * Exit can occur before the scheduler switches away.  Close the active
     * run interval here so wait4/waitid observe CPU consumed by short-lived
     * children without charging blocked lifetime as CPU time.
     */
    t->rusage_run_start_us = 0;
}

static void process_deliver_parent_death_signals(int parent_tid) {
    int child_pids[PROC_MAX_TASKS];
    uint8_t child_signals[PROC_MAX_TASKS];
    int count = 0;

    if (parent_tid <= 0) return;

    /*
     * PR_SET_PDEATHSIG follows the lifetime of the creating task, not merely
     * the thread-group leader exposed by getppid().  A process forked by a
     * pthread must therefore receive its signal when that pthread terminates
     * even if another thread in the parent process is still alive.  Collect
     * targets before delivery because a fatal signal can recursively tear
     * down a thread group and mutate the task/child lists.
     */
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *child = &g_tasks[i];
        if (child->state == TASK_UNUSED || child->state == TASK_ZOMBIE) continue;
        if (child->parent_death_signal == 0) continue;
        if (child->parent_tid != parent_tid) continue;
        child_pids[count] = child->pid;
        child_signals[count] = child->parent_death_signal;
        count++;
    }

    for (int i = 0; i < count; ++i) {
        (void)process_send_signal(child_pids[i], child_signals[i]);
    }
}

static int process_orphan_reaper(const task_t *exiting) {
    task_t *ancestor;
    if (!exiting) return 1;
    ancestor = exiting->parent;
    if (!ancestor && exiting->ppid > 0)
        ancestor = task_find_by_pid(exiting->ppid);
    for (int guard = 0; ancestor && guard < PROC_MAX_TASKS; ++guard) {
        task_t *leader = task_find_by_pid(process_tgid_of_task(ancestor));
        if (!leader) leader = ancestor;
        if (leader->state != TASK_UNUSED && leader->state != TASK_ZOMBIE &&
            leader->child_subreaper)
            return process_tgid_of_task(leader);
        if (leader->pid == 1) return 1;
        ancestor = leader->parent;
        if (!ancestor && leader->ppid > 0)
            ancestor = task_find_by_pid(leader->ppid);
    }
    return 1;
}

static void process_finish_task_exit(task_t *t, int code, const char *reason, int notify_parent) {
    task_t *parent;
    task_t *parent_account;
    task_t *vm_owner;
    int vm_owner_pid;
    int live_vm_others;
    int auto_reap;
    int orphan_reaper;
    uint64_t old_cr3;
    int exiting_current;
    if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) return;
    __atomic_store_n(&t->group_exit_pending, 0u, __ATOMIC_RELEASE);
    orphan_reaper = process_orphan_reaper(t);

    /*
     * Task teardown walks global kernel state: task slots, shared fd owners,
     * child lists, vma owners, robust futex lists, and wait bookkeeping.  Those
     * structures live in the kernel image/BSS and must remain readable even
     * when the dying task reached exit through a corrupted user CR3 or a bad
     * kernel continuation.  Linux keeps kernel memory mapped in every mm; until
     * EdgeOS has the same robust split, do teardown on the saved kernel CR3.
     *
     * If the current task is exiting, keep the kernel CR3 through the following
     * scheduler switch.  Restoring the known-bad task CR3 after marking it dead
     * can fault again before the scheduler reaches switch_task_context().
     */
    old_cr3 = cr3_read_local_process();
    exiting_current = (t == process_current_task());
    if (g_kernel_cr3 && old_cr3 != g_kernel_cr3) cr3_write(g_kernel_cr3);

    process_ptrace_tracer_exit(t);
    process_rusage_charge_current_run(t);
#ifdef CONFIG_BSD_PROCESS_ACCT
    {
        kernel_proc_task_view_t accounting_view;
        if (kernel_task_view_from_task(t, &accounting_view) == 0)
            kernel_process_accounting_task_exit(
                &accounting_view, code, t->termination_signal,
                !process_thread_group_has_other_live(
                    t, process_tgid_of_task(t)));
    }
#endif
    edge_linux_file_lock_task_exit(t->pid);
    kernel_sysv_sem_task_exit(t->pid);
    kernel_signal_queue_purge(t->pid, 1);
    if (process_tgid_of_task(t) == t->pid)
        kernel_signal_queue_purge(t->pid, 0);
    if (g_task_exit_hook) g_task_exit_hook(t);
    process_wake_vfork_parent(t);
    process_release_fds_if_last_user(t, reason);
    kernel_exec_file_release(t->exec_file_handle);
    t->exec_file_handle = KERNEL_EXEC_FILE_HANDLE_NONE;
    vm_owner_pid = process_vm_owner_pid_of_task_raw(t);
    vm_owner = task_find_by_pid(vm_owner_pid);
    live_vm_others = process_vm_live_users_raw(vm_owner_pid, t);
    /*
     * Linux mm lifetime is tied to mm users, not to the task that originally
     * allocated it.  GLib/GTK creates CLONE_VM workers; the thread-group leader
     * or helper that owns the EdgeOS fixed address-space slot can exit while
     * those workers are still resolving libraries, fonts, or DBus state.  Do
     * not tear down sparse mmap page tables until the last live task using this
     * vm exits, or the survivors fault on valid XFCE mappings and die.
     */
    if (live_vm_others <= 0 && vm_owner) {
        kernel_sysv_shm_address_space_release(
            (uintptr_t)vm_owner,
            process_tgid_of_task(t) > 0 ? process_tgid_of_task(t) : t->pid);
        process_user_mmap_reset(vm_owner);
        task_clear_user_regions(vm_owner);
        task_clear_user_vmas(vm_owner);
        if (vm_owner != t && vm_owner->state == TASK_ZOMBIE && !vm_owner->parent) {
            task_release_unused(vm_owner);
        }
    }
    t->exit_code = code;
    process_deliver_parent_death_signals(t->pid);
    process_adopt_orphans(t->pid, orphan_reaper);
    parent = t->parent;
    auto_reap = notify_parent &&
        process_parent_auto_reaps_child(parent, t);
    if (g_desktop_child_trace_budget > 0 &&
        (process_desktop_trace_task(t) || process_desktop_trace_task(parent))) {
        g_desktop_child_trace_budget--;
        printf("[deskchild] exit pid=%d cmd=%s ppid=%d parent=%d/%s code=%d reason=%s notify=%d budget=%d\n",
               t->pid, t->name, t->ppid,
               parent ? parent->pid : -1, parent ? parent->name : "-",
               code, reason ? reason : "-", notify_parent, g_desktop_child_trace_budget);
    }
    scheduler_task_set_zombie(t);
    if (t->cgroup_accounted) {
        t->cgroup_accounted = 0;
        cgroupfs_task_leave(t->cgroup_id);
    }
    if (g_task_zombie_hook) g_task_zombie_hook(t);
    if (process_tgid_of_task(t) > 0 &&
        process_tgid_of_task(t) != t->pid) {
        task_t *leader = task_find_by_pid(process_tgid_of_task(t));

        /*
         * waitpid() reports a thread-group leader only after the final member
         * exits.  The leader may already be a zombie, so the last sibling must
         * wake its parent's wait without generating a duplicate SIGCHLD.
         */
        if (leader && leader->state == TASK_ZOMBIE &&
            !process_thread_group_has_other_live(
                leader, process_tgid_of_task(t)))
            process_notify_waiter_for_task(leader);
    }
    if (!notify_parent && t != process_current_task() &&
        process_tgid_of_task(t) > 0 && process_tgid_of_task(t) != t->pid) {
        /*
         * CLONE_THREAD siblings killed as part of exit_group are not waitable
         * children on Linux.  Keeping each helper as a TASK_ZOMBIE pins one of
         * EdgeOS' finite task slots; GLib/XFCE creates enough short-lived
         * helper threads to exhaust PROC_MAX_TASKS and make later forks fail.
         * Red flag: do not apply this to process leaders, which remain
         * waitable by their parent and may own the fixed userspace mm slot.
        */
        task_release_unused(t);
        goto out_restore_cr3;
    }
    if (notify_parent) {
        task_t *tracer = t->ptrace.tracer_pid > 0 ?
            task_find_by_pid(t->ptrace.tracer_pid) : 0;
        if (tracer && process_tgid_of_task(tracer) != t->ppid)
            process_notify_waiter_for_task(t);
        else
            process_notify_parent_exit(parent, t, t->exit_signal);
    }
    if (auto_reap) {
        parent_account = parent ?
            task_find_by_pid(process_tgid_of_task(parent)) : 0;
        process_rusage_accumulate_reaped_child(
            parent_account ? parent_account : parent, t);
        task_child_unlink(t);
        t->ppid = 0;
        t->parent_tid = 0;
    }

out_restore_cr3:
    /*
     * Current pthread exits cannot be reapable until scheduler_yield() has
     * switched away from their live kernel stack.  Arm deferred collection
     * from the logical detached-zombie state rather than requiring that
     * physical handoff to have completed already.
     */
    if (task_is_detached_zombie_candidate_raw(t))
        __atomic_store_n(&g_detached_zombie_reap_pending, 1u,
                         __ATOMIC_RELEASE);
    if (!exiting_current && old_cr3 && old_cr3 != cr3_read_local_process()) {
        cr3_write(old_cr3);
    }
}

void process_release_detached_zombie_thread(task_t *t) {
    if (!t || t->state != TASK_ZOMBIE) return;
    if (t == process_current_task() || t->on_cpu || t->switch_pending) return;
    if (process_tgid_of_task(t) <= 0 || process_tgid_of_task(t) == t->pid) return;
    /*
     * Non-leader threads are joined inside the thread group rather than by the
     * parent process.  After they have been marked zombie and pidfd waiters have
     * been woken, the kernel can recycle the internal task slot.  This mirrors
     * Linux' externally visible behavior more closely than exposing every dead
     * pthread as a persistent child zombie.
     */
    task_release_unused(t);
}

static int process_thread_group_has_other_live(task_t *target, int tgid) {
    if (!target || tgid <= 0) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (t == target) continue;
        if (!process_task_live(t)) continue;
        if (process_tgid_of_task(t) == tgid) return 1;
    }
    return 0;
}

int process_task_group_exit_requested(const task_t *task, int *code) {
    if (!task || !__atomic_load_n(&task->group_exit_pending,
                                  __ATOMIC_ACQUIRE))
        return 0;
    if (code) *code = task->group_exit_code;
    return 1;
}

int process_current_group_exit_requested(int *code) {
    return process_task_group_exit_requested(process_current_task(), code);
}

static void process_request_group_leader_exit(task_t *leader, int code) {
    if (!process_task_live(leader)) return;
    leader->group_exit_code = code;
    __atomic_store_n(&leader->group_exit_pending, 1u, __ATOMIC_RELEASE);
    if (leader->state == TASK_BLOCKED || leader->state == TASK_STOPPED) {
        scheduler_task_make_runnable(
            leader, leader->assigned_cpu >= 0 ?
                (uint32_t)leader->assigned_cpu : scheduler_cpu_id());
    }
}

static int process_kill_thread_group(task_t *target, int code) {
    int tgid;
    int killed = 0;
    int defer_leader_exit;
    task_t *leader = 0;
    task_t *current = process_current_task();

    if (!process_task_live(target)) return -1;
    if (target->pid == 1) return -1;
    tgid = process_tgid_of_task(target);
    if (tgid <= 0) tgid = target->pid;
    leader = task_find_by_pid(tgid);
    defer_leader_exit = leader && current && current != leader &&
        process_tgid_of_task(current) == tgid;
    if (g_desktop_child_trace_budget > 0 &&
        (process_desktop_trace_task(target) || process_desktop_trace_task(leader))) {
        g_desktop_child_trace_budget--;
        printf("[deskchild] kill-thread-group target=%d/%s leader=%d/%s tgid=%d code=%d budget=%d\n",
               target ? target->pid : -1, target ? target->name : "-",
               leader ? leader->pid : -1, leader ? leader->name : "-",
               tgid, code, g_desktop_child_trace_budget);
    }

    /*
     * Publish group death before scanning members.  A sibling can otherwise
     * complete clone after the teardown scan has passed its new task slot,
     * leaving a live worker attached to a zombie leader.  Clone checks this
     * flag both before allocation and after assigning the child's tgid, so it
     * either aborts or becomes visible to the teardown scan.
     */
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];

        if (!process_task_live(t) || process_tgid_of_task(t) != tgid)
            continue;
        t->group_exit_code = code;
        __atomic_store_n(&t->group_exit_pending, 1u, __ATOMIC_RELEASE);
    }

    /*
     * Linux fatal signals are process-fatal for CLONE_THREAD groups.  Killing
     * only the addressed task leaves sibling pthreads blocked in futex/select
     * with the shared mm and files table still referenced; Python/Tk then
     * leaks task slots and later GUI subprocesses stall.  Tear down non-leader
     * siblings first and run the normal owner exit last so fd/mm lifetime
     * checks see all shared users gone before releasing process resources.
     */
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (!process_task_live(t)) continue;
        if (process_tgid_of_task(t) != tgid) continue;
        if (t == leader || t == target) continue;
        process_finish_task_exit(t, code, "kill-thread", 0);
        killed++;
    }

    if (defer_leader_exit)
        process_request_group_leader_exit(leader, code);

    if (process_task_live(target) && target != leader) {
        process_finish_task_exit(target, code, "kill-thread", 0);
        killed++;
    }

    if (!defer_leader_exit && process_task_live(leader) && leader->pid != 1) {
        process_finish_task_exit(leader, code, "kill", 1);
        killed++;
    } else if (!leader && process_task_live(target)) {
        process_finish_task_exit(target, code, "kill", 1);
        killed++;
    }

    return killed > 0 ? 0 : -1;
}

void process_exit_current(int code) {
    task_t *cur = process_current_task();
    int notify_parent;
    if (!cur) return;
    if (strncmp(cur->name, "systemd-journal", 15) == 0) {
        uint32_t available = cur->syscall_history_pos < TASK_SYSCALL_HISTORY ?
            cur->syscall_history_pos : TASK_SYSCALL_HISTORY;
        uint32_t start = cur->syscall_history_pos - available;
        printf("[journal-exit-history] pid=%d code=%d calls=%u\n",
               cur->pid, code, available);
        for (uint32_t offset = 0; offset < available; ++offset) {
            uint32_t slot = (start + offset) % TASK_SYSCALL_HISTORY;
            printf("[journal-exit-sys] nr=%u ret=%lld a1=0x%llx "
                   "a2=0x%llx a3=0x%llx a4=0x%llx a5=0x%llx a6=0x%llx\n",
                   (uint32_t)cur->syscall_history_nr[slot],
                   (long long)cur->syscall_history_ret[slot],
                   (unsigned long long)cur->syscall_history_arg1[slot],
                   (unsigned long long)cur->syscall_history_arg2[slot],
                   (unsigned long long)cur->syscall_history_arg3[slot],
                   (unsigned long long)cur->syscall_history_arg4[slot],
                   (unsigned long long)cur->syscall_history_arg5[slot],
                   (unsigned long long)cur->syscall_history_arg6[slot]);
        }
    }
#if EDGE_X11_TRACE
    if (strcmp(cur->name, "Xorg") == 0 || strcmp(cur->name, "xsetroot") == 0 ||
        strcmp(cur->name, "twm") == 0 || strcmp(cur->name, "xterm") == 0 ||
        strcmp(cur->name, "xclock") == 0) {
        printf("[x11dbg] proc-exit pid=%d tgid=%d cmd=%s code=%d fd_owner=%d vm_owner=%d\n",
               cur->pid, cur->tgid, cur->name, code, cur->fd_owner_pid, cur->vm_owner_pid);
    }
#endif
    if (cur->pid == 1) {
        const char *s = "[init-exit] pid=1 name=";
        while (*s) serial_console_write_raw(*s++);
        s = cur->name;
        while (s && *s) serial_console_write_raw(*s++);
        s = " code=";
        while (*s) serial_console_write_raw(*s++);
        if (code < 0) {
            serial_console_write_raw('-');
            code = -code;
        }
        {
            char buf[16];
            int n = 0;
            unsigned int u = (unsigned int)code;
            do {
                buf[n++] = (char)('0' + (u % 10u));
                u /= 10u;
            } while (u && n < (int)sizeof(buf));
            while (n > 0) serial_console_write_raw(buf[--n]);
        }
        serial_console_write_raw('\n');
        for (;;) __asm__ __volatile__("hlt");
    }
    /*
     * Linux only reports the thread-group leader as a waitable child.  A
     * CLONE_THREAD member exits through clear_child_tid/futex and pthread join
     * state; keeping it as a parent-visible zombie leaks internal task slots
     * and makes real desktop process creation fail under GTK/GLib thread churn.
     */
    notify_parent = (process_tgid_of_task(cur) <= 0 || process_tgid_of_task(cur) == cur->pid) ? 1 : 0;
    process_finish_task_exit(cur, code, "exit", notify_parent);
#if EDGE_SCHED_PROC_DEBUG
    printf("[proc] exit pid=%d ppid=%d parent=%d st=%d acpu=%d onrq=%d\n",
           cur->pid, cur->ppid, cur->parent ? cur->parent->pid : -1, (int)cur->state, cur->assigned_cpu, (int)cur->on_runqueue);
#endif
}

void process_exit_current_group(int code) {
    task_t *cur = process_current_task();
    if (!cur) return;
    /*
     * Hardware exceptions and fatal default signal actions are process-fatal on
     * Linux for CLONE_THREAD groups.  Exiting only the current pthread leaves
     * sibling workers blocked on futex/poll with a half-dead shared mm/files
     * table; real desktop workloads then leak task slots and appear to hang
     * after one helper thread faults.  Use the same teardown path as kill(2) so
     * the externally visible waitable zombie is the thread-group leader.
     */
    if (process_thread_group_has_other_live(cur, process_tgid_of_task(cur))) {
        (void)process_kill_thread_group(cur, code);
        return;
    }
    process_exit_current(code);
}

int process_wait_any(int *status) {
    return process_wait_pid_rusage(-1, status, 0, 0);
}

static task_t *process_wait_group_leader(task_t *waiter) {
    int tgid;
    task_t *leader;
    if (!waiter) return 0;
    tgid = process_tgid_of_task(waiter);
    if (tgid <= 0 || tgid == waiter->pid) return waiter;
    leader = task_find_by_pid(tgid);
    return leader ? leader : waiter;
}

static edge_linux_ptrace_exit_wait_action_t process_ptrace_exit_wait_action(
    const task_t *waiter, const task_t *child) {
    if (!waiter || !child) return EDGE_LINUX_PTRACE_EXIT_WAIT_DEFER;
    return edge_linux_ptrace_exit_wait_action(
        &child->ptrace, waiter->pid, process_tgid_of_task(waiter),
        child->ppid);
}

static int process_wait_owns_child(const task_t *waiter, const task_t *child,
                                   int options) {
    if (!waiter || !child) return 0;
    if (child->ptrace.tracer_pid == waiter->pid) return 1;
    /* CLONE_THREAD members are joined through clear_child_tid, not wait*. */
    if (process_tgid_of_task(child) != child->pid) return 0;
    if (options & PROCESS_WAIT_NOTHREAD)
        return child->parent_tid == waiter->pid;
    return child->ppid == process_tgid_of_task(waiter);
}

static int process_wait_accepts_exit_signal(const task_t *waiter,
                                            const task_t *child,
                                            int options) {
    int clone_child;
    if (!waiter || !child) return 0;
    if (options & PROCESS_WAIT_WALL) return 1;
    if (child->ptrace.tracer_pid == waiter->pid) return 1;
    clone_child = child->exit_signal != LINUX_SIGCHLD;
    return (options & PROCESS_WAIT_WCLONE) ? clone_child : !clone_child;
}

static int process_wait_matches(const task_t *waiter, const task_t *child,
                                const kernel_process_wait_query_t *query,
                                int options) {
    if (!process_wait_owns_child(waiter, child, options) ||
        !process_wait_accepts_exit_signal(waiter, child, options)) {
        return 0;
    }
    return kernel_process_wait_query_matches(
        query, child->pid, child->pgid);
}

enum process_wait_event_kind {
    PROCESS_WAIT_EVENT_NONE = 0,
    PROCESS_WAIT_EVENT_EXIT,
    PROCESS_WAIT_EVENT_STOP,
    PROCESS_WAIT_EVENT_CONTINUE,
};

static task_t *process_wait_find_event(
    task_t *waiter, const kernel_process_wait_query_t *query,
    int options, int *has_match, enum process_wait_event_kind *kind) {
    task_t *selected = 0;
    enum process_wait_event_kind selected_kind = PROCESS_WAIT_EVENT_NONE;
    int matched = 0;
    if (!g_tasks || !waiter) {
        if (has_match) *has_match = 0;
        if (kind) *kind = PROCESS_WAIT_EVENT_NONE;
        return 0;
    }
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *child = &g_tasks[i];
        if (child->state == TASK_UNUSED) continue;
        if (!process_wait_matches(waiter, child, query, options)) continue;
        matched = 1;
        if (selected) continue;
        if (child->state == TASK_ZOMBIE &&
            (options & PROCESS_WAIT_EXITED)) {
            /*
             * Linux delays reaping a dead thread-group leader until every
             * sibling has exited.  Releasing it earlier detaches the shared
             * process state while live browser workers still use it and makes
             * a subsequent launch attach to an unkillable half-dead group.
             */
            if (process_tgid_of_task(child) == child->pid &&
                process_thread_group_has_other_live(
                    child, process_tgid_of_task(child)))
                continue;
            if (process_ptrace_exit_wait_action(waiter, child) ==
                EDGE_LINUX_PTRACE_EXIT_WAIT_DEFER)
                continue;
            selected = child;
            selected_kind = PROCESS_WAIT_EVENT_EXIT;
        } else if (child->state == TASK_STOPPED && !child->stop_reported &&
                   (child->ptrace.tracer_pid == waiter->pid ||
                    (options & PROCESS_WAIT_STOPPED))) {
            selected = child;
            selected_kind = PROCESS_WAIT_EVENT_STOP;
        } else if (child->continued_pending &&
                   (options & PROCESS_WAIT_CONTINUED)) {
            selected = child;
            selected_kind = PROCESS_WAIT_EVENT_CONTINUE;
        }
    }
    if (has_match) *has_match = matched;
    if (kind) *kind = selected_kind;
    return selected;
}

static int process_wait_pid_rusage_uid_query_for_task(
    task_t *waiter, const kernel_process_wait_query_t *query,
    int *status, int options, process_rusage_snapshot_t *usage,
    uint32_t *uid) {
    task_t *account;
    if (!waiter || !query) return -1;
    account = process_wait_group_leader(waiter);

    for (;;) {
        int has_match = 0;
        task_t *t;
        enum process_wait_event_kind event = PROCESS_WAIT_EVENT_NONE;
        waiter->child_wait_active = 1;
        t = process_wait_find_event(
            waiter, query, options, &has_match, &event);
        if (t) {
            int reported;
            edge_linux_ptrace_exit_wait_action_t ptrace_action =
                event == PROCESS_WAIT_EVENT_EXIT ?
                    process_ptrace_exit_wait_action(waiter, t) :
                    EDGE_LINUX_PTRACE_EXIT_WAIT_REAP;
            if (edge_pid_namespace_global_to_visible(
                    query->pid_namespace_id, t->pid, &reported) < 0) {
                waiter->child_wait_active = 0;
                return -1;
            }
            waiter->child_wait_active = 0;
            if (uid) *uid = t->uid;
            if (status) {
                if (event == PROCESS_WAIT_EVENT_STOP) {
                    *status = (int)kernel_process_wait_stop_status(
                        t->stop_signal,
                        t->ptrace.tracer_pid == waiter->pid ?
                            t->ptrace.stop_event : 0u);
                } else if (event == PROCESS_WAIT_EVENT_CONTINUE) {
                    *status = (int)kernel_process_wait_continue_status();
                } else {
                    *status = process_wait_status_for_task(t);
                }
            }
            if (usage) {
                process_rusage_snapshot_task(t, usage);
                usage->user_time_us += t->rusage_child_user_time_us;
                usage->sys_time_us += t->rusage_child_sys_time_us;
                usage->minor_faults += t->rusage_child_minor_faults;
                usage->major_faults += t->rusage_child_major_faults;
                usage->voluntary_ctxt_switches += t->rusage_child_voluntary_ctxt_switches;
                usage->involuntary_ctxt_switches += t->rusage_child_involuntary_ctxt_switches;
            }
            /*
             * waitid(WNOWAIT) is a real Linux ABI contract: userland can
             * observe an exited child without consuming the zombie, then
             * later reap it with waitpid()/waitid() without WNOWAIT.  GLib
             * uses this pattern for child watches and pidfd integration.
             * Do not clear SIGCHLD or detach the child on the peek path.
             */
            if (options & PROCESS_WAIT_NOREAP) return reported;
            if (event == PROCESS_WAIT_EVENT_STOP) {
                t->stop_reported = 1;
                return reported;
            }
            if (event == PROCESS_WAIT_EVENT_CONTINUE) {
                t->continued_pending = 0;
                return reported;
            }
            if (ptrace_action == EDGE_LINUX_PTRACE_EXIT_WAIT_RELEASE) {
                task_t *parent = t->parent;
                edge_linux_ptrace_state_reset(&t->ptrace);
                t->stop_signal = 0;
                t->stop_reported = 0;
                t->continued_pending = 0;
                process_notify_parent_exit(parent, t, t->exit_signal);
                return reported;
            }
            if (g_desktop_child_trace_budget > 0 &&
                (process_desktop_trace_task(account) || process_desktop_trace_task(t))) {
                g_desktop_child_trace_budget--;
                printf("[deskchild] reap parent=%d/%s child=%d/%s status=0x%x opts=0x%x budget=%d\n",
                       account->pid, account->name, t->pid, t->name,
                       status ? *status : 0, options, g_desktop_child_trace_budget);
            }
            process_rusage_accumulate_reaped_child(account, t);
            process_release_fds_if_last_user(t, "wait_pid");
            task_child_unlink(t);
            task_release_unused(t);
            return reported;
        }
        if (!has_match) {
            waiter->child_wait_active = 0;
            return -1;
        }
        if (options & PROCESS_WAIT_NOHANG) {
            waiter->child_wait_active = 0;
            return 0;
        }
        /*
         * A signal wake makes a blocked wait syscall runnable, but the child
         * scan above can still have no event. Return to the syscall boundary
         * before parking again so fatal signals are delivered and catchable
         * signals observe Linux EINTR/SA_RESTART handling.
         */
        if (kernel_current_signal_wake_pending()) {
            waiter->child_wait_active = 0;
            return -EDGE_LINUX_EINTR;
        }
#if EDGE_SCHED_PROC_DEBUG
        printf("[proc] wait_pid block parent=%d st=%d acpu=%d onrq=%d\n",
               waiter->pid, (int)waiter->state, waiter->assigned_cpu, (int)waiter->on_runqueue);
#endif
        /*
         * Publish the blocked state before the final child-event check.  A
         * child can exit on another CPU after the scan above but before the
         * waiter becomes blockable.  Without this prepare/check/schedule
         * ordering, the exit wake observes a running task and the waiter then
         * sleeps forever even though its child is already a zombie.
         *
         * Once TASK_BLOCKED and child_wait_active are visible, either this
         * second scan observes the event or a later exit makes the waiter
         * runnable.  A sibling waiter may consume the event between scans; in
         * that case has_match becomes false and this caller must also wake so
         * the next loop reports ECHILD.
         */
        scheduler_task_set_blocked(waiter);
        has_match = 0;
        event = PROCESS_WAIT_EVENT_NONE;
        t = process_wait_find_event(
            waiter, query, options, &has_match, &event);
        if (t || !has_match || kernel_current_signal_wake_pending())
            scheduler_task_make_runnable(waiter, scheduler_cpu_id());
        scheduler_yield();
        waiter->child_wait_active = 0;
    }
}

static int process_wait_pid_rusage_uid_query(
    const kernel_process_wait_query_t *query, int *status, int options,
    process_rusage_snapshot_t *usage, uint32_t *uid) {
    return process_wait_pid_rusage_uid_query_for_task(
        process_current_task(), query, status, options, usage, uid);
}

static int process_wait_pid_rusage_uid(int pid, int *status, int options,
                                       process_rusage_snapshot_t *usage,
                                       uint32_t *uid) {
    kernel_process_wait_request_t request;
    kernel_process_wait_query_t query;
    task_t *waiter = process_current_task();

    if (!waiter) return -1;
    request.selector = pid;
    request.flags = (uint32_t)options;
    request.pid_namespace_id = waiter->namespaces.pid;
    if (kernel_process_wait_query_build(
            &request, waiter->pgid, &query) < 0)
        return -1;
    return process_wait_pid_rusage_uid_query(
        &query, status, options, usage, uid);
}

int process_wait_pid_rusage(int pid, int *status, int options,
                            process_rusage_snapshot_t *usage) {
    return process_wait_pid_rusage_uid(
        pid, status, options | PROCESS_WAIT_EXITED, usage, 0);
}

_Static_assert(PROCESS_WAIT_NOHANG == KERNEL_PROCESS_WAIT_NOHANG,
               "wait nohang flag mismatch");
_Static_assert(PROCESS_WAIT_NOREAP == KERNEL_PROCESS_WAIT_NOREAP,
               "wait noreap flag mismatch");
_Static_assert(PROCESS_WAIT_NOTHREAD == KERNEL_PROCESS_WAIT_NOTHREAD,
               "wait nothread flag mismatch");
_Static_assert(PROCESS_WAIT_WALL == KERNEL_PROCESS_WAIT_WALL,
               "wait wall flag mismatch");
_Static_assert(PROCESS_WAIT_WCLONE == KERNEL_PROCESS_WAIT_WCLONE,
               "wait wclone flag mismatch");
_Static_assert(PROCESS_WAIT_STOPPED == KERNEL_PROCESS_WAIT_STOPPED,
               "wait stopped flag mismatch");
_Static_assert(PROCESS_WAIT_CONTINUED == KERNEL_PROCESS_WAIT_CONTINUED,
               "wait continued flag mismatch");
_Static_assert(PROCESS_WAIT_EXITED == KERNEL_PROCESS_WAIT_EXITED,
               "wait exited flag mismatch");

int64_t arch_process_wait(const kernel_process_wait_query_t *query,
                          kernel_process_wait_result_t *result,
                          void *user_registers) {
    int options;
    int status = 0;
    int pid;
    uint32_t uid = 0;

    (void)user_registers;
    if (!query || !result) return -EDGE_LINUX_EINVAL;
    options = (int)query->flags;
    pid = process_wait_pid_rusage_uid_query(
        query, &status, options, &result->usage, &uid);
    /* Preserve interruptible wait errors; only -1 means no waitable child. */
    if (pid < -1) return pid;
    if (pid < 0) return -EDGE_LINUX_ECHILD;
    if (!pid) return 0;
    result->pid = pid;
    result->uid = uid;
    result->status = (uint32_t)status;
    return 1;
}

int64_t arch_process_wait_for_tid(
        const kernel_process_wait_query_t *query,
        kernel_process_wait_result_t *result, int32_t waiter_tid) {
    task_t *waiter;
    int status = 0;
    int pid;
    uint32_t uid = 0;

    if (!query || !result || waiter_tid <= 0 ||
        !(query->flags & KERNEL_PROCESS_WAIT_NOHANG))
        return -EDGE_LINUX_EINVAL;
    waiter = task_find_by_pid(waiter_tid);
    if (!waiter) return -EDGE_LINUX_ESRCH;
    pid = process_wait_pid_rusage_uid_query_for_task(
        waiter, query, &status, (int)query->flags,
        &result->usage, &uid);
    if (pid < -1) return pid;
    if (pid < 0) return -EDGE_LINUX_ECHILD;
    if (!pid) return 0;
    result->pid = pid;
    result->uid = uid;
    result->status = (uint32_t)status;
    return 1;
}

int process_wait_pid(int pid, int *status, int options) {
    return process_wait_pid_rusage(pid, status, options, 0);
}

int process_getrusage_self(process_rusage_snapshot_t *usage) {
    task_t *cur = process_current_task();
    if (!cur || !usage) return -1;
    process_rusage_snapshot_task(cur, usage);
    return 0;
}

int process_getrusage_children(process_rusage_snapshot_t *usage) {
    task_t *cur = process_current_task();
    if (!cur || !usage) return -1;
    process_rusage_snapshot_children(cur, usage);
    return 0;
}

void process_account_minor_fault(task_t *t) {
    if (!t) t = process_current_task();
    if (!t || t->state == TASK_UNUSED) return;
    t->rusage_minor_faults++;
}

void process_account_major_fault(task_t *t) {
    if (!t) t = process_current_task();
    if (!t || t->state == TASK_UNUSED) return;
    t->rusage_major_faults++;
}

int process_adopt_orphans(int from_ppid, int to_ppid) {
    task_t *from = task_find_by_pid(from_ppid);
    task_t *to = task_find_by_pid(to_ppid);
    int moved = 0;

    if (from) {
        task_t *next;
        for (task_t *c = from->first_child; c; c = next) {
            next = c->sibling_next;
            task_child_link(to, c);
            c->parent_tid = to ? to->pid : 0;
            moved++;
        }
        return moved;
    }

    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (t->state == TASK_UNUSED || t->ppid != from_ppid) continue;
        task_child_link(to, t);
        t->parent_tid = to ? to->pid : 0;
        moved++;
    }
    return moved;
}

int process_kill_pid(int pid, int code) {
    task_t *t = task_find_by_pid(pid);
    if (!t) return -1;
    if (pid == 1) return -1;
#if EDGE_X11_TRACE
    if (strcmp(t->name, "Xorg") == 0 || strcmp(t->name, "xsetroot") == 0 ||
        strcmp(t->name, "twm") == 0 || strcmp(t->name, "xterm") == 0 ||
        strcmp(t->name, "xclock") == 0) {
        printf("[x11dbg] proc-kill pid=%d tgid=%d cmd=%s code=%d fd_owner=%d vm_owner=%d\n",
               t->pid, t->tgid, t->name, code, t->fd_owner_pid, t->vm_owner_pid);
    }
#endif
    if (process_thread_group_has_other_live(t, process_tgid_of_task(t))) {
        return process_kill_thread_group(t, code);
    }
    process_finish_task_exit(t, code, "kill", 1);
    return t->state == TASK_ZOMBIE ? 0 : -1;
}

void process_list_print(void) {
    printf("PID PPID S NAME\n");
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (t->state == TASK_UNUSED) continue;
        char s = '?';
        if (t->state == TASK_RUNNING || t->state == TASK_RUNNABLE) s = 'R';
        else if (t->state == TASK_BLOCKED) s = 'S';
        else if (t->state == TASK_STOPPED) s = 'T';
        else if (t->state == TASK_ZOMBIE) s = 'Z';
        printf("%d %d %c %s\n", t->pid, t->ppid, s, t->name);
    }
}

int process_spawn_exec_env(const char *path, int argc, char **argv, int envc, char **envp) {
    task_t *parent = process_current_task();
    int child_idx = -1;
    char resolved_path[256];
    const char *exec_path = process_resolve_spawn_path(path, resolved_path, (int)sizeof(resolved_path));
    task_t *child = task_alloc_reserved(0, &child_idx);
    if (!child) {
        if (EDGE_SPAWN_DEBUG) {
            printf("[spawn] failed: no user address-space slot for %s\n", path ? path : "(null)");
        }
        task_dump_slots_local("spawn-no-user-as-slot");
        return -1;
    }
    if (parent) {
        if (edge_namespaces_inherit(&child->namespaces,
                                    &parent->namespaces) < 0) {
            task_release_unused(child);
            return -1;
        }
        if (task_seccomp_inherit(child, parent) < 0) {
            task_release_unused(child);
            return -1;
        }
    } else {
        edge_namespaces_bootstrap(&child->namespaces,
                                  lwip_stack_get_hostname());
        edge_seccomp_state_init(&child->seccomp);
    }

    child->ppid = parent ? process_tgid_of_task(parent) : 0;
    child->parent_tid = parent ? parent->pid : 0;
    if (edge_pid_namespace_task_attach(&child->namespaces,
                                       child->pid) < 0) {
        task_release_unused(child);
        return -1;
    }
    child->pid_namespace_attached = 1;
    child->exit_code = 0;
    child->exit_signal = LINUX_SIGCHLD;
    child->termination_signal = 0;
    child->kernel_stack_top = task_kernel_stack_top_for_index(child_idx);
    if (!child->kernel_stack_top) {
        task_dump_slots_local("spawn-no-kernel-stack");
        task_release_unused(child);
        return -1;
    }
    child->user_stack_top = USER_STACK_TOP;
    child->user_heap_base = USER_HEAP_BASE;
    child->user_brk = USER_HEAP_BASE;
    child->user_heap_limit = USER_HEAP_BASE + USER_HEAP_DEFAULT_DELTA;
    child->user_mmap_next = USER_MMAP_BASE;
    task_clear_user_vmas(child);
    child->user_vma_refs_owned = 1;
    child->fs_base = 0;
    child->gs_base = 0;
    if (parent) {
        task_copy_credentials(child, parent);
        task_copy_caps(child, parent);
        if (task_copy_groups(child, parent) < 0) {
            task_release_unused(child);
            return -1;
        }
        task_copy_resource_limits(child, parent);
        child->umask = parent->umask;
        task_copy_process_control(child, parent);
        child->pgid = parent->pgid;
        child->sid = parent->sid;
        child->ctty_kind = parent->ctty_kind;
        child->ctty_id = parent->ctty_id;
        child->cgroup_id = parent->cgroup_id;
        strcpy(child->cwd, parent->cwd[0] ? parent->cwd : "/");
        strcpy(child->root, parent->root[0] ? parent->root : "/");
        task_signal_actions_copy(child, parent);
        task_sigsys_action_copy(child, parent);
        child->sigaltstack_sp = parent->sigaltstack_sp;
        child->sigaltstack_size = parent->sigaltstack_size;
        child->sigaltstack_flags = parent->sigaltstack_flags;
        child->assigned_cpu = -1;
    } else {
        child->uid = child->gid = 0;
        child->euid = child->egid = 0;
        child->suid = child->sgid = 0;
        child->fsuid = child->fsgid = 0;
        child->dumpable = 1;
        child->no_new_privs = 0;
        task_set_root_caps(child);
        task_clear_groups(child);
        child->umask = 022;
        child->pgid = child->pid;
        child->sid = child->pid;
        child->ctty_kind = PROCESS_CTTY_NONE;
        child->ctty_id = -1;
        strcpy(child->cwd, "/");
        strcpy(child->root, "/");
        task_signal_actions_reset(child);
        task_sigsys_action_reset(child);
        child->sigaltstack_flags = EDGE_LINUX_SS_DISABLE;
        child->assigned_cpu = -1;
    }
    task_init_default_fx(child);
    task_child_link(parent, child);
#if EDGE_SCHED_PROC_DEBUG
    printf("[proc] spawn link parent=%d child=%d child_ppid=%d parent_first_child=%d\n",
           parent ? parent->pid : -1, child->pid, child->ppid,
           parent && parent->first_child ? parent->first_child->pid : -1);
#endif
    task_name_from_path(path, child->name, TASK_NAME_MAX);
    child->start_pending = 0;
    child->start_at_phdr = 0;
    child->start_at_phnum = 0;
    child->start_at_entry = 0;
    child->start_at_base = 0;

    if (task_index(child) >= USER_AS_MAX_TASKS) {
        if (EDGE_SPAWN_DEBUG) {
            printf("[spawn] failed: task index out of range idx=%d path=%s\n", task_index(child), path ? path : "(null)");
        }
        task_dump_slots_local("spawn-bad-user-as-index");
        task_child_unlink(child);
        task_release_unused(child);
        return -1;
    }

    task_clear_user_regions(child);
    if (task_build_address_space(child, 1) < 0) {
        if (EDGE_SPAWN_DEBUG) {
            printf("[spawn] failed: address-space build path=%s\n",
                   path ? path : "(null)");
        }
        task_child_unlink(child);
        task_release_unused(child);
        return -1;
    }
    if (EDGE_SPAWN_DEBUG) {
        printf("[spawn] child=%d addrspace ready cr3=0x%x\n",
               child->pid, (uint32_t)child->cr3);
    }

    process_exec_storage_reset(child);
    if (argc < 0) argc = 0;
    if (argc > EDGE_EXEC_ARG_MAX) {
        task_child_unlink(child);
        task_release_unused(child);
        return -1;
    }
    for (int i = 0; i < argc; ++i) {
        char *stored = 0;
        if (!argv || !argv[i]) break;
        if (process_exec_storage_append(child, argv[i], &stored) < 0) {
            task_child_unlink(child);
            task_release_unused(child);
            return -1;
        }
        (void)stored;
    }

    if (envc < 0) envc = 0;
    if (envc > EDGE_EXEC_ENV_MAX) {
        task_child_unlink(child);
        task_release_unused(child);
        return -1;
    }
    for (int i = 0; i < envc; ++i) {
        char *stored = 0;
        if (!envp || !envp[i]) break;
        if (kernel_exec_record_append(child->exec_record, envp[i], 1,
                                      &stored) < 0) {
            task_child_unlink(child);
            task_release_unused(child);
            return -1;
        }
    }
    if (!process_exec_storage_budget_ok(
            child, (int)child->exec_record->argc,
            (int)child->exec_record->envc)) {
        task_child_unlink(child);
        task_release_unused(child);
        return -1;
    }

    uint64_t old_cr3 = cr3_read();
    uint64_t rflags;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(rflags) :: "memory");
    if (EDGE_SPAWN_DEBUG) {
        printf("[spawn] child=%d switch cr3 old=0x%x new=0x%x\n",
               child->pid, (uint32_t)old_cr3, (uint32_t)child->cr3);
    }
    cr3_write(child->cr3);

    edge_elf_image_t elf_img;
    vfs_inode_t exec_ino;
    vfs_superblock_t *exec_sb = 0;
    int have_exec_ino = 0;
    if (EDGE_SPAWN_DEBUG) {
        printf("[spawn] child=%d elf load begin path=%s\n",
               child->pid, exec_path ? exec_path : "(null)");
    }
    if (vfs_resolve(exec_path, &exec_ino, &exec_sb, 0, 0) == 0)
        have_exec_ino = 1;
    if (elf_loader_exec_into(child->pid, exec_path, &elf_img) < 0) {
        if (EDGE_SPAWN_DEBUG) {
            int probe = elf_loader_probe(exec_path);
            printf("[spawn] elf load failed path=%s probe=%d parent_pid=%d child_pid=%d\n",
                   exec_path ? exec_path : "(null)", probe, parent ? parent->pid : 0, child->pid);
        }
        /*
         * The failed loader leaves the child's CR3 active while the scheduler
         * still identifies the parent as current.  Restore the parent before
         * teardown so task_release_unused() never frees fixed or sparse page
         * tables that hardware can still walk.
         */
        cr3_write(old_cr3);
        task_child_unlink(child);
        task_release_unused(child);
        if (rflags & (1ULL << 9)) __asm__ __volatile__("sti");
        return -1;
    }
    if (have_exec_ino)
        task_apply_exec_file_creds(child, exec_ino.mode, exec_ino.uid,
                                   exec_ino.gid,
                                   exec_sb ? exec_sb->mount_flags : 0u);
    strncpy(child->exec_path, exec_path, sizeof(child->exec_path) - 1u);
    child->exec_path[sizeof(child->exec_path) - 1u] = 0;
    child->execed_since_fork = 1;
    if (EDGE_SPAWN_DEBUG) {
        printf("[spawn] child=%d elf load done entry=0x%x at_base=0x%x main_hi=0x%x\n",
               child->pid, (uint32_t)elf_img.entry_rip, (uint32_t)elf_img.at_base, (uint32_t)elf_img.main_load_hi);
    }
    child->start_entry = elf_img.entry_rip;
    child->start_at_phdr = elf_img.at_phdr;
    child->start_at_phnum = elf_img.at_phnum;
    child->start_at_entry = elf_img.at_entry;
    child->start_at_base = elf_img.at_base;
    child->start_pending = 1;
    memset(&child->context, 0, sizeof(child->context));
    child->context.rsp = child->kernel_stack_top;
    child->context.rbp = child->kernel_stack_top;
    child->context.rip = (uint64_t)process_spawn_entry;
    scheduler_task_context_ready(child);
    if (EDGE_SPAWN_DEBUG) {
        printf("[spawn] child=%d context rip=0x%x rsp=0x%x\n",
               child->pid, (uint32_t)child->context.rip, (uint32_t)child->context.rsp);
    }
#if EDGE_SCHED_PROC_DEBUG
    printf("[proc] spawn child=%d -> BLOCKED\n", child->pid);
#endif
    scheduler_task_set_blocked(child);
#if EDGE_SCHED_PROC_DEBUG
    printf("[proc] spawn child=%d -> RUNNABLE cpu=%d\n", child->pid, process_pick_target_cpu());
#endif
    (void)process_cgroup_account_publish(child->pid);
    if (g_task_prestart_hook) g_task_prestart_hook(child);
    scheduler_task_make_runnable(child, (uint32_t)process_pick_target_cpu());

    cr3_write(old_cr3);
    if (rflags & (1ULL << 9)) __asm__ __volatile__("sti");
    return child->pid;
}

int process_spawn_exec(const char *path, int argc, char **argv) {
    return process_spawn_exec_env(path, argc, argv, 0, 0);
}

int process_set_fork_frame_rsp(int pid, uint64_t rsp) {
    task_t *t = task_find_by_pid(pid);
    if (!t) return -1;
    if (t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) return -1;
    t->fork_tf.rsp = rsp;
    return 0;
}

__attribute__((noreturn)) void process_enter_user_current(void) {
    task_t *cur = process_current_task();
    if (!cur || !cur->start_pending) {
        process_exit_current(-1);
        for (;;) __asm__ __volatile__("sti; hlt");
    }

    user_exec_image_t img;
    img.entry = cur->start_entry;
    img.user_stack_top = cur->user_stack_top;
    img.user_heap_base = cur->user_heap_base;
    img.at_phdr = cur->start_at_phdr;
    img.at_phnum = cur->start_at_phnum;
    img.at_entry = cur->start_at_entry;
    img.at_base = cur->start_at_base;
    img.secure_exec = 0;
    cur->start_pending = 0;
    if (!cur->exec_record) {
        process_exit_current(-1);
        for (;;) __asm__ __volatile__("sti; hlt");
    }
    user_exec_run(&img, (int)cur->exec_record->argc,
                  cur->exec_record->arguments,
                  (int)cur->exec_record->envc,
                  cur->exec_record->environment);
    process_exit_current(-1);
    for (;;) __asm__ __volatile__("sti; hlt");
}

const task_t *process_get_task(int pid) { return task_find_by_pid(pid); }
task_t *process_task_by_pid(int pid) { return task_find_by_pid(pid); }

int arch_proc_namespace_inode(int32_t pid, uint32_t kind,
                              uint64_t *inode_out) {
    const task_t *task;
    uint64_t inode;

    if (pid <= 0 || kind >= EDGE_NAMESPACE_KIND_COUNT || !inode_out)
        return -1;
    task = process_get_task(pid);
    if (!task || task->state == TASK_UNUSED) return -1;
    inode = edge_namespace_inode(
        &task->namespaces, (edge_namespace_kind_t)kind);
    if (!inode) return -1;
    *inode_out = inode;
    return 0;
}

static int process_proc_exec_vector(const kernel_exec_record_t *record,
                                    int environment_vector, char *buffer,
                                    uint32_t capacity) {
    uint32_t length = 0;
    uint32_t count;

    if (!buffer) return -1;
    if (!record) return 0;
    count = environment_vector ? record->envc : record->argc;
    for (uint32_t index = 0; index < count; ++index) {
        const char *value = environment_vector ?
            record->environment[index] : record->arguments[index];
        uint32_t size = 0;

        if (!kernel_exec_record_contains(record, value) || !value[0])
            continue;
        while (value[size]) ++size;
        ++size;
        if (size > capacity - length) return -1;
        memcpy(buffer + length, value, size);
        length += size;
    }
    return (int)length;
}

int arch_proc_task_cmdline(int32_t pid, char *buffer, uint32_t capacity) {
    const task_t *task;

    if (pid <= 0 || !buffer) return -1;
    task = process_get_task(pid);
    if (!task || task->state == TASK_UNUSED) return -1;
    return process_proc_exec_vector(task->exec_record, 0, buffer, capacity);
}

int arch_proc_task_environ(int32_t pid, char *buffer, uint32_t capacity) {
    const task_t *task;

    if (pid <= 0 || !buffer) return -1;
    task = process_get_task(pid);
    if (!task || task->state == TASK_UNUSED) return -1;
    return process_proc_exec_vector(task->exec_record, 1, buffer, capacity);
}

void process_update_thread_group_signal_action(int sig, uint64_t handler, uint64_t mask, uint64_t flags, uint64_t restorer) {
    task_t *cur = process_current_task();
    uint64_t context_id;
    if (!cur) return;
    context_id = cur->sighand_context_id;
    /*
     * Linux signal dispositions are shared through the sighand object.  The
     * context ID covers both normal thread groups and process-level
     * CLONE_SIGHAND users; the signal mask itself remains per-thread.
     */
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) continue;
        if (t->sighand_context_id != context_id) continue;
        if (sig <= 0 || sig > (int)EDGE_LINUX_SIGNAL_MAX) continue;
        t->signal_actions[sig - 1].handler = handler;
        t->signal_actions[sig - 1].mask = mask;
        t->signal_actions[sig - 1].flags = flags;
        t->signal_actions[sig - 1].restorer = restorer;
    }
}
const task_t *process_task_by_index(int index) {
    if (!g_tasks_ready || !g_tasks ||
        index < 0 || index >= PROC_MAX_TASKS) return 0;
    return &g_tasks[index];
}
task_t *process_current_task(void) { return scheduler_current_task(); }

int arch_runtime_yield(void) {
    if (!process_current_task()) return 0;
    scheduler_yield();
    return 1;
}

int arch_runtime_contention_begin(void) {
    return 0;
}

void arch_runtime_contention_end(int released) {
    (void)released;
}

void arch_runtime_fuse_notify(uint64_t description_identity) {
    (void)description_identity;
}

void arch_runtime_fuse_reply_wait(uint64_t description_identity) {
    (void)description_identity;
}

void arch_runtime_fuse_reply_notify(uint64_t description_identity,
                                    uintptr_t context_token) {
    (void)description_identity;
    (void)context_token;
}

uint64_t kernel_arch_scheduler_online_cpu_mask(void) {
    return scheduler_online_cpu_mask();
}

int64_t arch_scheduler_yield(void *user_registers) {
    (void)user_registers;
    scheduler_yield();
    return 0;
}

static int edge_process_runtime_fill_view(
    task_t *task, kernel_process_native_view_t *view) {
    if (!task || !view || task->state == TASK_UNUSED) return -1;
    memset(view, 0, sizeof(*view));
    view->context_token = (uintptr_t)task;
    view->pid = task->pid;
    view->tgid = process_tgid_of_task(task);
    view->ppid = task->ppid;
    view->uid = task->uid;
    view->euid = task->euid;
    view->suid = task->suid;
    view->gid = task->gid;
    view->egid = task->egid;
    view->sgid = task->sgid;
    view->dumpable = task->dumpable;
    view->stopped = task->state == TASK_STOPPED;
    view->zombie = task->state == TASK_ZOMBIE;
    view->stop_reported = task->stop_reported;
    view->stop_signal = task->stop_signal;
    view->comm = task->name;
    view->linux_thread = &task->linux_thread;
    view->namespaces = &task->namespaces;
    view->ptrace = &task->ptrace;
    view->signal_actions = task->signal_actions;
    view->signal_mask = &task->sigmask;
    return 0;
}

int edge_process_runtime_current_view(
    kernel_process_native_view_t *view) {
    return edge_process_runtime_fill_view(process_current_task(), view);
}

int edge_process_runtime_view(
    int32_t pid, kernel_process_native_view_t *view) {
    return edge_process_runtime_fill_view(task_find_by_pid(pid), view);
}

void edge_process_runtime_namespace_committed(
    const edge_namespace_set_t *namespaces) {
    (void)namespaces;
}

int edge_process_runtime_signal_delivery_commit(
    int32_t tid, uint32_t signal, int thread_directed) {
    task_t *target = task_find_by_pid(tid);
    int result;
    if (!target || target->state == TASK_UNUSED ||
        target->state == TASK_ZOMBIE)
        return -EDGE_LINUX_ESRCH;
    result = process_signal_mark_pending(
        target, (int)signal, thread_directed);
    return result < 0 ? -EDGE_LINUX_ESRCH : result;
}

int edge_process_runtime_signal_action_install(
    uint32_t signal, const edge_linux_signal_action_t *action) {
    if (!action || !edge_linux_signal_valid(signal) ||
        !process_current_task())
        return -EDGE_LINUX_EINVAL;
    process_update_thread_group_signal_action(
        (int)signal, action->handler, action->mask,
        action->flags, action->restorer);
    return 0;
}

void edge_process_runtime_signal_pending_discard(uint32_t signal) {
    task_t *task = process_current_task();
    task_t *leader;
    uint64_t bit;
    int group;
    if (!task || !edge_linux_signal_valid(signal)) return;
    group = process_tgid_of_task(task);
    bit = edge_linux_signal_mask_bit(signal);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *peer = &g_tasks[index];
        if (peer->state == TASK_UNUSED || peer->state == TASK_ZOMBIE ||
            process_tgid_of_task(peer) != group)
            continue;
        peer->signal_pending &= ~bit;
        kernel_signal_queue_purge_signal(peer->pid, signal, 1);
    }
    leader = task_find_by_pid(group);
    if (leader) {
        leader->signal_shared_pending &= ~bit;
        kernel_signal_queue_purge_signal(leader->pid, signal, 0);
    }
}

int edge_system_runtime_memory_information_sample(
    kernel_memory_information_sample_t *sample) {
    sample->total_ram_bytes = meminfo_total_bytes();
    sample->free_ram_bytes = meminfo_free_bytes();
    sample->total_swap_bytes = swap_total_bytes();
    sample->free_swap_bytes = swap_free_bytes();
    return 0;
}

int edge_process_runtime_fs_snapshot(
    int32_t pid, char *cwd, uint32_t cwd_capacity,
    char *root, uint32_t root_capacity) {
    task_t *current;
    uint64_t flags;
    int status = -EDGE_LINUX_ESRCH;

    if (pid <= 0 ||
        ((!cwd || !cwd_capacity) && (!root || !root_capacity)))
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_task_lock);
    current = task_find_by_pid(pid);
    if (current && current->state != TASK_UNUSED &&
        current->state != TASK_ZOMBIE) {
        status = 0;
        if (cwd)
            status = kernel_fs_context_copy_path(
                cwd, cwd_capacity,
                current->cwd[0] ? current->cwd : "/");
        if (status == 0 && root)
            status = kernel_fs_context_copy_path(
                root, root_capacity,
                current->root[0] ? current->root : "/");
    }
    spin_unlock_irqrestore(&g_task_lock, flags);
    return status;
}

int edge_process_runtime_fs_set_location(
    int32_t pid, const char *path, int set_root) {
    task_t *current;
    uint32_t length;
    uint64_t flags;
    uint64_t context_id;

    if (pid <= 0 || !path) return -EDGE_LINUX_EIO;
    length = (uint32_t)strlen(path);

    flags = spin_lock_irqsave(&g_task_lock);
    current = task_find_by_pid(pid);
    if (!current || current->state == TASK_UNUSED ||
        current->state == TASK_ZOMBIE) {
        spin_unlock_irqrestore(&g_task_lock, flags);
        return -EDGE_LINUX_EIO;
    }
    context_id = current->fs_context_id;
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *task = &g_tasks[index];
        char *destination;
        if (task->state == TASK_UNUSED || task->state == TASK_ZOMBIE)
            continue;
        if (task->fs_context_id != context_id)
            continue;
        destination = set_root ? task->root : task->cwd;
        memcpy(destination, path, length + 1u);
    }
    spin_unlock_irqrestore(&g_task_lock, flags);
    return 0;
}

int edge_process_runtime_fs_unshare(int32_t pid) {
    task_t *current;
    uint64_t flags;

    if (pid <= 0) return -EDGE_LINUX_EIO;
    flags = spin_lock_irqsave(&g_task_lock);
    current = task_find_by_pid(pid);
    if (!current || current->state == TASK_UNUSED ||
        current->state == TASK_ZOMBIE) {
        spin_unlock_irqrestore(&g_task_lock, flags);
        return -EDGE_LINUX_EIO;
    }
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        const task_t *peer = &g_tasks[index];
        if (peer != current && peer->state != TASK_UNUSED &&
            peer->state != TASK_ZOMBIE &&
            peer->fs_context_id == current->fs_context_id) {
            current->fs_context_id = g_next_fs_context_id++;
            if (!current->fs_context_id)
                current->fs_context_id = g_next_fs_context_id++;
            break;
        }
    }
    spin_unlock_irqrestore(&g_task_lock, flags);
    return 0;
}

int kernel_arch_serial_console_device(kernel_console_device_t *device) {
    if (!device) return -1;
    memset(device, 0, sizeof(*device));
    strcpy(device->name, "ttyS0");
    device->major = 4u;
    device->minor = 64u;
    return 0;
}

static int kernel_identity_view_from_task(
    const task_t *task, kernel_task_identity_view_t *view) {
    if (!task || !view || task->state == TASK_UNUSED) return -1;
    view->tid = task->pid;
    view->tgid = task->tgid;
    view->ppid = task->ppid;
    view->pgid = task->pgid;
    view->sid = task->sid;
    view->pid_namespace_id = edge_namespace_id(
        &task->namespaces, EDGE_NAMESPACE_PID);
    view->user_namespace_id = edge_namespace_id(
        &task->namespaces, EDGE_NAMESPACE_USER);
    view->state = task->state == TASK_ZOMBIE ? KERNEL_PROC_TASK_ZOMBIE :
        task->state == TASK_STOPPED ? KERNEL_PROC_TASK_STOPPED :
        task->state == TASK_BLOCKED ? KERNEL_PROC_TASK_SLEEPING :
                                      KERNEL_PROC_TASK_RUNNING;
    view->uid = task->uid;
    view->euid = task->euid;
    view->suid = task->suid;
    view->fsuid = task->fsuid;
    view->gid = task->gid;
    view->egid = task->egid;
    view->sgid = task->sgid;
    view->fsgid = task->fsgid;
    view->dumpable = task->dumpable;
    view->permitted_capabilities = task->capabilities.permitted;
    view->effective_capabilities = task->capabilities.effective;
    return 0;
}

static int kernel_task_view_from_task(const task_t *task,
                                      kernel_proc_task_view_t *view) {
    kernel_task_identity_view_t identity;
    const task_t *memory;
    if (kernel_identity_view_from_task(task, &identity) < 0 || !view)
        return -1;
    memset(view, 0, sizeof(*view));
    kernel_proc_task_view_set_identity(view, &identity);
    memory = process_vm_task((task_t *)task);
    if (memory) view->dumpable = memory->dumpable;
    view->tty_pgrp = task->pgid;
    view->nice_value = (int8_t)task->scheduler.nice;
    view->io_priority = task->io_priority;
    view->umask = (uint16_t)(task->umask & 0777u);
    view->parent_death_signal = task->parent_death_signal;
    view->no_new_privileges = task->no_new_privs;
    view->seccomp_mode = task->seccomp.length ?
        EDGE_LINUX_SECCOMP_MODE_FILTER : EDGE_LINUX_SECCOMP_MODE_DISABLED;
    view->thp_disabled = memory ? memory->thp_disabled : task->thp_disabled;
    view->execed_since_fork = task->execed_since_fork;
    view->child_subreaper = task->child_subreaper;
    view->oom_score_adj = task->oom_score_adj;
    view->oom_score_adj_min = task->oom_score_adj_min;
    view->timer_slack_ns = task->timer_slack_ns;
    view->default_timer_slack_ns = task->default_timer_slack_ns;
    linux_capabilities_copy(&view->capabilities, &task->capabilities);
    for (uint32_t resource = 0; resource < EDGE_LINUX_RLIMIT_COUNT;
         ++resource) {
        view->resource_limits[resource].current = task->rlimits[resource][0];
        view->resource_limits[resource].maximum = task->rlimits[resource][1];
    }
    view->scheduler = task->scheduler;
    view->scheduler_vruntime_us = task->scheduler_vruntime_us;
    view->scheduler_wait_us = task->scheduler_wait_us;
    view->scheduler_migrations = task->scheduler_migrations;
    if (task->scheduler_wait_start_us) {
        uint64_t now_us = boottime_monotonic_us();
        uint64_t pending_wait = now_us > task->scheduler_wait_start_us ?
            now_us - task->scheduler_wait_start_us : 0u;

        view->scheduler_wait_us =
            view->scheduler_wait_us > UINT64_MAX - pending_wait ?
            UINT64_MAX : view->scheduler_wait_us + pending_wait;
    }
    view->processor = task->assigned_cpu >= 0 ?
        (uint32_t)task->assigned_cpu : scheduler_cpu_id();
    view->start_time_ticks = task->rusage_start_us / 10000u;
    if (!view->start_time_ticks) view->start_time_ticks = 1u;
    process_rusage_snapshot_task(task, &view->usage);
    process_rusage_snapshot_children(task, &view->children_usage);
    view->memory_context_id = memory ? memory->cr3 : task->cr3;
    view->files_context_id = (uint64_t)(uint32_t)(
        task->fd_owner_pid > 0 ? task->fd_owner_pid : task->pid);
    view->fs_context_id = task->fs_context_id;
    view->sighand_context_id = task->sighand_context_id;
    /* EdgeOS has no independently allocated IO or SysV sem_undo context. */
    view->io_context_id = 0;
    view->sysvsem_context_id = 0;
    view->exec_file_handle = task->exec_file_handle;
    view->cgroup_id = task->cgroup_id;
    view->mount_namespace_id = edge_namespace_id(&task->namespaces,
                                                 EDGE_NAMESPACE_MNT);
    view->pid_namespace_id = edge_namespace_id(&task->namespaces,
                                               EDGE_NAMESPACE_PID);
    view->user_namespace_id = edge_namespace_id(&task->namespaces,
                                                EDGE_NAMESPACE_USER);
    view->syscall_nr = (uint32_t)task->last_syscall_nr;
    for (uint32_t argument = 0; argument < 6u; ++argument)
        view->syscall_args[argument] = task->last_syscall_args[argument];
    kernel_proc_task_view_set_names(view, task->name, task->exec_path);
    return 0;
}

uint64_t arch_process_task_lock(void) {
    return spin_lock_irqsave(&g_task_lock);
}

void arch_process_task_unlock(uint64_t flags) {
    spin_unlock_irqrestore(&g_task_lock, flags);
}

uint32_t arch_process_task_capacity(void) {
    return PROC_MAX_TASKS;
}

kernel_process_task_handle_t arch_process_task_at_locked(uint32_t slot) {
    if (slot >= PROC_MAX_TASKS) return 0;
    return (kernel_process_task_handle_t)(uintptr_t)&g_tasks[slot];
}

kernel_process_task_handle_t arch_process_task_find_locked(int32_t tid) {
    task_t *task;
    if (tid <= 0) return 0;
    task = task_find_by_pid(tid);
    return (kernel_process_task_handle_t)(uintptr_t)task;
}

kernel_process_task_handle_t arch_process_current_task_locked(void) {
    return (kernel_process_task_handle_t)(uintptr_t)process_current_task();
}

int arch_process_task_identity_locked(
    kernel_process_task_handle_t handle,
    kernel_task_identity_view_t *view) {
    task_t *task = (task_t *)(uintptr_t)handle;
    uintptr_t first = (uintptr_t)&g_tasks[0];
    uintptr_t last = (uintptr_t)&g_tasks[PROC_MAX_TASKS];

    if (!task || !view || (uintptr_t)task < first ||
        (uintptr_t)task >= last ||
        (((uintptr_t)task - first) % sizeof(*task)) != 0)
        return -1;
    return kernel_identity_view_from_task(task, view);
}

int arch_process_task_view_locked(kernel_process_task_handle_t handle,
                                  kernel_proc_task_view_t *view) {
    task_t *task = (task_t *)(uintptr_t)handle;
    uintptr_t first = (uintptr_t)&g_tasks[0];
    uintptr_t last = (uintptr_t)&g_tasks[PROC_MAX_TASKS];

    if (!task || !view || (uintptr_t)task < first ||
        (uintptr_t)task >= last ||
        (((uintptr_t)task - first) % sizeof(*task)) != 0)
        return -1;
    if (task->state == TASK_UNUSED) return 1;
    return kernel_task_view_from_task(task, view);
}

void arch_process_task_apply_locked(
    kernel_process_task_handle_t handle,
    const kernel_process_task_update_t *update) {
    task_t *task = (task_t *)(uintptr_t)handle;
    uintptr_t first = (uintptr_t)&g_tasks[0];
    uintptr_t last = (uintptr_t)&g_tasks[PROC_MAX_TASKS];

    if (!task || !update || (uintptr_t)task < first ||
        (uintptr_t)task >= last || task->state == TASK_UNUSED)
        return;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_SESSION) {
        task->pgid = update->pgid;
        task->sid = update->sid;
        if (update->detach_controlling_terminal) {
            task->ctty_kind = PROCESS_CTTY_NONE;
            task->ctty_id = -1;
        }
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_EXEC)
        task->execed_since_fork = update->execed_since_fork;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_CGROUP)
        task->cgroup_id = update->cgroup_id;
    if ((update->fields & KERNEL_PROCESS_TASK_UPDATE_RESOURCE_LIMIT) &&
        update->resource < EDGE_LINUX_RLIMIT_COUNT) {
        task->rlimits[update->resource][0] =
            update->resource_limit.current;
        task->rlimits[update->resource][1] =
            update->resource_limit.maximum;
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_OOM) {
        task->oom_score_adj = update->oom_score_adj;
        task->oom_score_adj_min = update->oom_score_adj_min;
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_IO_PRIORITY)
        task->io_priority = update->io_priority;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_SCHEDULER) {
        edge_linux_scheduler_state_apply_updates(
            &task->scheduler, &update->scheduler,
            update->scheduler_update_mask);
        if (update->scheduler_update_mask & EDGE_SCHEDULER_UPDATE_AFFINITY)
            task->need_resched = 1;
        if (update->scheduler_update_mask & EDGE_SCHEDULER_UPDATE_POLICY) {
            edge_linux_scheduler_entity_init(
                &task->scheduler_entity, &task->scheduler,
                boottime_monotonic_us());
            task->need_resched = 1;
        }
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_CREDENTIALS) {
        if (update->clear_parent_death_signal)
            task->parent_death_signal = 0;
        task->uid = update->credentials.uid;
        task->euid = update->credentials.euid;
        task->suid = update->credentials.suid;
        task->fsuid = update->credentials.fsuid;
        task->gid = update->credentials.gid;
        task->egid = update->credentials.egid;
        task->sgid = update->credentials.sgid;
        task->fsgid = update->credentials.fsgid;
        linux_capabilities_copy(
            &task->capabilities, &update->credentials.capabilities);
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_GROUPS) {
        if (!update->groups) {
            int result = linux_group_list_retain(
                update->previous_groups,
                &task->supplementary_groups);
            if (update->result) *update->result = result;
        } else if (update->previous_groups) {
            *update->previous_groups = task->supplementary_groups;
            task->supplementary_groups = *update->groups;
            linux_group_list_init(update->groups);
            if (update->result) *update->result = 0;
        }
    }
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_UMASK)
        task->umask = update->umask;
    if (update->fields & KERNEL_PROCESS_TASK_UPDATE_PRCTL) {
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL) {
            task->parent_death_signal =
                (uint8_t)update->prctl.parent_death_signal;
        }
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_DUMPABLE)
            task->dumpable = update->prctl.dumpable;
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_NO_NEW_PRIVILEGES) {
            task->no_new_privs =
                update->prctl.no_new_privileges ? 1u : 0u;
        }
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_TIMER_SLACK)
            task->timer_slack_ns = update->prctl.timer_slack_ns;
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_THP_DISABLED)
            task->thp_disabled = update->prctl.thp_disabled;
        if (update->prctl_update_mask &
            EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER) {
            task->child_subreaper =
                update->prctl.child_subreaper ? 1u : 0u;
        }
        if (update->prctl_update_mask & EDGE_LINUX_PRCTL_UPDATE_NAME) {
            strncpy(task->name, update->prctl.name, TASK_NAME_MAX - 1u);
            task->name[TASK_NAME_MAX - 1u] = 0;
        }
    }
}

edge_seccomp_state_t *arch_process_task_seccomp_locked(
    kernel_process_task_handle_t handle) {
    task_t *task = (task_t *)(uintptr_t)handle;
    if (!task || task->state == TASK_UNUSED || task->is_idle) return 0;
    return &task->seccomp;
}

void arch_process_task_seccomp_replace_locked(
    kernel_process_task_handle_t handle,
    const edge_seccomp_state_t *installed, int set_no_new_privileges) {
    task_t *task = (task_t *)(uintptr_t)handle;
    if (!task || task->state == TASK_UNUSED || task->is_idle || !installed)
        return;
    edge_seccomp_state_release(&task->seccomp);
    task->seccomp = *installed;
    if (set_no_new_privileges) task->no_new_privs = 1;
}

uint32_t *arch_process_task_membarrier_locked(
    kernel_process_task_handle_t handle) {
    task_t *task = (task_t *)(uintptr_t)handle;
    if (!task || task->state == TASK_UNUSED || task->is_idle) return 0;
    return &task->membarrier_registrations;
}

task_t *process_vm_task(task_t *t) { return task_vm_owner_local(t); }

static int x86_proc_vma_after(const kernel_proc_vma_cursor_t *after,
                              uint64_t start, uint32_t order) {
    if (!after || !after->valid) return 1;
    return start > after->start ||
           (start == after->start && order > after->order);
}

static uint64_t x86_proc_pte_for_task(task_t *memory, uint64_t address) {
    uint64_t *entry;
    uint64_t *table;
    uint32_t pte_index;
    uint32_t heap_slot;
    int index;

    if (!memory) return 0;
    index = task_index(memory);
    if (index < 0 || index >= USER_AS_MAX_TASKS) return 0;
    if (user_heap_slot_for_addr(
            address, &heap_slot, &pte_index) == 0 &&
        heap_slot < USER_HEAP_TOTAL_PDE_CNT) {
        table = g_user_heap_pt[index][heap_slot];
        return table ? table[pte_index] : 0;
    }
    entry = fixed_user_pte_for_addr_idx(index, address);
    if (entry) return *entry;
    table = sparse_mmap_lookup_pt(memory, address, 0);
    if (!table || sparse_mmap_indices(
            address, 0, 0, &pte_index) < 0)
        return 0;
    return table[pte_index];
}

static void x86_proc_vma_consider(
    const kernel_proc_vma_cursor_t *after,
    kernel_proc_vma_snapshot_t *best, int *found,
    uint64_t start, uint64_t end, uint32_t order, uint64_t file_offset,
    uint64_t inode, uint32_t flags, const char *path) {
    if (!best || !found || end <= start ||
        !x86_proc_vma_after(after, start, order))
        return;
    if (*found && (start > best->start ||
                   (start == best->start && order >= best->order)))
        return;
    memset(best, 0, sizeof(*best));
    best->start = start;
    best->end = end;
    best->file_offset = file_offset;
    best->inode = inode;
    best->flags = flags;
    best->order = order;
    if (path && path[0]) {
        strncpy(best->path, path, sizeof(best->path) - 1u);
        best->path[sizeof(best->path) - 1u] = 0;
    }
    *found = 1;
}

int arch_proc_vma_next(int32_t pid,
                       const kernel_proc_vma_cursor_t *after,
                       kernel_proc_vma_snapshot_t *snapshot) {
    uint64_t address_space = 0;
    uint64_t irq_flags;
    task_t *task;
    task_t *memory;
    int found = 0;
    int live;

    if (pid <= 0 || !snapshot) return -1;
    irq_flags = spin_lock_irqsave(&g_task_lock);
    task = task_find_by_pid(pid);
    memory = task ? task_vm_owner_local(task) : 0;
    if (!task || !memory || task->state == TASK_UNUSED ||
        memory->state == TASK_UNUSED) {
        spin_unlock_irqrestore(&g_task_lock, irq_flags);
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    address_space = memory->cr3;
    live = process_user_vma_live_count(memory);
    for (int index = 0; index < live; ++index) {
        const edge_user_vma_t *mapping = &memory->user_vmas[index];
        const char *path = mapping->file_backed ?
            process_user_mmap_file_path_for_slot(mapping->file_slot) : 0;
        uint32_t flags = 0;
        if (mapping->prot & 0x1u) flags |= KERNEL_PROC_MAP_READ;
        if (mapping->prot & 0x2u) flags |= KERNEL_PROC_MAP_WRITE;
        if (mapping->prot & 0x4u) flags |= KERNEL_PROC_MAP_EXEC;
        if (mapping->flags & USER_MAP_SHARED_FLAG)
            flags |= KERNEL_PROC_MAP_SHARED;
        x86_proc_vma_consider(
            after, snapshot, &found, mapping->start, mapping->end,
            (uint32_t)index, mapping->file_off,
            mapping->file_backed ? mapping->file_ino : 0u,
            flags, path);
    }
    if (memory->user_brk > memory->user_heap_base)
        x86_proc_vma_consider(
            after, snapshot, &found, memory->user_heap_base,
            (memory->user_brk + USER_PAGE_SIZE - 1u) &
                ~(USER_PAGE_SIZE - 1u),
            0x00010000u, 0, 0,
            KERNEL_PROC_MAP_READ | KERNEL_PROC_MAP_WRITE, "[heap]");
    if (memory->user_stack_top > USER_STACK_BASE)
        x86_proc_vma_consider(
            after, snapshot, &found, USER_STACK_BASE,
            memory->user_stack_top, 0x00010001u, 0, 0,
            KERNEL_PROC_MAP_READ | KERNEL_PROC_MAP_WRITE, "[stack]");
    spin_unlock_irqrestore(&g_task_lock, irq_flags);
    if (found && kernel_mm_seal_space_overlaps(
            address_space, snapshot->start,
            snapshot->end - snapshot->start))
        snapshot->flags |= KERNEL_PROC_MAP_SEALED;
    return found;
}

int arch_proc_vma_account(int32_t pid,
                          kernel_proc_vma_accounting_t *accounting) {
    uint64_t irq_flags;
    task_t *task;
    task_t *memory;
    int live;

    if (pid <= 0 || !accounting) return -1;
    irq_flags = spin_lock_irqsave(&g_task_lock);
    task = task_find_by_pid(pid);
    memory = task ? task_vm_owner_local(task) : 0;
    if (!task || !memory || task->state == TASK_UNUSED ||
        memory->state == TASK_UNUSED) {
        spin_unlock_irqrestore(&g_task_lock, irq_flags);
        return -1;
    }
    memset(accounting, 0, sizeof(*accounting));
    live = process_user_vma_live_count(memory);
    for (int index = 0; index < live; ++index) {
        const edge_user_vma_t *mapping = &memory->user_vmas[index];
        uint32_t flags = 0;

        if (mapping->prot & 0x1u) flags |= KERNEL_PROC_MAP_READ;
        if (mapping->prot & 0x2u) flags |= KERNEL_PROC_MAP_WRITE;
        if (mapping->prot & 0x4u) flags |= KERNEL_PROC_MAP_EXEC;
        if (mapping->flags & USER_MAP_SHARED_FLAG)
            flags |= KERNEL_PROC_MAP_SHARED;
        kernel_proc_vma_account_mapping(
            accounting, mapping->start, mapping->end, flags, 0);
    }
    if (memory->user_brk > memory->user_heap_base)
        kernel_proc_vma_account_mapping(
            accounting, memory->user_heap_base,
            (memory->user_brk + USER_PAGE_SIZE - 1u) &
                ~(USER_PAGE_SIZE - 1u),
            KERNEL_PROC_MAP_READ | KERNEL_PROC_MAP_WRITE, 0);
    if (memory->user_stack_top > USER_STACK_BASE)
        kernel_proc_vma_account_mapping(
            accounting, USER_STACK_BASE, memory->user_stack_top,
            KERNEL_PROC_MAP_READ | KERNEL_PROC_MAP_WRITE, 1);
    spin_unlock_irqrestore(&g_task_lock, irq_flags);
    return 0;
}

int arch_proc_vma_residency(int32_t pid, uint64_t start, uint64_t end,
                            kernel_proc_vma_residency_t *residency) {
    uint64_t irq_flags;
    task_t *task;
    task_t *memory;

    if (pid <= 0 || !residency || end <= start) return -1;
    memset(residency, 0, sizeof(*residency));
    start &= ~(USER_PAGE_SIZE - 1u);
    if (end > UINT64_MAX - (USER_PAGE_SIZE - 1u)) return -1;
    end = (end + USER_PAGE_SIZE - 1u) & ~(USER_PAGE_SIZE - 1u);
    irq_flags = spin_lock_irqsave(&g_task_lock);
    task = task_find_by_pid(pid);
    memory = task ? task_vm_owner_local(task) : 0;
    if (!task || !memory || task->state == TASK_UNUSED ||
        memory->state == TASK_UNUSED) {
        spin_unlock_irqrestore(&g_task_lock, irq_flags);
        return -1;
    }
    for (uint64_t address = start; address < end;
         address += USER_PAGE_SIZE) {
        uint64_t pte = x86_proc_pte_for_task(memory, address);
        uint64_t swap_entry;

        if (pte & PAGE_PRESENT) {
            uint32_t aliases = 1u;
            int backing_index = sparse_mmap_backing_index_from_phys(
                pte & UINT64_C(0x000ffffffffff000));

            if (backing_index >= 0) {
                uint64_t backing_flags = spin_lock_irqsave(
                    &g_user_mmap_backing_lock);
                aliases = g_user_mmap_backing_user_aliases[backing_index];
                spin_unlock_irqrestore(
                    &g_user_mmap_backing_lock, backing_flags);
                if (!aliases) aliases = 1u;
            }
            ++residency->resident_pages;
            if (kernel_mm_lock_space_contains(memory->cr3, address))
                ++residency->locked_resident_pages;
            if (aliases > 1u) ++residency->shared_resident_pages;
            residency->proportional_resident_bytes +=
                USER_PAGE_SIZE / aliases;
            continue;
        }
        if (edge_swap_map_acquire(
                memory->cr3, address, &swap_entry) == 0) {
            uint32_t references = swap_entry_references(swap_entry);

            ++residency->swapped_pages;
            if (references > 1u) --references;
            if (!references) references = 1u;
            residency->proportional_swapped_bytes +=
                USER_PAGE_SIZE / references;
            swap_release_entry(swap_entry);
        }
    }
    spin_unlock_irqrestore(&g_task_lock, irq_flags);
    return 0;
}

int process_exec_de_thread_current(void) {
    task_t *current = process_current_task();
    int thread_group;

    if (!current || !process_task_live(current)) return -1;
    thread_group = process_tgid_of_task(current);
    if (thread_group <= 0) return -1;

    /*
     * Linux exec replaces one process image, not one pthread image. Other
     * CLONE_THREAD members must be gone before the shared mm is rebuilt, or a
     * peer can resume in the new address space at an instruction from the old
     * executable. EdgeOS currently keeps the group leader as the exec caller;
     * validate that invariant before changing any task state.
     */
    if (thread_group != current->pid) return -1;

    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *peer = &g_tasks[index];
        if (peer == current || !process_task_live(peer) ||
            process_tgid_of_task(peer) != thread_group)
            continue;
        process_finish_task_exit(peer, 0, "exec-thread", 0);
    }
    current->tgid = current->pid;
    return 0;
}

int process_prepare_exec_current(void) {
    task_t *cur = process_current_task();
    int old_vm_owner_pid;
    const int trace_exec_prepare = 0;
    if (!cur) return -1;
    if (task_index(cur) >= USER_AS_MAX_TASKS) return -1;
    if (trace_exec_prepare && cur->pid > 0 && cur->pid <= 2) {
        proc_trace_puts("[exec-prepare] enter pid=");
        proc_trace_dec(cur->pid);
        proc_trace_puts(" vm_owner=");
        proc_trace_dec(cur->vm_owner_pid);
        proc_trace_puts(" cr3=");
        proc_trace_hex(cur->cr3);
        proc_trace_puts("\n");
    }

    old_vm_owner_pid = cur->vm_owner_pid;
    /*
     * execve() always installs a fresh mm for the calling task.  If the caller
     * is a CLONE_VM child, detach it from the old owner before resetting mmap
     * state.  process_user_mmap_reset() intentionally resolves through the mm
     * owner; doing this in the old order let an execing GTK/XFCE helper tear
     * down its parent's low sparse mmap roots and then later fault through the
     * supervisor 1 GiB identity map at normal Linux mmap addresses such as
     * 0xb0xxxxxx.  That showed up as crashes in fontconfig/tumbler/panel string
     * lookups after startxfce4.
     */
    if (old_vm_owner_pid > 0 && old_vm_owner_pid != cur->pid) {
        uint64_t rflags;
        uint64_t old_cr3 = backing_access_enter(&rflags);
        (void)old_cr3;
        if (trace_exec_prepare && cur->pid > 0 && cur->pid <= 2) {
            proc_trace_puts("[exec-prepare] detach-vm pid=");
            proc_trace_dec(cur->pid);
            proc_trace_puts(" old_cr3=");
            proc_trace_hex(old_cr3);
            proc_trace_puts(" flags=");
            proc_trace_hex(rflags);
            proc_trace_puts("\n");
        }
        /*
         * task_build_address_space() rewrites the task's PML4/PDPT arrays.  On
         * exec of a normal process those arrays are the active CR3, so edit them
         * only after switching to the kernel CR3.  Then enter the freshly built
         * user CR3 before elf_loader_exec()/user_exec_run() populate the new
         * image and initial stack.
         */
        /*
         * execve creates a new mm before destroying the old image.  Detach the
         * task first so every helper reached by task_build_address_space(), in
         * particular process_user_mmap_reset_internal(), resolves to this task
         * slot instead of clearing the former owner's live sparse roots.
         */
        cur->vm_owner_pid = cur->pid;
        cur->cr3 = 0;
        task_clear_user_regions(cur);
        if (trace_exec_prepare && cur->pid > 0 && cur->pid <= 2) proc_trace_puts("[exec-prepare] cleared\n");
        if (task_build_address_space(cur, 1) < 0) {
            printf("[exec-fail] address-space build pid=%d name=%s\n",
                   cur->pid, cur->name[0] ? cur->name : "?");
            scheduler_kill_current_and_yield(127);
            return -1;
        }
        if (trace_exec_prepare && cur->pid > 0 && cur->pid <= 2) proc_trace_puts("[exec-prepare] rebuilt\n");
        cr3_write(cur->cr3);
        /*
         * Do not restore IF here.  Linux syscall entry keeps interrupts under
         * entry/exit control, and EdgeOS' syscall dispatcher relies on the same
         * invariant while REGISTERS is live on the kernel stack.  Re-enabling
         * IRQs during exec allowed timer/preemption paths to run after CR3 had
         * been rewritten but before the syscall frame was complete, which reset
         * Alpine PID1's vfork/exec child while launching /sbin/openrc.
         */
    } else {
        uint64_t rflags;
        uint64_t old_cr3 = backing_access_enter(&rflags);
        (void)old_cr3;
        kernel_sysv_shm_address_space_release(
            (uintptr_t)cur, process_tgid_of_task(cur));
        if (trace_exec_prepare && cur->pid > 0 && cur->pid <= 2) {
            proc_trace_puts("[exec-prepare] same-vm pid=");
            proc_trace_dec(cur->pid);
            proc_trace_puts(" old_cr3=");
            proc_trace_hex(old_cr3);
            proc_trace_puts(" flags=");
            proc_trace_hex(rflags);
            proc_trace_puts("\n");
        }
        /*
         * The ELF loader writes PT_LOAD segments through their Linux user
         * virtual addresses.  Once fixed executable windows use 4 KiB PTEs for
         * Linux mprotect(2) semantics, exec must rebuild those PTEs before the
         * first copy to addresses such as 0x400000.  Do this under the kernel
         * CR3 for the same reason as CLONE_VM exec above: task_build_address_space()
         * edits the PML4/PDPT currently referenced by cur->cr3.
         */
        task_clear_user_regions(cur);
        if (trace_exec_prepare && cur->pid > 0 && cur->pid <= 2) proc_trace_puts("[exec-prepare] cleared\n");
        if (task_build_address_space(cur, 1) < 0) {
            printf("[exec-fail] address-space build pid=%d name=%s\n",
                   cur->pid, cur->name[0] ? cur->name : "?");
            scheduler_kill_current_and_yield(127);
            return -1;
        }
        if (trace_exec_prepare && cur->pid > 0 && cur->pid <= 2) proc_trace_puts("[exec-prepare] rebuilt\n");
        cr3_write(cur->cr3);
        /*
         * Keep IRQs masked until syscall return; see the CLONE_VM branch above.
         */
    }
    cur->vm_owner_pid = cur->pid;
    cur->user_stack_top = USER_STACK_TOP;
    cur->user_heap_base = USER_HEAP_BASE;
    cur->user_brk = USER_HEAP_BASE;
    cur->user_heap_limit = USER_HEAP_BASE + USER_HEAP_DEFAULT_DELTA;
    cur->user_mmap_next = USER_MMAP_BASE;
    task_clear_user_vmas(cur);
    cur->user_vma_refs_owned = 1;
    if (trace_exec_prepare && cur->pid > 0 && cur->pid <= 2) {
        proc_trace_puts("[exec-prepare] done pid=");
        proc_trace_dec(cur->pid);
        proc_trace_puts(" cr3=");
        proc_trace_hex(cur->cr3);
        proc_trace_puts("\n");
    }
    return 0;
}

int process_exec_reset_current(
    const kernel_exec_reset_configuration_t *configuration) {
    task_t *cur = process_current_task();

    if (!cur || !configuration) return -1;
    if (configuration->detach_signal_handlers)
        cur->sighand_context_id = task_sighand_context_alloc();
    if (configuration->reset_signal_dispositions) {
        for (uint32_t signal = 1;
             signal <= EDGE_LINUX_SIGNAL_MAX; ++signal) {
            edge_linux_signal_action_t *action =
                &cur->signal_actions[signal - 1u];
            uint64_t handler = action->handler;
            memset(action, 0, sizeof(*action));
            if (handler == LINUX_SIG_IGN)
                action->handler = LINUX_SIG_IGN;
        }
    }
    cur->seccomp_sigsys_valid = 0;
    cur->seccomp_notification_id = 0;
    cur->sig_stub_installed = 0;
    cur->active_signal_frame = 0;
    cur->active_signal_restorer_rsp = 0;
    if (configuration->disable_signal_altstack) {
        cur->sigaltstack_sp = 0;
        cur->sigaltstack_size = 0;
        cur->sigaltstack_flags = EDGE_LINUX_SS_DISABLE;
    }
    cur->signal_saved_mask = 0;
    cur->signal_restore_mask_pending = 0;
    if (configuration->reset_thread_state)
        kernel_linux_thread_state_exec(&cur->linux_thread);
    if (configuration->reset_membarrier)
        cur->membarrier_registrations = 0;
    if (configuration->reset_floating_point) {
        task_init_default_fx(cur);
        fxrstor_region(cur->fxsave_region);
    }
    if (configuration->reset_architecture_tls) {
        cur->fs_base = 0;
        cur->gs_base = 0;
        process_x86_ldt_reset(cur);
        edgeos_x86_64_set_fs_base(0);
        edgeos_x86_64_set_user_gs_base(0);
    }
    return 0;
}

void process_exec_wake_vfork_parent_current(void) {
    process_wake_vfork_parent(process_current_task());
}

int process_set_fs_base(uint64_t base) {
    task_t *cur = process_current_task();
    if (!cur) return -1;
    cur->fs_base = base;
    edgeos_x86_64_set_fs_base(base);
    return 0;
}

uint64_t process_get_fs_base(void) {
    task_t *cur = process_current_task();
    if (!cur) return 0;
    return cur->fs_base;
}

int process_set_gs_base(uint64_t base) {
    task_t *cur = process_current_task();
    if (!cur) return -1;
    cur->gs_base = base;
    edgeos_x86_64_set_user_gs_base(base);
    return 0;
}

uint64_t process_get_gs_base(void) {
    task_t *cur = process_current_task();
    if (!cur) return 0;
    return cur->gs_base;
}

#define EDGE_X86_LDT_ENTRY_COUNT 8192u
#define EDGE_X86_LDT_BYTE_COUNT \
    (EDGE_X86_LDT_ENTRY_COUNT * (uint32_t)sizeof(uint64_t))

static int process_x86_ldt_allocate_locked(task_t *owner) {
    void *memory = 0;
    uint64_t physical = 0;
    uint32_t pages;

    if (!owner) return -1;
    if (owner->x86_ldt_entries &&
        owner->x86_ldt_capacity == EDGE_X86_LDT_ENTRY_COUNT)
        return 0;
    pages = (EDGE_X86_LDT_BYTE_COUNT + USER_PAGE_SIZE - 1u) /
            USER_PAGE_SIZE;
    if (process_kernel_runtime_alloc_pages(
            pages, &memory, &physical) < 0 || !memory)
        return -1;
    (void)physical;
    owner->x86_ldt_entries = (uint64_t *)memory;
    owner->x86_ldt_capacity = EDGE_X86_LDT_ENTRY_COUNT;
    owner->x86_ldt_nr_entries = 0;
    return 0;
}

static void process_x86_ldt_refresh_online_cpus(void) {
    edge_cpumask_t online;

    edge_smp_online_mask(&online);
    (void)edge_smp_call(&online, EDGE_SMP_CALL_ARCH_MM_REFRESH);
}

int process_x86_ldt_snapshot(task_t *task, void *buffer,
                             uint32_t byte_count) {
    task_t *owner = task_vm_owner_local(task);
    uint32_t stored_bytes;
    uint64_t flags;

    if (!owner || (!buffer && byte_count) ||
        byte_count > EDGE_X86_LDT_BYTE_COUNT)
        return -1;
    flags = spin_lock_irqsave(&owner->x86_ldt_lock);
    if (!owner->x86_ldt_entries || !owner->x86_ldt_nr_entries) {
        spin_unlock_irqrestore(&owner->x86_ldt_lock, flags);
        return 0;
    }
    memset(buffer, 0, byte_count);
    stored_bytes = owner->x86_ldt_nr_entries * sizeof(uint64_t);
    if (stored_bytes > byte_count) stored_bytes = byte_count;
    memcpy(buffer, owner->x86_ldt_entries, stored_bytes);
    spin_unlock_irqrestore(&owner->x86_ldt_lock, flags);
    return (int)byte_count;
}

int process_x86_ldt_write(task_t *task, uint32_t entry,
                          uint64_t descriptor) {
    task_t *owner = task_vm_owner_local(task);
    uint64_t flags;

    if (!owner || entry >= EDGE_X86_LDT_ENTRY_COUNT) return -1;
    flags = spin_lock_irqsave(&owner->x86_ldt_lock);
    if (process_x86_ldt_allocate_locked(owner) < 0) {
        spin_unlock_irqrestore(&owner->x86_ldt_lock, flags);
        return -1;
    }
    owner->x86_ldt_entries[entry] = descriptor;
    if (owner->x86_ldt_nr_entries <= entry)
        owner->x86_ldt_nr_entries = entry + 1u;
    spin_unlock_irqrestore(&owner->x86_ldt_lock, flags);
    process_x86_ldt_refresh_online_cpus();
    return 0;
}

int process_x86_ldt_clone(task_t *destination, const task_t *source) {
    task_t *source_owner = task_vm_owner_local((task_t *)source);
    uint64_t flags;

    if (!destination || !source_owner) return -1;
    flags = spin_lock_irqsave(&source_owner->x86_ldt_lock);
    if (!source_owner->x86_ldt_entries ||
        !source_owner->x86_ldt_nr_entries) {
        spin_unlock_irqrestore(&source_owner->x86_ldt_lock, flags);
        return 0;
    }
    if (process_x86_ldt_allocate_locked(destination) < 0) {
        spin_unlock_irqrestore(&source_owner->x86_ldt_lock, flags);
        return -1;
    }
    memcpy(destination->x86_ldt_entries, source_owner->x86_ldt_entries,
           (uint64_t)source_owner->x86_ldt_nr_entries * sizeof(uint64_t));
    destination->x86_ldt_nr_entries = source_owner->x86_ldt_nr_entries;
    spin_unlock_irqrestore(&source_owner->x86_ldt_lock, flags);
    return 0;
}

void process_x86_ldt_reset(task_t *task) {
    task_t *owner = task_vm_owner_local(task);
    uint64_t flags;

    if (!owner) return;
    flags = spin_lock_irqsave(&owner->x86_ldt_lock);
    if (owner->x86_ldt_entries && owner->x86_ldt_capacity)
        memset(owner->x86_ldt_entries, 0,
               (uint64_t)owner->x86_ldt_capacity * sizeof(uint64_t));
    owner->x86_ldt_nr_entries = 0;
    spin_unlock_irqrestore(&owner->x86_ldt_lock, flags);
    process_x86_ldt_refresh_online_cpus();
}

void process_x86_ldt_activate(task_t *task) {
    task_t *owner = task_vm_owner_local(task);
    const uint64_t *entries = 0;
    uint32_t count = 0;
    uint64_t flags;

    if (!owner) {
        gdt_load_ldt(0, 0);
        return;
    }
    flags = spin_lock_irqsave(&owner->x86_ldt_lock);
    if (owner->x86_ldt_entries && owner->x86_ldt_nr_entries) {
        entries = owner->x86_ldt_entries;
        count = owner->x86_ldt_capacity;
    }
    gdt_load_ldt(entries, count);
    spin_unlock_irqrestore(&owner->x86_ldt_lock, flags);
}

uint32_t process_getuid(void) {
    task_t *cur = process_current_task();
    return cur ? cur->uid : 0;
}

uint32_t process_getgid(void) {
    task_t *cur = process_current_task();
    return cur ? cur->gid : 0;
}

uint32_t process_geteuid(void) {
    task_t *cur = process_current_task();
    return cur ? cur->euid : 0;
}

uint32_t process_getegid(void) {
    task_t *cur = process_current_task();
    return cur ? cur->egid : 0;
}

void process_apply_exec_file_creds(uint16_t mode, uint32_t file_uid,
                                   uint32_t file_gid,
                                   uint32_t mount_flags) {
    task_apply_exec_file_creds(process_current_task(), mode, file_uid,
                               file_gid, mount_flags);
}

int process_getpgid(int pid) {
    task_t *cur = process_current_task();
    task_t *t;
    if (!cur) return -1;
    if (pid == 0) pid = cur->pid;
    t = task_find_by_pid(pid);
    if (!t) return -1;
    return t->pgid;
}

int process_getsid(int pid) {
    task_t *cur = process_current_task();
    task_t *t;
    if (!cur) return -1;
    if (pid == 0) pid = cur->pid;
    t = task_find_by_pid(pid);
    if (!t) return -1;
    return t->sid;
}

int process_kill_pgid(int pgid, int code) {
    int pids[PROC_MAX_TASKS];
    int npids = 0;
    int killed = 0;
    if (pgid <= 0) return -1;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (t->state == TASK_UNUSED) continue;
        if (t->pid == 1) continue;
        if (t->pgid != pgid) continue;
        if (npids < PROC_MAX_TASKS) pids[npids++] = t->pid;
    }
    for (int i = 0; i < npids; ++i) {
        if (process_kill_pid(pids[i], code) == 0) killed++;
    }
    return killed > 0 ? 0 : -1;
}

static task_t *process_signal_group_leader(task_t *task) {
    task_t *leader;
    if (!task) return 0;
    leader = task_find_by_pid(process_tgid_of_task(task));
    return leader ? leader : task;
}

static void process_signal_continue_group(task_t *target) {
    int tgid = process_tgid_of_task(target);
    uint64_t stop_mask =
        edge_linux_signal_mask_bit(EDGE_LINUX_SIGSTOP) |
        edge_linux_signal_mask_bit(EDGE_LINUX_SIGTSTP) |
        edge_linux_signal_mask_bit(EDGE_LINUX_SIGTTIN) |
        edge_linux_signal_mask_bit(EDGE_LINUX_SIGTTOU);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *peer = &g_tasks[index];
        if (peer->state == TASK_UNUSED || peer->state == TASK_ZOMBIE ||
            process_tgid_of_task(peer) != tgid)
            continue;
        peer->signal_pending &= ~stop_mask;
        peer->signal_shared_pending &= ~stop_mask;
        if (peer->state == TASK_STOPPED && peer->ptrace.tracer_pid > 0 &&
            peer->ptrace.stop_reason != EDGE_LINUX_PTRACE_STOP_NONE) {
            peer->ptrace.group_stop_continue_pending = 1;
            continue;
        }
        if (peer->state == TASK_STOPPED) {
            peer->stop_signal = 0;
            peer->stop_reported = 0;
            peer->continued_pending = 1;
            scheduler_task_make_runnable(
                peer, peer->assigned_cpu >= 0 ?
                    (uint32_t)peer->assigned_cpu : scheduler_cpu_id());
            process_notify_waiter_for_task(peer);
        }
    }
}

/* Returns one when a pending record was installed and zero when discarded. */
static int process_signal_mark_pending(task_t *target, int signal,
                                       int thread_directed) {
    task_t *leader;
    task_t *wake_target;
    edge_linux_signal_action_t *action;
    edge_linux_signal_default_disposition_t disposition;
    uint64_t bit;
    if (!target || target->state == TASK_UNUSED ||
        target->state == TASK_ZOMBIE ||
        !edge_linux_signal_valid((uint32_t)signal))
        return -1;
    leader = process_signal_group_leader(target);
    /*
     * The leader can be a waitable zombie while another thread in its group
     * remains live.  Its signal actions and shared-pending word continue to
     * own the process-wide state until the final thread exits.
     */
    if (!leader || leader->state == TASK_UNUSED)
        return -1;
    action = &leader->signal_actions[signal - 1];
    disposition = edge_linux_signal_default_disposition((uint32_t)signal);
    bit = edge_linux_signal_mask_bit((uint32_t)signal);

    wake_target = target;
    if (!thread_directed) {
        wake_target = leader;
        for (int index = 0; index < PROC_MAX_TASKS; ++index) {
            task_t *peer = &g_tasks[index];
            if (peer->state == TASK_UNUSED || peer->state == TASK_ZOMBIE ||
                process_tgid_of_task(peer) != process_tgid_of_task(leader))
                continue;
            if (!(peer->sigmask & bit)) {
                wake_target = peer;
                break;
            }
        }
    }

    if (signal == LINUX_SIGCONT) process_signal_continue_group(target);
    if (action->handler == LINUX_SIG_IGN &&
        signal != LINUX_SIGKILL && signal != LINUX_SIGSTOP)
        return 0;
    if (action->handler == LINUX_SIG_DFL &&
        (disposition == EDGE_LINUX_SIGNAL_DEFAULT_IGNORE ||
         disposition == EDGE_LINUX_SIGNAL_DEFAULT_CONTINUE) &&
        !(wake_target->sigmask & bit))
        return 0;

    if (signal == LINUX_SIGSTOP || signal == LINUX_SIGTSTP ||
        signal == LINUX_SIGTTIN || signal == LINUX_SIGTTOU) {
        uint64_t continue_bit =
            edge_linux_signal_mask_bit(EDGE_LINUX_SIGCONT);
        target->signal_pending &= ~continue_bit;
        leader->signal_shared_pending &= ~continue_bit;
    }

    if (thread_directed) {
        target->signal_pending |= bit;
    } else {
        leader->signal_shared_pending |= bit;
    }
    if (wake_target->state == TASK_BLOCKED ||
        (signal == LINUX_SIGKILL && wake_target->state == TASK_STOPPED)) {
        scheduler_task_make_runnable(
            wake_target, wake_target->assigned_cpu >= 0 ?
                (uint32_t)wake_target->assigned_cpu : scheduler_cpu_id());
    }
    return 1;
}

static int process_signal_send_info_internal(
    task_t *task, int signal, int thread_directed,
    const void *signal_information) {
    return kernel_linux_signal_send(
        task ? task->pid : 0, (uint32_t)signal, thread_directed,
        signal_information);
}

static int process_signal_one(task_t *task, int signal) {
    return process_signal_mark_pending(task, signal, 0) < 0 ? -1 : 0;
}

int process_send_signal(int pid, int sig) {
    task_t *t;
    if (pid <= 0) return -1;
    t = task_find_by_pid(pid);
    if (!t) return -1;
    return process_signal_one(t, sig);
}

int process_send_signal_thread(int pid, int sig) {
    task_t *task;
    if (pid <= 0) return -1;
    task = task_find_by_pid(pid);
    if (!task) return -1;
    return process_signal_mark_pending(task, sig, 1) < 0 ? -1 : 0;
}

int process_send_signal_info(int pid, int sig, const void *signal_info) {
    task_t *task;
    if (pid <= 0 || sig <= 0 || sig > 64 || !signal_info) return -1;
    task = task_find_by_pid(pid);
    if (!task) return -1;
    return process_signal_send_info_internal(task, sig, 1, signal_info);
}

int process_send_signal_pgid(int pgid, int sig) {
    int tgids[PROC_MAX_TASKS];
    int ntgids = 0;
    int delivered = 0;
    if (pgid <= 0) return -1;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = &g_tasks[i];
        if (t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) continue;
        if (t->pgid != pgid) continue;
        int tgid = process_tgid_of_task(t);
        int seen = 0;
        for (int index = 0; index < ntgids; ++index) {
            if (tgids[index] == tgid) {
                seen = 1;
                break;
            }
        }
        if (seen) continue;
        tgids[ntgids++] = tgid;
        if (process_signal_one(t, sig) == 0) delivered++;
    }
    return delivered > 0 ? 0 : -1;
}

int process_send_signal_pgid_info(int pgid, int sig,
                                  const void *signal_info) {
    int tgids[PROC_MAX_TASKS];
    int ntgids = 0;
    int delivered = 0;
    if (pgid <= 0 || sig <= 0 || sig > 64 || !signal_info) return -1;
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *task = &g_tasks[index];
        if (task->state == TASK_UNUSED || task->state == TASK_ZOMBIE ||
            task->pgid != pgid)
            continue;
        int tgid = process_tgid_of_task(task);
        int seen = 0;
        for (int seen_index = 0; seen_index < ntgids; ++seen_index) {
            if (tgids[seen_index] == tgid) {
                seen = 1;
                break;
            }
        }
        if (seen) continue;
        tgids[ntgids++] = tgid;
        if (process_signal_send_info_internal(
                task, sig, 0, signal_info) == 0)
            ++delivered;
    }
    return delivered > 0 ? 0 : -1;
}

void process_stop_current_group(int signal) {
    task_t *current = process_current_task();
    int group;
    if (!current || signal <= 0 || signal > (int)EDGE_LINUX_SIGNAL_MAX)
        return;
    group = process_tgid_of_task(current);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        task_t *task = &g_tasks[index];
        if (task->state == TASK_UNUSED || task->state == TASK_ZOMBIE ||
            process_tgid_of_task(task) != group)
            continue;
        if (task->ptrace.tracer_pid > 0 &&
            task->ptrace.stop_reason != EDGE_LINUX_PTRACE_STOP_NONE)
            continue;
        task->stop_signal = (uint8_t)signal;
        task->stop_reported = 0;
        task->continued_pending = 0;
        scheduler_task_set_stopped(task);
        process_notify_waiter_for_task(task);
    }
}

typedef struct edge_x86_64_linux_user_regs {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t orig_rax;
    uint64_t rip;
    uint64_t cs;
    uint64_t eflags;
    uint64_t rsp;
    uint64_t ss;
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t ds;
    uint64_t es;
    uint64_t fs;
    uint64_t gs;
} edge_x86_64_linux_user_regs_t;

_Static_assert(sizeof(edge_x86_64_linux_user_regs_t) == 216,
               "Linux x86_64 ptrace register layout");

static edge_trap_frame_t *process_ptrace_frame(task_t *task) {
    if (!task) return 0;
    if (task->ptrace_live_frame)
        return (edge_trap_frame_t *)(uintptr_t)task->ptrace_live_frame;
    if (task->state == TASK_STOPPED) return &task->ptrace_frame;
    return &task->fork_tf;
}

static void process_ptrace_export_regs(
    const task_t *task, const edge_trap_frame_t *frame,
    edge_x86_64_linux_user_regs_t *registers) {
    if (!task || !frame || !registers) return;
    memset(registers, 0, sizeof(*registers));
    registers->r15 = frame->r15;
    registers->r14 = frame->r14;
    registers->r13 = frame->r13;
    registers->r12 = frame->r12;
    registers->rbp = frame->rbp;
    registers->rbx = frame->rbx;
    registers->r11 = frame->r11;
    registers->r10 = frame->r10;
    registers->r9 = frame->r9;
    registers->r8 = frame->r8;
    registers->rax = frame->rax;
    registers->rcx = frame->rcx;
    registers->rdx = frame->rdx;
    registers->rsi = frame->rsi;
    registers->rdi = frame->rdi;
    registers->orig_rax = task->ptrace.syscall_number;
    registers->rip = frame->rip;
    registers->cs = frame->cs;
    registers->eflags = frame->rflags;
    registers->rsp = frame->rsp;
    registers->ss = frame->ss;
    registers->fs_base = task->fs_base;
    registers->gs_base = task->gs_base;
}

static void process_ptrace_import_regs(
    task_t *task, edge_trap_frame_t *frame,
    const edge_x86_64_linux_user_regs_t *registers) {
    const uint64_t user_rflags_mask = 0x0000000000254dd5ULL;
    if (!task || !frame || !registers) return;
    frame->r15 = registers->r15;
    frame->r14 = registers->r14;
    frame->r13 = registers->r13;
    frame->r12 = registers->r12;
    frame->rbp = registers->rbp;
    frame->rbx = registers->rbx;
    frame->r11 = registers->r11;
    frame->r10 = registers->r10;
    frame->r9 = registers->r9;
    frame->r8 = registers->r8;
    frame->rax = registers->rax;
    frame->rcx = registers->rcx;
    frame->rdx = registers->rdx;
    frame->rsi = registers->rsi;
    frame->rdi = registers->rdi;
    frame->rip = registers->rip;
    frame->rsp = registers->rsp;
    frame->cs = USER_CS;
    frame->ss = USER_DS;
    frame->rflags = (frame->rflags & ~user_rflags_mask) |
                    (registers->eflags & user_rflags_mask) | 2ULL;
    task->fs_base = registers->fs_base;
    task->gs_base = registers->gs_base;
    task->ptrace.syscall_number = registers->orig_rax;
}

int arch_ptrace_attach(int32_t pid, int seized) {
    task_t *task = task_find_by_pid(pid);
    if (!task) return -EDGE_LINUX_ESRCH;
    if (seized) return 0;
    /*
     * PTRACE_ATTACH is asynchronous.  Queue the unmaskable stop on the exact
     * target thread and let its syscall/interrupt return path capture the live
     * user frame.  Stopping a remote CPU here would race that CPU and preserve
     * either a stale fork frame or a kernel-stack frame that it still owns.
     */
    if (process_signal_mark_pending(task, LINUX_SIGSTOP, 1) < 0) {
        edge_linux_ptrace_state_reset(&task->ptrace);
        return -EDGE_LINUX_ESRCH;
    }
    return 0;
}

int arch_ptrace_attach_child(int32_t pid, int seized) {
    task_t *task = task_find_by_pid(pid);
    edge_linux_ptrace_stop_t stop;
    edge_trap_frame_t *live;
    if (!task) return -EDGE_LINUX_ESRCH;
    live = process_ptrace_frame(task);
    if (live && live != &task->ptrace_frame) task->ptrace_frame = *live;
    memset(&stop, 0, sizeof(stop));
    stop.reason = seized ? EDGE_LINUX_PTRACE_STOP_INTERRUPT :
                           EDGE_LINUX_PTRACE_STOP_SIGNAL;
    stop.signal = seized ? EDGE_LINUX_PTRACE_SIGTRAP :
                           EDGE_LINUX_PTRACE_SIGSTOP;
    stop.event = seized ? EDGE_LINUX_PTRACE_EVENT_STOP : 0u;
    stop.instruction_pointer = task->ptrace_frame.rip;
    stop.stack_pointer = task->ptrace_frame.rsp;
    edge_linux_ptrace_state_record_stop(&task->ptrace, &stop);
    task->stop_signal = (uint8_t)stop.signal;
    /* The parent event must become visible before this initial child stop. */
    task->stop_reported = 1;
    scheduler_task_set_stopped(task);
    return 0;
}

static void process_ptrace_publish_event_child(task_t *parent) {
    task_t *child;
    uint8_t event;
    if (!parent) return;
    event = parent->ptrace.stop_event;
    if (event != EDGE_LINUX_PTRACE_EVENT_FORK &&
        event != EDGE_LINUX_PTRACE_EVENT_VFORK &&
        event != EDGE_LINUX_PTRACE_EVENT_CLONE)
        return;
    child = task_find_by_pid((int32_t)parent->ptrace.event_message);
    if (!child || child->ptrace.tracer_pid != parent->ptrace.tracer_pid ||
        child->state != TASK_STOPPED)
        return;
    child->stop_reported = 0;
    process_notify_waiter_for_task(child);
}

int arch_ptrace_detach(int32_t pid, uint32_t signal) {
    task_t *task = task_find_by_pid(pid);
    edge_trap_frame_t *live;
    if (!task) return -EDGE_LINUX_ESRCH;
    live = task->ptrace_live_frame ?
        (edge_trap_frame_t *)(uintptr_t)task->ptrace_live_frame : 0;
    if (live) *live = task->ptrace_frame;
    task->stop_signal = 0;
    task->stop_reported = 0;
    scheduler_task_make_runnable(
        task, task->assigned_cpu >= 0 ? (uint32_t)task->assigned_cpu :
                                       scheduler_cpu_id());
    if (signal) (void)process_signal_one(task, (int)signal);
    return 0;
}

int arch_ptrace_resume(int32_t pid,
                       edge_linux_ptrace_resume_mode_t mode,
                       uint32_t signal) {
    task_t *task = task_find_by_pid(pid);
    edge_linux_ptrace_signal_resume_action_t signal_action;
    kernel_signal_runtime_state_t signal_state;
    edge_trap_frame_t *frame;
    edge_linux_ptrace_stop_t deferred_stop;
    uint8_t continue_delivery;
    uint8_t group_stop_signal;
    if (!task) return -EDGE_LINUX_ESRCH;
    edge_linux_ptrace_signal_resume_action(
        &task->ptrace, signal, &signal_action);
    continue_delivery = task->ptrace.group_stop_continue_delivery;
    group_stop_signal = task->ptrace.group_stop_signal;
    task->ptrace.resume_mode = (uint8_t)mode;
    task->ptrace.injected_signal = (uint8_t)signal;
    task->ptrace.suppress_signal_stop = signal_action.suppress_signal_stop;
    if (signal_action.consume_signal &&
        kernel_arch_signal_runtime_state(task, &signal_state) == 0)
        (void)kernel_signal_pending_consume(
            &signal_state, signal_action.consume_signal, 0, 0);
    if (signal_action.inject_signal)
        (void)process_signal_mark_pending(
            task, (int)signal_action.inject_signal, 1);
    if (mode != EDGE_LINUX_PTRACE_RESUME_SYSCALL)
        task->ptrace.syscall_active = 0;
    process_ptrace_publish_event_child(task);
    if (mode == EDGE_LINUX_PTRACE_RESUME_LISTEN) {
        task->ptrace.stop_reason = EDGE_LINUX_PTRACE_STOP_NONE;
        task->ptrace.stop_signal = 0;
        task->ptrace.stop_event = 0;
        task->ptrace.syscall_info_op = 0;
        task->ptrace.signal_info_valid = 0;
        task->stop_reported = 1;
        if (task->ptrace.interrupt_pending) {
            task->ptrace.interrupt_pending = 0;
            memset(&deferred_stop, 0, sizeof(deferred_stop));
            deferred_stop.reason = EDGE_LINUX_PTRACE_STOP_INTERRUPT;
            deferred_stop.signal = LINUX_SIGTRAP;
            deferred_stop.event = EDGE_LINUX_PTRACE_EVENT_STOP;
            deferred_stop.instruction_pointer = task->ptrace_frame.rip;
            deferred_stop.stack_pointer = task->ptrace_frame.rsp;
            edge_linux_ptrace_state_record_stop(&task->ptrace,
                                                &deferred_stop);
            task->stop_signal = LINUX_SIGTRAP;
            task->stop_reported = 0;
            process_notify_waiter_for_task(task);
        }
        return 0;
    }
    task->stop_signal = 0;
    task->stop_reported = 0;
    task->ptrace.stop_reason = EDGE_LINUX_PTRACE_STOP_NONE;
    task->ptrace.stop_signal = 0;
    task->ptrace.stop_event = 0;
    task->ptrace.syscall_info_op = 0;
    task->ptrace.signal_info_valid = 0;
    if (continue_delivery) {
        task->ptrace.group_stop_continue_delivery = 0;
        if (!signal) {
            task->stop_signal = group_stop_signal;
            task->stop_reported = 1;
            return 0;
        }
        task->ptrace.group_stop_signal = 0;
    } else if (task->ptrace.group_stop_continue_pending) {
        task->ptrace.group_stop_continue_pending = 0;
        task->ptrace.group_stop_continue_delivery = 1;
        memset(&deferred_stop, 0, sizeof(deferred_stop));
        deferred_stop.reason = EDGE_LINUX_PTRACE_STOP_SIGNAL;
        deferred_stop.signal = LINUX_SIGCONT;
        deferred_stop.instruction_pointer = task->ptrace_frame.rip;
        deferred_stop.stack_pointer = task->ptrace_frame.rsp;
        edge_linux_ptrace_state_record_stop(&task->ptrace, &deferred_stop);
        edge_linux_ptrace_state_record_signal_info(
            &task->ptrace, LINUX_SIGCONT, 0, 0, 0);
        task->stop_signal = LINUX_SIGCONT;
        task->stop_reported = 0;
        process_notify_waiter_for_task(task);
        return 0;
    }
    frame = &task->ptrace_frame;
    if (mode == EDGE_LINUX_PTRACE_RESUME_SINGLESTEP)
        frame->rflags |= 1ULL << 8;
    else
        frame->rflags &= ~(1ULL << 8);
    if (task->ptrace_live_frame)
        *(edge_trap_frame_t *)(uintptr_t)task->ptrace_live_frame = *frame;
    scheduler_task_make_runnable(
        task, task->assigned_cpu >= 0 ? (uint32_t)task->assigned_cpu :
                                       scheduler_cpu_id());
    return 0;
}

int arch_ptrace_interrupt(int32_t pid) {
    task_t *task = task_find_by_pid(pid);
    edge_linux_ptrace_stop_t stop;
    edge_trap_frame_t *live;
    uint32_t stop_signal;
    int group_stopped;
    if (!task) return -EDGE_LINUX_EIO;
    group_stopped = task->state == TASK_STOPPED;
    stop_signal = group_stopped && task->stop_signal ?
        task->stop_signal : LINUX_SIGTRAP;
    if (!group_stopped) {
        task->ptrace.interrupt_pending = 1;
        if (process_signal_mark_pending(task, LINUX_SIGTRAP, 1) < 0) {
            task->ptrace.interrupt_pending = 0;
            return -EDGE_LINUX_ESRCH;
        }
        return 0;
    }
    if (group_stopped) {
        task->ptrace.interrupt_pending = 1;
        task->ptrace.group_stop_signal = (uint8_t)stop_signal;
    }
    live = process_ptrace_frame(task);
    if (live && live != &task->ptrace_frame) task->ptrace_frame = *live;
    memset(&stop, 0, sizeof(stop));
    stop.reason = EDGE_LINUX_PTRACE_STOP_INTERRUPT;
    stop.signal = stop_signal;
    stop.event = EDGE_LINUX_PTRACE_EVENT_STOP;
    stop.instruction_pointer = task->ptrace_frame.rip;
    stop.stack_pointer = task->ptrace_frame.rsp;
    edge_linux_ptrace_state_record_stop(&task->ptrace, &stop);
    task->stop_signal = (uint8_t)stop_signal;
    task->stop_reported = 0;
    scheduler_task_set_stopped(task);
    process_notify_waiter_for_task(task);
    return 0;
}

int arch_ptrace_kill(int32_t pid) {
    task_t *task = task_find_by_pid(pid);
    if (!task) return -EDGE_LINUX_ESRCH;
    task->termination_signal = LINUX_SIGKILL;
    return process_kill_pid(pid, 128 + LINUX_SIGKILL) < 0 ?
        -EDGE_LINUX_ESRCH : 0;
}

int kernel_ptrace_read_user_area(int32_t pid, uint64_t offset,
                                 uint64_t *value) {
    task_t *task = task_find_by_pid(pid);
    edge_x86_64_linux_user_regs_t registers;
    if (!task || !value || (offset & 7u) ||
        offset > sizeof(registers) - sizeof(*value))
        return -EDGE_LINUX_EIO;
    process_ptrace_export_regs(task, process_ptrace_frame(task), &registers);
    memcpy(value, (const uint8_t *)&registers + offset, sizeof(*value));
    return 0;
}

int kernel_ptrace_write_user_area(int32_t pid, uint64_t offset,
                                  uint64_t value) {
    task_t *task = task_find_by_pid(pid);
    edge_x86_64_linux_user_regs_t registers;
    edge_trap_frame_t *frame;
    if (!task || (offset & 7u) ||
        offset > sizeof(registers) - sizeof(value))
        return -EDGE_LINUX_EIO;
    frame = process_ptrace_frame(task);
    process_ptrace_export_regs(task, frame, &registers);
    memcpy((uint8_t *)&registers + offset, &value, sizeof(value));
    process_ptrace_import_regs(task, frame, &registers);
    return 0;
}

int kernel_ptrace_get_regset(int32_t pid, uint32_t note, void *buffer,
                             uint64_t *size) {
    task_t *task = task_find_by_pid(pid);
    uint64_t needed;
    if (!task || !buffer || !size) return -EDGE_LINUX_EIO;
    if (note == EDGE_LINUX_NT_PRSTATUS ||
        note == EDGE_LINUX_PTRACE_LEGACY_GPR) {
        edge_x86_64_linux_user_regs_t registers;
        needed = sizeof(registers);
        if (*size < needed) return -EDGE_LINUX_EIO;
        process_ptrace_export_regs(task, process_ptrace_frame(task),
                                   &registers);
        memcpy(buffer, &registers, sizeof(registers));
    } else if (note == EDGE_LINUX_NT_PRFPREG ||
               note == EDGE_LINUX_NT_X86_XSTATE ||
               note == EDGE_LINUX_PTRACE_LEGACY_FP ||
               note == EDGE_LINUX_PTRACE_LEGACY_FPX) {
        needed = sizeof(task->fxsave_region);
        if (*size < needed) return -EDGE_LINUX_EIO;
        memcpy(buffer, task->fxsave_region, needed);
    } else {
        return -EDGE_LINUX_EIO;
    }
    *size = needed;
    return 0;
}

int kernel_ptrace_set_regset(int32_t pid, uint32_t note, const void *buffer,
                             uint64_t size) {
    task_t *task = task_find_by_pid(pid);
    if (!task || !buffer) return -EDGE_LINUX_EIO;
    if (note == EDGE_LINUX_NT_PRSTATUS ||
        note == EDGE_LINUX_PTRACE_LEGACY_GPR) {
        if (size != sizeof(edge_x86_64_linux_user_regs_t))
            return -EDGE_LINUX_EIO;
        process_ptrace_import_regs(task, process_ptrace_frame(task),
            (const edge_x86_64_linux_user_regs_t *)buffer);
        return 0;
    }
    if (note == EDGE_LINUX_NT_PRFPREG ||
        note == EDGE_LINUX_NT_X86_XSTATE ||
        note == EDGE_LINUX_PTRACE_LEGACY_FP ||
        note == EDGE_LINUX_PTRACE_LEGACY_FPX) {
        if (size != sizeof(task->fxsave_region)) return -EDGE_LINUX_EIO;
        memcpy(task->fxsave_region, buffer, size);
        return 0;
    }
    return -EDGE_LINUX_EIO;
}

int arch_ptrace_stop_current(void *user_registers,
                             const edge_linux_ptrace_stop_t *stop) {
    task_t *task = process_current_task();
    edge_trap_frame_t *frame = (edge_trap_frame_t *)user_registers;
    kernel_signal_runtime_state_t signal_state;
    uint8_t signal_information[KERNEL_SIGNAL_INFO_SIZE];
    if (!task || !frame || !stop || task->ptrace.tracer_pid <= 0)
        return -EDGE_LINUX_ESRCH;
    {
        uint32_t internal_signal =
            edge_linux_ptrace_internal_stop_signal(stop);
        if (internal_signal &&
            kernel_arch_signal_runtime_state(task, &signal_state) == 0)
            (void)kernel_signal_pending_consume(
                &signal_state, internal_signal, 0, 0);
    }
    task->ptrace_frame = *frame;
    task->ptrace_live_frame = (uintptr_t)frame;
    if (stop->reason == EDGE_LINUX_PTRACE_STOP_INTERRUPT)
        task->ptrace.interrupt_pending = 0;
    edge_linux_ptrace_state_record_stop(&task->ptrace, stop);
    task->ptrace.instruction_pointer = frame->rip;
    task->ptrace.stack_pointer = frame->rsp;
    if (stop->reason == EDGE_LINUX_PTRACE_STOP_SYSCALL_ENTRY) {
        task->ptrace.syscall_active = 1;
        task->ptrace_frame.rax = (uint64_t)-(int64_t)EDGE_LINUX_ENOSYS;
    } else if (stop->reason == EDGE_LINUX_PTRACE_STOP_SYSCALL_EXIT) {
        task->ptrace.syscall_active = 0;
    }
    if (stop->reason == EDGE_LINUX_PTRACE_STOP_SIGNAL &&
        kernel_arch_signal_runtime_state(task, &signal_state) == 0 &&
        kernel_signal_pending_peek(
            &signal_state, stop->signal, signal_information)) {
        memcpy(task->ptrace.signal_info, signal_information,
               sizeof(signal_information));
        task->ptrace.signal_info_valid = 1;
    } else {
        edge_linux_ptrace_state_record_signal_info(
            &task->ptrace, stop->signal, 0x80, 0, 0);
    }
    task->stop_signal = (uint8_t)stop->signal;
    task->stop_reported = 0;
    scheduler_task_set_stopped(task);
    process_notify_waiter_for_task(task);
    scheduler_yield();
    if (task->state == TASK_ZOMBIE || task->state == TASK_UNUSED)
        return -EDGE_LINUX_ESRCH;
    *frame = task->ptrace_frame;
    task->ptrace_live_frame = 0;
    task->ptrace.stop_reason = EDGE_LINUX_PTRACE_STOP_NONE;
    task->ptrace.stop_signal = 0;
    task->ptrace.stop_event = 0;
    task->ptrace.syscall_info_op = 0;
    return 0;
}

int arch_ptrace_consume_syscall_restart(void *user_registers) {
    (void)user_registers;
    return 0;
}

int kernel_ptrace_current_syscall(void *user_registers, uint64_t *number,
                                  uint64_t arguments[6], int64_t *result) {
    task_t *task = process_current_task();
    edge_trap_frame_t *frame = (edge_trap_frame_t *)user_registers;
    if (!task || !frame) return -EDGE_LINUX_ESRCH;
    if (number) *number = task->ptrace.syscall_number;
    if (arguments) {
        arguments[0] = frame->rdi;
        arguments[1] = frame->rsi;
        arguments[2] = frame->rdx;
        arguments[3] = frame->r10;
        arguments[4] = frame->r8;
        arguments[5] = frame->r9;
    }
    if (result) *result = (int64_t)frame->rax;
    return 0;
}

int process_set_state(int pid, task_state_t state) {
    task_t *t = task_find_by_pid(pid);
    if (!t) return -1;
    switch (state) {
        case TASK_RUNNABLE:
        case TASK_RUNNING: {
            uint32_t cpu = (t->assigned_cpu >= 0) ? (uint32_t)t->assigned_cpu : (uint32_t)process_pick_target_cpu();
            scheduler_task_make_runnable(t, cpu);
            break;
        }
        case TASK_BLOCKED:
            scheduler_task_set_blocked(t);
            break;
        case TASK_STOPPED:
            scheduler_task_set_stopped(t);
            break;
        case TASK_ZOMBIE:
            scheduler_task_set_zombie(t);
            if (t->cgroup_accounted) {
                t->cgroup_accounted = 0;
                cgroupfs_task_leave(t->cgroup_id);
            }
            break;
        case TASK_UNUSED:
            task_release_unused(t);
            break;
        default:
            return -1;
    }
    return 0;
}

int process_pick_target_cpu(void) {
    return (int)scheduler_pick_target_cpu(UINT64_MAX);
}

int process_publish_new_task(int pid) {
    task_t *task = task_find_by_pid(pid);
    uint32_t target;

    if (!task || task->state != TASK_BLOCKED || task->on_cpu ||
        task->on_runqueue || !task->context_ready)
        return -1;

    /*
     * A clone is invisible to the scheduler until every architecture frame,
     * shared-object reference, namespace attachment, and cgroup account has
     * been completed.  Publish that fully initialized image with release
     * ordering, then select the least loaded allowed CPU for its first run.
     * Ordinary wakeups retain their previous CPU affinity and do not use this
     * first-publication path.
     */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    target = scheduler_pick_target_cpu(task->scheduler.affinity_mask);
    scheduler_task_make_runnable(task, target);
    return 0;
}
