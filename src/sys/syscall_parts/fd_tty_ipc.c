#include "kernel/input_device.h"

static int trace_initd_console_task(const task_t *t);
static int alloc_special_fd(edge_fd_kind_t kind, int obj_id, int flags);
static int console_line_referenced_elsewhere(int owner_pid, int line_id);
static uint64_t open_console_tty_fd(edge_fd_proc_t *p, const char *path, int flags);
static int socket_pending_trace_task(const task_t *t);
static int fd_release_entry(edge_fd_t *entry, task_t *task,
                            int close_process_locks,
                            int notify_last_close);
static int fd_remove_open(edge_fd_proc_t *process, int descriptor,
                          edge_fd_t *closing);
static void fd_proc_unpublished_discard(edge_fd_proc_t *process);

static int eventfd_snapshot(int eventfd_id,
                            kernel_eventfd_state_t *state) {
    return kernel_eventfd_query(eventfd_id, state) == 0;
}

static uint64_t eventfd_counter_snapshot(int eventfd_id) {
    kernel_eventfd_state_t state;
    return eventfd_snapshot(eventfd_id, &state) ? state.counter : 0;
}

static int timerfd_snapshot(int timerfd_id,
                            kernel_timerfd_state_t *state) {
    return kernel_timerfd_query(timerfd_id, state) == 0;
}

static uint64_t timerfd_expiration_snapshot(int timerfd_id) {
    kernel_timerfd_state_t state;
    return timerfd_snapshot(timerfd_id, &state) ? state.expirations : 0;
}

#ifndef EDGE_SYSCALL_DEBUG
#define EDGE_SYSCALL_DEBUG 0
#endif
#ifndef EDGE_BB_FD_TRACE
#define EDGE_BB_FD_TRACE 0
#endif
#ifndef EDGE_TTY_DEBUG
#define EDGE_TTY_DEBUG 0
#endif
#ifndef EDGE_TTY_JOBCONTROL_COMPAT
#define EDGE_TTY_JOBCONTROL_COMPAT 1
#endif
#ifndef EDGE_FD_FORK_DEBUG
#define EDGE_FD_FORK_DEBUG 0
#endif
#ifndef EDGE_SSH_IO_DEBUG
#define EDGE_SSH_IO_DEBUG 0
#endif
#ifndef EDGE_USER_TEXT_WRITE_DEBUG
#define EDGE_USER_TEXT_WRITE_DEBUG 0
#endif
#ifndef EDGE_X11_TRACE
#define EDGE_X11_TRACE 0
#endif
#ifndef EDGE_X11_UNIX_TRACE
#define EDGE_X11_UNIX_TRACE 0
#endif
#ifndef EDGE_UACCESS_DEBUG
#define EDGE_UACCESS_DEBUG 0
#endif

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1

static inline uint64_t page_align_up(uint64_t v) {
    return (v + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

static inline uint64_t page_align_down(uint64_t v) {
    return v & ~(PAGE_SIZE - 1);
}

static uint64_t g_syscall_debug_nr;
static uint64_t g_syscall_debug_rip;
static uint64_t g_syscall_debug_rsp;
static int g_syscall_debug_pid;
static int g_syscall_text_write_log_budget = 32;
static int g_uaccess_debug_budget = 64;

static inline uint64_t read_cr3_local(void) {
    uint64_t v;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));
    return v;
}

static uint64_t user_pte_flags_address_space(uint64_t cr3, uint64_t va) {
    uint64_t *pml4 = x86_page_table_alias(cr3);
    if (!pml4) return 0;
    uint64_t pml4e = pml4[(va >> 39) & 0x1FF];
    if (!(pml4e & PTE_PRESENT)) return 0;

    uint64_t *pdpt = x86_page_table_alias(pml4e);
    if (!pdpt) return 0;
    uint64_t pdpte = pdpt[(va >> 30) & 0x1FF];
    if (!(pdpte & PTE_PRESENT)) return 0;
    if (pdpte & PTE_PS) return pdpte & 0xFFFULL;

    uint64_t *pd = x86_page_table_alias(pdpte);
    if (!pd) return 0;
    uint64_t pde = pd[(va >> 21) & 0x1FF];
    if (!(pde & PTE_PRESENT)) return 0;
    if (pde & PTE_PS) return pde & 0xFFFULL;

    uint64_t *pt = x86_page_table_alias(pde);
    if (!pt) return 0;
    uint64_t pte = pt[(va >> 12) & 0x1FF];
    if (!(pte & PTE_PRESENT)) return 0;
    return pte & 0xFFFULL;
}

static uint64_t user_pte_flags(uint64_t va) {
    return user_pte_flags_address_space(
        read_cr3_local() & ~0xFFFULL, va);
}

static uint64_t user_pte_phys_for_cr3(uint64_t cr3, uint64_t va) {
    cr3 &= ~0xFFFULL;
    uint64_t *pml4 = x86_page_table_alias(cr3);
    if (!pml4) return 0;
    uint64_t pml4e = pml4[(va >> 39) & 0x1FF];
    uint64_t *pdpt;
    uint64_t pdpte;
    uint64_t *pd;
    uint64_t pde;
    uint64_t *pt;
    uint64_t pte;
    if (!(pml4e & PTE_PRESENT)) return 0;
    pdpt = x86_page_table_alias(pml4e);
    if (!pdpt) return 0;
    pdpte = pdpt[(va >> 30) & 0x1FF];
    if (!(pdpte & PTE_PRESENT)) return 0;
    if (pdpte & PTE_PS) return (pdpte & ~0x3FFFFFFFULL) + (va & 0x3FFFFFFFULL);
    pd = x86_page_table_alias(pdpte);
    if (!pd) return 0;
    pde = pd[(va >> 21) & 0x1FF];
    if (!(pde & PTE_PRESENT)) return 0;
    if (pde & PTE_PS) return (pde & ~0x1FFFFFULL) + (va & 0x1FFFFFULL);
    pt = x86_page_table_alias(pde);
    if (!pt) return 0;
    pte = pt[(va >> 12) & 0x1FF];
    if (!(pte & PTE_PRESENT)) return 0;
    return (pte & ~0xFFFULL) + (va & 0xFFFULL);
}

extern char _kernel_start;
extern char _kernel_end;

static int user_range_overlaps(uint64_t addr, uint64_t len, uint64_t start, uint64_t end) {
    uint64_t last;
    if (len == 0 || start >= end) return 0;
    last = addr + len;
    if (last < addr) return 1;
    return addr < end && last > start;
}

static int user_range_within(uint64_t addr, uint64_t len, uint64_t start, uint64_t end) {
    uint64_t last;
    if (len == 0 || start >= end) return 0;
    last = addr + len;
    if (last < addr) return 0;
    return addr >= start && last <= end;
}

static int user_range_known_fixed_window(uint64_t addr, uint64_t len) {
    if (user_range_within(addr, len, USER_LOW_BASE_ADDR, USER_LOW_BASE_ADDR + USER_LOW_SIZE_ADDR)) return 1;
    if (user_range_within(addr, len, USER_TEXT_BASE_ADDR, USER_TEXT_BASE_ADDR + USER_TEXT_SIZE_ADDR)) return 1;
    if (user_range_within(addr, len, USER_STACK_BASE_ADDR, USER_STACK_BASE_ADDR + USER_STACK_SIZE_ADDR)) return 1;
    if (user_range_within(addr, len, USER_HEAP_BASE_ADDR, USER_HEAP_ABS_LIMIT_ADDR)) return 1;
    if (user_range_within(addr, len, USER_BIGPIE_BASE_ADDR, USER_BIGPIE_BASE_ADDR + USER_BIGPIE_SIZE_ADDR)) return 1;
    return 0;
}

static int x86_user_range_arch_ok(uint64_t addr, uint64_t len) {
    if (user_range_overlaps(addr, len, (uint64_t)(uintptr_t)&_kernel_start,
                            (uint64_t)(uintptr_t)&_kernel_end) &&
        !user_range_known_fixed_window(addr, len)) {
        /*
         * EdgeOS keeps a supervisor identity map for early kernel/device paths,
         * and the kernel image's .bss also contains static backing arrays for
         * fixed userspace windows.  Reject true kernel text/data addresses, but
         * keep the known user windows legal or every normal pointer around
         * 0x20000000 becomes EFAULT.  Long-term, demand-mapped userspace pages
         * should replace these static windows so uaccess can validate strictly
         * from page-table U/S bits instead of numeric compatibility windows.
         */
        return 0;
    }
    return 1;
}

static int user_range_ok(uint64_t addr, uint64_t len) {
    return edge_linux_user_range_valid(addr, len, USER_MIN_ADDR,
                                       USER_MAX_ADDR) &&
           x86_user_range_arch_ok(addr, len);
}

static int user_sparse_range_access_ok(uint64_t addr, uint64_t len, int write) {
    task_t *cur;
    uint64_t end;

    if (len == 0) return 1;
    end = addr + len;
    if (end < addr) return 0;

    cur = process_current_task();
    for (uint64_t page = page_align_down(addr); page < end; page += PAGE_SIZE) {
        uint64_t flags;

        if (!process_user_mmap_range_ok(page, 1)) continue;

        /*
         * copy_{to,from}_user() is allowed to touch valid userspace mappings,
         * including lazy sparse mmap pages.  It must not blindly memcpy into a
         * numerically user-looking address after munmap() or before a lazy page
         * is faulted in.  Fault in sparse pages through the same path as a
         * userspace page fault; if no VMA/protection permits the access, return
         * EFAULT to the syscall instead of taking a kernel page fault.
         *
         * Red flag: do not make user_range_ok() itself check PTEs.  Several
         * legacy fixed userspace windows overlap static kernel backing arrays
         * and are handled by the compatibility range checks above.  This helper
         * is intentionally limited to the sparse mmap regions used by modern
         * Linux userspace.
         */
        flags = user_pte_flags(page);
        if ((flags & PTE_PRESENT) == 0 ||
            (flags & PTE_USER) == 0 ||
            (write && (flags & PTE_WRITE) == 0)) {
            (void)process_user_mmap_handle_fault(cur, page, write);
            flags = user_pte_flags(page);
        }

        if ((flags & PTE_PRESENT) == 0 ||
            (flags & PTE_USER) == 0 ||
            (write && (flags & PTE_WRITE) == 0)) {
#if EDGE_UACCESS_DEBUG
            if (g_uaccess_debug_budget > 0) {
                printf("[uaccess] reject pid=%d task=%s nr=%u rip=0x%x addr=0x%x page=0x%x len=0x%x write=%d pte=0x%x\n",
                       cur ? cur->pid : g_syscall_debug_pid,
                       cur ? cur->name : "?",
                       (uint32_t)g_syscall_debug_nr,
                       (uint32_t)g_syscall_debug_rip,
                       (uint32_t)addr,
                       (uint32_t)page,
                       (uint32_t)len,
                       write ? 1 : 0,
                       (uint32_t)flags);
                g_uaccess_debug_budget--;
            }
#endif
            return 0;
        }
    }
    return 1;
}

static int user_access_ok(uint64_t addr, uint64_t len, int write) {
    if (!user_range_ok(addr, len)) return 0;
    return user_sparse_range_access_ok(addr, len, write);
}

static int copy_from_user(void *dst, uint64_t src_u, uint64_t len) {
    if (!user_access_ok(src_u, len, 0)) return -1;
    return process_read_user_memory(process_getpid(), src_u, dst, len);
}

static int copy_to_user(uint64_t dst_u, const void *src, uint64_t len) {
    if (!user_access_ok(dst_u, len, 1)) return -1;
#if EDGE_USER_TEXT_WRITE_DEBUG
    if (len && g_syscall_text_write_log_budget > 0) {
        uint64_t text_lo = USER_TEXT_BASE_ADDR;
        uint64_t text_hi = USER_TEXT_BASE_ADDR + USER_TEXT_SIZE_ADDR;
        uint64_t low_lo = USER_LOW_BASE_ADDR;
        uint64_t low_hi = USER_LOW_BASE_ADDR + USER_LOW_SIZE_ADDR;
        uint64_t bb_lo = BUSYBOX_CRASH_PAGE_LO;
        uint64_t bb_hi = BUSYBOX_CRASH_PAGE_HI;
        uint64_t hp_lo = SHELL_HEAP_PROBE_LO;
        uint64_t hp_hi = SHELL_HEAP_PROBE_HI;
        uint64_t end = dst_u + len;
        int hit_text;
        int hit_low;
        int hit_bb;
        int hit_heap_probe;
        if (end < dst_u) end = ~0ULL;
        hit_text = !(end <= text_lo || dst_u >= text_hi);
        hit_low  = !(end <= low_lo  || dst_u >= low_hi);
        hit_bb   = !(end <= bb_lo   || dst_u >= bb_hi);
        hit_heap_probe = !(end <= hp_lo || dst_u >= hp_hi);
        if (hit_text || hit_bb || hit_heap_probe) {
            task_t *t = process_current_task();
            const uint8_t *b = (const uint8_t *)src;
            printf("[uwrite-user] pid=%d task=%s nr=%d user_rip=0x%x dst=0x%x len=0x%x zone=%s%s%s%s src=%x %x %x %x\n",
                   t ? t->pid : g_syscall_debug_pid,
                   t ? t->name : "?",
                   (int)g_syscall_debug_nr,
                   (uint32)g_syscall_debug_rip,
                   (uint32)dst_u,
                   (uint32)len,
                   hit_bb ? "bb" : "",
                   hit_text ? (hit_bb ? "+text" : "text") : "",
                   hit_heap_probe ? ((hit_bb || hit_text) ? "+heap" : "heap") : "",
                   (!hit_bb && !hit_text && hit_low) ? "low" : "",
                   (len > 0 && b) ? (uint32)b[0] : 0,
                   (len > 1 && b) ? (uint32)b[1] : 0,
                   (len > 2 && b) ? (uint32)b[2] : 0,
                   (len > 3 && b) ? (uint32)b[3] : 0);
            g_syscall_text_write_log_budget--;
        }
    }
#endif
    return process_write_user_memory(process_getpid(), dst_u, src, len);
}

static int copy_user_cstr(char *dst, int dst_sz, uint64_t src_u) {
    if (!dst || dst_sz <= 1) return -1;
    if (!src_u) {
        dst[0] = 0;
        return 0;
    }
    for (int i = 0; i < dst_sz - 1; ++i) {
        char c = 0;
        if (copy_from_user(&c, src_u + (uint64_t)i, 1) < 0) return -1;
        dst[i] = c;
        if (!c) return 0;
    }
    dst[dst_sz - 1] = 0;
    return -1;
}

static uint64_t rdtsc64_local(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static int fd_async_input_slot(const edge_fd_t *e) {
    uintptr_t address;
    uintptr_t fd_begin;
    uintptr_t fd_end;
    uintptr_t offset;
    uint32_t fd_index;

    if (!e) return -1;
    address = (uintptr_t)e;
    for (uint32_t proc_index = 0; proc_index < EDGE_MAX_FD_PROCS;
         ++proc_index) {
        edge_fd_proc_t *process = g_fd_procs[proc_index];
        if (!process) continue;
        fd_begin = (uintptr_t)&process->fds[0];
        fd_end = (uintptr_t)&process->fds[EDGE_MAX_FD];
        if (address < fd_begin || address >= fd_end) continue;
        offset = address - fd_begin;
        if ((offset % sizeof(edge_fd_t)) != 0) return -1;
        fd_index = (uint32_t)(offset / sizeof(edge_fd_t));
        if (fd_index >= EDGE_MAX_FD) return -1;
        return (int)(proc_index * EDGE_MAX_FD + fd_index);
    }
    return -1;
}

static edge_fd_t *fd_async_input_from_slot(uint32_t slot) {
    uint32_t proc_index;
    uint32_t fd_index;
    if (slot >= EDGE_ASYNC_INPUT_SLOT_COUNT) return 0;
    proc_index = slot / EDGE_MAX_FD;
    fd_index = slot % EDGE_MAX_FD;
    return g_fd_procs[proc_index] ?
        &g_fd_procs[proc_index]->fds[fd_index] : 0;
}

static int fd_async_input_eligible(const edge_fd_t *e) {
    if (!e || !e->used || e->kind != FD_VFS) return 0;
    if ((e->flags & LINUX_O_ASYNC) == 0 || e->async_owner == 0) return 0;
    return path_is_event_input(e->path) || path_is_mouse_input(e->path);
}

static void fd_async_input_watch_remove_index_locked(uint32_t index) {
    uint32_t removed_slot;
    uint32_t last_index;
    uint32_t last_slot;

    if (g_async_input_watcher_count > EDGE_ASYNC_INPUT_SLOT_COUNT)
        g_async_input_watcher_count = EDGE_ASYNC_INPUT_SLOT_COUNT;
    if (index >= g_async_input_watcher_count) return;
    removed_slot = g_async_input_watchers[index];
    for (;;) {
        last_index = g_async_input_watcher_count - 1u;
        last_slot = g_async_input_watchers[last_index];
        g_async_input_watchers[last_index] = 0;
        g_async_input_watcher_count = last_index;
        if (last_index == index) break;
        if (last_slot >= EDGE_ASYNC_INPUT_SLOT_COUNT ||
            last_slot == removed_slot)
            continue;
        g_async_input_watchers[index] = last_slot;
        g_async_input_watch_positions[last_slot] = index + 1u;
        break;
    }
    if (removed_slot < EDGE_ASYNC_INPUT_SLOT_COUNT &&
        g_async_input_watch_positions[removed_slot] == index + 1u)
        g_async_input_watch_positions[removed_slot] = 0;
}

static void fd_async_input_watch_remove_slot_locked(uint32_t slot) {
    uint32_t position;
    uint32_t index;

    if (slot >= EDGE_ASYNC_INPUT_SLOT_COUNT) return;
    if (g_async_input_watcher_count > EDGE_ASYNC_INPUT_SLOT_COUNT)
        g_async_input_watcher_count = EDGE_ASYNC_INPUT_SLOT_COUNT;
    position = g_async_input_watch_positions[slot];
    if (position == 0) return;
    index = position - 1u;
    if (index >= g_async_input_watcher_count || g_async_input_watchers[index] != slot) {
        /* Recover the reverse index without dropping a live Linux SIGIO owner. */
        for (index = 0; index < g_async_input_watcher_count; ++index) {
            if (g_async_input_watchers[index] == slot) break;
        }
        if (index >= g_async_input_watcher_count) {
            g_async_input_watch_positions[slot] = 0;
            return;
        }
    }
    fd_async_input_watch_remove_index_locked(index);
}

static void fd_async_input_watch_remove(edge_fd_t *e) {
    uint64_t irq_flags =
        spin_lock_irqsave(&g_async_input_watch_lock);
    int slot = fd_async_input_slot(e);
    if (slot >= 0)
        fd_async_input_watch_remove_slot_locked((uint32_t)slot);
    spin_unlock_irqrestore(&g_async_input_watch_lock, irq_flags);
}

static void fd_async_input_watch_update(edge_fd_t *e) {
    uint64_t irq_flags =
        spin_lock_irqsave(&g_async_input_watch_lock);
    int slot_value = fd_async_input_slot(e);
    uint32_t slot;
    uint32_t index;
    if (slot_value < 0) {
        spin_unlock_irqrestore(&g_async_input_watch_lock, irq_flags);
        return;
    }
    slot = (uint32_t)slot_value;
    if (!fd_async_input_eligible(e)) {
        fd_async_input_watch_remove_slot_locked(slot);
        spin_unlock_irqrestore(&g_async_input_watch_lock, irq_flags);
        return;
    }
    if (g_async_input_watch_positions[slot] != 0) {
        spin_unlock_irqrestore(&g_async_input_watch_lock, irq_flags);
        return;
    }
    if (g_async_input_watcher_count >= EDGE_ASYNC_INPUT_SLOT_COUNT) {
        printf("[input] asynchronous descriptor registry exhausted\n");
        spin_unlock_irqrestore(&g_async_input_watch_lock, irq_flags);
        return;
    }
    index = g_async_input_watcher_count++;
    g_async_input_watchers[index] = slot;
    g_async_input_watch_positions[slot] = index + 1u;
    spin_unlock_irqrestore(&g_async_input_watch_lock, irq_flags);
}

static void fd_signal_async_input_ready(void) {
    /*
     * Linux evdev supports O_ASYNC/F_SETOWN by delivering SIGIO when input
     * arrives.  Xorg's evdev backend can choose that path and then stop
     * polling /dev/input/event*.  EdgeOS' xHCI stack is currently advanced
     * by usb_poll(), so after each poll pass scan async input descriptors and
     * wake their owners if their per-open event cursor has data.
     */
    uint32_t index = 0;
    for (;;) {
        uint64_t irq_flags =
            spin_lock_irqsave(&g_async_input_watch_lock);
        uint32_t slot;
        int owner = 0;
        int signal = 0;
        edge_fd_t *e;
        int pending = 0;

        if (g_async_input_watcher_count >
            EDGE_ASYNC_INPUT_SLOT_COUNT)
            g_async_input_watcher_count =
                EDGE_ASYNC_INPUT_SLOT_COUNT;
        if (index >= g_async_input_watcher_count) {
            spin_unlock_irqrestore(
                &g_async_input_watch_lock, irq_flags);
            break;
        }
        slot = g_async_input_watchers[index];
        if (slot >= EDGE_ASYNC_INPUT_SLOT_COUNT) {
            fd_async_input_watch_remove_index_locked(index);
            spin_unlock_irqrestore(
                &g_async_input_watch_lock, irq_flags);
            continue;
        }
        e = fd_async_input_from_slot(slot);
        if (!fd_async_input_eligible(e)) {
            fd_async_input_watch_remove_slot_locked(slot);
            spin_unlock_irqrestore(
                &g_async_input_watch_lock, irq_flags);
            continue;
        }
        if (path_is_event_input(e->path)) {
            int event_id = path_input_event_index(e->path);
            int tail = fd_description_input_tail(e);
            pending = keyboard_event_pending_from(
                event_id, tail);
            if (pending < (int)EDGE_LINUX_INPUT_EVENT_SIZE) pending = 0;
        } else {
            pending = keyboard_mouse_pending();
        }
        if (pending > 0) {
            signal = e->async_signal > 0
                ? e->async_signal : LINUX_SIGIO;
            owner = e->async_owner;
        }
        spin_unlock_irqrestore(
            &g_async_input_watch_lock, irq_flags);
        if (owner > 0)
            (void)process_send_signal(owner, signal);
        else if (owner < 0)
            (void)process_send_signal_pgid(-owner, signal);
        ++index;
    }
}

static inline void wait_poll_pump_step(void) {
    uint64_t now_us;
    /*
     * Mixed poll/select wait sets such as Xorg's client socket plus evdev/VT
     * fds cannot safely sleep on the socket wait queue alone until every fd
     * kind has a real wait queue.  Pump the polled hardware backends and yield
     * without HLT so request/reply-heavy X11 clients do not pay a timer tick
     * for each small round trip.
     */
    /*
     * Network IRQs and the bounded timer fallback publish general deferred
     * work.  Polling the complete receive ring on every immediately-ready
     * GUI fd turns harmless X11/DBus POLLOUT traffic into a permanent device
     * scan and creates avoidable contention with browser socket syscalls.
     * Claim the shared latch here so an IRQ is still serviced at the next
     * process-context opportunity without repeatedly scanning an idle queue.
     */
    if (scheduler_take_deferred_work())
        syscall_network_poll();
#ifdef CONFIG_USB
    usb_poll();
#endif
    fd_signal_async_input_ready();
    keyboard_poll_controller();
    /*
     * Xorg/fbdev updates the framebuffer through mmap, so there may be no
     * syscall on the drawing fd that EdgeOS can use as a damage signal.  The
     * timer IRQ marks the mmap presenter due, but the virtio-gpu transfer must
     * run from process context.  Full desktop startup can spend long stretches
     * in short epoll/poll/ioctl syscalls, so pump presentation here at display
     * cadence and keep Linux fbdev clients visible under GUI event-loop pressure.
     *
     * Red flag: this is deliberately generic for any fbdev mmap owner.  Do not
     * key it on Xorg, XFCE, paths, or rootfs contents.
     */
    now_us = boottime_monotonic_us();
    if (fb_user_mmap_active() && now_us >= g_gui_fb_mmap_pump_next_us) {
        g_gui_fb_mmap_pump_next_us = now_us + 10000ull;
        /*
         * A ready-only desktop loop can consume the display work latch before
         * the framebuffer presenter runs.  Drive the cadence directly from
         * this process-context checkpoint; fb_user_mmap_tick() still performs
         * its own damage and interval checks and submits nothing while idle.
         */
        fb_user_mmap_tick((uint32_t)(now_us / 10000ull));
    }
}

static inline void wait_poll_yield_step(void) {
    wait_poll_pump_step();
    scheduler_yield();
    /*
     * Open a real IRQ window without halting.  Syscalls run with interrupts
     * masked; a pure pause loop can starve timer/device IRQ delivery while an
     * X11 client is inside a poll/select retry loop.
     */
    __asm__ __volatile__("sti; pause; cli" ::: "memory");
    if (scheduler_take_deferred_work())
        syscall_network_poll();
#ifdef CONFIG_USB
    usb_poll();
#endif
    fd_signal_async_input_ready();
    keyboard_poll_controller();
}

static inline void wait_gui_ready_defer_resched_step(void) {
    task_t *cur;
    /*
     * Ready poll/epoll returns are Linux-visible ABI results.  Do not context
     * switch in the middle of calculating/copying those results: a cooperative
     * schedule at that point makes debugging impossible if a low-level context
     * save bug ever corrupts a caller's stack or return register.  Instead,
     * pump hardware/framebuffer work now and ask the syscall exit path to run
     * the scheduler after rax has been set to the exact Linux return value.
     */
    wait_poll_pump_step();
    __asm__ __volatile__("sti; pause; cli" ::: "memory");
    wait_poll_pump_step();
    cur = process_current_task();
    if (cur && !cur->is_idle) cur->need_resched = 1;
}

static inline void wait_gui_ready_preempt_step(void) {
    task_t *cur;
    int force_yield = 0;
    /*
     * Immediate poll/epoll readiness is still a syscall return.  Open an IRQ
     * window so the scheduler tick can request preemption.  Until syscall
     * return is fully preemptible, retain a bounded handoff for the small set
     * of desktop servers selected by the caller; otherwise a continuously
     * ready X server can delay the clients waiting for its replies.
     *
     * Do not HLT here because request/reply loops need a low-latency return to
     * userspace.
     */
    wait_poll_pump_step();
    __asm__ __volatile__("sti; pause; cli" ::: "memory");
    wait_poll_pump_step();

    cur = process_current_task();
    if (cur && !cur->is_idle && cur->need_resched) {
        force_yield = 1;
    } else if (++g_gui_ready_preempt_burst >= 8u) {
        g_gui_ready_preempt_burst = 0;
        force_yield = 1;
    }
    if (force_yield) {
        if (g_gui_wait_block_trace_budget > 0) {
            if (gui_diag_task(cur)) {
                printf("[gui-wait] ready-preempt pid=%d cmd=%s need=%u sys=%llu ret=%lld budget=%d\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       cur ? (unsigned)cur->need_resched : 0u,
                       cur ? (unsigned long long)cur->last_syscall_nr : 0ull,
                       cur ? (long long)cur->last_syscall_ret : 0ll,
                       g_gui_wait_block_trace_budget - 1);
                g_gui_wait_block_trace_budget--;
            }
        }
        wait_poll_yield_step();
    }
}

static inline void wait_blocking_step(void) {
    /* Prevent one blocking syscall from starving userspace or hardware IRQs.
     * The syscall frame normally runs with IRQs masked; blocking waits must
     * briefly open an interrupt window so NIC/keyboard/timer IRQs can make
     * progress, then restore the masked state expected by syscall return.
     *
     * USB/xHCI input is currently polled rather than interrupt-completed.
     * Keep it moving from the common blocking wait path so Linux input users
     * such as Xorg can block in read/epoll/select on /dev/input/event* without
     * needing an unrelated syscall to pump the controller.
     */
    wait_poll_yield_step();
    scheduler_yield();
    __asm__ __volatile__("sti; hlt; cli" ::: "memory");
    wait_poll_yield_step();
}

typedef enum edge_waiter_membership_kind {
    EDGE_WAITER_SOCKET,
    EDGE_WAITER_EVENTFD_READ,
    EDGE_WAITER_EVENTFD_WRITE,
    EDGE_WAITER_PIPE_READ,
    EDGE_WAITER_PIPE_WRITE,
} edge_waiter_membership_kind_t;

static edge_waiter_owner_t *waiter_owner_find(int pid, int create) {
    edge_waiter_owner_t *reusable_owner = 0;
    uint32_t start;

    if (pid <= 0) return 0;
    _Static_assert((PROC_MAX_TASKS & (PROC_MAX_TASKS - 1u)) == 0,
                   "waiter owner capacity must be a power of two");
    start = ((uint32_t)pid * 2654435761u) & (PROC_MAX_TASKS - 1u);
    for (uint32_t probe = 0; probe < PROC_MAX_TASKS; ++probe) {
        edge_waiter_owner_t *owner =
            &g_waiter_owners[(start + probe) & (PROC_MAX_TASKS - 1u)];
        if (owner->pid == pid) return owner;
        if (owner->pid < 0) {
            if (!reusable_owner) reusable_owner = owner;
            continue;
        }
        if (owner->pid != 0) continue;
        if (!create) return 0;
        if (!reusable_owner) reusable_owner = owner;
        memset(reusable_owner, 0, sizeof(*reusable_owner));
        reusable_owner->pid = pid;
        return reusable_owner;
    }
    if (!create || !reusable_owner) return 0;
    memset(reusable_owner, 0, sizeof(*reusable_owner));
    reusable_owner->pid = pid;
    return reusable_owner;
}

static uint64_t *waiter_owner_membership(edge_waiter_owner_t *owner,
                                         edge_waiter_membership_kind_t kind,
                                         uint32_t *limit_out) {
    if (!owner || !limit_out) return 0;
    switch (kind) {
        case EDGE_WAITER_SOCKET:
            *limit_out = EDGE_MAX_SOCKETS;
            return owner->sockets;
        case EDGE_WAITER_EVENTFD_READ:
            *limit_out = EDGE_MAX_EVENTFDS;
            return owner->eventfd_read;
        case EDGE_WAITER_EVENTFD_WRITE:
            *limit_out = EDGE_MAX_EVENTFDS;
            return owner->eventfd_write;
        case EDGE_WAITER_PIPE_READ:
            *limit_out = EDGE_MAX_PIPES;
            return owner->pipe_read;
        case EDGE_WAITER_PIPE_WRITE:
            *limit_out = EDGE_MAX_PIPES;
            return owner->pipe_write;
    }
    *limit_out = 0;
    return 0;
}

static int waiter_owner_mark(int pid, edge_waiter_membership_kind_t kind,
                             int object_id) {
    edge_waiter_owner_t *owner = waiter_owner_find(pid, 1);
    uint64_t *membership;
    uint32_t limit;
    if (!owner) {
        g_waiter_index_degraded = 1;
        return -1;
    }
    membership = waiter_owner_membership(owner, kind, &limit);
    if (!membership || object_id < 0 || (uint32_t)object_id >= limit) {
        g_waiter_index_degraded = 1;
        return -1;
    }
    membership[(uint32_t)object_id / 64u] |=
        1ull << ((uint32_t)object_id % 64u);
    return 0;
}

static int waiter_membership_any(const uint64_t *membership, uint32_t limit) {
    uint32_t words = EDGE_WAITER_BITMAP_WORDS(limit);
    if (!membership) return 0;
    for (uint32_t i = 0; i < words; ++i)
        if (membership[i]) return 1;
    return 0;
}

static void waiter_owner_release_if_empty(edge_waiter_owner_t *owner) {
    if (!owner) return;
    if (waiter_membership_any(owner->sockets, EDGE_MAX_SOCKETS) ||
        waiter_membership_any(owner->eventfd_read, EDGE_MAX_EVENTFDS) ||
        waiter_membership_any(owner->eventfd_write, EDGE_MAX_EVENTFDS) ||
        waiter_membership_any(owner->pipe_read, EDGE_MAX_PIPES) ||
        waiter_membership_any(owner->pipe_write, EDGE_MAX_PIPES))
        return;
    /*
     * Preserve the probe chain after deletion.  A zero pid terminates a
     * lookup; the negative tombstone can be reused by the next insertion but
     * cannot hide colliding owners that were inserted later in the chain.
     */
    memset(owner, 0, sizeof(*owner));
    owner->pid = -1;
}

static void waiter_remove_indexed(int *waiters, int object_count,
                                  int waiters_per_object,
                                  uint64_t *membership, int pid) {
    uint32_t words;
    if (!waiters || object_count <= 0 || waiters_per_object <= 0 ||
        !membership || pid <= 0)
        return;
    words = EDGE_WAITER_BITMAP_WORDS((uint32_t)object_count);
    for (uint32_t word = 0; word < words; ++word) {
        uint64_t bits = membership[word];
        while (bits) {
            uint32_t bit = (uint32_t)__builtin_ctzll(bits);
            uint32_t object_id = word * 64u + bit;
            if (object_id < (uint32_t)object_count) {
                int *object_waiters = waiters +
                    object_id * (uint32_t)waiters_per_object;
                for (int i = 0; i < waiters_per_object; ++i)
                    if (object_waiters[i] == pid) object_waiters[i] = 0;
            }
            bits &= bits - 1u;
        }
        membership[word] = 0;
    }
}

static int socket_waiter_add(int sock_id, int pid, uint16_t events) {
    int free_slot = -1;
    int result = -1;
    int table_full = 0;
    uint64_t irq_flags;
    const uint16_t read_events = LINUX_POLLIN | LINUX_POLLPRI |
                                 LINUX_POLLRDNORM | LINUX_POLLRDBAND |
                                 LINUX_POLLRDHUP;
    const uint16_t write_events = LINUX_POLLOUT |
                                  LINUX_POLLWRNORM | LINUX_POLLWRBAND;
    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS || pid <= 0) return -1;
    /*
     * Keep the full Linux poll vocabulary in the waiter registration.  GLib,
     * DBus, XCB, and libevent frequently wait on POLLRDNORM/POLLWRNORM rather
     * than only POLLIN/POLLOUT; collapsing those bits loses directionality and
     * can turn a write-space wait into a read wait.  Red flag: if new poll
     * classes are added to poll_fd_revents(), update this mask and the wake
     * checks below in the same patch.
     */
    events &= (read_events | write_events);
    if (events == 0) events = LINUX_POLLIN | LINUX_POLLPRI;
    irq_flags = spin_lock_irqsave(&g_waiter_lock);
    for (int i = 0; i < EDGE_SOCKET_WAITERS; ++i) {
        int cur = g_socket_waiter_pids[sock_id][i];
        if (cur == pid) {
            g_socket_waiter_events[sock_id][i] |= events;
            result = waiter_owner_mark(
                pid, EDGE_WAITER_SOCKET, sock_id);
            spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
            return result;
        }
        if (cur == 0 && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        g_socket_waiter_pids[sock_id][free_slot] = pid;
        g_socket_waiter_events[sock_id][free_slot] = events;
        result = waiter_owner_mark(
            pid, EDGE_WAITER_SOCKET, sock_id);
        if (result < 0) {
            g_socket_waiter_pids[sock_id][free_slot] = 0;
            g_socket_waiter_events[sock_id][free_slot] = 0;
            g_socket_waiter_overflow[sock_id] = 1;
        }
    } else {
        /*
         * Remember that at least one blocked consumer could not join the exact
         * object wait queue.  The next readiness transition must use the
         * conservative fd-owner fallback even if registered waiters were also
         * woken; that fallback wakes the overflow consumers so they can retry
         * registration after slots are released.
         */
        g_socket_waiter_overflow[sock_id] = 1;
        table_full = 1;
    }
    spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    if (table_full) {
        static int socket_waiter_full_budget = 32;
        const task_t *t = process_get_task(pid);
        if (socket_waiter_full_budget > 0) {
            printf("[sockwait] full sid=%d pid=%d cmd=%s events=0x%x budget=%d\n",
                   sock_id, pid, t && t->name[0] ? t->name : "?",
                   (unsigned)events, socket_waiter_full_budget - 1);
            socket_waiter_full_budget--;
        }
    }
    return result;
}

static void waiter_remove_pid_full_scan(int pid) {
    if (pid <= 0) return;
    for (int sid = 0; sid < EDGE_MAX_SOCKETS; ++sid) {
        for (int i = 0; i < EDGE_SOCKET_WAITERS; ++i) {
            if (g_socket_waiter_pids[sid][i] == pid) {
                g_socket_waiter_pids[sid][i] = 0;
                g_socket_waiter_events[sid][i] = 0;
            }
        }
    }
    for (int id = 0; id < EDGE_MAX_EVENTFDS; ++id) {
        for (int i = 0; i < EDGE_EVENTFD_WAITERS; ++i) {
            if (g_eventfd_read_waiter_pids[id][i] == pid)
                g_eventfd_read_waiter_pids[id][i] = 0;
            if (g_eventfd_write_waiter_pids[id][i] == pid)
                g_eventfd_write_waiter_pids[id][i] = 0;
        }
    }
    for (int id = 0; id < EDGE_MAX_PIPES; ++id) {
        for (int i = 0; i < EDGE_PIPE_WAITERS; ++i) {
            if (g_pipe_read_waiter_pids[id][i] == pid)
                g_pipe_read_waiter_pids[id][i] = 0;
            if (g_pipe_write_waiter_pids[id][i] == pid)
                g_pipe_write_waiter_pids[id][i] = 0;
        }
    }
}

static void waiter_remove_pid(int pid) {
    edge_waiter_owner_t *owner;
    uint64_t irq_flags;
    if (pid <= 0) return;
    irq_flags = spin_lock_irqsave(&g_waiter_lock);
    owner = waiter_owner_find(pid, 0);
    if (owner) {
        for (uint32_t word = 0;
             word < EDGE_WAITER_BITMAP_WORDS(EDGE_MAX_SOCKETS); ++word) {
            uint64_t bits = owner->sockets[word];
            while (bits) {
                uint32_t bit = (uint32_t)__builtin_ctzll(bits);
                uint32_t sid = word * 64u + bit;
                if (sid < EDGE_MAX_SOCKETS) {
                    for (int i = 0; i < EDGE_SOCKET_WAITERS; ++i) {
                        if (g_socket_waiter_pids[sid][i] == pid) {
                            g_socket_waiter_pids[sid][i] = 0;
                            g_socket_waiter_events[sid][i] = 0;
                        }
                    }
                }
                bits &= bits - 1u;
            }
            owner->sockets[word] = 0;
        }
        waiter_remove_indexed(&g_eventfd_read_waiter_pids[0][0],
                              EDGE_MAX_EVENTFDS, EDGE_EVENTFD_WAITERS,
                              owner->eventfd_read, pid);
        waiter_remove_indexed(&g_eventfd_write_waiter_pids[0][0],
                              EDGE_MAX_EVENTFDS, EDGE_EVENTFD_WAITERS,
                              owner->eventfd_write, pid);
        waiter_remove_indexed(&g_pipe_read_waiter_pids[0][0],
                              EDGE_MAX_PIPES, EDGE_PIPE_WAITERS,
                              owner->pipe_read, pid);
        waiter_remove_indexed(&g_pipe_write_waiter_pids[0][0],
                              EDGE_MAX_PIPES, EDGE_PIPE_WAITERS,
                              owner->pipe_write, pid);
        waiter_owner_release_if_empty(owner);
    }

    /*
     * Missing metadata normally means that this task had no registered
     * waiters.  A complete scan is needed only after an indexing allocation or
     * validation failure; keeping that recovery mode sticky preserves wakeup
     * correctness without putting O(objects * waiters) work on every X11 poll.
     */
    if (g_waiter_index_degraded) waiter_remove_pid_full_scan(pid);
    spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
}

static int eventfd_waiter_add_to(
        int waiters[EDGE_MAX_EVENTFDS][EDGE_EVENTFD_WAITERS],
        edge_waiter_membership_kind_t kind, int eventfd_id, int pid) {
    int free_slot = -1;
    int result = -1;
    int table_full = 0;
    uint64_t irq_flags;
    if (eventfd_id < 0 || eventfd_id >= EDGE_MAX_EVENTFDS || pid <= 0) return -1;
    irq_flags = spin_lock_irqsave(&g_waiter_lock);
    for (int i = 0; i < EDGE_EVENTFD_WAITERS; ++i) {
        int cur = waiters[eventfd_id][i];
        if (cur == pid) {
            result = waiter_owner_mark(pid, kind, eventfd_id);
            spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
            return result;
        }
        if (cur == 0 && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        waiters[eventfd_id][free_slot] = pid;
        result = waiter_owner_mark(pid, kind, eventfd_id);
        if (result < 0) waiters[eventfd_id][free_slot] = 0;
    } else {
        table_full = 1;
    }
    spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    if (table_full) {
        static int eventfd_waiter_full_budget = 32;
        const task_t *t = process_get_task(pid);
        if (eventfd_waiter_full_budget > 0) {
            printf("[eventwait] full id=%d pid=%d cmd=%s budget=%d\n",
                   eventfd_id, pid, t && t->name[0] ? t->name : "?",
                   eventfd_waiter_full_budget - 1);
            eventfd_waiter_full_budget--;
        }
    }
    return result;
}

static int eventfd_read_waiter_add(int eventfd_id, int pid) {
    return eventfd_waiter_add_to(g_eventfd_read_waiter_pids,
                                 EDGE_WAITER_EVENTFD_READ, eventfd_id, pid);
}

static int eventfd_write_waiter_add(int eventfd_id, int pid) {
    return eventfd_waiter_add_to(g_eventfd_write_waiter_pids,
                                 EDGE_WAITER_EVENTFD_WRITE, eventfd_id, pid);
}

static int pipe_waiter_add_to(
        int waiters[EDGE_MAX_PIPES][EDGE_PIPE_WAITERS],
        edge_waiter_membership_kind_t kind, int pipe_id, int pid) {
    uint8_t *overflow;
    int free_slot = -1;
    int result = -1;
    int table_full = 0;
    uint64_t irq_flags;
    if (pipe_id < 0 || pipe_id >= EDGE_MAX_PIPES || pid <= 0) return -1;
    overflow = kind == EDGE_WAITER_PIPE_READ ?
        &g_pipe_read_waiter_overflow[pipe_id] :
        &g_pipe_write_waiter_overflow[pipe_id];
    irq_flags = spin_lock_irqsave(&g_waiter_lock);
    for (int i = 0; i < EDGE_PIPE_WAITERS; ++i) {
        int cur = waiters[pipe_id][i];
        if (cur == pid) {
            result = waiter_owner_mark(pid, kind, pipe_id);
            spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
            return result;
        }
        if (cur == 0 && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        waiters[pipe_id][free_slot] = pid;
        result = waiter_owner_mark(pid, kind, pipe_id);
        if (result < 0) {
            waiters[pipe_id][free_slot] = 0;
            *overflow = 1;
        }
    } else {
        *overflow = 1;
        table_full = 1;
    }
    spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    if (table_full) {
        static int pipe_waiter_full_budget = 32;
        const task_t *t = process_get_task(pid);
        if (pipe_waiter_full_budget > 0) {
            printf("[pipewait] full id=%d pid=%d cmd=%s budget=%d\n",
                   pipe_id, pid, t && t->name[0] ? t->name : "?",
                   pipe_waiter_full_budget - 1);
            pipe_waiter_full_budget--;
        }
    }
    return result;
}

static int pipe_read_waiter_add(int pipe_id, int pid) {
    return pipe_waiter_add_to(g_pipe_read_waiter_pids,
                              EDGE_WAITER_PIPE_READ, pipe_id, pid);
}

static int pipe_write_waiter_add(int pipe_id, int pid) {
    return pipe_waiter_add_to(g_pipe_write_waiter_pids,
                              EDGE_WAITER_PIPE_WRITE, pipe_id, pid);
}

static void socket_maybe_promote_deferred_fin(edge_socket_t *s) {
    if (!s || !s->tcp_fin_pending || s->rx_closed) return;
    if (s->rx_len > 0) {
        s->tcp_fin_pending = 0;
        s->rx_closed = 1;
    }
}

static void socket_drain_deferred_fin(edge_socket_t *s) {
    if (!s || !s->tcp_fin_pending || s->rx_closed) return;
    for (int i = 0; i < 32 && s->rx_len == 0 && s->tcp_fin_pending; ++i) {
        lwip_stack_poll();
        if (s->rx_len > 0 || !s->tcp_fin_pending) break;
        wait_poll_yield_step();
    }
    if (s->rx_len > 0) {
        s->tcp_fin_pending = 0;
        s->rx_closed = 1;
    } else if (s->tcp_fin_pending) {
        s->tcp_fin_pending = 0;
        s->rx_closed = 1;
    }
}

static void socket_poll_state_snapshot(
    edge_socket_t *socket, int extra_readable,
    kernel_socket_poll_state_t *state) {
    kernel_unix_socket_poll_result_t unix_result;
    int peer_valid = 0;
    edge_socket_t *peer = 0;

    memset(state, 0, sizeof(*state));
    memset(&unix_result, 0, sizeof(unix_result));
    if (!socket || !socket->used) return;

    state->valid = 1;
    state->stream.error = socket->connect_error;
    state->stream.connecting = socket->connect_in_progress != 0;
    state->stream.connected = socket->connected != 0;
    state->stream.closed = socket->closed != 0;
    state->stream.shutdown_write = socket->shutdown_write != 0;
    state->readable = extra_readable ||
        (socket->listening && socket_pending_count(socket) > 0) ||
        socket_has_receive_data(socket);
    if (socket->domain == LINUX_AF_UNIX) {
        socket_unix_poll_snapshot(socket, &unix_result);
        state->read_closed = unix_result.read_closed;
        state->hangup = unix_result.hangup;
    } else {
        state->read_closed =
            kernel_socket_type_has_peer_eof((uint32_t)socket->type) &&
            (socket->rx_closed || socket->closed);
        state->hangup = socket->closed != 0;
    }
    if (socket->closed &&
        socket->domain != LINUX_AF_INET &&
        socket->domain != LINUX_AF_INET6 &&
        socket->domain != LINUX_AF_UNIX)
        state->readable = 1;

    if ((socket->domain == LINUX_AF_INET ||
         socket->domain == LINUX_AF_INET6) &&
        socket->type == LINUX_SOCK_STREAM && socket->lwip_pcb) {
        state->use_stream_write_policy = 1;
        if (socket->connected)
            state->stream.send_space =
                tcp_sndbuf((struct tcp_pcb *)socket->lwip_pcb);
        return;
    }

    if (socket->domain == LINUX_AF_UNIX) {
        state->writable = unix_result.writable;
        return;
    }

    if (socket->domain != LINUX_AF_UNIX &&
        !((socket->domain == LINUX_AF_INET ||
           socket->domain == LINUX_AF_INET6) &&
          socket->type == LINUX_SOCK_STREAM)) {
        state->writable = !socket->closed;
        return;
    }

    if (socket->shutdown_write || socket->closed) {
        state->writable = 1;
        return;
    }
    if (socket->unix_peer_id >= 0 &&
        socket->unix_peer_id < EDGE_MAX_SOCKETS) {
        peer = &g_sockets[socket->unix_peer_id];
        peer_valid = peer->used;
    }
    if (socket_type_is_record(socket->type) && !socket->connected) {
        state->writable = 1;
    } else if (peer_valid &&
               (peer->shutdown_read ||
                (peer->rx_len < socket_rx_capacity(peer) &&
                 (!socket_type_is_record(socket->type) ||
                  peer->packet_count < EDGE_SOCKET_PACKET_QUEUE)))) {
        state->writable = 1;
    }
}

static int socket_poll_requested_events(
    const kernel_socket_poll_state_t *state, uint16_t requested) {
    return (int)kernel_wait_poll_project(
        kernel_socket_poll_events(state), (int16_t)requested);
}

static int socket_ready_for_waiter(int sock_id, uint16_t events) {
    edge_socket_t *s;
    kernel_socket_poll_state_t state;
    int extra_readable = 0;

    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS) return LINUX_POLLNVAL;
    s = &g_sockets[sock_id];
    if (!s->used) return LINUX_POLLNVAL;
    if (s->tcp_fin_pending) socket_drain_deferred_fin(s);
    else socket_maybe_promote_deferred_fin(s);
    if (s->packet_handle >= 0 &&
        edge_linux_packet_ring_ready(s->packet_handle))
        extra_readable = 1;
    socket_poll_state_snapshot(s, extra_readable, &state);
    return socket_poll_requested_events(&state, events);
}

static int socket_waiter_wake_registered(int sock_id, task_t *cur) {
    int waiter_pids[EDGE_SOCKET_WAITERS];
    uint16_t waiter_events[EDGE_SOCKET_WAITERS];
    uint64_t irq_flags;
    int woke = 0;
    static int wake_trace_budget = EDGE_GUI_DEEP_TRACE ? 128 : 0;
    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS) return 0;
    irq_flags = spin_lock_irqsave(&g_waiter_lock);
    memcpy(waiter_pids, g_socket_waiter_pids[sock_id],
           sizeof(waiter_pids));
    memcpy(waiter_events, g_socket_waiter_events[sock_id],
           sizeof(waiter_events));
    spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    for (int i = 0; i < EDGE_SOCKET_WAITERS; ++i) {
        int pid = waiter_pids[i];
        uint16_t events = waiter_events[i];
        task_t *t;
        if (pid <= 0) continue;
        t = (task_t *)(uintptr_t)process_get_task(pid);
        if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE)
            continue;
        if (cur && t == cur) continue;
        if ((socket_ready_for_waiter(sock_id, events) &
             (LINUX_POLLIN | LINUX_POLLPRI | LINUX_POLLRDNORM |
              LINUX_POLLRDBAND | LINUX_POLLOUT | LINUX_POLLWRNORM |
              LINUX_POLLWRBAND | LINUX_POLLRDHUP | LINUX_POLLERR |
              LINUX_POLLHUP | LINUX_POLLNVAL)) == 0) {
            continue;
        }
        if (t->state == TASK_BLOCKED && t->fd_wait_active) {
            uint32_t cpu = scheduler_cpu_id();
            scheduler_task_make_runnable(t, cpu);
            if ((x11_debug_task(t) || xfce_debug_task(t)) && wake_trace_budget-- > 0) {
                printf("[sockwake] registered sid=%d pid=%d cmd=%s ev=0x%x peer=%d rx=%u\n",
                       sock_id, t->pid, t->name, events,
                       g_sockets[sock_id].unix_peer_id, g_sockets[sock_id].rx_len);
            }
            woke++;
        }
    }
    return woke;
}

static int eventfd_waiter_wake_registered(int waiters[EDGE_MAX_EVENTFDS][EDGE_EVENTFD_WAITERS],
                                          const char *side, int eventfd_id, task_t *cur) {
    int waiter_pids[EDGE_EVENTFD_WAITERS];
    uint64_t irq_flags;
    int woke = 0;
    static int wake_trace_budget = EDGE_GUI_DEEP_TRACE ? 128 : 0;
    if (eventfd_id < 0 || eventfd_id >= EDGE_MAX_EVENTFDS) return 0;
    irq_flags = spin_lock_irqsave(&g_waiter_lock);
    memcpy(waiter_pids, waiters[eventfd_id], sizeof(waiter_pids));
    spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    for (int i = 0; i < EDGE_EVENTFD_WAITERS; ++i) {
        int pid = waiter_pids[i];
        task_t *t;
        if (pid <= 0) continue;
        t = (task_t *)(uintptr_t)process_get_task(pid);
        if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE)
            continue;
        if (cur && t == cur) continue;
        if (t->state == TASK_BLOCKED && t->fd_wait_active) {
            uint32_t cpu = scheduler_cpu_id();
            scheduler_task_make_runnable(t, cpu);
            if (wake_trace_budget > 0 && gui_wake_trace_task(t)) {
                printf("[eventwake] %s id=%d pid=%d cmd=%s counter=%llu\n",
                       side ? side : "?", eventfd_id, t->pid, t->name,
                       (unsigned long long)
                           eventfd_counter_snapshot(eventfd_id));
                wake_trace_budget--;
            }
            woke++;
        }
    }
    return woke;
}

static int pipe_read_ready_for_wakeup(int pipe_id) {
    edge_pipe_t *pp;
    if (pipe_id < 0 || pipe_id >= EDGE_MAX_PIPES) return 1;
    pp = &g_pipes[pipe_id];
    if (!pp->used) return 1;
    /*
     * Normal pipe readers wake for data or EOF.  A blocking FIFO reader in
     * open(2) also waits on this queue before it has a returned fd; a pending
     * writer is enough to complete that Linux FIFO rendezvous even though no
     * data has been written yet.  The subsequent read(2) path will re-check
     * count/writers and sleep again until bytes or EOF are actually visible.
     */
    return kernel_pipe_read_wake_ready(pp, 1);
}

static int pipe_write_ready_for_wakeup(int pipe_id) {
    edge_pipe_t *pp;
    if (pipe_id < 0 || pipe_id >= EDGE_MAX_PIPES) return 1;
    pp = &g_pipes[pipe_id];
    if (!pp->used) return 1;
    return kernel_pipe_write_wake_ready(pp);
}

static int pipe_waiter_wake_registered(int waiters[EDGE_MAX_PIPES][EDGE_PIPE_WAITERS],
                                       const char *side, int pipe_id,
                                       int (*ready_fn)(int), task_t *cur) {
    int waiter_pids[EDGE_PIPE_WAITERS];
    uint64_t irq_flags;
    int woke = 0;
    static int wake_trace_budget = EDGE_GUI_DEEP_TRACE ? 128 : 0;
    if (pipe_id < 0 || pipe_id >= EDGE_MAX_PIPES) return 0;
    if (ready_fn && !ready_fn(pipe_id)) return 0;
    irq_flags = spin_lock_irqsave(&g_waiter_lock);
    memcpy(waiter_pids, waiters[pipe_id], sizeof(waiter_pids));
    spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    for (int i = 0; i < EDGE_PIPE_WAITERS; ++i) {
        int pid = waiter_pids[i];
        task_t *t;
        if (pid <= 0) continue;
        t = (task_t *)(uintptr_t)process_get_task(pid);
        if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE)
            continue;
        if (cur && t == cur) continue;
        if (t->state == TASK_BLOCKED && t->fd_wait_active) {
            uint32_t cpu = scheduler_cpu_id();
            scheduler_task_make_runnable(t, cpu);
            if (wake_trace_budget > 0 && gui_wake_trace_task(t)) {
                printf("[pipewake] %s id=%d pid=%d cmd=%s count=%u r=%d w=%d\n",
                       side ? side : "?", pipe_id, t->pid, t->name,
                       g_pipes[pipe_id].count, g_pipes[pipe_id].readers,
                       g_pipes[pipe_id].writers);
                wake_trace_budget--;
            }
            woke++;
        }
    }
    return woke;
}

static int waiter_membership_ready_for_pid(const uint64_t *membership,
                                           uint32_t limit, int pid,
                                           edge_waiter_membership_kind_t kind) {
    uint32_t words = EDGE_WAITER_BITMAP_WORDS(limit);

    if (!membership || pid <= 0) return 0;
    for (uint32_t word = 0; word < words; ++word) {
        uint64_t bits = membership[word];
        while (bits) {
            uint32_t bit = (uint32_t)__builtin_ctzll(bits);
            uint32_t object_id = word * 64u + bit;
            int ready = 0;

            if (object_id >= limit) break;
            switch (kind) {
                case EDGE_WAITER_SOCKET: {
                    uint16_t events = 0;
                    uint64_t irq_flags =
                        spin_lock_irqsave(&g_waiter_lock);
                    for (int index = 0;
                         index < EDGE_SOCKET_WAITERS; ++index) {
                        if (g_socket_waiter_pids[object_id][index] == pid)
                            events |=
                                g_socket_waiter_events[object_id][index];
                    }
                    spin_unlock_irqrestore(
                        &g_waiter_lock, irq_flags);
                    if (events)
                        ready = socket_ready_for_waiter(
                            (int)object_id, events);
                    break;
                }
                case EDGE_WAITER_EVENTFD_READ:
                case EDGE_WAITER_EVENTFD_WRITE: {
                    kernel_eventfd_state_t state;
                    if (eventfd_snapshot((int)object_id, &state))
                        ready = kind == EDGE_WAITER_EVENTFD_WRITE ?
                            state.counter < UINT64_MAX - 1u :
                            state.counter > 0;
                    break;
                }
                case EDGE_WAITER_PIPE_READ:
                    ready = pipe_read_ready_for_wakeup(
                        (int)object_id);
                    break;
                case EDGE_WAITER_PIPE_WRITE:
                    ready = pipe_write_ready_for_wakeup(
                        (int)object_id);
                    break;
            }
            if (ready) return 1;
            bits &= bits - 1u;
        }
    }
    return 0;
}

static int waiter_task_ready_after_block(int pid) {
    edge_waiter_owner_t owner_snapshot;
    edge_waiter_owner_t *owner;
    uint64_t irq_flags;

    memset(&owner_snapshot, 0, sizeof(owner_snapshot));
    irq_flags = spin_lock_irqsave(&g_waiter_lock);
    owner = waiter_owner_find(pid, 0);
    if (owner) memcpy(&owner_snapshot, owner, sizeof(owner_snapshot));
    spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    if (!owner_snapshot.pid) return 0;
    if (waiter_membership_ready_for_pid(
            owner_snapshot.sockets, EDGE_MAX_SOCKETS, pid,
            EDGE_WAITER_SOCKET))
        return 1;
    if (waiter_membership_ready_for_pid(
            owner_snapshot.eventfd_read, EDGE_MAX_EVENTFDS, pid,
            EDGE_WAITER_EVENTFD_READ))
        return 1;
    if (waiter_membership_ready_for_pid(
            owner_snapshot.eventfd_write, EDGE_MAX_EVENTFDS, pid,
            EDGE_WAITER_EVENTFD_WRITE))
        return 1;
    if (waiter_membership_ready_for_pid(
            owner_snapshot.pipe_read, EDGE_MAX_PIPES, pid,
            EDGE_WAITER_PIPE_READ))
        return 1;
    return waiter_membership_ready_for_pid(
        owner_snapshot.pipe_write, EDGE_MAX_PIPES, pid,
        EDGE_WAITER_PIPE_WRITE);
}

static int signal_pending_wait_wakeup(const task_t *task) {
    uint64_t available;

    if (!task) return 0;
    if (process_task_group_exit_requested(task, 0)) return 1;
    available = task_pending_signal_mask(task) &
        (~task->sigmask | EDGE_LINUX_SIGNAL_UNBLOCKABLE_MASK);
    for (uint32_t signal = 1; signal <= EDGE_LINUX_SIGNAL_MAX; ++signal) {
        edge_linux_signal_action_t *action;
        edge_linux_signal_default_disposition_t disposition;

        if (!(available & edge_linux_signal_mask_bit(signal))) continue;
        action = task_signal_action_local(task, signal);
        if (!action || action->handler == LINUX_SIG_IGN) continue;
        disposition = edge_linux_signal_default_disposition(signal);
        if (action->handler == LINUX_SIG_DFL &&
            (disposition == EDGE_LINUX_SIGNAL_DEFAULT_IGNORE ||
             disposition == EDGE_LINUX_SIGNAL_DEFAULT_CONTINUE))
            continue;
        return 1;
    }
    return 0;
}

static void socket_blocking_wait_step_checked(
        uint64_t deadline_us, fd_wait_post_block_fn post_block,
        void *post_block_context) {
    task_t *cur = process_current_task();
    if (!cur || cur->is_idle) {
        wait_blocking_step();
        return;
    }

    /*
     * Linux wait queues leave tasks off the run queue until readiness, a
     * signal, or an optional timeout.  Keeping socket/pipe waiters runnable
     * made quiet daemons such as udhcpc burn a vCPU while blocked in
     * recvfrom/poll/select.  EdgeOS still uses compact fd-owner scans for
     * wakeups; sleep_waiters_irq_poll() handles finite deadlines.
     */
    if (deadline_us) {
        cur->sleep_deadline_us = deadline_us;
        cur->sleep_wait_active = 1;
    } else {
        cur->sleep_wait_active = 0;
        cur->sleep_deadline_us = 0;
    }
    cur->fd_wait_active = 1;
    scheduler_task_set_blocked(cur);
    /*
     * Publish the blocked state before the final condition check.  A producer
     * can otherwise make an fd ready after the caller's pre-sleep scan but
     * before this task becomes blockable: its wake sees a runnable task, then
     * this path sleeps forever on an infinite poll.  Once TASK_BLOCKED and
     * fd_wait_active are visible, either this check observes readiness or a
     * later producer wake makes the task runnable.
     */
    /*
     * A checked poll/select/epoll wait must use its syscall-level predicate.
     * The compact object helper is level-triggered and does not know whether
     * an EPOLLET watch already consumed the current edge; consulting it first
     * would immediately requeue a correctly blocked edge-triggered waiter.
     * Direct blocking I/O has no callback and still uses the object helper.
     */
    if (signal_pending_wait_wakeup(cur) ||
        (post_block ? post_block(post_block_context) :
                      waiter_task_ready_after_block(cur->pid)))
        scheduler_task_make_runnable(cur, scheduler_cpu_id());
    if (g_gui_wait_block_trace_budget > 0 && gui_diag_task(cur)) {
        printf("[gui-wait] block pid=%d cmd=%s deadline=%llu sys=%llu ret=%lld budget=%d\n",
               cur->pid, cur->name,
               (unsigned long long)deadline_us,
               (unsigned long long)cur->last_syscall_nr,
               (long long)cur->last_syscall_ret,
               g_gui_wait_block_trace_budget - 1);
        g_gui_wait_block_trace_budget--;
    }
    scheduler_yield();

    cur = process_current_task();
    if (cur && !cur->is_idle) {
        if (g_gui_wait_block_trace_budget > 0 && gui_diag_task(cur)) {
            printf("[gui-wait] wake pid=%d cmd=%s state=%d deadline=%llu sys=%llu ret=%lld budget=%d\n",
                   cur->pid, cur->name, (int)cur->state,
                   (unsigned long long)cur->sleep_deadline_us,
                   (unsigned long long)cur->last_syscall_nr,
                   (long long)cur->last_syscall_ret,
                   g_gui_wait_block_trace_budget - 1);
            g_gui_wait_block_trace_budget--;
        }
        cur->fd_wait_active = 0;
        cur->sleep_wait_active = 0;
        cur->sleep_deadline_us = 0;
        waiter_remove_pid(cur->pid);
    }
}

static void socket_blocking_wait_step(uint64_t deadline_us) {
    socket_blocking_wait_step_checked(deadline_us, 0, 0);
}

static edge_futex_waiter_t *futex_waiter_find_slot_by_pid(int pid) {
    if (pid <= 0) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        if (g_futex_waiters[i].used && g_futex_waiters[i].pid == pid) return &g_futex_waiters[i];
    }
    return 0;
}

static edge_futex_waiter_t *futex_waiter_alloc_slot_for_pid(int pid) {
    edge_futex_waiter_t *w = futex_waiter_find_slot_by_pid(pid);
    if (w) return w;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        if (!g_futex_waiters[i].used) return &g_futex_waiters[i];
    }
    return 0;
}

static void futex_waiter_clear(edge_futex_waiter_t *w) {
    if (!w) return;
    w->used = 0;
    w->waiting = 0;
    w->pid = 0;
    w->private_key = 0;
    w->uaddr = 0;
    w->bitset = 0;
    w->deadline_us = 0;
    w->result = 0;
    w->waitv_index = -1;
    w->waitv_count = 0;
}

static void futex_waiter_cancel_pid(int pid) {
    uint64_t irq_flags;

    if (pid <= 0) return;
    irq_flags = spin_lock_irqsave(&g_futex_lock);
    for (int index = 0; index < PROC_MAX_TASKS; ++index) {
        edge_futex_waiter_t *waiter = &g_futex_waiters[index];
        if (waiter->used && waiter->pid == pid)
            futex_waiter_clear(waiter);
    }
    kernel_futex_pi_waiter_cancel_locked(pid);
    spin_unlock_irqrestore(&g_futex_lock, irq_flags);
}

static int futex_private_key_for_task(task_t *t) {
    task_t *mm;
    if (!t) return 0;
    mm = process_vm_task(t);
    if (!mm) mm = t;
    return mm->pid > 0 ? mm->pid : t->pid;
}

static int futex_key_for_task(task_t *task, uint64_t address,
                              int private_futex, uint64_t *uaddr_key,
                              int *private_key) {
    uint64_t physical;
    if (!task || !uaddr_key || !private_key || (address & 3u))
        return -EINVAL;
    physical = user_pte_phys_for_cr3(task->cr3, address);
    if (!physical) return -EFAULT;
    if (private_futex) {
        *uaddr_key = address;
        *private_key = futex_private_key_for_task(task);
    } else {
        *uaddr_key = physical;
        *private_key = 0;
    }
    return 0;
}

static int futex_waiter_wake_matching_locked(uint64_t uaddr, int private_key,
                                              uint32_t max_wake,
                                              uint32_t mask, int result) {
    uint32_t woke = 0;
#if EDGE_XFCE_BOOT_TRACE
    static int futex_wake_trace_budget = 128;
#endif
    if (!max_wake) return 0;
    for (int i = 0; i < PROC_MAX_TASKS && woke < max_wake; ++i) {
        edge_futex_waiter_t *w = &g_futex_waiters[i];
        task_t *t;
        uint32_t wake_cpu;
        int vector_index = -1;
        if (!w->used || !w->waiting) continue;
        if (w->waitv_count) {
            for (uint32_t vector = 0; vector < w->waitv_count; ++vector) {
                if (w->waitv_keys[vector].uaddr == uaddr &&
                    w->waitv_keys[vector].private_key == private_key) {
                    vector_index = (int)vector;
                    break;
                }
            }
            if (vector_index < 0) continue;
        } else {
            if (w->uaddr != uaddr || w->private_key != private_key ||
                !(w->bitset & mask))
                continue;
            {
                kernel_futex_key_t key;
                key.value = uaddr;
                key.scope = (uintptr_t)(uint32_t)private_key;
                if (kernel_futex_pi_requeue_waiter_locked(
                        &key, w->pid))
                    continue;
            }
        }
        t = (task_t *)(uintptr_t)process_get_task(w->pid);
        w->waiting = 0;
        w->result = vector_index >= 0 ? vector_index : result;
        if (t && t->state == TASK_BLOCKED) {
            /*
             * Futex wake is the userspace scheduler fast path used by DBus,
             * GLib, pthread mutexes, and condition variables.  Linux wakes the
             * waiter promptly even if it last ran on another CPU.  Use the
             * current CPU for this dense handoff path: retaining the previous
             * CPU adds remote notification latency and regresses browser
             * process startup under KVM.
             */
            wake_cpu = scheduler_cpu_id();
            scheduler_task_make_runnable(t, wake_cpu);
        }
#if EDGE_XFCE_BOOT_TRACE
        if (futex_wake_trace_budget > 0 && t && t->name[0] &&
            (strcmp(t->name, "Xorg") == 0 ||
             strcmp(t->name, "xfce4-session") == 0 ||
             strcmp(t->name, "xfwm4") == 0 ||
             strcmp(t->name, "xfce4-panel") == 0 ||
             strcmp(t->name, "xfdesktop") == 0 ||
             strcmp(t->name, "xfsettingsd") == 0 ||
             strcmp(t->name, "dbus-daemon") == 0)) {
            printf("[futexdbg] wake u=0x%x key=%d pid=%d cmd=%s state=%d max=%d mask=0x%x result=%d budget=%d\n",
                   (uint32_t)uaddr, private_key, t->pid, t->name, t->state,
                   max_wake, mask, result, futex_wake_trace_budget);
            futex_wake_trace_budget--;
        }
#endif
        woke++;
    }
    return woke;
}

static int futex_waiter_wake_matching_key(uint64_t uaddr, int private_key,
                                           uint32_t max_wake,
                                           uint32_t mask, int result) {
    uint64_t flags;
    int woke;
    if (!max_wake) return 0;
    flags = spin_lock_irqsave(&g_futex_lock);
    woke = futex_waiter_wake_matching_locked(uaddr, private_key, max_wake, mask, result);
    spin_unlock_irqrestore(&g_futex_lock, flags);
    return woke;
}

static int futex_waiter_requeue_matching_locked(
    uint64_t old_uaddr, int old_private_key, uint64_t new_uaddr,
    int new_private_key, uint32_t max_requeue, uint32_t mask) {
    uint32_t moved = 0;
    if (!max_requeue) return 0;
    for (int i = 0; i < PROC_MAX_TASKS && moved < max_requeue; ++i) {
        edge_futex_waiter_t *w = &g_futex_waiters[i];
        if (!w->used || !w->waiting) continue;
        if (w->waitv_count) {
            int matched = 0;
            for (uint32_t vector = 0; vector < w->waitv_count; ++vector) {
                if (w->waitv_keys[vector].uaddr != old_uaddr ||
                    w->waitv_keys[vector].private_key != old_private_key)
                    continue;
                w->waitv_keys[vector].uaddr = new_uaddr;
                w->waitv_keys[vector].private_key = new_private_key;
                matched = 1;
                break;
            }
            if (!matched) continue;
        } else {
            if (w->uaddr != old_uaddr ||
                w->private_key != old_private_key ||
                !(w->bitset & mask))
                continue;
            w->uaddr = new_uaddr;
            w->private_key = new_private_key;
        }
        /*
         * Linux FUTEX_REQUEUE keeps the task asleep but moves it from one
         * futex key to another, normally from a condition variable to the
         * associated mutex.  Returning ENOSYS here lets userland believe the
         * condition variable operation happened while the waiter is still
         * queued on the old key, which strands GLib/Pango worker handoffs.
         */
        moved++;
    }
    return moved;
}

static void futex_waiters_irq_poll(void) {
    uint64_t now_us = boottime_monotonic_us();
    uint64_t flags = spin_lock_irqsave(&g_futex_lock);
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        edge_futex_waiter_t *w = &g_futex_waiters[i];
        task_t *t;
        uint32_t wake_cpu;
        if (!w->used) continue;
        t = (task_t *)(uintptr_t)process_get_task(w->pid);
        if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) {
            futex_waiter_clear(w);
            continue;
        }
        if (!w->waiting) continue;
        if (!w->deadline_us || now_us < w->deadline_us) continue;
        w->waiting = 0;
        w->result = -ETIMEDOUT;
        if (t->state == TASK_BLOCKED) {
            /*
             * Timer polling is intentionally centralized, but timeout expiry
             * must not concentrate every sleeping task on that timer CPU.
             * Preserve the waiter's runqueue owner and use the reschedule IPI
             * implemented by the shared scheduler when that owner is remote.
             * An explicit FUTEX_WAKE remains a dense handoff to the waker;
             * timeout placement is a different policy because no userspace
             * waker supplies useful locality.
             */
            wake_cpu = t->assigned_cpu >= 0 ?
                (uint32_t)t->assigned_cpu : scheduler_cpu_id();
            scheduler_task_make_runnable(t, wake_cpu);
        }
    }
    spin_unlock_irqrestore(&g_futex_lock, flags);
}

static void task_timer_poll(void) {
    kernel_posix_timer_poll();
    kernel_itimer_real_poll();
}

static void sleep_waiters_irq_poll(void) {
    uint64_t now = boottime_monotonic_us();
    task_timer_poll();
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = (task_t *)(uintptr_t)process_task_by_index(i);
        if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) continue;
        if (!t->sleep_wait_active) continue;
        if (now < t->sleep_deadline_us) continue;
        t->sleep_wait_active = 0;
        t->sleep_deadline_us = 0;
        if (t->state == TASK_BLOCKED) {
            if (g_sleep_trace_budget > 0) {
                printf("[sleepdbg] irq-expire pid=%d cmd=%s now=%llu cpu=%u assigned=%d state=%d budget=%d\n",
                       t->pid, t->name,
                       (unsigned long long)now,
                       scheduler_cpu_id(),
                       t->assigned_cpu,
                       (int)t->state,
                       g_sleep_trace_budget - 1);
                g_sleep_trace_budget--;
            }
            /*
             * Timer polling is centralized on one CPU.  Moving every expired
             * sleeper to that CPU collapses SMP desktop workloads onto a
             * single runqueue, especially software-rendered compositors and
             * browser workers that use frequent short sleeps.  Keep the task
             * on its previous owner; scheduler_task_make_runnable() sends the
             * remote reschedule IPI and handles a concurrent stack handoff.
             *
             * Red flag: this is runqueue placement policy for every timed
             * sleeper.  Do not add desktop, process, or rootfs special cases.
             */
            uint32_t wake_cpu = t->assigned_cpu >= 0 ?
                (uint32_t)t->assigned_cpu : scheduler_cpu_id();
            scheduler_task_make_runnable(t, wake_cpu);
        }
    }
}

static uint32_t edge_bswap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) |
           ((v & 0xFF000000u) >> 24);
}

static int fdset_test(const uint8_t *set, int fd) {
    if (!set || fd < 0 || fd >= EDGE_SELECT_FD_MAX) return 0;
    return (set[fd >> 3] & (uint8_t)(1u << (fd & 7))) != 0;
}

static uint16_t edge_bswap16(uint16_t v) {
    return (uint16_t)(((v & 0x00FFu) << 8) | ((v & 0xFF00u) >> 8));
}

static void edge_ip6_to_bytes(const ip6_addr_t *a, uint8_t out[16]) {
    if (!a || !out) return;
    for (int i = 0; i < 4; ++i) {
        uint32_t w = lwip_htonl(a->addr[i]);
        out[i * 4 + 0] = (uint8_t)((w >> 24) & 0xFFu);
        out[i * 4 + 1] = (uint8_t)((w >> 16) & 0xFFu);
        out[i * 4 + 2] = (uint8_t)((w >> 8) & 0xFFu);
        out[i * 4 + 3] = (uint8_t)(w & 0xFFu);
    }
}

static void x86_file_description_detach(void *context,
                                        uint64_t identity) {
    (void)context;
    input_device_release_description(identity);
    kernel_epoll_detach_description(identity);
    kernel_proc_maps_description_release(identity);
}

static void net_init_defaults(void) {
    kernel_file_description_ops_t file_description_ops = {
        .detach_description = x86_file_description_detach,
        .release_payload = 0,
        .context = 0,
    };

    spinlock_init(&g_raw_ipv4_tx_lock);
    spinlock_init(&g_waiter_lock);
    spinlock_init(&g_fd_proc_registry_lock);
    if (kernel_file_description_runtime_initialize(
            &file_description_ops) < 0)
        printf("[file-description] shared runtime initialization failed\n");
    memset(&g_if_lo, 0, sizeof(g_if_lo));
    strcpy(g_if_lo.name, "lo");
    g_if_lo.up = 1;
    g_if_lo.ifindex = 1;
    g_if_lo.flags = LINUX_IFF_UP | LINUX_IFF_RUNNING | LINUX_IFF_LOOPBACK;
    g_if_lo.mtu = 65536;
    g_if_lo.ipv4_addr_be = edge_bswap32(0x7F000001u);
    g_if_lo.ipv4_netmask_be = edge_bswap32(0xFF000000u);
    g_if_lo.ipv4_bcast_be = edge_bswap32(0x7FFFFFFFu);
    g_if_lo.ipv4_dst_be = g_if_lo.ipv4_addr_be;

    memset(&g_if_eth0, 0, sizeof(g_if_eth0));
    strcpy(g_if_eth0.name, "eth0");
    g_if_eth0.up = 1;
    g_if_eth0.ifindex = 2;
    g_if_eth0.flags = LINUX_IFF_UP | LINUX_IFF_RUNNING | LINUX_IFF_BROADCAST | LINUX_IFF_MULTICAST;
    g_if_eth0.mtu = 1500;
    g_if_eth0.mac[0] = 0x52;
    g_if_eth0.mac[1] = 0x54;
    g_if_eth0.mac[2] = 0x00;
    g_if_eth0.mac[3] = 0x12;
    g_if_eth0.mac[4] = 0x34;
    g_if_eth0.mac[5] = 0x56;
    /*
     * Mirror the stable QEMU user-net defaults used by lwIP.  DHCP/netlink
     * support can still overwrite these values, but the kernel must not depend
     * on an incomplete userspace configuration path before basic networking
     * works.  See lwip_stack_init() for the validation required before making
     * this DHCP-only again.
     */
    g_if_eth0.ipv4_addr_be = edge_bswap32(0x0A00020Fu);
    g_if_eth0.ipv4_netmask_be = edge_bswap32(0xFFFFFF00u);
    g_if_eth0.ipv4_bcast_be = edge_bswap32(0x0A0002FFu);
    g_if_eth0.ipv4_dst_be = edge_bswap32(0x0A000202u);
}

static edge_netif_t *netif_by_name(const char *name) {
    if (!name || !name[0]) return &g_if_eth0;
    if (strcmp(name, g_if_lo.name) == 0) return &g_if_lo;
    if (strcmp(name, g_if_eth0.name) == 0) return &g_if_eth0;
    return 0;
}

static edge_netif_t *netif_by_index(int ifindex) {
    if (ifindex == g_if_lo.ifindex) return &g_if_lo;
    if (ifindex == g_if_eth0.ifindex) return &g_if_eth0;
    return 0;
}

static void netif_apply_ipv4_to_lwip(const edge_netif_t *nif) {
    if (!nif || strcmp(nif->name, "eth0") != 0) return;
    (void)lwip_stack_configure_ipv4(nif->ipv4_addr_be,
                                    nif->ipv4_netmask_be,
                                    nif->ipv4_dst_be);
}

static int socket_alloc(void) {
    static int socket_high_water;
    static int socket_oom_log_budget = 16;
    static int socket_alloc_trace_budget = EDGE_XFCE_BOOT_TRACE ? 128 : 0;
    if (!g_socket_table_ready || !g_sockets || !g_socket_rx_storage_ready) {
        task_t *cur = process_current_task();
        if (socket_oom_log_budget-- > 0) {
            printf("[sock-alloc] no-runtime-backing pid=%d cmd=%s max=%d table_ready=%d table_pages=%u rx_ready=%d rx_pages=%u\n",
                   cur ? cur->pid : -1,
                   cur && cur->name[0] ? cur->name : "?",
                   EDGE_MAX_SOCKETS, g_socket_table_ready, g_socket_table_pages,
                   g_socket_rx_storage_ready, g_socket_rx_storage_pages);
        }
        return -1;
    }
    {
        int i = kernel_socket_slot_claim(
            g_socket_slot_claims, EDGE_MAX_SOCKETS);

        if (i >= 0) {
            int used = 0;
            uint64_t waiter_irq_flags;
            task_t *cur = process_current_task();
            memset(&g_sockets[i], 0, sizeof(g_sockets[i]));
            waiter_irq_flags =
                spin_lock_irqsave(&g_waiter_lock);
            memset(g_socket_waiter_pids[i], 0,
                   sizeof(g_socket_waiter_pids[i]));
            memset(g_socket_waiter_events[i], 0,
                   sizeof(g_socket_waiter_events[i]));
            g_socket_waiter_overflow[i] = 0;
            spin_unlock_irqrestore(
                &g_waiter_lock, waiter_irq_flags);
            g_sockets[i].rx_buf = socket_rx_buffer_for_id(i);
            if (!g_sockets[i].rx_buf) {
                kernel_socket_slot_release(
                    g_socket_slot_claims, EDGE_MAX_SOCKETS, (uint32_t)i);
                return -1;
            }
            memset(g_sockets[i].rx_buf, 0, EDGE_SOCKET_RX_BUF_SIZE);
            spinlock_init(&g_sockets[i].io_lock);
            kernel_socket_rights_queue_initialize(
                &g_sockets[i].rights,
                KERNEL_SOCKET_RIGHTS_DEFAULT_QUEUE_LIMIT);
            kernel_socket_accept_queue_initialize(
                &g_sockets[i].accept_queue);
            kernel_socket_readiness_initialize(&g_sockets[i].readiness);
            kernel_socket_external_readiness_initialize(
                &g_sockets[i].external_readiness,
                lwip_stack_packet_frame_readiness_sequence(),
                lwip_stack_icmp_readiness_sequence(), 0u);
            g_sockets[i].used = 1;
            g_sockets[i].refs = 1;
            g_sockets[i].packet_handle = -1;
            g_sockets[i].bpf_filter_object_id = -1;
            if (socket_alloc_trace_budget > 0 && socket_pending_trace_task(cur)) {
                printf("[sock-life] alloc pid=%d cmd=%s sid=%d budget=%d\n",
                       cur ? cur->pid : -1,
                       cur && cur->name[0] ? cur->name : "?",
                       i, socket_alloc_trace_budget - 1);
                socket_alloc_trace_budget--;
            }
            for (int j = 0; j < EDGE_MAX_SOCKETS; ++j) {
                if (g_sockets[j].used) used++;
            }
            if (used > socket_high_water) socket_high_water = used;
            return i;
        }
    }
    if (socket_oom_log_budget-- > 0) {
        int unix_stream = 0, unix_listen = 0, inet = 0, netlink = 0, packet = 0;
        int connected = 0, closed = 0, pending_total = 0, refs_total = 0;
        task_t *cur = process_current_task();
        for (int i = 0; i < EDGE_MAX_SOCKETS; ++i) {
            edge_socket_t *s = &g_sockets[i];
            if (!s->used) continue;
            refs_total += s->refs;
            pending_total += socket_pending_count(s);
            if (s->domain == LINUX_AF_UNIX && s->type == LINUX_SOCK_STREAM) unix_stream++;
            else if (s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) inet++;
            else if (s->domain == LINUX_AF_NETLINK) netlink++;
            else if (s->domain == LINUX_AF_PACKET) packet++;
            if (s->listening) unix_listen++;
            if (s->connected || s->unix_peer_id >= 0) connected++;
            if (s->closed || s->rx_closed) closed++;
        }
        printf("[sock-alloc] exhausted pid=%d cmd=%s used=%d max=%d high=%d refs=%d unix_stream=%d listeners=%d inet=%d netlink=%d packet=%d connected=%d closed=%d pending=%d budget=%d\n",
               cur ? cur->pid : -1,
               cur && cur->name[0] ? cur->name : "?",
               EDGE_MAX_SOCKETS, EDGE_MAX_SOCKETS, socket_high_water,
               refs_total, unix_stream, unix_listen, inet, netlink, packet,
               connected, closed, pending_total, socket_oom_log_budget);
    }
    return -1;
}

static int socket_id_from_ptr(edge_socket_t *s) {
    if (!s) return -1;
    for (int i = 0; i < EDGE_MAX_SOCKETS; ++i) {
        if (&g_sockets[i] == s) return i;
    }
    return -1;
}

static void socket_set_cred_from_task(edge_socket_t *s, const task_t *t) {
    if (!s) return;
    s->cred_pid = t ? kernel_unix_socket_credential_pid(
        t->pid, t->tgid) : 0;
    s->cred_uid = t ? t->euid : 0;
    s->cred_gid = t ? t->egid : 0;
}

static void socket_set_peer_cred(edge_socket_t *s, const edge_socket_t *peer) {
    if (!s || !peer) return;
    s->peer_cred_pid = peer->cred_pid;
    s->peer_cred_uid = peer->cred_uid;
    s->peer_cred_gid = peer->cred_gid;
}

static void socket_set_peer_cred_from_task(edge_socket_t *s, const task_t *t) {
    if (!s) return;
    s->peer_cred_pid = t ? kernel_unix_socket_credential_pid(
        t->pid, t->tgid) : 0;
    s->peer_cred_uid = t ? t->euid : 0;
    s->peer_cred_gid = t ? t->egid : 0;
}

static uint16_t socket_alloc_ephemeral_port_be(void) {
    uint16_t p = g_next_ephemeral_port;
    g_next_ephemeral_port++;
    if (g_next_ephemeral_port < 49152) {
        g_next_ephemeral_port = 49152;
    }
    return edge_bswap16(p);
}

static void socket_set_bind_inet(edge_socket_t *s, uint32_t addr_be, uint16_t port_be) {
    struct edge_sockaddr_in sin;
    if (!s) return;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = LINUX_AF_INET;
    sin.sin_port = port_be;
    sin.sin_addr = addr_be;
    memcpy(s->bind_addr, &sin, sizeof(sin));
    s->bind_len = sizeof(sin);
}

static void socket_set_bind_inet6(edge_socket_t *s, const uint8_t addr[16], uint16_t port_be, uint32_t scope_id) {
    struct edge_sockaddr_in6 sin6;
    if (!s || !addr) return;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = LINUX_AF_INET6;
    sin6.sin6_port = port_be;
    sin6.sin6_scope_id = scope_id;
    memcpy(sin6.sin6_addr, addr, 16);
    memcpy(s->bind_addr, &sin6, sizeof(sin6));
    s->bind_len = sizeof(sin6);
}

static void socket_set_addr_unix_raw(uint8_t *dst, uint32_t *dst_len, const char *path) {
    struct edge_sockaddr_un sun;
    uint32_t path_len = 0;
    if (!dst || !dst_len) return;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = LINUX_AF_UNIX;
    if (path) {
        while (path_len < sizeof(sun.sun_path) && path[path_len]) path_len++;
        if (path_len > 0) memcpy(sun.sun_path, path, path_len);
    }
    memcpy(dst, &sun, sizeof(sun));
    *dst_len = (uint32_t)(sizeof(sun.sun_family) + path_len + ((path_len > 0) ? 1u : 0u));
}

static void socket_set_peer_unix(edge_socket_t *s, const char *path) {
    if (!s) return;
    socket_set_addr_unix_raw(s->peer_addr, &s->peer_len, path);
}

static void socket_set_rx_peer_unix(edge_socket_t *s, const char *path) {
    if (!s) return;
    socket_set_addr_unix_raw(s->rx_peer, &s->rx_peer_len, path);
}

static uint32_t netlink_align(uint32_t n) {
    return (n + 3u) & ~3u;
}

static int netlink_port_in_use(const edge_socket_t *owner, uint32_t port_id) {
    if (!port_id) return 0;
    for (int index = 0; index < EDGE_MAX_SOCKETS; ++index) {
        const edge_socket_t *candidate = &g_sockets[index];
        if (candidate != owner && candidate->used &&
            candidate->domain == LINUX_AF_NETLINK &&
            candidate->network_namespace == owner->network_namespace &&
            candidate->netlink_port_id == port_id)
            return 1;
    }
    return 0;
}

static int netlink_bind_port(edge_socket_t *socket, uint32_t requested,
                             uint32_t groups) {
    static uint32_t next_dynamic_port = 0x80000000u;
    uint32_t port_id = requested;
    if (!socket || socket->domain != LINUX_AF_NETLINK) return -EINVAL;
    if (socket->netlink_port_id) return -EINVAL;
    if (!port_id) port_id = (uint32_t)process_gettgid();
    if (requested && netlink_port_in_use(socket, port_id)) return -EADDRINUSE;
    while (!port_id || netlink_port_in_use(socket, port_id)) {
        port_id = next_dynamic_port++;
        if (next_dynamic_port < 0x80000000u) next_dynamic_port = 0x80000000u;
    }
    socket->netlink_port_id = port_id;
    socket->netlink_groups = groups;
    return 0;
}

static int netlink_ensure_bound(edge_socket_t *socket) {
    return socket && socket->netlink_port_id ? 0 :
           netlink_bind_port(socket, 0, 0);
}

static uint32_t netlink_append_link(uint8_t *buf, uint32_t off, uint32_t cap,
                                    const struct edge_linux_nlmsghdr *req,
                                    const edge_netif_t *nif) {
    struct edge_linux_nlmsghdr hdr;
    struct edge_linux_ifinfomsg ifi;
    struct edge_linux_rtattr attr;
    const char *name;
    uint32_t name_len;
    uint32_t attr_len;
    uint32_t msg_len;
    uint32_t padded_attr_len;
    if (!buf || !req || !nif) return off;
    name = nif->name;
    name_len = (uint32_t)strlen(name) + 1u;
    attr_len = (uint32_t)sizeof(attr) + name_len;
    padded_attr_len = netlink_align(attr_len);
    msg_len = (uint32_t)sizeof(hdr) + (uint32_t)sizeof(ifi) + padded_attr_len;
    if (off + msg_len > cap) return off;

    memset(&hdr, 0, sizeof(hdr));
    hdr.nlmsg_len = msg_len;
    hdr.nlmsg_type = LINUX_RTM_NEWLINK;
    hdr.nlmsg_flags = (req->nlmsg_flags & LINUX_NLM_F_DUMP) ?
                      LINUX_NLM_F_MULTI : 0;
    hdr.nlmsg_seq = req->nlmsg_seq;
    hdr.nlmsg_pid = req->nlmsg_pid;
    memcpy(buf + off, &hdr, sizeof(hdr));
    off += (uint32_t)sizeof(hdr);

    memset(&ifi, 0, sizeof(ifi));
    ifi.ifi_type = (uint16_t)((strcmp(nif->name, "lo") == 0) ? LINUX_ARPHRD_LOOPBACK : LINUX_ARPHRD_ETHER);
    ifi.ifi_index = nif->ifindex;
    ifi.ifi_flags = nif->flags;
    ifi.ifi_change = 0xFFFFFFFFu;
    memcpy(buf + off, &ifi, sizeof(ifi));
    off += (uint32_t)sizeof(ifi);

    memset(&attr, 0, sizeof(attr));
    attr.rta_len = (uint16_t)attr_len;
    attr.rta_type = LINUX_IFLA_IFNAME;
    memcpy(buf + off, &attr, sizeof(attr));
    memcpy(buf + off + sizeof(attr), name, name_len);
    memset(buf + off + attr_len, 0, padded_attr_len - attr_len);
    off += padded_attr_len;
    return off;
}

static uint32_t netlink_attr_put(uint8_t *buf, uint32_t off, uint32_t cap,
                                 uint16_t type, const void *data, uint32_t data_len) {
    struct edge_linux_rtattr attr;
    uint32_t attr_len = (uint32_t)sizeof(attr) + data_len;
    uint32_t padded = netlink_align(attr_len);
    if (!buf || !data || off + padded > cap) return off;
    memset(&attr, 0, sizeof(attr));
    attr.rta_len = (uint16_t)attr_len;
    attr.rta_type = type;
    memcpy(buf + off, &attr, sizeof(attr));
    memcpy(buf + off + sizeof(attr), data, data_len);
    if (padded > attr_len) memset(buf + off + attr_len, 0, padded - attr_len);
    return off + padded;
}

static uint8_t ipv4_prefix_from_mask_be(uint32_t mask_be) {
    uint32_t mask = edge_bswap32(mask_be);
    uint8_t prefix = 0;
    for (int bit = 31; bit >= 0; --bit) {
        if ((mask & (1u << bit)) == 0) break;
        prefix++;
    }
    return prefix;
}

static uint32_t ipv4_mask_be_from_prefix(uint8_t prefix) {
    uint32_t mask;
    if (prefix == 0) return 0;
    if (prefix >= 32) return edge_bswap32(0xFFFFFFFFu);
    mask = 0xFFFFFFFFu << (32u - prefix);
    return edge_bswap32(mask);
}

static uint32_t ipv4_broadcast_be(uint32_t addr_be, uint32_t mask_be) {
    uint32_t addr = edge_bswap32(addr_be);
    uint32_t mask = edge_bswap32(mask_be);
    return edge_bswap32((addr & mask) | ~mask);
}

static uint32_t netlink_append_addr(uint8_t *buf, uint32_t off, uint32_t cap,
                                    const struct edge_linux_nlmsghdr *req,
                                    const edge_netif_t *nif) {
    struct edge_linux_nlmsghdr hdr;
    struct edge_linux_ifaddrmsg ifa;
    uint32_t start = off;
    if (!buf || !req || !nif || nif->ipv4_addr_be == 0) return off;
    if (off + sizeof(hdr) + sizeof(ifa) > cap) return off;

    memset(&hdr, 0, sizeof(hdr));
    hdr.nlmsg_type = LINUX_RTM_NEWADDR;
    hdr.nlmsg_flags = LINUX_NLM_F_MULTI;
    hdr.nlmsg_seq = req->nlmsg_seq;
    hdr.nlmsg_pid = req->nlmsg_pid;
    memcpy(buf + off, &hdr, sizeof(hdr));
    off += (uint32_t)sizeof(hdr);

    memset(&ifa, 0, sizeof(ifa));
    ifa.ifa_family = LINUX_AF_INET;
    ifa.ifa_prefixlen = ipv4_prefix_from_mask_be(nif->ipv4_netmask_be);
    ifa.ifa_index = (uint32_t)nif->ifindex;
    memcpy(buf + off, &ifa, sizeof(ifa));
    off += (uint32_t)sizeof(ifa);

    off = netlink_attr_put(buf, off, cap, LINUX_IFA_ADDRESS, &nif->ipv4_addr_be, sizeof(nif->ipv4_addr_be));
    off = netlink_attr_put(buf, off, cap, LINUX_IFA_LOCAL, &nif->ipv4_addr_be, sizeof(nif->ipv4_addr_be));
    if (nif->ipv4_bcast_be != 0) {
        off = netlink_attr_put(buf, off, cap, LINUX_IFA_BROADCAST, &nif->ipv4_bcast_be, sizeof(nif->ipv4_bcast_be));
    }

    hdr.nlmsg_len = off - start;
    memcpy(buf + start, &hdr, sizeof(hdr));
    return off;
}

static uint32_t netlink_append_route(uint8_t *buf, uint32_t off, uint32_t cap,
                                     const struct edge_linux_nlmsghdr *req,
                                     const edge_netif_t *nif,
                                     uint32_t destination_be,
                                     uint8_t destination_prefix,
                                     int include_gateway) {
    struct edge_linux_nlmsghdr hdr;
    struct edge_linux_rtmsg rtm;
    struct edge_linux_rta_cacheinfo cache_info;
    uint32_t start = off;
    uint32_t oif;
    if (!buf || !req || !nif || !nif->ipv4_addr_be) return off;
    if (off + sizeof(hdr) + sizeof(rtm) > cap) return off;

    memset(&hdr, 0, sizeof(hdr));
    hdr.nlmsg_type = LINUX_RTM_NEWROUTE;
    hdr.nlmsg_flags = (req->nlmsg_flags & LINUX_NLM_F_DUMP) ?
                      LINUX_NLM_F_MULTI : 0u;
    hdr.nlmsg_seq = req->nlmsg_seq;
    hdr.nlmsg_pid = req->nlmsg_pid;
    memcpy(buf + off, &hdr, sizeof(hdr));
    off += (uint32_t)sizeof(hdr);

    memset(&rtm, 0, sizeof(rtm));
    rtm.rtm_family = LINUX_AF_INET;
    rtm.rtm_dst_len = destination_prefix;
    rtm.rtm_table = LINUX_RT_TABLE_MAIN;
    rtm.rtm_protocol = LINUX_RTPROT_BOOT;
    rtm.rtm_scope = nif == &g_if_lo ? LINUX_RT_SCOPE_HOST :
                    include_gateway ? LINUX_RT_SCOPE_UNIVERSE :
                    LINUX_RT_SCOPE_LINK;
    rtm.rtm_type = LINUX_RTN_UNICAST;
    memcpy(buf + off, &rtm, sizeof(rtm));
    off += (uint32_t)sizeof(rtm);

    if (destination_prefix)
        off = netlink_attr_put(buf, off, cap, LINUX_RTA_DST,
                               &destination_be, sizeof(destination_be));
    oif = (uint32_t)nif->ifindex;
    off = netlink_attr_put(buf, off, cap, LINUX_RTA_OIF, &oif, sizeof(oif));
    if (include_gateway && nif->ipv4_dst_be)
        off = netlink_attr_put(buf, off, cap, LINUX_RTA_GATEWAY,
                               &nif->ipv4_dst_be, sizeof(nif->ipv4_dst_be));
    off = netlink_attr_put(buf, off, cap, LINUX_RTA_PREFSRC,
                           &nif->ipv4_addr_be, sizeof(nif->ipv4_addr_be));
    memset(&cache_info, 0, sizeof(cache_info));
    off = netlink_attr_put(buf, off, cap, EDGE_LINUX_RTA_CACHEINFO,
                           &cache_info, sizeof(cache_info));

    hdr.nlmsg_len = off - start;
    memcpy(buf + start, &hdr, sizeof(hdr));
    return off;
}

static uint32_t netlink_append_neighbor(uint8_t *buf, uint32_t off, uint32_t cap,
                                       const struct edge_linux_nlmsghdr *req,
                                       uint32_t address_be,
                                       const uint8_t mac[6], int32_t ifindex) {
    struct edge_linux_nlmsghdr hdr;
    struct edge_linux_ndmsg ndm;
    uint32_t start = off;
    if (!buf || !req || !mac ||
        off + sizeof(hdr) + sizeof(ndm) + 24u > cap)
        return off;
    memset(&hdr, 0, sizeof(hdr));
    hdr.nlmsg_type = LINUX_RTM_NEWNEIGH;
    hdr.nlmsg_flags = LINUX_NLM_F_MULTI;
    hdr.nlmsg_seq = req->nlmsg_seq;
    hdr.nlmsg_pid = req->nlmsg_pid;
    memcpy(buf + off, &hdr, sizeof(hdr));
    off += (uint32_t)sizeof(hdr);
    memset(&ndm, 0, sizeof(ndm));
    ndm.ndm_family = LINUX_AF_INET;
    ndm.ndm_ifindex = ifindex;
    ndm.ndm_state = LINUX_NUD_REACHABLE;
    ndm.ndm_type = LINUX_RTN_UNICAST;
    memcpy(buf + off, &ndm, sizeof(ndm));
    off += (uint32_t)sizeof(ndm);
    off = netlink_attr_put(buf, off, cap, LINUX_NDA_DST,
                           &address_be, sizeof(address_be));
    off = netlink_attr_put(buf, off, cap, LINUX_NDA_LLADDR, mac, 6u);
    hdr.nlmsg_len = off - start;
    memcpy(buf + start, &hdr, sizeof(hdr));
    return off;
}

static int netlink_queue_done(edge_socket_t *s,
                              const struct edge_linux_nlmsghdr *req,
                              uint32_t response_start, uint32_t off) {
    struct {
        struct edge_linux_nlmsghdr header;
        int32_t status;
    } done;
    if (!s || !req || response_start > off || off > socket_rx_capacity(s))
        return -EINVAL;
    if (s->packet_count >= EDGE_SOCKET_PACKET_QUEUE ||
        (off > response_start &&
         s->packet_count + 1u >= EDGE_SOCKET_PACKET_QUEUE))
        return -EAGAIN;
    if (off + sizeof(done) > socket_rx_capacity(s)) return -ENOBUFS;
    if (off > response_start &&
        socket_packet_push(s, off - response_start) < 0)
        return -EAGAIN;
    memset(&done, 0, sizeof(done));
    done.header.nlmsg_len = (uint32_t)sizeof(done);
    done.header.nlmsg_type = LINUX_NLMSG_DONE;
    done.header.nlmsg_flags = LINUX_NLM_F_MULTI;
    done.header.nlmsg_seq = req->nlmsg_seq;
    done.header.nlmsg_pid = req->nlmsg_pid;
    memcpy(s->rx_buf + off, &done, sizeof(done));
    off += (uint32_t)sizeof(done);
    if (socket_packet_push(s, (uint32_t)sizeof(done)) < 0) return -EAGAIN;
    s->rx_len = off;
    fd_wake_socket_waiters_events(socket_id_from_ptr(s),
                                  LINUX_POLLIN | LINUX_POLLPRI);
    return 0;
}

static int netlink_queue_single(edge_socket_t *s, uint32_t response_start,
                                uint32_t off) {
    if (!s || response_start >= off || off > socket_rx_capacity(s))
        return -ENETUNREACH;
    if (s->packet_count >= EDGE_SOCKET_PACKET_QUEUE)
        return -EAGAIN;
    if (socket_packet_push(s, off - response_start) < 0)
        return -EAGAIN;
    s->rx_len = off;
    fd_wake_socket_waiters_events(socket_id_from_ptr(s),
                                  LINUX_POLLIN | LINUX_POLLPRI);
    return 0;
}

static int netlink_queue_error_reply(edge_socket_t *s,
                                     const struct edge_linux_nlmsghdr *req,
                                     int32_t error) {
    struct edge_linux_nlmsghdr out;
    struct edge_linux_nlmsgerr body;
    uint32_t start;
    uint32_t length = (uint32_t)(sizeof(out) + sizeof(body));
    if (!s || !req) return -EINVAL;
    start = s->rx_len;
    if (s->packet_count >= EDGE_SOCKET_PACKET_QUEUE ||
        start + length > socket_rx_capacity(s))
        return -EAGAIN;
    memset(&out, 0, sizeof(out));
    memset(&body, 0, sizeof(body));
    out.nlmsg_len = length;
    out.nlmsg_type = LINUX_NLMSG_ERROR;
    out.nlmsg_seq = req->nlmsg_seq;
    out.nlmsg_pid = req->nlmsg_pid;
    body.error = error;
    body.msg = *req;
    memcpy(s->rx_buf + start, &out, sizeof(out));
    memcpy(s->rx_buf + start + sizeof(out), &body, sizeof(body));
    if (socket_packet_push(s, length) < 0) return -EAGAIN;
    s->rx_len = start + length;
    fd_wake_socket_waiters_events(socket_id_from_ptr(s),
                                  LINUX_POLLIN | LINUX_POLLPRI);
    return 0;
}

static int netlink_queue_getlink(edge_socket_t *s,
                                 const struct edge_linux_nlmsghdr *req,
                                 const uint8_t *request, uint32_t length) {
    struct edge_linux_ifinfomsg query;
    const edge_netif_t *target = 0;
    int target_specified = 0;
    uint32_t start;
    uint32_t off;
    uint32_t dynamic_matches = 0;
    int result;
    if (!s || !req || !request || length < sizeof(*req)) return -EINVAL;
    start = s->rx_len;
    off = start;
    if (req->nlmsg_flags & LINUX_NLM_F_DUMP) {
        off = netlink_append_link(s->rx_buf, off,
                (uint32_t)socket_rx_capacity(s), req, &g_if_lo);
        if (!s->network_namespace)
            off = netlink_append_link(s->rx_buf, off,
                    (uint32_t)socket_rx_capacity(s), req, &g_if_eth0);
        result = edge_linux_rtnetlink_append_links(
            s->network_namespace, s->netlink_port_id, request, length,
            s->rx_buf, (uint32_t)socket_rx_capacity(s),
            &off, &dynamic_matches);
        if (result < 0) return result;
        return netlink_queue_done(s, req, start, off);
    }

    memset(&query, 0, sizeof(query));
    if (req->nlmsg_len >= sizeof(*req) + sizeof(query) &&
        req->nlmsg_len <= length) {
        uint32_t attr_offset = (uint32_t)(sizeof(*req) + sizeof(query));
        memcpy(&query, request + sizeof(*req), sizeof(query));
        if (query.ifi_index) {
            target_specified = 1;
            target = netif_by_index(query.ifi_index);
        }
        while (attr_offset + sizeof(struct edge_linux_rtattr) <=
               req->nlmsg_len) {
            struct edge_linux_rtattr attr;
            const uint8_t *name;
            uint32_t name_length;
            memcpy(&attr, request + attr_offset, sizeof(attr));
            if (attr.rta_len < sizeof(attr) ||
                attr_offset + attr.rta_len > req->nlmsg_len)
                break;
            if (attr.rta_type == LINUX_IFLA_IFNAME) {
                target_specified = 1;
                name = request + attr_offset + sizeof(attr);
                name_length = attr.rta_len - (uint32_t)sizeof(attr);
                if (name_length >= 3u && name[0] == 'l' &&
                    name[1] == 'o' && name[2] == 0)
                    target = &g_if_lo;
                else if (!s->network_namespace && name_length >= 5u &&
                         name[0] == 'e' &&
                         name[1] == 't' && name[2] == 'h' &&
                         name[3] == '0' && name[4] == 0)
                    target = &g_if_eth0;
                else
                    target = 0;
            }
            attr_offset += netlink_align(attr.rta_len);
        }
    }
    if (!target_specified)
        return netlink_queue_error_reply(s, req, -EINVAL);
    if (!target) {
        result = edge_linux_rtnetlink_append_links(
            s->network_namespace, s->netlink_port_id, request, length,
            s->rx_buf, (uint32_t)socket_rx_capacity(s),
            &off, &dynamic_matches);
        if (result < 0) return result;
        if (!dynamic_matches)
            return netlink_queue_error_reply(s, req, -ENODEV);
        if (socket_packet_push(s, off - start) < 0) return -EAGAIN;
        s->rx_len = off;
        fd_wake_socket_waiters_events(
            socket_id_from_ptr(s), LINUX_POLLIN | LINUX_POLLPRI);
        return 0;
    }
    off = netlink_append_link(s->rx_buf, off,
            (uint32_t)socket_rx_capacity(s), req, target);
    if (off == start) return -ENOBUFS;
    if (socket_packet_push(s, off - start) < 0) return -EAGAIN;
    s->rx_len = off;
    fd_wake_socket_waiters_events(socket_id_from_ptr(s),
                                  LINUX_POLLIN | LINUX_POLLPRI);
    return 0;
}

static int netlink_queue_getaddr(
    edge_socket_t *s, const struct edge_linux_nlmsghdr *req,
    const uint8_t *request, uint32_t length) {
    uint32_t start;
    uint32_t off;
    uint32_t dynamic_matches = 0;
    int result;
    if (!s || !req) return -EINVAL;
    start = s->rx_len;
    off = start;
    off = netlink_append_addr(s->rx_buf, off, (uint32_t)socket_rx_capacity(s), req, &g_if_lo);
    if (!s->network_namespace)
        off = netlink_append_addr(s->rx_buf, off,
            (uint32_t)socket_rx_capacity(s), req, &g_if_eth0);
    result = edge_linux_rtnetlink_append_addresses(
        s->network_namespace, s->netlink_port_id, request, length,
        s->rx_buf, (uint32_t)socket_rx_capacity(s),
        &off, &dynamic_matches);
    if (result < 0) return result;
    return netlink_queue_done(s, req, start, off);
}

static int netlink_queue_getroute(edge_socket_t *s,
                                  const struct edge_linux_nlmsghdr *req,
                                  const uint8_t *request, uint32_t length) {
    struct edge_linux_rtmsg query;
    const edge_netif_t *target = &g_if_eth0;
    uint32_t destination_be = 0;
    uint32_t attribute_offset;
    int include_gateway = 1;
    uint32_t start;
    uint32_t off;
    uint32_t dynamic_matches = 0;
    int result;
    if (!s || !req) return -EINVAL;
    memset(&query, 0, sizeof(query));
    if (request && length >= sizeof(*req) + sizeof(query)) {
        memcpy(&query, request + sizeof(*req), sizeof(query));
        attribute_offset = (uint32_t)(sizeof(*req) + sizeof(query));
        while (attribute_offset + sizeof(struct edge_linux_rtattr) <=
               req->nlmsg_len && attribute_offset +
               sizeof(struct edge_linux_rtattr) <= length) {
            struct edge_linux_rtattr attribute;
            memcpy(&attribute, request + attribute_offset, sizeof(attribute));
            if (attribute.rta_len < sizeof(attribute) ||
                attribute_offset + attribute.rta_len > req->nlmsg_len ||
                attribute_offset + attribute.rta_len > length)
                break;
            if (attribute.rta_type == LINUX_RTA_DST &&
                attribute.rta_len >= sizeof(attribute) + sizeof(destination_be))
                memcpy(&destination_be,
                       request + attribute_offset + sizeof(attribute),
                       sizeof(destination_be));
            attribute_offset += netlink_align(attribute.rta_len);
        }
    }
    start = s->rx_len;
    off = start;
    result = edge_linux_rtnetlink_append_route(
        s->network_namespace, s->netlink_port_id, request, length,
        s->rx_buf, (uint32_t)socket_rx_capacity(s),
        &off, &dynamic_matches);
    if (result < 0) return result;
    if (dynamic_matches)
        return (req->nlmsg_flags & LINUX_NLM_F_DUMP) == LINUX_NLM_F_DUMP ?
            netlink_queue_done(s, req, start, off) :
            netlink_queue_single(s, start, off);
    if (s->network_namespace)
        return (req->nlmsg_flags & LINUX_NLM_F_DUMP) == LINUX_NLM_F_DUMP ?
            netlink_queue_done(s, req, start, off) :
            netlink_queue_error_reply(s, req, -ENETUNREACH);
    if (query.rtm_family == 0 || query.rtm_family == LINUX_AF_INET) {
        if (query.rtm_dst_len && (destination_be & 0xffu) == 0x7fu) {
            target = &g_if_lo;
            include_gateway = 0;
        } else if (query.rtm_dst_len &&
                   (destination_be & g_if_eth0.ipv4_netmask_be) ==
                   (g_if_eth0.ipv4_addr_be & g_if_eth0.ipv4_netmask_be)) {
            include_gateway = 0;
        }
        off = netlink_append_route(s->rx_buf, off,
                (uint32_t)socket_rx_capacity(s), req, target,
                destination_be, query.rtm_dst_len, include_gateway);
    }
    return (req->nlmsg_flags & LINUX_NLM_F_DUMP) == LINUX_NLM_F_DUMP ?
        netlink_queue_done(s, req, start, off) :
        netlink_queue_single(s, start, off);
}

static int netlink_queue_getrule(edge_socket_t *s,
                                 const struct edge_linux_nlmsghdr *req,
                                 const uint8_t *request, uint32_t length) {
    uint32_t start;
    uint32_t off;
    uint32_t matches = 0;
    int result;

    if (!s || !req) return -EINVAL;
    start = s->rx_len;
    off = start;
    result = edge_linux_rtnetlink_append_rules(
        s->network_namespace, s->netlink_port_id, request, length,
        s->rx_buf, (uint32_t)socket_rx_capacity(s), &off, &matches);
    if (result < 0) return result;
    return netlink_queue_done(s, req, start, off);
}

static int netlink_queue_getnexthop(
    edge_socket_t *s, const struct edge_linux_nlmsghdr *req,
    const uint8_t *request, uint32_t length) {
    uint32_t start;
    uint32_t off;
    uint32_t matches = 0u;
    int result;

    if (!s || !req) return -EINVAL;
    start = s->rx_len;
    off = start;
    result = edge_linux_rtnetlink_append_nexthops(
        s->network_namespace, s->netlink_port_id, request, length,
        s->rx_buf, (uint32_t)socket_rx_capacity(s), &off, &matches);
    if (result < 0) return result;
    return netlink_queue_done(s, req, start, off);
}

static int netlink_queue_getneigh(edge_socket_t *s,
                                  const struct edge_linux_nlmsghdr *req,
                                  const uint8_t *request, uint32_t length) {
    struct edge_linux_ndmsg query;
    uint32_t start;
    uint32_t off;
    uint32_t dynamic_matches = 0;
    int result;
    if (!s || !req) return -EINVAL;
    memset(&query, 0, sizeof(query));
    if (request && length >= sizeof(*req) + sizeof(query))
        memcpy(&query, request + sizeof(*req), sizeof(query));
    start = s->rx_len;
    off = start;
    if ((query.ndm_family == 0 || query.ndm_family == LINUX_AF_INET) &&
        (query.ndm_ifindex == 0 || query.ndm_ifindex == g_if_eth0.ifindex)) {
        lwip_stack_poll();
        for (int ordinal = 0; ordinal < 256; ++ordinal) {
            uint32_t address_be;
            uint8_t mac[6];
            int ifindex;
            if (lwip_stack_get_ipv4_neighbor(ordinal, &address_be, mac,
                                              &ifindex) < 0)
                break;
            if (query.ndm_ifindex && query.ndm_ifindex != ifindex) continue;
            off = netlink_append_neighbor(s->rx_buf, off,
                    (uint32_t)socket_rx_capacity(s), req, address_be, mac,
                    ifindex);
        }
    }
    result = edge_linux_rtnetlink_append_neighbors(
        s->network_namespace, s->netlink_port_id, request, length,
        s->rx_buf, (uint32_t)socket_rx_capacity(s),
        &off, &dynamic_matches);
    if (result < 0) return result;
    return netlink_queue_done(s, req, start, off);
}

static int netlink_queue_getmdb(edge_socket_t *s,
                                const struct edge_linux_nlmsghdr *req,
                                const uint8_t *request, uint32_t length) {
    uint32_t start;
    uint32_t off;
    uint32_t matches = 0u;
    int result;

    if (!s || !req) return -EINVAL;
    start = s->rx_len;
    off = start;
    result = edge_linux_rtnetlink_append_mdb(
        s->network_namespace, s->netlink_port_id, request, length,
        s->rx_buf, (uint32_t)socket_rx_capacity(s),
        &off, &matches);
    if (result < 0) return result;
    return netlink_queue_done(s, req, start, off);
}

static int netlink_queue_getqdisc(edge_socket_t *s,
                                  const struct edge_linux_nlmsghdr *req,
                                  const uint8_t *request, uint32_t length) {
    uint32_t start;
    uint32_t off;
    uint32_t matches = 0u;
    int result;

    if (!s || !req) return -EINVAL;
    start = s->rx_len;
    off = start;
    result = edge_linux_rtnetlink_append_qdiscs(
        s->network_namespace, s->netlink_port_id, request, length,
        s->rx_buf, (uint32_t)socket_rx_capacity(s),
        &off, &matches);
    if (result < 0) return result;
    return netlink_queue_done(s, req, start, off);
}

static void netlink_apply_newaddr(const uint8_t *req, uint32_t len,
                                  const struct edge_linux_nlmsghdr *in) {
    const struct edge_linux_ifaddrmsg *ifa;
    uint32_t off;
    uint32_t addr_be = 0;
    uint32_t local_be = 0;
    uint32_t bcast_be = 0;
    edge_netif_t *nif;
    if (!req || !in || len < sizeof(*in) + sizeof(*ifa)) return;
    ifa = (const struct edge_linux_ifaddrmsg *)(req + sizeof(*in));
    if (ifa->ifa_family != LINUX_AF_INET) return;
    nif = (ifa->ifa_index == (uint32_t)g_if_lo.ifindex) ? &g_if_lo :
          (ifa->ifa_index == (uint32_t)g_if_eth0.ifindex) ? &g_if_eth0 : 0;
    if (!nif) return;

    off = (uint32_t)sizeof(*in) + (uint32_t)sizeof(*ifa);
    while (off + sizeof(struct edge_linux_rtattr) <= len) {
        struct edge_linux_rtattr attr;
        uint32_t data_len;
        memcpy(&attr, req + off, sizeof(attr));
        if (attr.rta_len < sizeof(attr) || off + attr.rta_len > len) break;
        data_len = (uint32_t)attr.rta_len - (uint32_t)sizeof(attr);
        if (data_len >= sizeof(uint32_t)) {
            if (attr.rta_type == LINUX_IFA_ADDRESS) memcpy(&addr_be, req + off + sizeof(attr), sizeof(addr_be));
            else if (attr.rta_type == LINUX_IFA_LOCAL) memcpy(&local_be, req + off + sizeof(attr), sizeof(local_be));
            else if (attr.rta_type == LINUX_IFA_BROADCAST) memcpy(&bcast_be, req + off + sizeof(attr), sizeof(bcast_be));
        }
        off += netlink_align((uint32_t)attr.rta_len);
    }

    if (local_be == 0) local_be = addr_be;
    if (local_be == 0) return;
    nif->ipv4_addr_be = local_be;
    nif->ipv4_netmask_be = ipv4_mask_be_from_prefix(ifa->ifa_prefixlen);
    nif->ipv4_bcast_be = bcast_be ? bcast_be : ipv4_broadcast_be(local_be, nif->ipv4_netmask_be);
    netif_apply_ipv4_to_lwip(nif);
}

static void netlink_apply_deladdr(const uint8_t *req, uint32_t len,
                                  const struct edge_linux_nlmsghdr *in) {
    const struct edge_linux_ifaddrmsg *ifa;
    edge_netif_t *nif;
    if (!req || !in || len < sizeof(*in) + sizeof(*ifa)) return;
    ifa = (const struct edge_linux_ifaddrmsg *)(req + sizeof(*in));
    if (ifa->ifa_family != LINUX_AF_INET) return;
    nif = (ifa->ifa_index == (uint32_t)g_if_lo.ifindex) ? &g_if_lo :
          (ifa->ifa_index == (uint32_t)g_if_eth0.ifindex) ? &g_if_eth0 : 0;
    if (!nif || nif == &g_if_lo) return;
    nif->ipv4_addr_be = 0;
    nif->ipv4_netmask_be = 0;
    nif->ipv4_bcast_be = 0;
    nif->ipv4_dst_be = 0;
    netif_apply_ipv4_to_lwip(nif);
}

static void netlink_apply_route(const uint8_t *req, uint32_t len,
                                const struct edge_linux_nlmsghdr *in,
                                int add) {
    const struct edge_linux_rtmsg *rtm;
    uint32_t off;
    uint32_t gateway_be = 0;
    uint32_t oif = 0;
    if (!req || !in || len < sizeof(*in) + sizeof(*rtm)) return;
    rtm = (const struct edge_linux_rtmsg *)(req + sizeof(*in));
    if (rtm->rtm_family != LINUX_AF_INET) return;

    off = (uint32_t)sizeof(*in) + (uint32_t)sizeof(*rtm);
    while (off + sizeof(struct edge_linux_rtattr) <= len) {
        struct edge_linux_rtattr attr;
        uint32_t data_len;
        memcpy(&attr, req + off, sizeof(attr));
        if (attr.rta_len < sizeof(attr) || off + attr.rta_len > len) break;
        data_len = (uint32_t)attr.rta_len - (uint32_t)sizeof(attr);
        if (data_len >= sizeof(uint32_t)) {
            if (attr.rta_type == LINUX_RTA_GATEWAY) memcpy(&gateway_be, req + off + sizeof(attr), sizeof(gateway_be));
            else if (attr.rta_type == LINUX_RTA_OIF) memcpy(&oif, req + off + sizeof(attr), sizeof(oif));
        }
        off += netlink_align((uint32_t)attr.rta_len);
    }

    if (oif != 0 && oif != (uint32_t)g_if_eth0.ifindex) return;
    if (rtm->rtm_dst_len != 0) return;
    g_if_eth0.ipv4_dst_be = add ? gateway_be : 0;
    netif_apply_ipv4_to_lwip(&g_if_eth0);
}

static int netlink_queue_status(edge_socket_t *s, const uint8_t *req, uint32_t len) {
    struct edge_linux_nlmsghdr in;
    struct edge_linux_nlmsghdr reply_request;
    struct edge_linux_nlmsghdr out;
    uint32_t start;
    int dynamic_handled = 0;
    int dynamic_result;
    if (!s || !req || len < sizeof(in)) return -EINVAL;
    memcpy(&in, req, sizeof(in));
    if (in.nlmsg_len < sizeof(in) || in.nlmsg_len > len) return -EINVAL;
    if (netlink_ensure_bound(s) < 0) return -EADDRINUSE;
    reply_request = in;
    reply_request.nlmsg_pid = s->netlink_port_id;

    if (in.nlmsg_type == LINUX_RTM_GETLINK) {
        return netlink_queue_getlink(s, &reply_request, req, len);
    }
    if (in.nlmsg_type == LINUX_RTM_GETADDR) {
        return netlink_queue_getaddr(
            s, &reply_request, req, len);
    }
    if (in.nlmsg_type == LINUX_RTM_GETROUTE) {
        return netlink_queue_getroute(s, &reply_request, req, len);
    }
    if (in.nlmsg_type == LINUX_RTM_GETNEIGH) {
        return netlink_queue_getneigh(s, &reply_request, req, len);
    }
    if (in.nlmsg_type == LINUX_RTM_GETRULE) {
        return netlink_queue_getrule(s, &reply_request, req, len);
    }
    if (in.nlmsg_type == LINUX_RTM_GETQDISC) {
        return netlink_queue_getqdisc(
            s, &reply_request, req, len);
    }
    if (in.nlmsg_type == LINUX_RTM_GETNEXTHOP) {
        return netlink_queue_getnexthop(
            s, &reply_request, req, len);
    }
    if (in.nlmsg_type == LINUX_RTM_GETMDB) {
        return netlink_queue_getmdb(
            s, &reply_request, req, len);
    }
    dynamic_result = edge_linux_rtnetlink_apply(
        s->network_namespace, req, len, &dynamic_handled);
    if (dynamic_handled && dynamic_result < 0)
        return netlink_queue_error_reply(
            s, &reply_request, dynamic_result);
    if (dynamic_handled) goto queue_status;
    if (in.nlmsg_type == LINUX_RTM_NEWADDR) {
        netlink_apply_newaddr(req, len, &in);
    } else if (in.nlmsg_type == LINUX_RTM_DELADDR) {
        netlink_apply_deladdr(req, len, &in);
    } else if (in.nlmsg_type == LINUX_RTM_NEWROUTE) {
        netlink_apply_route(req, len, &in, 1);
    } else if (in.nlmsg_type == LINUX_RTM_DELROUTE) {
        netlink_apply_route(req, len, &in, 0);
    }

queue_status:
    start = s->rx_len;
    if (s->packet_count >= EDGE_SOCKET_PACKET_QUEUE ||
        start + sizeof(out) + sizeof(struct edge_linux_nlmsgerr) >
            socket_rx_capacity(s))
        return -EAGAIN;
    memset(&out, 0, sizeof(out));
    out.nlmsg_seq = in.nlmsg_seq;
    out.nlmsg_pid = s->netlink_port_id;

    if (in.nlmsg_flags & LINUX_NLM_F_ACK) {
        struct edge_linux_nlmsgerr err;
        memset(&err, 0, sizeof(err));
        err.error = 0;
        memcpy(&err.msg, &in, sizeof(in));
        out.nlmsg_len = (uint32_t)(sizeof(out) + sizeof(err));
        out.nlmsg_type = LINUX_NLMSG_ERROR;
        memcpy(s->rx_buf + start, &out, sizeof(out));
        memcpy(s->rx_buf + start + sizeof(out), &err, sizeof(err));
    } else {
        out.nlmsg_len = (uint32_t)sizeof(out);
        out.nlmsg_type = LINUX_NLMSG_DONE;
        memcpy(s->rx_buf + start, &out, sizeof(out));
    }
    if (socket_packet_push(s, out.nlmsg_len) < 0) return -EAGAIN;
    s->rx_len = start + out.nlmsg_len;
    fd_wake_socket_waiters_events(socket_id_from_ptr(s),
                                  LINUX_POLLIN | LINUX_POLLPRI);
    return 0;
}

/*
 * Route netlink is datagram based even when opened as SOCK_RAW.  A multipart
 * dump may place several nlmsghdr records in one datagram, but NLMSG_DONE is a
 * subsequent datagram.  Keeping explicit packet lengths is essential: if a
 * consumer stops parsing after a matching route, the completion datagram must
 * remain queued for its next recvfrom(2), exactly as it does on Linux.
 */
static uint64_t netlink_record_recv_iov(int fd, edge_socket_t *s,
                                        edge_fd_t *fde,
                                        const kernel_socket_iovec_source_t *source,
                                        uint64_t iov_count, uint64_t flags_u,
                                        int *msg_flags) {
    task_t *cur = process_current_task();
    uint64_t capacity = 0;
    uint32_t packet_len;
    uint32_t copied = 0;
    int dontwait = (flags_u & LINUX_MSG_DONTWAIT) != 0;
    int peek = (flags_u & LINUX_MSG_PEEK) != 0;

    (void)fd;
    if (!s || s->domain != LINUX_AF_NETLINK || !source || iov_count == 0)
        return (uint64_t)-EINVAL;
    for (uint64_t index = 0; index < iov_count; ++index) {
        struct edge_linux_iovec iov;
        int status = kernel_socket_iovec_source_read(
            source, (uint32_t)index, &iov);
        if (status < 0) return (uint64_t)(int64_t)status;
        if (UINT64_MAX - capacity < iov.iov_len) capacity = UINT64_MAX;
        else capacity += iov.iov_len;
    }
    while (s->packet_count == 0) {
        if (dontwait || (fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock)
            return (uint64_t)-EAGAIN;
        if (signal_pending_interrupt()) return tty_interrupt_current_ret();
        if (fde && cur)
            socket_waiter_add(fde->pipe_id, cur->pid,
                              LINUX_POLLIN | LINUX_POLLPRI);
        if (s->packet_count != 0) {
            if (cur) waiter_remove_pid(cur->pid);
            continue;
        }
        socket_blocking_wait_step(0);
    }

    packet_len = socket_packet_front_length(s);
    if (packet_len == 0 || packet_len > s->rx_len) return (uint64_t)-EIO;
    s->received_timestamp_us = s->packet_timestamps_us[s->packet_head];
    s->received_cred_pid = s->packet_sender_pids[s->packet_head];
    s->received_cred_uid = s->packet_sender_uids[s->packet_head];
    s->received_cred_gid = s->packet_sender_gids[s->packet_head];
    s->rx_peer_len = s->packet_source_lengths[s->packet_head];
    if (s->rx_peer_len)
        memcpy(s->rx_peer, s->packet_source_addresses[s->packet_head],
               s->rx_peer_len);
    for (uint64_t index = 0; index < iov_count && copied < packet_len; ++index) {
        struct edge_linux_iovec iov;
        uint32_t count = packet_len - copied;
        int status = kernel_socket_iovec_source_read(
            source, (uint32_t)index, &iov);
        if (status < 0) return copied ? copied : (uint64_t)(int64_t)status;
        if (iov.iov_len < count) count = (uint32_t)iov.iov_len;
        if (count && copy_to_user(iov.iov_base, s->rx_buf + copied,
                                  count) < 0)
            return copied ? copied : (uint64_t)-EFAULT;
        copied += count;
    }
    if (msg_flags && capacity < packet_len) *msg_flags |= LINUX_MSG_TRUNC;
    if (!peek) {
        if (packet_len < s->rx_len)
            memmove(s->rx_buf, s->rx_buf + packet_len, s->rx_len - packet_len);
        s->rx_len -= packet_len;
        socket_packet_pop(s);
    }
    return (flags_u & LINUX_MSG_TRUNC) ? packet_len : copied;
}

static int sockaddr_un_path_from_buf(const uint8_t *buf, uint32_t len, char *path, int path_sz) {
    static const char hexadecimal[] = "0123456789abcdef";
    uint16_t fam = 0;
    uint32_t path_len;
    const uint8_t *src;
    uint32_t out = 0;
    if (!buf || len < sizeof(fam) || !path || path_sz <= 0) return -1;
    memcpy(&fam, buf, sizeof(fam));
    if (fam != LINUX_AF_UNIX) return -1;
    path[0] = 0;
    if (len <= sizeof(fam)) return 0;
    src = buf + sizeof(fam);
    path_len = len - (uint32_t)sizeof(fam);
    if (path_len > 108) path_len = 108;
    if (path_len > 0 && src[0] == '\0') {
        /*
         * Linux AF_UNIX supports an abstract namespace when sun_path[0] is NUL.
         * Xorg creates its "local" listener this way before clients connect to
         * DISPLAY=:0.  EdgeOS keeps socket bindings in an in-kernel registry, so
         * encode abstract names as a non-filesystem key and avoid touching VFS.
         */
        if (path_sz < 2 || (uint32_t)path_sz < 2u * path_len)
            return -1;
        path[0] = '@';
        out = 1;
        src++;
        path_len--;
        for (uint32_t i = 0; i < path_len; ++i) {
            path[out++] = hexadecimal[src[i] >> 4];
            path[out++] = hexadecimal[src[i] & 15u];
        }
        path[out] = 0;
        return 0;
    }
    while (path_len > 0 && src[path_len - 1] == '\0') path_len--;
    if ((int)path_len >= path_sz) path_len = (uint32_t)(path_sz - 1);
    if (path_len > 0) memcpy(path, src, path_len);
    path[path_len] = 0;
    if (path[0]) {
        char resolved[EDGE_UNIX_BINDING_KEY_SIZE];
        if (kernel_unix_socket_resolve_path(
                path, resolved, sizeof(resolved)) < 0)
            return -1;
        strncpy(path, resolved, (uint32_t)(path_sz - 1));
        path[path_sz - 1] = 0;
    }
    return 0;
}

static int unix_binding_key_is_abstract(const char *path) {
    return path && path[0] == '@';
}

static int unix_binding_find_path(const char *path) {
    if (!path || !path[0]) return -1;
    for (int i = 0; i < EDGE_MAX_UNIX_BINDINGS; ++i) {
        if (g_unix_bindings[i].used && strcmp(g_unix_bindings[i].path, (char *)path) == 0) return i;
    }
    return -1;
}

static int unix_binding_find_sock(int sock_id) {
    for (int i = 0; i < EDGE_MAX_UNIX_BINDINGS; ++i) {
        if (g_unix_bindings[i].used && g_unix_bindings[i].sock_id == sock_id) return i;
    }
    return -1;
}

static int unix_binding_register(const char *path, int sock_id);

static int unix_socket_bound_path_matches(const edge_socket_t *s, const char *path) {
    char bound_path[EDGE_UNIX_BINDING_KEY_SIZE];
    if (!s || !path || !path[0]) return 0;
    if (!s->used || s->domain != LINUX_AF_UNIX ||
        !(s->type == LINUX_SOCK_STREAM || s->type == LINUX_SOCK_SEQPACKET)) {
        return 0;
    }
    if (s->bind_len < sizeof(uint16_t) || s->bind_len > sizeof(s->bind_addr)) return 0;
    if (sockaddr_un_path_from_buf(s->bind_addr, s->bind_len,
                                  bound_path, sizeof(bound_path)) < 0) {
        return 0;
    }
    return strcmp(bound_path, path) == 0;
}

static int unix_binding_find_live_listener_path(const char *path) {
    if (!path || !path[0] || !g_sockets) return -1;
    for (int sid = 0; sid < EDGE_MAX_SOCKETS; ++sid) {
        edge_socket_t *s = &g_sockets[sid];
        if (!s->used || !s->listening) continue;
        if (unix_socket_bound_path_matches(s, path)) return sid;
    }
    return -1;
}

static int unix_binding_lookup_listener(const char *path) {
    int idx;
    int sid;
    edge_socket_t *s;

    idx = unix_binding_find_path(path);
    if (idx >= 0) {
        sid = g_unix_bindings[idx].sock_id;
        if (sid >= 0 && sid < EDGE_MAX_SOCKETS) {
            s = &g_sockets[sid];
            if (s->used && s->listening && unix_socket_bound_path_matches(s, path)) {
                return sid;
            }
        }
    }

    /*
     * The Linux-visible AF_UNIX endpoint is owned by the bound socket object.
     * The small registry above is only EdgeOS' pathname cache used to avoid a
     * full socket-table scan.  If lifecycle churn or a stale pathname unlink
     * invalidates the cache while the listening socket still exists, connect(2)
     * must find the live bound listener instead of returning ENOENT to normal
     * Linux clients such as Xorg, D-Bus, and ICE.
     */
    sid = unix_binding_find_live_listener_path(path);
    if (sid >= 0) {
        if (idx >= 0) {
            g_unix_bindings[idx].sock_id = sid;
        } else {
            (void)unix_binding_register(path, sid);
        }
        return sid;
    }

    return -1;
}

static int x11_unix_path_is_traced(const char *path) {
#if EDGE_X11_UNIX_TRACE
    return path && path[0] && strstr(path, ".X11-unix") != 0;
#else
    (void)path;
    return 0;
#endif
}

static const char *unix_binding_path_for_sock(int sock_id) {
    int idx = unix_binding_find_sock(sock_id);
    return idx >= 0 ? g_unix_bindings[idx].path : 0;
}

static int g_x11_unix_trace_budget = 160;

static void x11_unix_trace_binding(const char *op, const char *path, int fd, int sock_id, int rc) {
    task_t *cur;
    int idx;
    int bind_sock = -1;
    edge_socket_t *s = 0;

    if (!x11_unix_path_is_traced(path)) return;
    if (g_x11_unix_trace_budget-- <= 0) return;

    cur = process_current_task();
    idx = unix_binding_find_path(path);
    if (idx >= 0) bind_sock = g_unix_bindings[idx].sock_id;
    if (sock_id >= 0 && sock_id < EDGE_MAX_SOCKETS && g_sockets[sock_id].used) {
        s = &g_sockets[sock_id];
    } else if (bind_sock >= 0 && bind_sock < EDGE_MAX_SOCKETS && g_sockets[bind_sock].used) {
        s = &g_sockets[bind_sock];
    }

    printf("[x11unix] %s pid=%d cmd=%s fd=%d sid=%d idx=%d bsid=%d rc=%d abs=%d used=%d refs=%d listen=%d pend=%d conn=%d peer=%d rx=%u closed=%d path=%s\n",
           op ? op : "?",
           cur ? cur->pid : -1,
           cur ? cur->name : "?",
           fd, sock_id, idx, bind_sock, rc,
           unix_binding_key_is_abstract(path) ? 1 : 0,
           s ? s->used : 0,
           s ? s->refs : 0,
           s ? s->listening : 0,
           s ? socket_pending_count(s) : 0,
           s ? s->connected : 0,
           s ? s->unix_peer_id : -1,
           s ? s->rx_len : 0,
           s ? s->closed : 0,
           path);
}

static int unix_binding_register(const char *path, int sock_id) {
    int idx;
    if (!path || !path[0]) return -EINVAL;
    idx = unix_binding_find_path(path);
    if (idx >= 0) {
        x11_unix_trace_binding("register-busy", path, -1, sock_id, -EADDRINUSE);
        return -EADDRINUSE;
    }
    for (int i = 0; i < EDGE_MAX_UNIX_BINDINGS; ++i) {
        if (!g_unix_bindings[i].used) {
            memset(&g_unix_bindings[i], 0, sizeof(g_unix_bindings[i]));
            g_unix_bindings[i].used = 1;
            g_unix_bindings[i].sock_id = sock_id;
            strncpy(g_unix_bindings[i].path, path, sizeof(g_unix_bindings[i].path) - 1);
            g_unix_bindings[i].path[sizeof(g_unix_bindings[i].path) - 1] = 0;
            x11_unix_trace_binding("register-ok", path, -1, sock_id, 0);
            return 0;
        }
    }
    x11_unix_trace_binding("register-nomem", path, -1, sock_id, -ENOMEM);
    return -ENOMEM;
}

static void unix_binding_unregister_path(const char *path) {
    int idx = unix_binding_find_path(path);
    if (idx >= 0) {
        x11_unix_trace_binding("unregister-path", path, -1, g_unix_bindings[idx].sock_id, 0);
        memset(&g_unix_bindings[idx], 0, sizeof(g_unix_bindings[idx]));
    } else {
        x11_unix_trace_binding("unregister-path-miss", path, -1, -1, -ENOENT);
    }
}

static void unix_binding_unregister_sock(int sock_id) {
    int idx = unix_binding_find_sock(sock_id);
    if (idx >= 0) {
        x11_unix_trace_binding("unregister-sock", g_unix_bindings[idx].path, -1, sock_id, 0);
        memset(&g_unix_bindings[idx], 0, sizeof(g_unix_bindings[idx]));
    }
}

static void socket_autobind_inet(edge_socket_t *s) {
    uint32_t local_address;

    if (!s) return;
    if (s->bind_len >= sizeof(struct edge_sockaddr_in)) return;
    local_address = g_if_eth0.ipv4_addr_be;
    if (s->network_namespace)
        (void)edge_linux_rtnetlink_ipv4_primary(
            s->network_namespace, &local_address);
    socket_set_bind_inet(
        s, local_address, socket_alloc_ephemeral_port_be());
    if (s->domain == LINUX_AF_INET &&
        s->type == LINUX_SOCK_DGRAM &&
        s->lwip_pcb && s->local_port_be == 0) {
        struct udp_pcb *up = (struct udp_pcb *)s->lwip_pcb;
        ip_addr_t local;
        ip_addr_set_zero_ip4(&local);
        ip_2_ip4(&local)->addr = local_address;
        if (EDGE_LWIP_CALL(udp_bind(
                up, &local,
                edge_bswap16(((struct edge_sockaddr_in *)s->bind_addr)->sin_port))) == ERR_OK) {
            s->local_port_be = ((struct edge_sockaddr_in *)s->bind_addr)->sin_port;
        }
    } else if (s->domain == LINUX_AF_INET &&
               s->type == LINUX_SOCK_STREAM &&
               s->lwip_pcb && s->local_port_be == 0) {
        struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
        ip_addr_t local;
        ip_addr_set_zero_ip4(&local);
        ip_2_ip4(&local)->addr = local_address;
        if (EDGE_LWIP_CALL(tcp_bind(
                tp, &local,
                edge_bswap16(((struct edge_sockaddr_in *)s->bind_addr)->sin_port))) == ERR_OK) {
            s->local_port_be = ((struct edge_sockaddr_in *)s->bind_addr)->sin_port;
        }
    }
}

static void socket_autobind_inet6(edge_socket_t *s) {
    uint8_t any6[16];
    if (!s) return;
    if (s->bind_len >= sizeof(struct edge_sockaddr_in6)) return;
    memset(any6, 0, sizeof(any6));
    socket_set_bind_inet6(s, any6, socket_alloc_ephemeral_port_be(), 0);
    if (s->domain == LINUX_AF_INET6 &&
        s->type == LINUX_SOCK_DGRAM &&
        s->lwip_pcb && s->local_port_be == 0) {
        struct udp_pcb *up = (struct udp_pcb *)s->lwip_pcb;
        ip_addr_t any;
        ip_addr_set_zero_ip6(&any);
        if (EDGE_LWIP_CALL(udp_bind(
                up, &any,
                edge_bswap16(((struct edge_sockaddr_in6 *)s->bind_addr)->sin6_port))) == ERR_OK) {
            s->local_port_be = ((struct edge_sockaddr_in6 *)s->bind_addr)->sin6_port;
        }
    } else if (s->domain == LINUX_AF_INET6 &&
               s->type == LINUX_SOCK_STREAM &&
               s->lwip_pcb && s->local_port_be == 0) {
        struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
        ip_addr_t any;
        ip_addr_set_zero_ip6(&any);
        if (EDGE_LWIP_CALL(tcp_bind(
                tp, &any,
                edge_bswap16(((struct edge_sockaddr_in6 *)s->bind_addr)->sin6_port))) == ERR_OK) {
            s->local_port_be = ((struct edge_sockaddr_in6 *)s->bind_addr)->sin6_port;
        }
    }
}

static int sockaddr_in_from_buf(const uint8_t *buf, uint32_t len, struct edge_sockaddr_in *sin) {
    if (!sin || !buf || len < sizeof(*sin)) return -1;
    memcpy(sin, buf, sizeof(*sin));
    if (sin->sin_family != LINUX_AF_INET) return -1;
    return 0;
}

static int sockaddr_in6_from_buf(const uint8_t *buf, uint32_t len, struct edge_sockaddr_in6 *sin6) {
    if (!sin6 || !buf || len < sizeof(*sin6)) return -1;
    memcpy(sin6, buf, sizeof(*sin6));
    if (sin6->sin6_family != LINUX_AF_INET6) return -1;
    return 0;
}

static void sockaddr_in_to_user_peer(edge_socket_t *s, uint32_t src_ip_be, uint16_t src_port_be) {
    struct edge_sockaddr_in sin;
    if (!s) return;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = LINUX_AF_INET;
    sin.sin_addr = src_ip_be;
    sin.sin_port = src_port_be;
    memcpy(s->rx_peer, &sin, sizeof(sin));
    s->rx_peer_len = sizeof(sin);
}

static void sockaddr_in6_to_user_peer(edge_socket_t *s, const uint8_t src_ip6[16], uint16_t src_port_be, uint32_t scope_id) {
    struct edge_sockaddr_in6 sin6;
    if (!s || !src_ip6) return;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = LINUX_AF_INET6;
    sin6.sin6_port = src_port_be;
    sin6.sin6_scope_id = scope_id;
    memcpy(sin6.sin6_addr, src_ip6, 16);
    memcpy(s->rx_peer, &sin6, sizeof(sin6));
    s->rx_peer_len = sizeof(sin6);
}

static void edge_ip_receive_metadata_current(
        kernel_socket_ip_receive_metadata_t *metadata) {
    const ip_addr_t *destination;
    struct netif *input;

    if (!metadata) return;
    memset(metadata, 0, sizeof(*metadata));
    destination = ip_current_dest_addr();
    input = ip_current_input_netif();
    metadata->interface_index = input ? netif_get_index(input) : 0u;
    if (ip_current_is_v6()) {
        const struct ip6_hdr *header = ip6_current_header();

        metadata->family = LINUX_AF_INET6;
        if (destination && IP_IS_V6(destination))
            edge_ip6_to_bytes(
                ip_2_ip6(destination), metadata->destination_address);
        if (header) {
            metadata->hop_limit = IP6H_HOPLIM(header);
            metadata->traffic_class = (uint8_t)IP6H_TC(header);
        }
        return;
    }
    metadata->family = LINUX_AF_INET;
    if (destination && IP_IS_V4(destination))
        memcpy(metadata->destination_address,
               &ip_2_ip4(destination)->addr, 4u);
    if (input)
        memcpy(metadata->local_address, &netif_ip4_addr(input)->addr, 4u);
    if (ip4_current_header()) {
        metadata->hop_limit = IPH_TTL(ip4_current_header());
        metadata->traffic_class = IPH_TOS(ip4_current_header());
    }
}

static void edge_ip_receive_metadata_local(
        kernel_socket_ip_receive_metadata_t *metadata,
        const edge_socket_t *sender, const ip_addr_t *source,
        const ip_addr_t *destination) {
    struct netif *output;

    if (!metadata) return;
    memset(metadata, 0, sizeof(*metadata));
    if (!destination || !IP_IS_V4(destination)) return;
    metadata->family = LINUX_AF_INET;
    memcpy(metadata->destination_address,
           &ip_2_ip4(destination)->addr, 4u);
    if (ip_addr_isloopback(destination))
        memcpy(metadata->local_address,
               &ip_2_ip4(destination)->addr, 4u);
    metadata->hop_limit = sender && sender->lwip_pcb ?
        ((const struct udp_pcb *)sender->lwip_pcb)->ttl : 64u;
    metadata->traffic_class = sender && sender->lwip_pcb ?
        ((const struct udp_pcb *)sender->lwip_pcb)->tos : 0u;
    output = ip_route(source, destination);
    if (!output) return;
    metadata->interface_index = netif_get_index(output);
    if (!ip_addr_isloopback(destination))
        memcpy(metadata->local_address, &netif_ip4_addr(output)->addr, 4u);
}

static void edge_udp_receive_enqueue(
        edge_socket_t *s, struct udp_pcb *pcb, struct pbuf *p,
        const ip_addr_t *addr, u16_t port,
        const kernel_socket_ip_receive_metadata_t *ip_metadata) {
    edge_linux_netfilter_tuple_t tuple;
    uint8_t source_storage[sizeof(s->rx_peer)];
    uint32_t source_length = 0;
    uint32_t start;
    int sid;
    uint16_t n;
    if (!s || !p || !addr) {
        if (p) pbuf_free(p);
        return;
    }
    if (s->packet_count >= EDGE_SOCKET_PACKET_QUEUE) {
        pbuf_free(p);
        return;
    }
    start = s->rx_len;
    if (start >= socket_rx_capacity(s)) {
        pbuf_free(p);
        return;
    }
    n = p->tot_len > socket_rx_capacity(s) - start ?
        (uint16_t)(socket_rx_capacity(s) - start) : (uint16_t)p->tot_len;
    if (pbuf_copy_partial(p, s->rx_buf + start, n, 0) != n) {
        pbuf_free(p);
        return;
    }
    memset(source_storage, 0, sizeof(source_storage));
    memset(&tuple, 0, sizeof(tuple));
    tuple.network_namespace = s->network_namespace;
    tuple.family = IP_IS_V4(addr) ? LINUX_AF_INET : LINUX_AF_INET6;
    tuple.protocol = LINUX_IPPROTO_UDP;
    tuple.source_port = port;
    tuple.destination_port = pcb ? pcb->local_port : 0u;
    if (IP_IS_V4(addr)) {
        uint32_t source_address = ip4_addr_get_u32(ip_2_ip4(addr));

        memcpy(tuple.source_address, &source_address, sizeof(source_address));
        if (pcb && IP_IS_V4(&pcb->local_ip)) {
            uint32_t destination_address =
                ip4_addr_get_u32(ip_2_ip4(&pcb->local_ip));
            memcpy(tuple.destination_address, &destination_address,
                   sizeof(destination_address));
        }
        (void)edge_linux_netfilter_translate_local(
            &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE);
        memcpy(&source_address, tuple.source_address,
               sizeof(source_address));
        {
            struct edge_sockaddr_in source;

            memset(&source, 0, sizeof(source));
            source.sin_family = LINUX_AF_INET;
            source.sin_addr = source_address;
            source.sin_port = edge_bswap16(tuple.source_port);
            memcpy(source_storage, &source, sizeof(source));
            source_length = sizeof(source);
        }
    } else if (IP_IS_V6(addr)) {
        uint8_t src6[16];
        edge_ip6_to_bytes(ip_2_ip6(addr), src6);
        memcpy(tuple.source_address, src6, sizeof(src6));
        if (pcb && IP_IS_V6(&pcb->local_ip))
            edge_ip6_to_bytes(
                ip_2_ip6(&pcb->local_ip), tuple.destination_address);
        (void)edge_linux_netfilter_translate_local(
            &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE);
        {
            struct edge_sockaddr_in6 source;

            memset(&source, 0, sizeof(source));
            source.sin6_family = LINUX_AF_INET6;
            source.sin6_port = edge_bswap16(tuple.source_port);
            memcpy(source.sin6_addr, tuple.source_address, 16u);
            memcpy(source_storage, &source, sizeof(source));
            source_length = sizeof(source);
        }
    }
    if (!source_length ||
        socket_packet_push_source(
            s, n, source_storage, source_length, 0, 0, 0,
            ip_metadata) < 0) {
        pbuf_free(p);
        return;
    }
    s->rx_len = start + n;
    sid = socket_id_from_ptr(s);
    if (sid >= 0) fd_wake_socket_waiters_events(sid, LINUX_POLLIN | LINUX_POLLPRI);
    pbuf_free(p);
}

static void edge_udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                             const ip_addr_t *addr, u16_t port) {
    kernel_socket_ip_receive_metadata_t metadata;

    edge_ip_receive_metadata_current(&metadata);
    edge_udp_receive_enqueue(
        (edge_socket_t *)arg, pcb, p, addr, port, &metadata);
}

static int socket_observed_tcp_fin(edge_socket_t *s, struct tcp_pcb *tpcb) {
    uint32_t counter = 0;
    uint32_t local_ip;
    uint32_t remote_ip;
    if (!s || !tpcb) return 1;
    if (!IP_IS_V4(&tpcb->local_ip) || !IP_IS_V4(&tpcb->remote_ip)) return 1;
    local_ip = ip4_addr_get_u32(ip_2_ip4(&tpcb->local_ip));
    remote_ip = ip4_addr_get_u32(ip_2_ip4(&tpcb->remote_ip));
    if (!lwip_stack_tcp_rx_fin_seen_v4(local_ip, tpcb->local_port, remote_ip, tpcb->remote_port, &counter)) {
        return 0;
    }
    if (counter == 0 || counter == s->tcp_fin_rx_seen) return 0;
    s->tcp_fin_rx_seen = counter;
    return 1;
}

static err_t edge_tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    edge_socket_t *s = (edge_socket_t *)arg;
    if (!s) return ERR_OK;
    if (tpcb && s->lwip_pcb && tpcb != (struct tcp_pcb *)s->lwip_pcb) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    if (!p) {
        if (tpcb && !socket_observed_tcp_fin(s, tpcb)) {
            return ERR_OK;
        }
        /*
         * lwIP reports a peer FIN as a NULL pbuf.  In EdgeOS' poll-driven
         * raw-lwIP integration this close callback can be observed before
         * payload callbacks queued in the same receive burst.  Linux userspace
         * must see queued bytes before EOF/RDHUP, so defer an empty FIN until
         * the socket receive path drains pending lwIP work or payload is
         * queued behind it.
         */
        (void)tpcb;
        if (s->rx_len > 0) {
            s->rx_closed = 1;
            s->tcp_fin_pending = 0;
        } else if (!s->tcp_fin_pending) {
            s->tcp_fin_pending = 1;
        }
        fd_wake_socket_waiters(socket_id_from_ptr(s));
        return ERR_OK;
    }
    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }
    if (s->rx_len > socket_rx_capacity(s) ||
        p->tot_len > (socket_rx_capacity(s) - s->rx_len)) {
        return ERR_MEM;
    }
    if (p->tot_len > 0 &&
        pbuf_copy_partial(p, s->rx_buf + s->rx_len, (u16_t)p->tot_len, 0) != p->tot_len) {
        pbuf_free(p);
        return ERR_MEM;
    }
    s->rx_len += p->tot_len;
    if (s->tcp_fin_pending) {
        s->tcp_fin_pending = 0;
        s->rx_closed = 1;
    }
    fd_wake_socket_waiters_events(socket_id_from_ptr(s), LINUX_POLLIN | LINUX_POLLPRI);
    pbuf_free(p);
    return ERR_OK;
}

static void socket_tcp_receive_consumed(edge_socket_t *s, uint32_t consumed) {
    struct tcp_pcb *tp;
    if (!s || consumed == 0 || !s->lwip_pcb) return;
    if (!(s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6)) return;
    if (s->type != LINUX_SOCK_STREAM) return;
    tp = (struct tcp_pcb *)s->lwip_pcb;
    lwip_stack_core_enter();
    while (consumed > 0) {
        u16_t chunk = (u16_t)(consumed > 0xFFFFu ? 0xFFFFu : consumed);
        tcp_recved(tp, chunk);
        consumed -= chunk;
    }
    (void)tcp_output(tp);
    lwip_stack_core_exit();
}

static err_t edge_tcp_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t acknowledged) {
    edge_socket_t *s = (edge_socket_t *)arg;
    (void)acknowledged;
    if (!s) return ERR_OK;
    if (tpcb && s->lwip_pcb && tpcb != (struct tcp_pcb *)s->lwip_pcb) return ERR_OK;
    /*
     * Linux wakes socket writers when ACK processing releases send-buffer
     * space.  This callback runs in the deferred process-context network
     * bottom half, so it can safely wake exact POLLOUT waiters.
     */
    fd_wake_socket_waiters_events(socket_id_from_ptr(s),
                                  LINUX_POLLOUT | LINUX_POLLWRNORM);
    return ERR_OK;
}

static void edge_tcp_err_cb(void *arg, err_t err) {
    edge_socket_t *s = (edge_socket_t *)arg;
    int active_open;
    if (!s) return;
    active_open = s->connect_in_progress;
    s->connect_error = kernel_socket_lwip_errno(err, active_open);
    s->connect_in_progress = 0;
    s->connect_start_us = 0;
    s->rx_closed = 1;
    s->closed = 1;
    s->lwip_pcb = 0;
    fd_wake_socket_waiters(socket_id_from_ptr(s));
}

static err_t edge_tcp_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err) {
    edge_socket_t *s = (edge_socket_t *)arg;
    if (!s) return ERR_OK;
    if (tpcb && s->lwip_pcb && tpcb != (struct tcp_pcb *)s->lwip_pcb) return ERR_OK;
    s->connect_in_progress = 0;
    s->connect_start_us = 0;
    s->connect_error = kernel_socket_lwip_errno(err, 1);
    if (err == ERR_OK) {
        s->connected = 1;
        s->rx_closed = 0;
        s->tcp_fin_pending = 0;
        s->closed = 0;
    }
    fd_wake_socket_waiters_events(socket_id_from_ptr(s), LINUX_POLLOUT);
    return ERR_OK;
}

static int lwip_err_to_linux_errno(int err) {
    return kernel_socket_lwip_errno(err, 0);
}

static uint64_t socket_connect_timeout_us(edge_socket_t *s) {
    return kernel_socket_connect_timeout_us(
        s ? s->recv_timeout_us : 0u);
}

static int socket_maybe_timeout_connect(edge_socket_t *s) {
    if (!s || !s->connect_in_progress) return 0;
    if (!kernel_socket_connect_timeout_expired(
            s->connect_start_us, boottime_monotonic_us(),
            s->recv_timeout_us))
        return 0;
    s->connect_in_progress = 0;
    s->connect_start_us = 0;
    s->connect_error = ETIMEDOUT;
    s->connected = 0;
    s->rx_closed = 1;
    s->closed = 1;
    if (s->lwip_pcb) {
        struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
        s->lwip_pcb = 0;
        EDGE_LWIP_DO({
            tcp_arg(tp, 0);
            tcp_abort(tp);
        });
    }
    fd_wake_socket_waiters_events(
        socket_id_from_ptr(s),
        LINUX_POLLIN | LINUX_POLLOUT |
        LINUX_POLLERR | LINUX_POLLHUP);
    return 1;
}

static void socket_expire_connect_timeouts(void) {
    uint64_t now_us;

    now_us = boottime_monotonic_us();
    if (!kernel_socket_connect_deadline_tracker_take_due(
            &g_socket_connect_deadline_tracker, now_us))
        return;
    for (int index = 0; index < EDGE_MAX_SOCKETS; ++index) {
        edge_socket_t *socket = &g_sockets[index];

        if (!socket->used || !socket->connect_in_progress)
            continue;
        if (!socket_maybe_timeout_connect(socket)) {
            kernel_socket_connect_deadline_tracker_note(
                &g_socket_connect_deadline_tracker,
                kernel_socket_connect_deadline_us(
                    socket->connect_start_us,
                    socket->recv_timeout_us));
        }
    }
}

static void socket_try_refill_tcp_refused(edge_socket_t *s) {
    if (!s || !s->lwip_pcb) return;
    if (!(s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6)) return;
    if (s->type != LINUX_SOCK_STREAM) return;
    if (s->listening || !s->connected) return;
    if (s->rx_len >= socket_rx_capacity(s)) return;
    lwip_stack_core_enter();
    (void)tcp_process_refused_data((struct tcp_pcb *)s->lwip_pcb);
    (void)tcp_output((struct tcp_pcb *)s->lwip_pcb);
    lwip_stack_core_exit();
}

static uint16_t edge_tcp_count_queue_pbufs(struct tcp_seg *seg) {
    uint32_t count = 0;
    while (seg) {
        count += pbuf_clen(seg->p);
        if (count > 0xFFFFu) return 0xFFFFu;
        seg = seg->next;
    }
    return (uint16_t)count;
}

static void edge_tcp_normalize_send_queue(struct tcp_pcb *tp) {
    uint32_t count;
    if (!tp) return;
    count = edge_tcp_count_queue_pbufs(tp->unsent);
    count += edge_tcp_count_queue_pbufs(tp->unacked);
    if (count > 0xFFFFu) count = 0xFFFFu;
    tp->snd_queuelen = (uint16_t)count;
    if (!tp->unsent) tp->unsent_oversize = 0;
}

static int socket_pending_trace_task(const task_t *t) {
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "xfconfd") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0 ||
           strcmp(t->name, "gdbus") == 0 ||
           strcmp(t->name, "gmain") == 0;
}

static int socket_pending_count(const edge_socket_t *listener) {
    return listener ?
        (int)kernel_socket_accept_queue_count(
            &listener->accept_queue) : 0;
}

static int socket_pending_enqueue(edge_socket_t *listener, int sock_id) {
    task_t *cur = process_current_task();
    int listener_sid;
    int result;
    static int pending_trace_budget = EDGE_XFCE_BOOT_TRACE ? 128 : 0;
    if (!listener) return -1;
    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS || !g_sockets[sock_id].used) return -1;
    listener_sid = socket_id_from_ptr(listener);
    /*
     * Linux's accept queue owns a reference to each child socket until accept(2)
     * dequeues it or the listener is torn down.  The connecting peer may close
     * immediately after connect(2); that must not free the server-side child
     * before Xorg, DBus, or ICE accepts it.
     */
    socket_add_ref(sock_id);
    g_sockets[sock_id].acceptq_refs++;
    result = kernel_socket_accept_queue_enqueue(
        &listener->accept_queue, sock_id);
    if (result < 0) {
        socket_acceptq_release(sock_id);
        return -1;
    }
    if (pending_trace_budget > 0 &&
        (socket_pending_trace_task(cur) ||
         (sock_id >= 0 && sock_id < EDGE_MAX_SOCKETS &&
          socket_pending_trace_task(process_get_task(g_sockets[sock_id].peer_cred_pid))))) {
        edge_socket_t *child = (sock_id >= 0 && sock_id < EDGE_MAX_SOCKETS) ? &g_sockets[sock_id] : 0;
        printf("[acceptq] enqueue pid=%d cmd=%s listener=%d child=%d child_used=%d child_refs=%d child_peer=%d peerpid=%d pending=%d backlog=%d budget=%d\n",
               cur ? cur->pid : -1,
               cur && cur->name[0] ? cur->name : "?",
               listener_sid, sock_id,
               child ? child->used : -1,
               child ? child->refs : -1,
               child ? child->unix_peer_id : -1,
               child ? child->peer_cred_pid : -1,
               socket_pending_count(listener), listener->backlog,
               pending_trace_budget - 1);
        pending_trace_budget--;
    }
    return 0;
}

static int socket_pending_dequeue(edge_socket_t *listener) {
    int32_t sock_id = -1;

    if (!listener ||
        kernel_socket_accept_queue_dequeue(
            &listener->accept_queue, &sock_id) < 0)
        return -1;
    return (int)sock_id;
}

static void socket_drop_ref_locked(int sock_id, int acceptq_release);

static void socket_acceptq_release(int sock_id) {
    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS) return;
    if (!g_sockets[sock_id].used) return;
    if (g_sockets[sock_id].acceptq_refs <= 0) {
        static int acceptq_underflow_budget = 32;
        task_t *cur = process_current_task();
        if (acceptq_underflow_budget > 0) {
            printf("[acceptq] release-underflow pid=%d cmd=%s child=%d refs=%d budget=%d\n",
                   cur ? cur->pid : -1,
                   cur && cur->name[0] ? cur->name : "?",
                   sock_id, g_sockets[sock_id].refs,
                   acceptq_underflow_budget - 1);
            acceptq_underflow_budget--;
        }
        return;
    }
    g_sockets[sock_id].acceptq_refs--;
    socket_drop_ref_locked(sock_id, 1);
}

static void socket_pending_remove_sock(int sock_id) {
    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS) return;
    for (int sid = 0; sid < EDGE_MAX_SOCKETS; ++sid) {
        edge_socket_t *listener = &g_sockets[sid];
        uint32_t old_count;
        uint32_t removed;
        uint32_t new_count;

        if (!listener->used || !listener->listening) continue;
        old_count = kernel_socket_accept_queue_count(
            &listener->accept_queue);
        if (!old_count) continue;
        removed = kernel_socket_accept_queue_remove(
            &listener->accept_queue, sock_id);
        if (removed) {
            task_t *cur = process_current_task();
            static int pending_remove_trace_budget = 64;
            new_count = old_count - removed;
            if (pending_remove_trace_budget > 0 && socket_pending_trace_task(cur)) {
                printf("[acceptq] remove pid=%d cmd=%s listener=%d child=%d old=%u new=%u budget=%d\n",
                       cur ? cur->pid : -1,
                       cur && cur->name[0] ? cur->name : "?",
                       sid, sock_id, old_count, new_count,
                       pending_remove_trace_budget - 1);
                pending_remove_trace_budget--;
            }
            fd_wake_socket_waiters_events(sid, LINUX_POLLIN | LINUX_POLLPRI);
        }
    }
}

static int socket_pending_anywhere(int sock_id, int *listener_out) {
    if (listener_out) *listener_out = -1;
    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS) return 0;
    for (int sid = 0; sid < EDGE_MAX_SOCKETS; ++sid) {
        edge_socket_t *listener = &g_sockets[sid];
        if (!listener->used || !listener->listening) continue;
        if (kernel_socket_accept_queue_contains(
                &listener->accept_queue, sock_id)) {
            if (listener_out) *listener_out = sid;
            return 1;
        }
    }
    return 0;
}

static err_t edge_tcp_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
    edge_socket_t *listener = (edge_socket_t *)arg;
    int sid;
    edge_socket_t *child;

    if (!listener || !newpcb || err != ERR_OK) {
        if (newpcb) tcp_abort(newpcb);
        return ERR_ABRT;
    }
    if (!listener->listening) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    sid = socket_alloc();
    if (sid < 0) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    child = &g_sockets[sid];
    child->domain = listener->domain;
    child->type = listener->type;
    child->protocol = listener->protocol;
    child->option_state = listener->option_state;
    child->filter_len = listener->filter_len;
    if (child->filter_len)
        memcpy(child->filter, listener->filter,
               (uint64_t)child->filter_len * sizeof(child->filter[0]));
    if (listener->bpf_filter_object_id >= 0) {
        if (kernel_bpf_object_retain(
                listener->bpf_filter_object_id) < 0) {
            socket_drop_ref(sid);
            tcp_abort(newpcb);
            return ERR_ABRT;
        }
        child->bpf_filter_object_id =
            listener->bpf_filter_object_id;
    }
    child->ip_ttl = listener->ip_ttl ? listener->ip_ttl : 64;
    child->ip_tos = listener->ip_tos;
    child->ip_pktinfo = listener->ip_pktinfo;
    child->ip_recverr = listener->ip_recverr;
    child->ip_recvttl = listener->ip_recvttl;
    child->ip_freebind = listener->ip_freebind;
    child->ip_mtu_discover = listener->ip_mtu_discover;
    child->ipv6_v6only = listener->ipv6_v6only;
    child->ipv6_recverr = listener->ipv6_recverr;
    child->ipv6_recvpktinfo = listener->ipv6_recvpktinfo;
    child->ipv6_recvhoplimit = listener->ipv6_recvhoplimit;
    child->ipv6_recvtclass = listener->ipv6_recvtclass;
    child->tcp_keepalive = listener->tcp_keepalive;
    child->tcp_keepidle_sec = listener->tcp_keepidle_sec;
    child->tcp_keepintvl_sec = listener->tcp_keepintvl_sec;
    child->tcp_keepcnt = listener->tcp_keepcnt;
    child->network_namespace = listener->network_namespace;
    child->connected = 1;
    child->lwip_pcb = newpcb;
    newpcb->ttl = child->ip_ttl;
    newpcb->tos = child->ip_tos;
    if (child->tcp_keepalive) ip_set_option(newpcb, SOF_KEEPALIVE);
    else ip_reset_option(newpcb, SOF_KEEPALIVE);
#if LWIP_TCP_KEEPALIVE
    newpcb->keep_idle = (uint32_t)((child->tcp_keepidle_sec > 0 ? child->tcp_keepidle_sec : 7200) * 1000u);
    newpcb->keep_intvl = (uint32_t)((child->tcp_keepintvl_sec > 0 ? child->tcp_keepintvl_sec : 75) * 1000u);
    newpcb->keep_cnt = (uint32_t)(child->tcp_keepcnt > 0 ? child->tcp_keepcnt : 9);
#endif
    child->local_port_be = edge_bswap16(newpcb->local_port);

    if (child->domain == LINUX_AF_INET) {
        uint32_t lip = ip4_addr_get_u32(ip_2_ip4(&newpcb->local_ip));
        uint32_t rip = ip4_addr_get_u32(ip_2_ip4(&newpcb->remote_ip));
        socket_set_bind_inet(child, lip, edge_bswap16(newpcb->local_port));
        sockaddr_in_to_user_peer(child, rip, edge_bswap16(newpcb->remote_port));
        memcpy(child->peer_addr, child->rx_peer, child->rx_peer_len);
        child->peer_len = child->rx_peer_len;
        socket_set_bind_inet(listener, lip, edge_bswap16(newpcb->local_port));
        listener->local_port_be = edge_bswap16(newpcb->local_port);
    } else if (child->domain == LINUX_AF_INET6) {
        uint8_t lip6[16];
        uint8_t rip6[16];
        edge_ip6_to_bytes(ip_2_ip6(&newpcb->local_ip), lip6);
        edge_ip6_to_bytes(ip_2_ip6(&newpcb->remote_ip), rip6);
        socket_set_bind_inet6(child, lip6, edge_bswap16(newpcb->local_port), 0);
        sockaddr_in6_to_user_peer(child, rip6, edge_bswap16(newpcb->remote_port), 0);
        memcpy(child->peer_addr, child->rx_peer, child->rx_peer_len);
        child->peer_len = child->rx_peer_len;
        socket_set_bind_inet6(listener, lip6, edge_bswap16(newpcb->local_port), 0);
        listener->local_port_be = edge_bswap16(newpcb->local_port);
    }

    tcp_arg(newpcb, child);
    tcp_recv(newpcb, edge_tcp_recv_cb);
    tcp_err(newpcb, edge_tcp_err_cb);
    tcp_sent(newpcb, edge_tcp_sent_cb);

    if (socket_pending_enqueue(listener, sid) < 0) {
        child->lwip_pcb = 0;
        socket_drop_ref(sid);
        tcp_abort(newpcb);
        return ERR_ABRT;
    }
    fd_wake_socket_waiters_events(socket_id_from_ptr(listener), LINUX_POLLIN | LINUX_POLLPRI);
    return ERR_OK;
}

static void socket_add_ref(int sock_id) {
    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS) return;
    if (!g_sockets[sock_id].used) return;
    g_sockets[sock_id].refs++;
}

static kernel_socket_rights_pool_t *socket_rights_pool(void) {
    return kernel_socket_rights_default_pool();
}

static void socket_rights_record_drop(
        kernel_socket_rights_record_handle_t *record) {
    kernel_socket_rights_pool_t *pool = socket_rights_pool();
    if (!pool || !record || !*record) return;
    (void)kernel_socket_rights_record_drop(pool, record);
}

static void socket_rights_clear_all(edge_socket_t *socket) {
    kernel_socket_rights_pool_t *pool = socket_rights_pool();
    if (!socket) return;
    if (pool)
        (void)kernel_socket_rights_queue_clear(
            pool, &socket->rights);
    kernel_socket_rights_queue_initialize(
        &socket->rights,
        KERNEL_SOCKET_RIGHTS_DEFAULT_QUEUE_LIMIT);
}

static int socket_rights_enqueue(
        edge_socket_t *socket,
        kernel_socket_rights_record_handle_t *record,
        kernel_socket_rights_association_kind_t association_kind,
        uint64_t association_sequence) {
    kernel_socket_rights_pool_t *pool = socket_rights_pool();
    if (!socket || !pool || !record || !*record)
        return -EINVAL;
    return kernel_socket_rights_queue_enqueue(
        pool, &socket->rights, record,
        association_kind, association_sequence);
}

static int socket_rights_peek_at(
        edge_socket_t *socket, uint32_t ordinal,
        kernel_socket_rights_record_info_t *information) {
    kernel_socket_rights_pool_t *pool = socket_rights_pool();
    if (!socket || !pool || !information)
        return -EINVAL;
    return kernel_socket_rights_queue_peek_at(
        pool, &socket->rights, ordinal, information);
}

static int socket_rights_take_front(
        edge_socket_t *socket,
        kernel_socket_rights_record_handle_t *record) {
    kernel_socket_rights_pool_t *pool = socket_rights_pool();
    if (!socket || !pool || !record)
        return -EINVAL;
    return kernel_socket_rights_queue_take(
        pool, &socket->rights, record);
}

static void socket_rights_drop_front(edge_socket_t *socket) {
    kernel_socket_rights_pool_t *pool = socket_rights_pool();
    if (!socket || !pool) return;
    (void)kernel_socket_rights_queue_drop(
        pool, &socket->rights);
}

static void socket_rights_note_stream_read(
        edge_socket_t *socket, uint64_t bytes_read) {
    if (!socket || !bytes_read) return;
    socket->unix_stream_head_sequence += bytes_read;
}

static void socket_rights_note_packet_read(edge_socket_t *socket) {
    if (!socket) return;
    ++socket->unix_packet_head_sequence;
}

static int x11_fd_trace_task(const task_t *t) {
#if EDGE_X11_TRACE
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "InputThread") == 0 ||
           strcmp(t->name, "xsetroot") == 0 ||
           strcmp(t->name, "twm") == 0 ||
           strcmp(t->name, "xterm") == 0 ||
           strcmp(t->name, "xclock") == 0 ||
           strcmp(t->name, "xwininfo") == 0 ||
           strcmp(t->name, "xdpyinfo") == 0 ||
           strcmp(t->name, "xdotool") == 0;
#else
    (void)t;
    return 0;
#endif
}

static void socket_release_lwip_pcb(edge_socket_t *s) {
    if (!s || !s->lwip_pcb) return;
    if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_DGRAM) {
        EDGE_LWIP_DO(udp_remove((struct udp_pcb *)s->lwip_pcb));
    } else if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
               s->type == LINUX_SOCK_STREAM) {
        struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
        lwip_stack_core_enter();
        tcp_arg(tp, 0);
        if (s->listening) {
            tcp_accept(tp, 0);
            if (tcp_close(tp) != ERR_OK) tcp_abort(tp);
        } else {
            tcp_recv(tp, 0);
            tcp_err(tp, 0);
            tcp_sent(tp, 0);
            tcp_poll(tp, 0, 0);
            /*
             * EdgeOS raw lwIP callbacks use edge_socket_t as the callback arg.
             * Once the final file descriptor is closed the socket slot can be
             * reused immediately, so a gracefully closing client PCB must not
             * remain alive in lwIP and later deliver FIN/data callbacks into a
             * recycled slot.  Abort here is the correct ownership boundary for
             * the current kernel integration; user-visible close(2) still
             * succeeds, and unacked data lifetime is owned by lwIP only while
             * an EdgeOS socket object exists.
             */
            tcp_abort(tp);
        }
        lwip_stack_core_exit();
    }
    s->lwip_pcb = 0;
}

static void socket_drop_ref_locked(int sock_id, int acceptq_release) {
    task_t *cur = process_current_task();
    static int x11_sock_drop_budget = 120;
    static int acceptq_hold_budget = EDGE_XFCE_BOOT_TRACE ? 96 : 0;
    static int acceptq_drop_trace_budget = EDGE_XFCE_BOOT_TRACE ? 160 : 0;
    if (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS) return;
    if (!g_sockets[sock_id].used) return;
    if (g_sockets[sock_id].acceptq_refs > 0 && !acceptq_release) {
        if (acceptq_hold_budget > 0) {
            printf("[acceptq] hold-drop pid=%d cmd=%s child=%d refs=%d qrefs=%d peer=%d peerpid=%d budget=%d\n",
                   cur ? cur->pid : -1,
                   cur && cur->name[0] ? cur->name : "?",
                   sock_id, g_sockets[sock_id].refs,
                   g_sockets[sock_id].acceptq_refs,
                   g_sockets[sock_id].unix_peer_id,
                   g_sockets[sock_id].peer_cred_pid,
                   acceptq_hold_budget - 1);
            acceptq_hold_budget--;
        }
        return;
    }
    if (g_sockets[sock_id].refs > 1) {
        if (g_sockets[sock_id].acceptq_refs > 0 && acceptq_drop_trace_budget > 0) {
            printf("[acceptq] drop-ref pid=%d cmd=%s child=%d refs=%d qrefs=%d peer=%d peerpid=%d budget=%d\n",
                   cur ? cur->pid : -1,
                   cur && cur->name[0] ? cur->name : "?",
                   sock_id, g_sockets[sock_id].refs,
                   g_sockets[sock_id].acceptq_refs,
                   g_sockets[sock_id].unix_peer_id,
                   g_sockets[sock_id].peer_cred_pid,
                   acceptq_drop_trace_budget - 1);
            acceptq_drop_trace_budget--;
        }
        if (g_sockets[sock_id].domain == LINUX_AF_UNIX && x11_fd_trace_task(cur) && x11_sock_drop_budget-- > 0) {
            printf("[x11dbg] unix-drop-ref pid=%d cmd=%s sid=%d refs=%d peer=%d listening=%d rx=%u closed=%d\n",
                   cur->pid, cur->name, sock_id, g_sockets[sock_id].refs,
                   g_sockets[sock_id].unix_peer_id, g_sockets[sock_id].listening,
                   g_sockets[sock_id].rx_len, g_sockets[sock_id].closed);
        }
        g_sockets[sock_id].refs--;
        return;
    }
    if (g_sockets[sock_id].acceptq_refs > 0 && acceptq_drop_trace_budget > 0) {
        printf("[acceptq] drop-last pid=%d cmd=%s child=%d refs=%d qrefs=%d peer=%d peerpid=%d budget=%d\n",
               cur ? cur->pid : -1,
               cur && cur->name[0] ? cur->name : "?",
               sock_id, g_sockets[sock_id].refs,
               g_sockets[sock_id].acceptq_refs,
               g_sockets[sock_id].unix_peer_id,
               g_sockets[sock_id].peer_cred_pid,
               acceptq_drop_trace_budget - 1);
        acceptq_drop_trace_budget--;
    }
    if (g_sockets[sock_id].domain == LINUX_AF_UNIX && x11_fd_trace_task(cur) && x11_sock_drop_budget-- > 0) {
        printf("[x11dbg] unix-drop-last pid=%d cmd=%s sid=%d peer=%d listening=%d pending=%d rx=%u closed=%d\n",
               cur->pid, cur->name, sock_id, g_sockets[sock_id].unix_peer_id,
               g_sockets[sock_id].listening,
               socket_pending_count(&g_sockets[sock_id]),
               g_sockets[sock_id].rx_len, g_sockets[sock_id].closed);
    }
    {
        int queued_listener = -1;
        if (!acceptq_release && socket_pending_anywhere(sock_id, &queued_listener)) {
            if (g_sockets[sock_id].refs < 1) g_sockets[sock_id].refs = 1;
            if (g_sockets[sock_id].acceptq_refs < 1) g_sockets[sock_id].acceptq_refs = 1;
            if (acceptq_hold_budget > 0) {
                printf("[acceptq] hold-pending pid=%d cmd=%s listener=%d child=%d refs=%d qrefs=%d peer=%d peerpid=%d budget=%d\n",
                       cur ? cur->pid : -1,
                       cur && cur->name[0] ? cur->name : "?",
                       queued_listener, sock_id,
                       g_sockets[sock_id].refs,
                       g_sockets[sock_id].acceptq_refs,
                       g_sockets[sock_id].unix_peer_id,
                       g_sockets[sock_id].peer_cred_pid,
                       acceptq_hold_budget - 1);
                acceptq_hold_budget--;
            }
            return;
        }
    }
    if (acceptq_drop_trace_budget > 0 &&
        (socket_pending_trace_task(cur) ||
         socket_pending_trace_task(process_get_task(g_sockets[sock_id].peer_cred_pid)) ||
         g_sockets[sock_id].listening ||
         socket_pending_count(&g_sockets[sock_id]) > 0 ||
         g_sockets[sock_id].acceptq_refs > 0)) {
        printf("[sock-life] free pid=%d cmd=%s sid=%d refs=%d qrefs=%d domain=%d type=%d listen=%d pending=%d peer=%d peerpid=%d closed=%d rxclosed=%d budget=%d\n",
               cur ? cur->pid : -1,
               cur && cur->name[0] ? cur->name : "?",
               sock_id,
               g_sockets[sock_id].refs,
               g_sockets[sock_id].acceptq_refs,
               g_sockets[sock_id].domain,
               g_sockets[sock_id].type,
               g_sockets[sock_id].listening,
               socket_pending_count(&g_sockets[sock_id]),
               g_sockets[sock_id].unix_peer_id,
               g_sockets[sock_id].peer_cred_pid,
               g_sockets[sock_id].closed,
               g_sockets[sock_id].rx_closed,
               acceptq_drop_trace_budget - 1);
        acceptq_drop_trace_budget--;
    }
    /*
     * A listening AF_UNIX socket owns queued child sockets until accept(2)
     * returns them.  If any queued child is dropped through an error path or a
     * listener teardown, every pending queue must stop referencing that socket
     * slot before it can be reused.  Linux never exposes stale accept queue
     * entries to Xorg/DBus/ICE; leaving a dead slot here makes accept(2) fail
     * even though readiness reported a connection.
     */
    socket_pending_remove_sock(sock_id);
    if (g_sockets[sock_id].listening) {
        while (socket_pending_count(&g_sockets[sock_id]) > 0) {
            int psid = socket_pending_dequeue(&g_sockets[sock_id]);
            if (psid >= 0) {
                socket_acceptq_release(psid);
                if (psid >= 0 && psid < EDGE_MAX_SOCKETS && g_sockets[psid].used) {
                    socket_drop_ref(psid);
                }
            }
        }
    }
    socket_rights_clear_all(&g_sockets[sock_id]);
    unix_binding_unregister_sock(sock_id);
    if (g_sockets[sock_id].packet_handle >= 0)
        edge_linux_packet_socket_release(g_sockets[sock_id].packet_handle);
    if (g_sockets[sock_id].bpf_filter_object_id >= 0)
        kernel_bpf_object_release(
            g_sockets[sock_id].bpf_filter_object_id);
    kernel_socket_multicast_state_release(
        &g_sockets[sock_id].option_state);
    if ((g_sockets[sock_id].domain == LINUX_AF_UNIX ||
         ((g_sockets[sock_id].domain == LINUX_AF_INET || g_sockets[sock_id].domain == LINUX_AF_INET6) &&
          g_sockets[sock_id].type == LINUX_SOCK_STREAM && !g_sockets[sock_id].lwip_pcb)) &&
        g_sockets[sock_id].unix_peer_id >= 0 &&
        g_sockets[sock_id].unix_peer_id < EDGE_MAX_SOCKETS &&
        g_sockets[g_sockets[sock_id].unix_peer_id].used &&
        kernel_unix_socket_close_notifies_peer(
            g_sockets[sock_id].type,
            g_sockets[g_sockets[sock_id].unix_peer_id].unix_peer_id == sock_id)) {
        edge_socket_t *peer = &g_sockets[g_sockets[sock_id].unix_peer_id];
        peer->closed = 1;
        if (kernel_socket_type_has_peer_eof(peer->type)) peer->rx_closed = 1;
        peer->unix_peer_id = -1;
        fd_wake_socket_waiters(g_sockets[sock_id].unix_peer_id);
    }
    socket_release_lwip_pcb(&g_sockets[sock_id]);
    memset(&g_sockets[sock_id], 0, sizeof(g_sockets[sock_id]));
    kernel_socket_slot_release(
        g_socket_slot_claims, EDGE_MAX_SOCKETS, (uint32_t)sock_id);
}

static void socket_drop_ref(int sock_id) {
    socket_drop_ref_locked(sock_id, 0);
}

#define EDGE_SYMLINK_PREFIX "edgeos-symlink:"

static int edge_read_symlink_target(const char *path, char *target, int target_sz) {
    char buf[512];
    int n;
    int prefix_len = (int)strlen(EDGE_SYMLINK_PREFIX);
    if (!path || !target || target_sz <= 0) return -1;
    n = vfs_readlink(path, target, (uint32_t)(target_sz - 1));
    if (n >= 0) {
        target[n] = 0;
        return n;
    }
    n = vfs_read_file(path, buf, (uint32_t)(sizeof(buf) - 1));
    if (n < prefix_len) return -1;
    if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
    buf[n] = 0;
    if (strncmp(buf, EDGE_SYMLINK_PREFIX, (uint32_t)prefix_len) != 0) return -1;
    strncpy(target, buf + prefix_len, (uint32_t)(target_sz - 1));
    target[target_sz - 1] = 0;
    return (int)strlen(target);
}

static int edge_resolve_symlink_path(const char *path, char *out, int out_sz) {
    char target[256];
    int pi = 0;
    int oi = 0;
    if (!path || !out || out_sz <= 1) return -1;
    if (edge_read_symlink_target(path, target, (int)sizeof(target)) < 0) return -1;
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

static int edge_rewrite_sys_class_block_child_path(const char *path, char *out, int out_sz) {
    static const char prefix[] = "/sys/class/block/";
    char name[BLOCK_NAME_MAX];
    char parent[BLOCK_NAME_MAX];
    block_device_t *dev;
    const char *p;
    const char *rest;
    int ni = 0;
    int oi = 0;
    if (!path || !out || out_sz <= 1) return -1;
    if (strncmp(path, prefix, sizeof(prefix) - 1u) != 0) return -1;
    p = path + sizeof(prefix) - 1u;
    while (p[ni] && p[ni] != '/') {
        if (ni + 1 >= (int)sizeof(name)) return -1;
        name[ni] = p[ni];
        ++ni;
    }
    name[ni] = 0;
    if (!name[0] || p[ni] != '/') return -1;
    dev = block_find(name);
    if (!dev) return -1;
    rest = p + ni + 1;
    if (!rest[0]) return -1;
    if (block_is_partition(dev)) {
        if (block_partition_parent_name(dev, parent, sizeof(parent)) < 0) return -1;
    } else {
        strncpy(parent, name, sizeof(parent) - 1);
        parent[sizeof(parent) - 1] = 0;
    }
#define EDGE_REWRITE_PUT_CH(ch_) do { if (oi >= out_sz - 1) return -1; out[oi++] = (ch_); out[oi] = 0; } while (0)
#define EDGE_REWRITE_PUT_STR(s_) do { const char *edge_s_ = (s_); while (*edge_s_) EDGE_REWRITE_PUT_CH(*edge_s_++); } while (0)
    EDGE_REWRITE_PUT_STR("/sys/block/");
    EDGE_REWRITE_PUT_STR(parent);
    if (block_is_partition(dev)) {
        EDGE_REWRITE_PUT_CH('/');
        EDGE_REWRITE_PUT_STR(name);
    }
    EDGE_REWRITE_PUT_CH('/');
    EDGE_REWRITE_PUT_STR(rest);
#undef EDGE_REWRITE_PUT_STR
#undef EDGE_REWRITE_PUT_CH
    return 0;
}

static int edge_resolve_symlink_components(const char *path, char *out, int out_sz) {
    char cur[256];
    if (!path || !out || out_sz <= 1 || path[0] != '/') return -1;
    if (edge_rewrite_sys_class_block_child_path(path, out, out_sz) == 0) return 0;
    strncpy(cur, path, sizeof(cur) - 1);
    cur[sizeof(cur) - 1] = 0;

    for (int pass = 0; pass < 8; ++pass) {
        int changed = 0;
        int len = (int)strlen(cur);
        for (int i = 1; i <= len; ++i) {
            char prefix[256];
            char resolved[256];
            char next[256];
            int plen;
            int ni = 0;
            if (cur[i] != '/' && cur[i] != 0) continue;
            plen = i;
            if (plen <= 0 || plen >= (int)sizeof(prefix)) return -1;
            memcpy(prefix, cur, (uint32_t)plen);
            prefix[plen] = 0;
            if (edge_resolve_symlink_path(prefix, resolved, (int)sizeof(resolved)) < 0) continue;
            for (int r = 0; resolved[r] && ni < (int)sizeof(next) - 1; ++r) next[ni++] = resolved[r];
            if (cur[i] == '/') {
                if (ni > 1 && next[ni - 1] == '/') ni--;
                for (int r = i; cur[r] && ni < (int)sizeof(next) - 1; ++r) next[ni++] = cur[r];
            }
            next[ni] = 0;
            strncpy(cur, next, sizeof(cur) - 1);
            cur[sizeof(cur) - 1] = 0;
            changed = 1;
            break;
        }
        if (!changed) {
            strncpy(out, cur, (uint32_t)(out_sz - 1));
            out[out_sz - 1] = 0;
            return 0;
        }
    }
    return -1;
}

static int edge_child_path(char *out, int out_sz, const char *dir, const char *name) {
    int di = 0;
    if (!out || out_sz <= 1 || !dir || !name) return -1;
    if (dir[0] != '/') return -1;
    out[di++] = '/';
    if (!(dir[0] == '/' && dir[1] == 0)) {
        for (int i = 1; dir[i] && di < out_sz - 1; ++i) out[di++] = dir[i];
    }
    if (di > 1 && out[di - 1] != '/' && di < out_sz - 1) out[di++] = '/';
    for (int i = 0; name[i] && di < out_sz - 1; ++i) out[di++] = name[i];
    out[di] = 0;
    return 0;
}

static int build_at_path(int dirfd, const char *path_in, char *out, int out_sz) {
    task_t *task;
    const char *base;
    const char *root;
    if (!path_in || !out || out_sz <= 1) return -1;
    task = process_current_task();
    if (!task) return -1;
    root = task->root[0] ? task->root : "/";
    if (path_in[0] == '/' || dirfd == LINUX_AT_FDCWD) {
        base = task->cwd[0] ? task->cwd : "/";
    } else {
        edge_fd_proc_t *p = fd_proc_with_stdio();
        edge_fd_t *e = fd_get(p, dirfd);
        if (!e || e->kind != FD_VFS) return -1;
        if ((e->inode.mode & 0xF000) != VFS_INODE_DIR) return -1;
        if (!e->path[0] || e->path[0] != '/') return -1;
        base = e->path;
    }
    return kernel_fs_path_resolve(
        root, base, path_in, (char *)task->scratch->xattr_scratch,
        sizeof(task->scratch->xattr_scratch), out, (uint32_t)out_sz) == 0 ? 0 : -1;
}

static void fill_kstat(const vfs_inode_t *ino,
                       edge_x86_64_linux_stat_t *st) {
    memset(st, 0, sizeof(*st));
    if (!ino) return;
    st->st_dev = 1;
    st->st_ino = ino->ino;
    st->st_nlink = vfs_inode_link_count(ino);
    st->st_mode = ino->mode;
    st->st_uid = ino->uid;
    st->st_gid = ino->gid;
    st->st_rdev = ino->rdev;
    st->st_size = (int64_t)ino->size;
    st->st_blksize = 4096;
    st->st_blocks = ((int64_t)ino->size + 511) / 512;
    /*
     * Real inode timestamps must be stable.  Reporting "now" for zero-valued
     * ext4 timestamps makes repeated stat(2) calls disagree, which breaks
     * Linux userland cache validation such as fontconfig's directory checksum.
     * Synthetic nodes that intentionally want volatile timestamps use
     * fill_kstat_mode_size(); persistent VFS inodes report the inode value.
     */
    st->st_atim.tv_sec = (int64_t)ino->atime;
    st->st_atim.tv_nsec = 0;
    st->st_mtim.tv_sec = (int64_t)ino->mtime;
    st->st_mtim.tv_nsec = 0;
    st->st_ctim.tv_sec = (int64_t)ino->ctime;
    st->st_ctim.tv_nsec = 0;
}

static uint64_t linux_makedev(uint32_t major, uint32_t minor) {
    return ((uint64_t)(minor & 0xFFu)) |
           ((uint64_t)(major & 0xFFFu) << 8) |
           ((uint64_t)(minor & ~0xFFu) << 12) |
           ((uint64_t)(major & ~0xFFFu) << 32);
}

static uint64_t linux_tty_rdev_from_line(int line_id) {
    if (line_id == 0) return linux_makedev(4, 64);
    if (line_id >= 1 && line_id <= EDGE_FB_VT_COUNT) return linux_makedev(4, (uint32_t)line_id);
    return 0;
}

static uint64_t linux_tty_rdev_from_path(const char *path) {
    if (!path || !path[0]) return 0;
    if (strcmp(path, "/dev/console") == 0) return linux_makedev(5, 1);
    if (strcmp(path, "/dev/tty") == 0) return linux_makedev(5, 0);
    if (strcmp(path, "/dev/ttyS0") == 0) return linux_makedev(4, 64);
    if (strcmp(path, "/dev/tty0") == 0) return linux_makedev(4, 0);
    if (strncmp(path, "/dev/tty", 8) == 0) {
        uint32_t vt = 0;
        const char *p = path + 8;
        if (!*p) return 0;
        while (*p >= '0' && *p <= '9') {
            vt = vt * 10u + (uint32_t)(*p - '0');
            ++p;
        }
        if (*p == 0 && vt >= 1 && vt <= EDGE_FB_VT_COUNT) return linux_makedev(4, vt);
    }
    return 0;
}

static uint64_t linux_graphics_input_rdev_from_path(const char *path) {
    if (!path || !path[0]) return 0;
    if (uvc_path_kind(path)) return linux_makedev(EDGE_UVC_VIDEO_MAJOR, EDGE_UVC_VIDEO_MINOR);
    if (strcmp(path, "/dev/dri/card0") == 0) return linux_makedev(226, 0);
    if (edge_drm_path_is_render(path)) return linux_makedev(226, 128);
    if (strcmp(path, "/dev/input/mice") == 0) return linux_makedev(13, 63);
    if (strcmp(path, "/dev/input/mouse0") == 0) return linux_makedev(13, 32);
    if (strncmp(path, "/dev/input/event", 16) == 0) {
        uint32_t ev = 0;
        const char *p = path + 16;
        if (!*p) return 0;
        while (*p >= '0' && *p <= '9') {
            ev = ev * 10u + (uint32_t)(*p - '0');
            ++p;
        }
        if (*p == 0 && ev < EDGE_INPUT_DEVICE_MAX)
            return linux_makedev(13, 64u + ev);
    }
    if (strcmp(path, "/dev/uinput") == 0) return linux_makedev(10, 223);
    return 0;
}

static uint64_t linux_misc_rdev_from_path(const char *path) {
    if (!path || !path[0]) return 0;
    if (strcmp(path, "/dev/null") == 0) return linux_makedev(1, 3);
    if (strcmp(path, "/dev/zero") == 0) return linux_makedev(1, 5);
    if (strcmp(path, "/dev/full") == 0) return linux_makedev(1, 7);
    if (strcmp(path, "/dev/random") == 0) return linux_makedev(1, 8);
    if (strcmp(path, "/dev/urandom") == 0) return linux_makedev(1, 9);
    if (strcmp(path, "/dev/kmsg") == 0) return linux_makedev(1, 11);
    if (strcmp(path, "/dev/ptmx") == 0) return linux_makedev(5, 2);
#ifdef CONFIG_WATCHDOG
    if ((strcmp(path, "/dev/watchdog") == 0 || strcmp(path, "/dev/watchdog0") == 0) &&
        watchdog_available()) {
        return linux_makedev(10, 130);
    }
#endif
    return 0;
}

static int path_is_audio_device(const char *path) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO)
    return path &&
           (strcmp(path, "/dev/dsp") == 0 ||
            strcmp(path, "/dev/audio") == 0 ||
            strcmp(path, "/dev/mixer") == 0) &&
           audio_available();
#else
    (void)path;
    return 0;
#endif
}

static int path_is_alsa_device(const char *path) {
    int kind = alsa_path_kind(path);
    return alsa_available() &&
           (kind == EDGE_ALSA_NODE_CONTROL ||
            kind == EDGE_ALSA_NODE_PCM_PLAYBACK ||
            kind == EDGE_ALSA_NODE_PCM_CAPTURE ||
            kind == EDGE_ALSA_NODE_TIMER);
}

static uint64_t linux_devnode_ino_from_path(const char *path) {
    uint64_t base = 0xD0000000u + (uint64_t)block_count();
    if (!path || !path[0]) return 0;
    if (strcmp(path, "/dev/console") == 0) return base + 0u;
    if (strcmp(path, "/dev/tty") == 0) return base + 1u;
    if (strcmp(path, "/dev/tty0") == 0) return base + 2u;
    if (strcmp(path, "/dev/ttyS0") == 0) return base + 10u;
    if (strncmp(path, "/dev/tty", 8) == 0) {
        uint32_t vt = 0;
        const char *p = path + 8;
        if (!*p) return 0;
        while (*p >= '0' && *p <= '9') {
            vt = vt * 10u + (uint32_t)(*p - '0');
            ++p;
        }
        if (*p == 0 && vt >= 1 && vt <= EDGE_FB_VT_COUNT) return base + 2u + vt;
        return 0;
    }
    if (strcmp(path, "/dev/null") == 0) return base + 11u;
    if (strcmp(path, "/dev/zero") == 0) return base + 12u;
    if (strcmp(path, "/dev/fb0") == 0) return base + 13u;
    if (strcmp(path, "/dev/random") == 0) return base + 14u;
    if (strcmp(path, "/dev/urandom") == 0) return base + 15u;
    if (strcmp(path, "/dev/ptmx") == 0) return base + 16u;
    if (strcmp(path, "/dev/pts") == 0) return base + 17u;
    if (strcmp(path, "/dev/input") == 0) return base + 18u;
    if (strcmp(path, "/dev/input/mice") == 0) return base + 19u;
    if (strcmp(path, "/dev/input/mouse0") == 0) return base + 20u;
    if (strncmp(path, "/dev/input/event", 16) == 0) {
        uint32_t ev = 0;
        const char *p = path + 16;
        if (!*p) return 0;
        while (*p >= '0' && *p <= '9') {
            ev = ev * 10u + (uint32_t)(*p - '0');
            ++p;
        }
        if (*p == 0 && ev < EDGE_INPUT_DEVICE_MAX)
            return base + 21u + ev;
        return 0;
    }
    if (strcmp(path, "/dev/uinput") == 0) return base + 60u;
    if (strcmp(path, "/dev/dri") == 0) return base + 61u;
    if (strcmp(path, "/dev/dri/card0") == 0) return base + 62u;
    if (edge_drm_path_is_render(path)) return base + 63u;
    if (strcmp(path, "/dev/kmsg") == 0) return base + 64u;
    if (strcmp(path, "/dev/rtc") == 0) return base + 65u;
    if (strcmp(path, "/dev/rtc0") == 0) return base + 66u;
    if (strcmp(path, "/dev/watchdog") == 0) return base + 67u;
    if (strcmp(path, "/dev/watchdog0") == 0) return base + 68u;
    if (strcmp(path, "/dev/dsp") == 0) return base + 69u;
    if (strcmp(path, "/dev/audio") == 0) return base + 70u;
    if (strcmp(path, "/dev/mixer") == 0) return base + 71u;
    if (strcmp(path, EDGE_UVC_PATH_VIDEO0) == 0) return uvc_inode();
    if (strcmp(path, "/dev/snd") == 0) return alsa_inode_from_kind(EDGE_ALSA_NODE_SND_DIR);
    if (strcmp(path, EDGE_ALSA_PATH_CONTROL) == 0) return alsa_inode_from_kind(EDGE_ALSA_NODE_CONTROL);
    if (strcmp(path, EDGE_ALSA_PATH_PCM_PLAYBACK) == 0) return alsa_inode_from_kind(EDGE_ALSA_NODE_PCM_PLAYBACK);
    if (strcmp(path, EDGE_ALSA_PATH_PCM_CAPTURE) == 0) return alsa_inode_from_kind(EDGE_ALSA_NODE_PCM_CAPTURE);
    if (strcmp(path, EDGE_ALSA_PATH_TIMER) == 0) return alsa_inode_from_kind(EDGE_ALSA_NODE_TIMER);
    return 0;
}

static void fill_kstat_mode_size(uint16_t mode, uint32_t size,
                                 edge_x86_64_linux_stat_t *st) {
    uint64_t now_us = boottime_realtime_us();
    int64_t now_sec = (int64_t)(now_us / 1000000ull);
    int64_t now_nsec = (int64_t)((now_us % 1000000ull) * 1000ull);
    memset(st, 0, sizeof(*st));
    st->st_dev = 1;
    st->st_ino = 0;
    st->st_nlink = 1;
    st->st_mode = mode;
    st->st_uid = 0;
    st->st_gid = 0;
    st->st_rdev = 0;
    st->st_size = (int64_t)size;
    st->st_blksize = 4096;
    st->st_blocks = ((int64_t)size + 511) / 512;
    st->st_atim.tv_sec = now_sec;
    st->st_atim.tv_nsec = now_nsec;
    st->st_mtim.tv_sec = now_sec;
    st->st_mtim.tv_nsec = now_nsec;
    st->st_ctim.tv_sec = now_sec;
    st->st_ctim.tv_nsec = now_nsec;
}

static task_t *task_by_pid_mutable_local(int pid) {
    if (pid <= 0) return process_current_task();
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *t = process_task_by_index(i);
        if (!t || t->state == TASK_UNUSED) continue;
        if (t->pid == pid) return (task_t *)(uintptr_t)t;
    }
    return 0;
}

static edge_fd_proc_t *fd_proc_storage_allocate(void) {
    uint32_t pages =
        (uint32_t)((sizeof(edge_fd_proc_t) + 4095u) / 4096u);
    edge_fd_proc_t *process = 0;
    uint64_t irq_flags;

    irq_flags = spin_lock_irqsave(&g_fd_proc_registry_lock);
    if (g_fd_proc_cache_count != 0u)
        process = g_fd_proc_cache[--g_fd_proc_cache_count];
    spin_unlock_irqrestore(&g_fd_proc_registry_lock, irq_flags);
    if (!process)
        process = (edge_fd_proc_t *)arch_vm_alloc_pages(pages);
    if (!process) return 0;
    memset(process, 0, (uint64_t)pages * 4096u);
    process->cache_owned =
        (uint32_t)(process_user_mmap_backing_page_index(process) < 0);
    return process;
}

static void fd_proc_storage_release(edge_fd_proc_t *process) {
    uint32_t pages;
    uint32_t cache_owned;

    if (!process) return;
    pages = (uint32_t)((sizeof(*process) + 4095u) / 4096u);
    cache_owned = process->cache_owned;
    if (cache_owned) {
        uint64_t irq_flags;

        memset(process, 0, (uint64_t)pages * 4096u);
        process->cache_owned = 1u;
        irq_flags = spin_lock_irqsave(&g_fd_proc_registry_lock);
        if (g_fd_proc_cache_count < g_fd_proc_cache_reserved) {
            g_fd_proc_cache[g_fd_proc_cache_count++] = process;
            process = 0;
        }
        spin_unlock_irqrestore(&g_fd_proc_registry_lock, irq_flags);
        if (!process) return;
    }
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page(
            (uint8_t *)process + (uint64_t)page * 4096u);
}

static edge_fd_proc_t *fd_proc_lookup_or_create(
        int pid, int create, int ensure_stdio) {
    edge_fd_proc_t *candidate = 0;

    for (;;) {
        edge_fd_proc_t *process = 0;
        int free_slot = -1;
        uint64_t irq_flags =
            spin_lock_irqsave(&g_fd_proc_registry_lock);

        for (int index = 0; index < EDGE_MAX_FD_PROCS; ++index) {
            edge_fd_proc_t *current = __atomic_load_n(
                &g_fd_procs[index], __ATOMIC_ACQUIRE);
            if (current && !__atomic_load_n(
                    &current->detached, __ATOMIC_ACQUIRE) &&
                current->pid == pid) {
                process = current;
                break;
            }
            if (create && !current && free_slot < 0)
                free_slot = index;
        }
        if (!process && candidate && free_slot >= 0) {
            __atomic_store_n(
                &g_fd_procs[free_slot], candidate, __ATOMIC_RELEASE);
            process = candidate;
            candidate = 0;
        }
        spin_unlock_irqrestore(&g_fd_proc_registry_lock, irq_flags);

        if (process) {
            if (candidate) fd_proc_unpublished_discard(candidate);
            return process;
        }
        if (!create || free_slot < 0) {
            if (candidate) fd_proc_unpublished_discard(candidate);
            return 0;
        }
        if (candidate) continue;

        candidate = fd_proc_storage_allocate();
        if (!candidate) return 0;
        if (kernel_fd_table_runtime_initialize(
                &candidate->table_runtime, candidate->slot_states,
                EDGE_MAX_FD) < 0) {
            fd_proc_storage_release(candidate);
            return 0;
        }
        candidate->references = 1u;
        candidate->pid = pid;
        if (ensure_stdio) fd_ensure_stdio(candidate);
    }
}

static edge_fd_proc_t *fd_proc_for_pid(int pid, int create) {
    return fd_proc_lookup_or_create(pid, create, 1);
}

static edge_fd_proc_t *fd_proc_for_pid_empty(int pid, int create) {
    return fd_proc_lookup_or_create(pid, create, 0);
}

static int fd_proc_table_retain(edge_fd_proc_t *process) {
    uint32_t references;

    if (!process ||
        __atomic_load_n(&process->detached, __ATOMIC_ACQUIRE))
        return -EBADF;
    references = __atomic_load_n(
        &process->references, __ATOMIC_ACQUIRE);
    for (;;) {
        if (!references || references == UINT32_MAX)
            return references ? -EOVERFLOW : -EBADF;
        if (__atomic_compare_exchange_n(
                &process->references, &references,
                references + 1u, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
    if (__atomic_load_n(&process->detached, __ATOMIC_ACQUIRE)) {
        fd_proc_table_release(process);
        return -EBADF;
    }
    return 0;
}

static void fd_proc_table_free(edge_fd_proc_t *process) {
    fd_proc_storage_release(process);
}

static void fd_proc_table_retire_or_free(edge_fd_proc_t *process) {
    uint64_t irq_flags;
    int defer_free;

    if (!process) return;
    irq_flags = spin_lock_irqsave(&g_fd_proc_registry_lock);
    defer_free = g_fd_proc_registry_readers != 0u;
    if (defer_free) {
        process->retired_next = g_fd_proc_retired_head;
        g_fd_proc_retired_head = process;
    }
    spin_unlock_irqrestore(&g_fd_proc_registry_lock, irq_flags);
    if (!defer_free) fd_proc_table_free(process);
}

static void fd_proc_table_release(edge_fd_proc_t *process) {
    uint32_t remaining;

    if (!process) return;
    remaining = __atomic_sub_fetch(
        &process->references, 1u, __ATOMIC_ACQ_REL);
    if (remaining) return;
    fd_proc_table_retire_or_free(process);
}

static void fd_proc_registry_read_begin(void) {
    uint64_t irq_flags;

    irq_flags = spin_lock_irqsave(&g_fd_proc_registry_lock);
    __atomic_add_fetch(
        &g_fd_proc_registry_readers, 1u, __ATOMIC_ACQ_REL);
    spin_unlock_irqrestore(&g_fd_proc_registry_lock, irq_flags);
}

static void fd_proc_registry_read_end(void) {
    edge_fd_proc_t *retired = 0;
    uint64_t irq_flags;

    irq_flags = spin_lock_irqsave(&g_fd_proc_registry_lock);
    if (g_fd_proc_registry_readers != 0u &&
        --g_fd_proc_registry_readers == 0u) {
        retired = g_fd_proc_retired_head;
        g_fd_proc_retired_head = 0;
    }
    spin_unlock_irqrestore(&g_fd_proc_registry_lock, irq_flags);
    while (retired) {
        edge_fd_proc_t *next = retired->retired_next;
        fd_proc_table_free(retired);
        retired = next;
    }
}

static int fd_proc_registry_detach(edge_fd_proc_t *process) {
    int slot = -1;
    uint64_t irq_flags;

    if (!process) return -1;
    irq_flags = spin_lock_irqsave(&g_fd_proc_registry_lock);
    for (int index = 0; index < EDGE_MAX_FD_PROCS; ++index) {
        if (g_fd_procs[index] != process) continue;
        __atomic_store_n(
            &g_fd_procs[index], 0, __ATOMIC_RELEASE);
        slot = index;
        break;
    }
    spin_unlock_irqrestore(&g_fd_proc_registry_lock, irq_flags);
    return slot;
}

static int fd_cancel_constructed_reserved(
        edge_fd_proc_t *process, int descriptor) {
    edge_fd_t clone;
    uint32_t number;
    uint64_t irq_flags;
    int result;

    if (!process || descriptor < 0 ||
        descriptor >= EDGE_MAX_FD)
        return -EBADF;
    number = (uint32_t)descriptor;
    memset(&clone, 0, sizeof(clone));
    irq_flags = kernel_fd_table_lock(
        &process->table_runtime);
    if (kernel_fd_table_state_locked(
            &process->table_runtime, number) !=
            KERNEL_FD_SLOT_RESERVED ||
        process->fds[number].used) {
        kernel_fd_table_unlock(
            &process->table_runtime, irq_flags);
        return -EBADF;
    }
    if (process->fds[number].file_ref <= 0) {
        result = kernel_fd_table_cancel_reservation_locked(
            &process->table_runtime, number);
        if (result == 0)
            memset(&process->fds[number], 0,
                   sizeof(process->fds[number]));
        kernel_fd_table_unlock(
            &process->table_runtime, irq_flags);
        return result;
    }
    result = kernel_fd_table_begin_cancel_batch_locked(
        &process->table_runtime, &number, 1u);
    if (result == 0) {
        clone = process->fds[number];
        memset(&process->fds[number], 0,
               sizeof(process->fds[number]));
    }
    kernel_fd_table_unlock(
        &process->table_runtime, irq_flags);
    if (result < 0) return result;

    clone.used = 1;
    (void)fd_release_entry(&clone, 0, 0, 0);
    irq_flags = kernel_fd_table_lock(
        &process->table_runtime);
    result = kernel_fd_table_complete_close_locked(
        &process->table_runtime, number);
    kernel_fd_table_unlock(
        &process->table_runtime, irq_flags);
    return result;
}

static void fd_proc_unpublished_discard(edge_fd_proc_t *process) {
    if (!process) return;
    for (int descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
        edge_fd_t closing;

        if (fd_remove_open(process, descriptor, &closing) == 0) {
            (void)fd_release_entry(&closing, 0, 0, 0);
        } else {
            (void)fd_cancel_constructed_reserved(process, descriptor);
        }
    }
    fd_proc_storage_release(process);
}

static void fd_proc_release(int pid);
static void fd_wake_pidfd_waiters(int target_pid);

static int fd_owner_pid_current(void) {
    int pid = process_getfdpid();
    return pid > 0 ? pid : process_getpid();
}

static uint64_t do_sys_kill(uint64_t pid, uint64_t sig);

static edge_fd_proc_t *fd_proc_with_stdio(void) {
    edge_fd_proc_t *p = fd_proc_for_pid(fd_owner_pid_current(), 1);
    return p;
}

void syscall_ensure_process_stdio(int pid) {
    edge_fd_proc_t *process;
    if (pid <= 0) return;
    process = fd_proc_for_pid_empty(pid, 1);
    if (process) fd_ensure_console_stdio(process, console_line_default());
}

static void syscall_task_prestart(task_t *task) {
    if (task && task->pid == 1) syscall_ensure_process_stdio(task->pid);
}

static void fd_release_current_if_last_thread(void) {
    int tgid = process_gettgid();
    if (tgid > 0 && process_thread_group_size(tgid) > 1) return;
    fd_proc_release(fd_owner_pid_current());
}

static void clear_task_child_tid_if_needed(task_t *t) {
    int32_t zero = 0;
    int write_ok;
    uint64_t futex_key;
    int private_key;
#if EDGE_XFCE_BOOT_TRACE
    static int clear_tid_trace_budget = 96;
#endif
    if (!t || !t->linux_thread.clear_child_tid) return;
    /*
     * Linux CLONE_CHILD_CLEARTID is part of pthread thread-exit semantics:
     * the exiting thread clears its userspace TID word and futex-wakes a
     * joiner waiting on that address.  This must also happen when EdgeOS tears
     * down a non-current sibling during exit_group; otherwise the group leader
     * can block forever in FUTEX_WAIT on a stale TID value.
     */
    write_ok = process_write_user_memory(
        t->pid, t->linux_thread.clear_child_tid, &zero, sizeof(zero));
#if EDGE_XFCE_BOOT_TRACE
    if (clear_tid_trace_budget > 0 && t->name[0] &&
        (strcmp(t->name, "Xorg") == 0 ||
         strcmp(t->name, "InputThread") == 0 ||
         strcmp(t->name, "xfce4-session") == 0 ||
         strcmp(t->name, "xfwm4") == 0 ||
         strcmp(t->name, "xfce4-panel") == 0 ||
         strcmp(t->name, "xfdesktop") == 0 ||
         strcmp(t->name, "xfsettingsd") == 0)) {
        printf("[cleartid] pid=%d cmd=%s tgid=%d addr=0x%x write=%d key=0 budget=%d\n",
               t->pid, t->name, t->tgid > 0 ? t->tgid : t->pid,
               (uint32_t)t->linux_thread.clear_child_tid, write_ok,
               clear_tid_trace_budget);
        clear_tid_trace_budget--;
    }
#endif
    if (write_ok == 0) {
        /*
         * Linux's clear_child_tid wake is a plain FUTEX_WAKE, not
         * FUTEX_PRIVATE_FLAG.  pthread joiners in musl/Xorg wait with
         * FUTEX_WAIT on this word, so using the mm-private key strands them.
         */
        if (futex_key_for_task(t, t->linux_thread.clear_child_tid, 0,
                               &futex_key, &private_key) == 0)
            (void)futex_waiter_wake_matching_key(
                futex_key, private_key, 1u, UINT32_MAX, 0);
    }
    t->linux_thread.clear_child_tid = 0;
}

static void robust_futex_mark_owner_died(task_t *owner, uint64_t entry_u,
                                         int64_t futex_offset, int pi,
                                         int pending) {
    uint64_t futex_u;
    uint32_t word;
    uint32_t new_word;
    uint64_t futex_key;
    int private_key;
    if (!owner || !entry_u) return;
    futex_u = (uint64_t)((int64_t)entry_u + futex_offset);
    if ((futex_u & 3u) != 0) return;
    if (!user_range_ok(futex_u, sizeof(word))) return;
    if (copy_from_user(&word, futex_u, sizeof(word)) < 0) return;
    if (pending && !pi && !(word & LINUX_FUTEX_TID_MASK)) {
        if (futex_key_for_task(owner, futex_u, 0,
                               &futex_key, &private_key) == 0)
            (void)futex_waiter_wake_matching_key(
                futex_key, private_key, 1u, UINT32_MAX, 0);
        return;
    }
    if ((word & LINUX_FUTEX_TID_MASK) != (uint32_t)owner->pid) return;
    if (pi) {
        uint64_t irq_flags = spin_lock_irqsave(&g_futex_lock);
        int handled = kernel_futex_pi_owner_died_locked(
            futex_u, owner->pid, word);
        spin_unlock_irqrestore(&g_futex_lock, irq_flags);
        if (handled != 0) return;
    }
    new_word = (word & ~LINUX_FUTEX_TID_MASK) | LINUX_FUTEX_OWNER_DIED;
    if (copy_to_user(futex_u, &new_word, sizeof(new_word)) < 0) return;
    if (futex_key_for_task(owner, futex_u, 0,
                           &futex_key, &private_key) == 0)
        (void)futex_waiter_wake_matching_key(
            futex_key, private_key, 1u, UINT32_MAX, 0);
}

static int robust_futex_can_access_task_user(task_t *t) {
    task_t *cur = process_current_task();
    if (!t || !cur) return 0;
    if (t == cur) return 1;
    /*
     * Robust lists are userspace pointers.  EdgeOS usercopy helpers operate in
     * the currently active address space, so only process a non-current task
     * when it shares the current CR3, as CLONE_VM/CLONE_THREAD tasks do.
     * External kill of an unrelated process must not read the caller's address
     * space through the victim's robust-list pointer.
     */
    return cur->cr3 != 0 && cur->cr3 == t->cr3;
}

static void robust_futex_cleanup_task(task_t *t) {
    uint64_t head_u;
    uint64_t next_u;
    uint64_t pending_u = 0;
    uint64_t pending_entry;
    uint32_t current_modifier;
    uint32_t pending_modifier;
    int64_t futex_offset = 0;
    int compat;

    if (!t) return;
    waiter_remove_pid(t->pid);
    if (!t->linux_thread.robust_list_head) return;
    if (!robust_futex_can_access_task_user(t)) return;
    compat = t->linux_thread.robust_list_length ==
             EDGE_LINUX_COMPAT_ROBUST_LIST_HEAD_SIZE;
    if (t->linux_thread.robust_list_length && !compat &&
        t->linux_thread.robust_list_length != LINUX_ROBUST_LIST_HEAD_SIZE)
        return;
    head_u = t->linux_thread.robust_list_head;
    if (compat) {
        uint32_t compat_next;
        int32_t compat_offset;
        uint32_t compat_pending;

        if (!user_range_ok(
                head_u, EDGE_LINUX_COMPAT_ROBUST_LIST_HEAD_SIZE))
            return;
        if (copy_from_user(&compat_next, head_u,
                           sizeof(compat_next)) < 0 ||
            copy_from_user(&compat_offset, head_u + 4,
                           sizeof(compat_offset)) < 0 ||
            copy_from_user(&compat_pending, head_u + 8,
                           sizeof(compat_pending)) < 0)
            return;
        next_u = compat_next;
        futex_offset = compat_offset;
        pending_u = compat_pending;
    } else {
        if (!user_range_ok(head_u, LINUX_ROBUST_LIST_HEAD_SIZE)) return;
        if (copy_from_user(&next_u, head_u, sizeof(next_u)) < 0) return;
        if (copy_from_user(&futex_offset, head_u + 8,
                           sizeof(futex_offset)) < 0)
            return;
        if (copy_from_user(&pending_u, head_u + 16,
                           sizeof(pending_u)) < 0)
            return;
    }

    current_modifier = (uint32_t)(next_u & LINUX_FUTEX_ROBUST_MOD_MASK);
    next_u &= ~(uint64_t)LINUX_FUTEX_ROBUST_MOD_MASK;
    pending_modifier =
        (uint32_t)(pending_u & LINUX_FUTEX_ROBUST_MOD_MASK);
    pending_entry = pending_u & ~(uint64_t)LINUX_FUTEX_ROBUST_MOD_MASK;

    for (uint32_t i = 0; i < LINUX_ROBUST_LIST_LIMIT && next_u && next_u != head_u; ++i) {
        uint64_t entry_u = next_u;
        uint64_t encoded_next;
        if (compat) {
            uint32_t compat_encoded_next;

            if (!user_range_ok(entry_u, sizeof(compat_encoded_next))) break;
            if (copy_from_user(&compat_encoded_next, entry_u,
                               sizeof(compat_encoded_next)) < 0)
                break;
            encoded_next = compat_encoded_next;
        } else {
            if (!user_range_ok(entry_u, sizeof(next_u))) break;
            if (copy_from_user(&encoded_next, entry_u,
                               sizeof(encoded_next)) < 0)
                break;
        }
        if (entry_u != pending_entry)
            robust_futex_mark_owner_died(
                t, entry_u, futex_offset,
                (current_modifier & LINUX_FUTEX_ROBUST_MOD_PI) != 0,
                0);
        current_modifier =
            (uint32_t)(encoded_next & LINUX_FUTEX_ROBUST_MOD_MASK);
        next_u = encoded_next & ~(uint64_t)LINUX_FUTEX_ROBUST_MOD_MASK;
    }
    if (pending_entry)
        robust_futex_mark_owner_died(
            t, pending_entry, futex_offset,
            (pending_modifier & LINUX_FUTEX_ROBUST_MOD_PI) != 0, 1);
    t->linux_thread.robust_list_head = 0;
    t->linux_thread.robust_list_length = 0;
}

static void syscall_task_exit_cleanup(task_t *t) {
    uint64_t start_time_ticks;

    if (!t) return;
    start_time_ticks = t->rusage_start_us / 10000u;
    if (!start_time_ticks) start_time_ticks = 1u;
    kernel_bpf_task_storage_task_exit(t->pid, start_time_ticks);
    kernel_io_uring_task_release(t->pid);
    kernel_epoll_wait_lease_release(&t->epoll_wait_lease);
    tty_session_release_task(t);
    futex_waiter_cancel_pid(t->pid);
    robust_futex_cleanup_task(t);
    clear_task_child_tid_if_needed(t);
}

static void syscall_task_zombie_cleanup(task_t *t) {
    if (!t) return;
    /*
     * pidfd readiness is defined by the task's exited state.  Notify after the
     * process core has published TASK_ZOMBIE; waking before that transition
     * lets epoll observe a live task and miss the only edge, forcing GLib child
     * supervision to wait for its timeout on every short-lived loader.
     */
    fd_wake_pidfd_waiters(t->pid);
}

static __attribute__((noreturn)) void exit_current_thread_or_group(int code) {
    int tid = process_gettid();
    int tgid = process_gettgid();

    /*
     * Keep the historical EdgeOS rule that an exiting group leader terminates
     * its remaining threads, but route that teardown through the process core.
     * The process core orders non-leaders before the leader and owns fd, mm,
     * parent-death signal, and orphan lifetimes.  Bypassing it used to strand
     * GLib/Glycin helper processes after their supervising pthread exited.
     */
    if (tgid > 0 && tid == tgid) {
        kernel_aio_release_owner(tgid);
        kernel_posix_timer_delete_process(tgid);
        kernel_itimer_real_delete_process(tgid);
        process_exit_current_group(code);
    } else {
        process_exit_current(code);
    }
    scheduler_yield();
    for (;;) {
        __asm__ __volatile__("sti; hlt");
    }
}

static __attribute__((noreturn)) void exit_entire_thread_group(int code) {
    task_t *cur = process_current_task();
    int tgid = process_gettgid();

    if (!cur || tgid <= 0) {
        exit_current_thread_or_group(code);
    }

    /*
     * exit_group may be called by any pthread.  process_exit_current_group()
     * runs the registered cleanup hook for every member while the shared mm is
     * still alive, then exits the leader last.  That ordering is required for
     * robust futex owner death, clear_child_tid, and PR_SET_PDEATHSIG semantics.
     */
    kernel_posix_timer_delete_process(tgid);
    kernel_itimer_real_delete_process(tgid);
    kernel_aio_release_owner(tgid);
    process_exit_current_group(code);
    scheduler_yield();
    for (;;) {
        __asm__ __volatile__("sti; hlt");
    }
}

__attribute__((noreturn)) void arch_current_exit(int32_t code,
                                                 int whole_thread_group) {
    if (whole_thread_group)
        exit_entire_thread_group(code);
    exit_current_thread_or_group(code);
}

static kernel_file_description_locator_t file_ref_locator(int id) {
    return kernel_file_description_handle_locator((uint32_t)id);
}

static int file_ref_alloc(uint32_t initial_status_flags) {
    uint32_t handle = 0;
    uint64_t identity = 0;

    if (kernel_file_description_create(
            0, initial_status_flags, 0, &handle, &identity) < 0)
        return 0;
    (void)identity;
    return (int)handle;
}

static uint64_t file_ref_identity(int id) {
    uint64_t identity = 0;

    if (id <= 0 ||
        kernel_file_description_identity(
            file_ref_locator(id), &identity) < 0)
        return 0;
    return identity;
}

static int file_ref_get(int id) {
    if (id <= 0) return -1;
    return kernel_file_description_retain(
               file_ref_locator(id)) == 0 ? 0 : -1;
}

static int file_ref_epoll_pin(uint64_t identity) {
    if (!identity) return -1;
    return kernel_file_description_pin_identity(identity) == 0 ? 0 : -1;
}

static void file_ref_epoll_unpin(uint64_t identity) {
    if (!identity) return;
    (void)kernel_file_description_unpin_identity(identity);
}

static int file_ref_put(int id) {
    kernel_file_description_release_t release;

    if (id <= 0 ||
        kernel_file_description_release_begin(
            file_ref_locator(id), &release) < 0)
        return -1;
    if (release.active &&
        kernel_file_description_release_finish(&release) < 0)
        return -1;
    return (int)release.remaining_references;
}

static int fd_mount_monitor_snapshot(const edge_fd_t *e,
                                     uint32_t *namespace_id,
                                     uint32_t *observed_generation) {
    if (!e || e->kind != FD_VFS || e->file_ref <= 0 ||
        !namespace_id || !observed_generation)
        return 0;
    return kernel_file_description_mount_snapshot(
               file_ref_locator(e->file_ref), namespace_id,
               observed_generation) == 0;
}

static void fd_mount_monitor_initialize(edge_fd_t *e) {
    int32_t target_pid;
    uint32_t namespace_id;
    uint32_t generation;
    if (!e || e->kind != FD_VFS || e->file_ref <= 0)
        return;
    if (!kernel_linux_mount_monitor_target(e->path, process_getpid(),
                                           &target_pid) ||
        kernel_process_mount_namespace_id(target_pid, &namespace_id) < 0)
        return;
    generation = vfs_mount_namespace_event_generation(namespace_id);
    (void)kernel_file_description_mount_bind(
        file_ref_locator(e->file_ref), namespace_id, generation);
}

static int fd_is_mount_event_source(const edge_fd_t *e) {
    uint32_t namespace_id;
    uint32_t observed_generation;

    return fd_mount_monitor_snapshot(
        e, &namespace_id, &observed_generation);
}

static int fd_mount_monitor_pending(const edge_fd_t *e) {
    uint32_t namespace_id;
    uint32_t observed;
    if (!fd_mount_monitor_snapshot(e, &namespace_id, &observed))
        return 0;
    return vfs_mount_namespace_event_generation(namespace_id) != observed;
}

static void fd_mount_monitor_acknowledge(edge_fd_t *e) {
    uint32_t namespace_id;
    uint32_t observed_generation;

    if (!fd_mount_monitor_snapshot(
            e, &namespace_id, &observed_generation))
        return;
    (void)observed_generation;
    (void)kernel_file_description_mount_acknowledge(
        file_ref_locator(e->file_ref), namespace_id,
        vfs_mount_namespace_event_generation(namespace_id));
}

static void fd_mount_event_notify(uint32_t namespace_id) {
    task_t *current = process_current_task();
    for (int process = 0; process < EDGE_MAX_FD_PROCS; ++process) {
        edge_fd_proc_t *owner = g_fd_procs[process];
        if (!owner || owner->pid <= 0) continue;
        for (int descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
            edge_fd_t *entry = &owner->fds[descriptor];
            uint32_t monitored_namespace;
            uint32_t observed_generation;
            if (!fd_mount_monitor_snapshot(
                    entry, &monitored_namespace, &observed_generation))
                continue;
            (void)observed_generation;
            if (monitored_namespace != namespace_id)
                continue;
            fd_wake_fd_owner_tasks(owner->pid, current, "mount");
            break;
        }
    }
}

static int fd_is_console_active_event_path(const edge_fd_t *e) {
    return e && e->kind == FD_VFS &&
           strcmp(e->path, "/sys/class/tty/tty0/active") == 0;
}

static void fd_console_active_monitor_initialize(edge_fd_t *e) {
    if (!fd_is_console_active_event_path(e) || e->file_ref <= 0)
        return;
    (void)kernel_file_description_notify_bind(
        file_ref_locator(e->file_ref),
        KERNEL_FILE_DESCRIPTION_NOTIFY_CONSOLE_ACTIVE,
        console_active_vt_generation());
}

static int fd_console_active_monitor_snapshot(
        const edge_fd_t *e, uint32_t *source,
        uint32_t *observed_generation) {
    uint32_t ignored_source;
    uint32_t ignored_generation;

    if (!e || e->kind != FD_VFS || e->file_ref <= 0)
        return 0;
    if (!source) source = &ignored_source;
    if (!observed_generation) observed_generation = &ignored_generation;
    return kernel_file_description_notify_snapshot(
               file_ref_locator(e->file_ref), source,
               observed_generation) == 0;
}

static int fd_is_console_active_event_source(const edge_fd_t *e) {
    uint32_t source;

    return fd_console_active_monitor_snapshot(e, &source, 0) &&
           source == KERNEL_FILE_DESCRIPTION_NOTIFY_CONSOLE_ACTIVE;
}

static int fd_console_active_monitor_pending(const edge_fd_t *e) {
    uint32_t source;
    uint32_t observed_generation;

    if (!fd_console_active_monitor_snapshot(
            e, &source, &observed_generation) ||
        source != KERNEL_FILE_DESCRIPTION_NOTIFY_CONSOLE_ACTIVE)
        return 0;
    return observed_generation != console_active_vt_generation();
}

static void fd_console_active_monitor_acknowledge(edge_fd_t *e) {
    uint32_t source;

    if (!fd_console_active_monitor_snapshot(e, &source, 0) ||
        source != KERNEL_FILE_DESCRIPTION_NOTIFY_CONSOLE_ACTIVE)
        return;
    (void)kernel_file_description_notify_acknowledge(
        file_ref_locator(e->file_ref), source,
        console_active_vt_generation());
}

static void fd_console_active_event_notify(uint32_t generation) {
    task_t *current = process_current_task();

    (void)generation;
    fd_proc_registry_read_begin();
    for (int process = 0; process < EDGE_MAX_FD_PROCS; ++process) {
        edge_fd_proc_t *owner = __atomic_load_n(
            &g_fd_procs[process], __ATOMIC_ACQUIRE);

        if (!owner || owner->pid <= 0 ||
            __atomic_load_n(&owner->detached, __ATOMIC_ACQUIRE))
            continue;
        for (int descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
            edge_fd_t *entry = &owner->fds[descriptor];

            if (!entry->used ||
                !fd_is_console_active_event_source(entry))
                continue;
            fd_wake_fd_owner_tasks(owner->pid, current, "console-active");
            break;
        }
    }
    fd_proc_registry_read_end();
}

static void fd_wake_tun_description(uint64_t description_identity) {
    task_t *current = process_current_task();

    if (!description_identity) return;
    fd_proc_registry_read_begin();
    for (int process = 0; process < EDGE_MAX_FD_PROCS; ++process) {
        edge_fd_proc_t *owner = __atomic_load_n(
            &g_fd_procs[process], __ATOMIC_ACQUIRE);

        if (!owner || owner->pid <= 0 ||
            __atomic_load_n(&owner->detached, __ATOMIC_ACQUIRE))
            continue;
        for (int descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
            edge_fd_t *entry = &owner->fds[descriptor];

            if (!entry->used || entry->kind != FD_TUN ||
                file_ref_identity(entry->file_ref) != description_identity)
                continue;
            fd_wake_fd_owner_tasks(owner->pid, current, "tun");
            break;
        }
    }
    fd_proc_registry_read_end();
}

static int fd_release_entry(edge_fd_t *entry, task_t *task,
                            int close_process_locks,
                            int notify_last_close) {
    kernel_file_description_release_t release;
    kernel_file_lock_info_t lock_information;
    int have_lock_information;
    int finish_status = 0;

    if (!entry || !entry->used || entry->file_ref <= 0) return -EBADF;
    have_lock_information =
        fd_file_lock_info_for_entry(entry, task, &lock_information) == 0;
    if (kernel_file_description_release_begin(
            file_ref_locator(entry->file_ref), &release) < 0) {
        /*
         * The descriptor has already been detached from its table.  Its
         * backing-object reference is independent of the open-description
         * handle and must be dropped even if that handle was concurrently
         * invalidated.  Leaking this reference keeps pipe writers and socket
         * endpoints alive after process exit, so readers never observe EOF.
         */
        fd_drop_backing_object(entry);
        return -EBADF;
    }

    if (have_lock_information) {
        /*
         * The release token is the serialization point for the final open-file
         * description reference.  A snapshot taken before release_begin()
         * can race with dup(), fork(), pidfd_getfd(), or SCM_RIGHTS and make
         * OFD/flock cleanup run too early.
         */
        lock_information.description_references =
            release.remaining_references + 1u;
        if (!close_process_locks) {
            lock_information.process_id = 0;
            lock_information.task_id = 0;
        }
        edge_linux_file_lock_descriptor_closed(&lock_information);
    }

#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if (release.last_reference && entry->kind == FD_VFS &&
        (entry->inode.mode & 0xf000u) == VFS_INODE_CHR) {
        int bridge_status =
            bsd_bridge_cdev_close(release.identity);

        if (bridge_status < 0 &&
            bridge_status != BSD_BRIDGE_CDEV_NOT_HANDLED)
            finish_status = bridge_status;
    }
#endif

    if (release.last_reference && entry->kind == FD_VFS &&
        !(entry->flags & LINUX_O_PATH) &&
        alsa_path_kind(entry->path) != EDGE_ALSA_NODE_NONE)
        alsa_close(entry->path);

    if (release.last_reference && entry->kind == FD_VFS &&
        edge_drm_path_is_device(entry->path))
        edge_drm_release_client(release.identity);

    if (release.last_reference && entry->kind == FD_TUN)
        edge_linux_tun_close(release.identity);

#ifdef CONFIG_FUSE_FS
    if (release.last_reference && entry->kind == FD_VFS &&
        (entry->inode.mode & 0xf000u) == VFS_INODE_CHR &&
        edge_fuse_is_device(entry->inode.rdev))
        edge_fuse_device_close(release.identity);
#endif

    if (release.last_reference && entry->kind == FD_VFS) {
        if (notify_last_close && entry->path[0])
            edge_inotify_notify_path(
                entry->path,
                (entry->flags & LINUX_O_ACCMODE) != LINUX_O_RDONLY ?
                    EDGE_IN_CLOSE_WRITE : EDGE_IN_CLOSE_NOWRITE,
                0);
        /*
         * close(2) ends the open inode lifetime but does not imply fsync(2).
         * Dirty filesystem cache pages remain owned by writeback policy.
         */
        vfs_inode_close(entry->sb, &entry->inode);
    }

    /*
     * Backing-object release belongs inside the active final-close token.
     * This prevents another generation of the shared description handle from
     * becoming observable before the old pipe/socket/VFS teardown completes.
     */
    fd_drop_backing_object(entry);

    if (release.last_reference && entry->kind == FD_VFS &&
        strcmp(entry->path, "/dev/fb0") == 0 &&
        g_fb_console_hold_count > 0) {
        g_fb_console_hold_count--;
        if (g_fb_console_hold_count == 0 &&
            !syscall_console_active_vt_in_graphics()) {
            fb_release_user_mmap();
            fb_console_set_present_enabled(1);
        }
    }

    if (release.active &&
        kernel_file_description_release_finish(&release) < 0)
        if (finish_status == 0)
            finish_status = -EIO;
    if (finish_status < 0) return finish_status;
    return (int)release.remaining_references;
}

static int fd_file_lock_info_for_entry(
    const edge_fd_t *entry, const task_t *task,
    kernel_file_lock_info_t *information) {
    kernel_file_description_snapshot_t description;
    int references;
    uint32_t object_class = EDGE_FILE_LOCK_OBJECT_ANONYMOUS;
    uint64_t object_identity = 0;
    const char *identity_path = 0;

    if (!entry || !entry->used ||
        entry->file_ref <= 0 ||
        !information)
        return -EBADF;
    if (kernel_file_description_snapshot(
            file_ref_locator(entry->file_ref), &description) < 0)
        return -EBADF;
    references = (int)description.references;
    memset(information, 0, sizeof(*information));
    if (entry->kind == FD_VFS && entry->sb) {
        information->filesystem = (uint64_t)(uintptr_t)entry->sb;
        information->inode = entry->inode.ino;
        information->size = entry->inode.size;
    } else {
        switch (entry->kind) {
            case FD_CONSOLE:
                object_class = EDGE_FILE_LOCK_OBJECT_TTY;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                identity_path = entry->path;
                break;
            case FD_PIPE_R:
            case FD_PIPE_W:
            case FD_PIPE_RW:
                object_class = EDGE_FILE_LOCK_OBJECT_PIPE;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_SOCKET:
                object_class = EDGE_FILE_LOCK_OBJECT_SOCKET;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_PTY_MASTER:
                object_class = EDGE_FILE_LOCK_OBJECT_PTY_MASTER;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_PTY_SLAVE:
                object_class = EDGE_FILE_LOCK_OBJECT_PTY_SLAVE;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_EVENTFD:
                object_class = EDGE_FILE_LOCK_OBJECT_EVENTFD;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_TIMERFD:
                object_class = EDGE_FILE_LOCK_OBJECT_TIMERFD;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_SIGNALFD:
                object_class = EDGE_FILE_LOCK_OBJECT_SIGNALFD;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_EPOLL:
                object_class = EDGE_FILE_LOCK_OBJECT_EPOLL;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_PIDFD:
                object_class = EDGE_FILE_LOCK_OBJECT_PIDFD;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_INOTIFY:
                object_class = EDGE_FILE_LOCK_OBJECT_INOTIFY;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_FANOTIFY:
            case FD_USERFAULTFD:
            case FD_PERF_EVENT:
                object_class = EDGE_FILE_LOCK_OBJECT_ANONYMOUS;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_MEMFD:
                object_class = EDGE_FILE_LOCK_OBJECT_MEMFD;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_DMA_BUF:
            case FD_DRM_SYNC:
            case FD_IO_URING:
            case FD_LANDLOCK:
            case FD_BPF:
            case FD_SECCOMP:
                object_class = EDGE_FILE_LOCK_OBJECT_ANONYMOUS;
                object_identity = (uint64_t)(uint32_t)entry->pipe_id;
                break;
            case FD_NAMESPACE:
                object_class = EDGE_FILE_LOCK_OBJECT_NAMESPACE;
                object_identity = ((uint64_t)entry->namespace_kind << 32) |
                                  entry->namespace_id;
                break;
            case FD_VFS:
                object_class = strcmp(entry->path, "/dev/null") == 0 ?
                    EDGE_FILE_LOCK_OBJECT_NULL :
                    EDGE_FILE_LOCK_OBJECT_ANONYMOUS;
                object_identity = description.identity;
                identity_path = entry->path;
                break;
            default:
                return -EBADF;
        }
        edge_linux_file_lock_pseudo_identity(
            object_class, object_identity, identity_path,
            &information->filesystem, &information->inode);
    }
    information->open_description = description.identity;
    information->offset = fd_description_offset(entry);
    information->status_flags = (uint32_t)entry->flags;
    information->description_references = (uint32_t)references;
    information->process_id = task ?
        (task->tgid > 0 ? task->tgid : task->pid) : process_gettgid();
    information->task_id = task ? task->pid : process_gettid();
    return 0;
}

static uint64_t fd_description_offset(const edge_fd_t *e) {
    uint64_t offset;

    if (!e) return 0;
    if (e->file_ref > 0 &&
        kernel_file_description_offset_load(
            file_ref_locator(e->file_ref), &offset) == 0)
        return offset;
    return e->pos;
}

static void kernel_fd_apply_status_flags(edge_fd_t *entry, uint32_t mask,
                                         uint32_t flags) {
    if (!entry || !entry->used) return;
    entry->flags = (int)(((uint32_t)entry->flags & ~mask) |
                         (flags & mask));
    if (entry->kind == FD_SOCKET && entry->pipe_id >= 0 &&
        entry->pipe_id < EDGE_MAX_SOCKETS &&
        g_sockets[entry->pipe_id].used)
        g_sockets[entry->pipe_id].nonblock =
            (entry->flags & LINUX_O_NONBLOCK) != 0;
    fd_async_input_watch_update(entry);
}

static int fd_description_refresh_status(edge_fd_t *entry) {
    uint32_t flags;

    if (!entry || entry->file_ref <= 0) return -EBADF;
    if (kernel_file_description_status_load(
            file_ref_locator(entry->file_ref), &flags) < 0)
        return -EBADF;
    kernel_fd_apply_status_flags(entry, UINT32_MAX, flags);
    return 0;
}

static void fd_description_set_offset(edge_fd_t *e, uint64_t offset) {
    if (!e) return;
    e->pos = offset;
    if (e->file_ref > 0)
        (void)kernel_file_description_offset_store(
            file_ref_locator(e->file_ref), offset);
}

static void fd_description_advance(edge_fd_t *e, uint64_t amount) {
    uint64_t offset;
    int status;

    if (!e) return;
    if (e->file_ref > 0) {
        status = kernel_file_description_offset_add(
            file_ref_locator(e->file_ref), amount, &offset);
        if (status == 0) {
            e->pos = offset;
            return;
        }
        if (status == -EDGE_LINUX_EOVERFLOW) return;
    }
    e->pos += amount;
}

static int fd_description_input_tail(const edge_fd_t *e) {
    uint64_t cursor;
    int32_t clock_id;

    if (!e) return 0;
    if (e->file_ref > 0 &&
        kernel_file_description_input_state_load(
            file_ref_locator(e->file_ref), &cursor, &clock_id) == 0 &&
        cursor <= INT32_MAX)
        return (int)cursor;
    return e->input_event_tail;
}

static void fd_description_set_input_tail(edge_fd_t *e, int tail) {
    if (!e) return;
    e->input_event_tail = tail;
    if (e->file_ref > 0 && tail >= 0)
        (void)kernel_file_description_input_cursor_store(
            file_ref_locator(e->file_ref), (uint64_t)(uint32_t)tail);
}

static void fd_description_set_input_clock(edge_fd_t *e, int clock_id) {
    if (!e) return;
    if (e->file_ref > 0)
        (void)kernel_file_description_input_clock_store(
            file_ref_locator(e->file_ref), clock_id);
}

static int fd_description_read_input(edge_fd_t *e, int event_id,
                                     char *buffer, uint32_t length) {
    int access;
    if (!e || !buffer || !length) return 0;
    if (e->file_ref > 0 && event_id >= 0) {
        access = edge_linux_input_description_may_read(
            (uint32_t)event_id, file_ref_locator(e->file_ref));
        if (access <= 0) return access < 0 ? access : 0;
    }
    if (e->file_ref <= 0)
        return keyboard_event_read_from_clock(
            event_id, &e->input_event_tail, LINUX_CLOCK_REALTIME,
            buffer, length, 0);

    for (;;) {
        uint64_t cursor;
        uint64_t expected;
        int32_t clock_id;
        int tail;
        int read_count;
        int status;

        status = kernel_file_description_input_state_load(
            file_ref_locator(e->file_ref), &cursor, &clock_id);
        if (status < 0 || cursor > INT32_MAX)
            return 0;
        tail = (int)cursor;
        read_count = keyboard_event_read_from_clock(
            event_id, &tail, clock_id, buffer, length, 0);
        expected = cursor;
        status = kernel_file_description_input_cursor_compare_exchange(
            file_ref_locator(e->file_ref), &expected,
            (uint64_t)(uint32_t)tail);
        if (status < 0) return 0;
        if (status == 0) continue;
        e->input_event_tail = tail;
        return read_count;
    }
}

static edge_memfd_t *memfd_get(int id) {
    if (id <= 0 || id >= EDGE_MEMFD_MAX) return 0;
    if (!g_memfds[id].used) return 0;
    return &g_memfds[id];
}

static int memfd_entry_is_secret(const edge_fd_t *entry) {
    edge_memfd_t *memory;

    if (!entry || entry->kind != FD_MEMFD) return 0;
    memory = memfd_get(entry->pipe_id);
    return memory && memory->secret;
}

static int memfd_alloc_obj(const char *name, uint32_t flags, int secret) {
    for (int i = 1; i < EDGE_MEMFD_MAX; ++i) {
        edge_memfd_t *mf = &g_memfds[i];
        if (mf->used) continue;
        memset(mf, 0, sizeof(*mf));
        mf->used = 1;
        mf->secret = secret ? 1u : 0u;
        mf->huge_shift = (flags & KERNEL_MEMFD_HUGETLB) ?
            (uint8_t)((flags & KERNEL_MEMFD_HUGE_MASK) ?
                (flags & KERNEL_MEMFD_HUGE_MASK) >>
                    KERNEL_MEMFD_HUGE_SHIFT :
                KERNEL_MEMFD_DEFAULT_HUGE_SHIFT) : 0u;
        mf->descriptor_refs = 1;
        mf->id = i;
        mf->seals = (flags & KERNEL_MEMFD_ALLOW_SEALING) ?
            0 : LINUX_F_SEAL_SEAL;
        for (uint32_t p = 0; p < EDGE_MEMFD_MAX_PAGES; ++p) mf->page_idx[p] = -1;
        if (name && name[0]) {
            strncpy(mf->name, name, sizeof(mf->name) - 1);
            mf->name[sizeof(mf->name) - 1] = 0;
        }
        return i;
    }
    return -1;
}

static void memfd_add_ref(int id) {
    edge_memfd_t *mf = memfd_get(id);
    if (!mf) return;
    if (mf->descriptor_refs != UINT32_MAX) mf->descriptor_refs++;
}

static uint32_t memfd_swap_metadata_pages(void) {
    return (uint32_t)(((uint64_t)EDGE_MEMFD_MAX_PAGES * sizeof(uint64_t) +
                       PAGE_SIZE - 1u) / PAGE_SIZE);
}

static int memfd_ensure_swap_metadata(edge_memfd_t *mf) {
    uint32_t pages;

    if (!mf) return -1;
    if (mf->swap_entries) return 0;
    pages = memfd_swap_metadata_pages();
    mf->swap_entries = (uint64_t *)arch_vm_alloc_pages(pages);
    if (!mf->swap_entries) return -1;
    memset(mf->swap_entries, 0, (uint64_t)pages * PAGE_SIZE);
    return 0;
}

static void memfd_drop_storage_page(edge_memfd_t *mf, uint64_t page_no) {
    if (!mf || page_no >= EDGE_MEMFD_MAX_PAGES) return;
    if (mf->page_idx[page_no] >= 0) {
        process_user_mmap_release_backing_page(mf->page_idx[page_no]);
        mf->page_idx[page_no] = -1;
    }
    if (mf->swap_entries && mf->swap_entries[page_no]) {
        swap_release_entry(mf->swap_entries[page_no]);
        mf->swap_entries[page_no] = 0;
    }
}

static void memfd_destroy_if_unreferenced(edge_memfd_t *mf) {
    uint32_t metadata_pages;

    if (!mf) return;
    if (mf->descriptor_refs || mf->mapping_refs) return;
    for (uint32_t i = 0; i < EDGE_MEMFD_MAX_PAGES; ++i)
        memfd_drop_storage_page(mf, i);
    metadata_pages = memfd_swap_metadata_pages();
    for (uint32_t page = 0; mf->swap_entries && page < metadata_pages;
         ++page)
        arch_vm_free_page((uint8_t *)mf->swap_entries +
                          (uint64_t)page * PAGE_SIZE);
    memset(mf, 0, sizeof(*mf));
}

static void memfd_drop_ref(int id) {
    edge_memfd_t *mf = memfd_get(id);
    if (!mf) return;
    if (mf->descriptor_refs > 0) mf->descriptor_refs--;
    memfd_destroy_if_unreferenced(mf);
}

static int memfd_id_from_path(const char *path) {
    int id = 0;
    const char *p;
    if (!path || strncmp(path, "memfd:", 6) != 0) return -1;
    p = path + 6;
    if (*p < '0' || *p > '9') return -1;
    while (*p >= '0' && *p <= '9') {
        id = id * 10 + (*p - '0');
        if (id >= EDGE_MEMFD_MAX) return -1;
        ++p;
    }
    if (*p != ':') return -1;
    return id;
}

static void memfd_build_path(char *dst, uint32_t dst_sz, int id, const char *name) {
    uint32_t out = 0;
    char digits[16];
    int nd = 0;
    const char prefix[] = "memfd:";
    if (!dst || dst_sz == 0) return;
    for (uint32_t i = 0; prefix[i] && out + 1 < dst_sz; ++i) dst[out++] = prefix[i];
    if (id == 0) {
        digits[nd++] = '0';
    } else {
        int v = id;
        while (v > 0 && nd < (int)sizeof(digits)) {
            digits[nd++] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    while (nd > 0 && out + 1 < dst_sz) dst[out++] = digits[--nd];
    if (out + 1 < dst_sz) dst[out++] = ':';
    if (name) {
        for (uint32_t i = 0; name[i] && out + 1 < dst_sz; ++i) dst[out++] = name[i];
    }
    dst[out] = 0;
}

static int memfd_storage_base_page(edge_memfd_t *mf, uint64_t page_no,
                                   int create) {
    int idx;
    void *page;
    uint64_t swap_entry;
    uint32_t stored_cgroup;

    if (!mf || page_no >= EDGE_MEMFD_MAX_PAGES) return -1;
    if (mf->page_idx[page_no] >= 0) return mf->page_idx[page_no];
    swap_entry = mf->swap_entries ? mf->swap_entries[page_no] : 0;
    if (swap_entry) {
        idx = process_user_mmap_alloc_backing_page();
        if (idx < 0) return -1;
        page = process_user_mmap_backing_page_ptr(idx);
        if (!page || swap_load_page(
                swap_entry, page, &stored_cgroup) < 0) {
            process_user_mmap_release_backing_page(idx);
            return -1;
        }
        (void)stored_cgroup;
        mf->page_idx[page_no] = idx;
        mf->swap_entries[page_no] = 0;
        swap_release_entry(swap_entry);
        return idx;
    }
    if (!create) return -1;
    idx = process_user_mmap_alloc_backing_page();
    if (idx < 0) return -1;
    page = process_user_mmap_backing_page_ptr(idx);
    if (!page) {
        process_user_mmap_release_backing_page(idx);
        return -1;
    }
    memset(page, 0, PAGE_SIZE);
    mf->page_idx[page_no] = idx;
    return idx;
}

static int memfd_storage_page(edge_memfd_t *mf, uint64_t page_no, int create) {
    uint64_t group_pages;
    uint64_t group_start;
    uint8_t allocated[
        (UINT64_C(1) << (KERNEL_MEMFD_DEFAULT_HUGE_SHIFT - 12u)) / 8u];
    int result;

    if (!mf || page_no >= EDGE_MEMFD_MAX_PAGES) return -1;
    if (!create || !mf->huge_shift)
        return memfd_storage_base_page(mf, page_no, create);
    group_pages = UINT64_C(1) << (mf->huge_shift - 12u);
    group_start = page_no & ~(group_pages - 1u);
    if (group_pages > sizeof(allocated) * 8u ||
        group_start > EDGE_MEMFD_MAX_PAGES - group_pages)
        return -1;
    memset(allocated, 0, sizeof(allocated));
    for (uint64_t index = 0; index < group_pages; ++index) {
        uint64_t current = group_start + index;
        int was_absent = mf->page_idx[current] < 0 &&
                         (!mf->swap_entries ||
                          !mf->swap_entries[current]);
        result = memfd_storage_base_page(mf, current, 1);
        if (result < 0) {
            for (uint64_t rollback = 0; rollback < index; ++rollback) {
                uint64_t slot = group_start + rollback;
                if (!(allocated[rollback / 8u] &
                      (uint8_t)(1u << (rollback & 7u))))
                    continue;
                process_user_mmap_release_backing_page(
                    mf->page_idx[slot]);
                mf->page_idx[slot] = -1;
            }
            return -1;
        }
        if (was_absent)
            allocated[index / 8u] |=
                (uint8_t)(1u << (index & 7u));
    }
    return mf->page_idx[page_no];
}

static int memfd_read_to_kernel(edge_memfd_t *mf, uint64_t off, void *buf, uint64_t len) {
    uint64_t done = 0;
    if (!mf || !buf) return -EINVAL;
    if (off >= mf->size) {
        memset(buf, 0, (size_t)len);
        return 0;
    }
    if (len > mf->size - off) len = mf->size - off;
    while (done < len) {
        uint64_t pos = off + done;
        uint64_t page_no = pos / PAGE_SIZE;
        uint64_t in_page = pos & (PAGE_SIZE - 1);
        uint64_t n = PAGE_SIZE - in_page;
        int idx;
        void *page;
        if (n > len - done) n = len - done;
        idx = memfd_storage_page(mf, page_no, 0);
        if (idx < 0) {
            memset((char *)buf + done, 0, (size_t)n);
        } else {
            page = process_user_mmap_backing_page_ptr(idx);
            if (!page) return -EIO;
            memcpy((char *)buf + done, (char *)page + in_page, (size_t)n);
        }
        done += n;
    }
    return (int)done;
}

static int memfd_write_from_kernel_common(edge_memfd_t *mf, uint64_t off,
                                          const void *buf, uint64_t len,
                                          int existing_shared_mapping) {
    uint64_t end;
    uint64_t done = 0;
    if (!mf || (!buf && len)) return -EINVAL;
    if (mf->seals & LINUX_F_SEAL_WRITE) return -EPERM;
    if (!existing_shared_mapping && (mf->seals & LINUX_F_SEAL_FUTURE_WRITE))
        return -EPERM;
    end = off + len;
    if (end < off) return -EFBIG;
    if (end > ((uint64_t)EDGE_MEMFD_MAX_PAGES * PAGE_SIZE)) return -EFBIG;
    if (end > mf->size && (mf->seals & LINUX_F_SEAL_GROW)) return -EPERM;
    while (done < len) {
        uint64_t pos = off + done;
        uint64_t page_no = pos / PAGE_SIZE;
        uint64_t in_page = pos & (PAGE_SIZE - 1);
        uint64_t n = PAGE_SIZE - in_page;
        int idx;
        void *page;
        if (n > len - done) n = len - done;
        idx = memfd_storage_page(mf, page_no, 1);
        if (idx < 0) return done ? (int)done : -ENOMEM;
        page = process_user_mmap_backing_page_ptr(idx);
        if (!page) return done ? (int)done : -EIO;
        memcpy((char *)page + in_page, (const char *)buf + done, (size_t)n);
        done += n;
    }
    if (end > mf->size) mf->size = end;
    return (int)done;
}

static int memfd_write_from_kernel(edge_memfd_t *mf, uint64_t off,
                                   const void *buf, uint64_t len) {
    return memfd_write_from_kernel_common(mf, off, buf, len, 0);
}

static int memfd_write_mapping_from_kernel(edge_memfd_t *mf, uint64_t off,
                                           const void *buf, uint64_t len) {
    /*
     * F_SEAL_FUTURE_WRITE blocks write(2) and new writable mappings, but Linux
     * keeps mappings established before the seal writable.  Fixed-layout
     * EdgeOS mappings need an explicit writeback on msync/munmap, so preserve
     * that existing-mapping exception here.  Sparse mappings use the memfd's
     * backing pages directly and never enter this copy path.
     */
    return memfd_write_from_kernel_common(mf, off, buf, len, 1);
}

static int memfd_truncate(edge_memfd_t *mf, uint64_t len) {
    uint64_t old_pages;
    uint64_t new_pages;
    if (!mf) return -EINVAL;
    if (mf->huge_shift &&
        (len & ((UINT64_C(1) << mf->huge_shift) - 1u)))
        return -EINVAL;
    if (len > ((uint64_t)EDGE_MEMFD_MAX_PAGES * PAGE_SIZE)) return -EFBIG;
    if (len < mf->size && (mf->seals & LINUX_F_SEAL_SHRINK)) return -EPERM;
    if (len > mf->size && (mf->seals & LINUX_F_SEAL_GROW)) return -EPERM;
    old_pages = page_align_up(mf->size) / PAGE_SIZE;
    new_pages = page_align_up(len) / PAGE_SIZE;
    if (new_pages < old_pages) {
        /*
         * Linux invalidates PTEs for shmem pages removed by truncate.  Merely
         * dropping the memfd's object reference leaves live MAP_SHARED PTEs
         * pointing at the old page, so a later grow exposes stale allocator
         * metadata instead of zero-filled storage.
         */
        memfd_unmap_truncated_pages(mf->id, len);
        for (uint64_t i = new_pages; i < old_pages && i < EDGE_MEMFD_MAX_PAGES; ++i) {
            memfd_drop_storage_page(mf, i);
        }
    }
    if (len < mf->size && (len & (PAGE_SIZE - 1)) != 0 && new_pages > 0) {
        uint64_t page_no = len / PAGE_SIZE;
        uint64_t in_page = len & (PAGE_SIZE - 1);
        int idx = memfd_storage_page(mf, page_no, 0);
        void *page = idx >= 0 ? process_user_mmap_backing_page_ptr(idx) : 0;
        if (page) memset((char *)page + in_page, 0, PAGE_SIZE - in_page);
    }
    mf->size = len;
    return 0;
}

static uint64_t memfd_fcntl_add_seals(edge_fd_t *e, uint64_t seals_u) {
    uint32_t seals = (uint32_t)seals_u;
    edge_memfd_t *mf;
    if (!e || e->kind != FD_MEMFD) return (uint64_t)-EINVAL;
    if (seals & ~LINUX_F_SEAL_VALID) return (uint64_t)-EINVAL;
    mf = memfd_get(e->pipe_id);
    if (!mf) return (uint64_t)-EBADF;
    if (mf->secret) return (uint64_t)-EINVAL;
    if (mf->seals & LINUX_F_SEAL_SEAL) return (uint64_t)-EPERM;
    if ((seals & LINUX_F_SEAL_WRITE) && memfd_has_writable_shared_mapping(mf->id)) return (uint64_t)-EBUSY;
    mf->seals |= seals;
    return 0;
}

int64_t arch_memfd_create_descriptor(const char *name, uint32_t flags) {
    edge_fd_proc_t *p;
    edge_fd_t *e;
    int id;
    int fd;

    p = fd_proc_with_stdio();
    if (!p) return -ENOMEM;
    id = memfd_alloc_obj(name, flags, 0);
    if (id < 0) return -ENFILE;
    fd = fd_alloc(p, 0);
    if (fd < 0) {
        memfd_drop_ref(id);
        return -EMFILE;
    }
    e = &p->fds[fd];
    e->file_ref = file_ref_alloc(LINUX_O_RDWR);
    if (!e->file_ref) {
        fd_abort_reserved(p, fd);
        memfd_drop_ref(id);
        return -ENFILE;
    }
    e->kind = FD_MEMFD;
    e->flags = LINUX_O_RDWR;
    e->fd_flags = (flags & KERNEL_MEMFD_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    e->pipe_id = id;
    e->inode.mode = (uint16_t)(VFS_INODE_FILE | 0777);
    e->inode.size = 0;
    e->inode.ino = 0xE1000000u + (uint32_t)id;
    memfd_build_path(e->path, sizeof(e->path), id, name);
    if (fd_publish(p, fd) < 0) {
        (void)file_ref_put(e->file_ref);
        memfd_drop_ref(id);
        fd_abort_reserved(p, fd);
        return -EBADF;
    }
    return fd;
}

int64_t arch_memfd_secret_descriptor(uint32_t descriptor_flags) {
    edge_fd_proc_t *process;
    edge_fd_t *entry;
    int object_id;
    int descriptor;

    process = fd_proc_with_stdio();
    if (!process) return -ENOMEM;
    object_id = memfd_alloc_obj("secretmem", 0u, 1);
    if (object_id < 0) return -ENFILE;
    descriptor = fd_alloc(process, 0);
    if (descriptor < 0) {
        memfd_drop_ref(object_id);
        return -EMFILE;
    }
    entry = &process->fds[descriptor];
    entry->file_ref = file_ref_alloc(LINUX_O_RDWR);
    if (!entry->file_ref) {
        fd_abort_reserved(process, descriptor);
        memfd_drop_ref(object_id);
        return -ENFILE;
    }
    entry->kind = FD_MEMFD;
    entry->flags = LINUX_O_RDWR;
    entry->fd_flags =
        (descriptor_flags & KERNEL_MEMFD_CLOEXEC) ?
            LINUX_FD_CLOEXEC : 0;
    entry->pipe_id = object_id;
    entry->inode.mode = (uint16_t)(VFS_INODE_FILE | 0600);
    entry->inode.size = 0;
    entry->inode.ino = 0xE1000000u + (uint32_t)object_id;
    memfd_build_path(
        entry->path, sizeof(entry->path), object_id, "secretmem");
    if (fd_publish(process, descriptor) < 0) {
        (void)file_ref_put(entry->file_ref);
        memfd_drop_ref(object_id);
        fd_abort_reserved(process, descriptor);
        return -EBADF;
    }
    return descriptor;
}

static void fd_drop_backing_object(edge_fd_t *e) {
    if (!e || !e->used) return;
    fd_async_input_watch_remove(e);
    if (e->kind == FD_PIPE_R || e->kind == FD_PIPE_RW) pipe_drop_reader(e->pipe_id);
    if (e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW) pipe_drop_writer(e->pipe_id);
    if (e->kind == FD_SOCKET) socket_drop_ref(e->pipe_id);
    if (e->kind == FD_PTY_MASTER) pty_drop_ref(e->pipe_id, 1);
    if (e->kind == FD_PTY_SLAVE) pty_drop_ref(e->pipe_id, 0);
    if (e->kind == FD_EVENTFD) kernel_eventfd_release(e->pipe_id);
    if (e->kind == FD_TIMERFD) kernel_timerfd_release(e->pipe_id);
    if (e->kind == FD_SIGNALFD) kernel_signalfd_release(e->pipe_id);
    if (e->kind == FD_EPOLL) kernel_epoll_object_release(e->pipe_id);
    if (e->kind == FD_INOTIFY) kernel_inotify_release(e->pipe_id);
    if (e->kind == FD_FANOTIFY) kernel_fanotify_release(e->pipe_id);
    if (e->kind == FD_USERFAULTFD)
        kernel_userfaultfd_release(e->pipe_id);
    if (e->kind == FD_PERF_EVENT)
        kernel_perf_event_release(e->pipe_id);
    if (e->kind == FD_MEMFD) memfd_drop_ref(e->pipe_id);
    if (e->kind == FD_DMA_BUF) edge_drm_prime_release(e->pipe_id);
    if (e->kind == FD_DRM_SYNC)
        edge_virtgpu_sync_file_release(e->pipe_id);
    if (e->kind == FD_MOUNT) kernel_mount_api_release(e->pipe_id);
    if (e->kind == FD_MQUEUE) kernel_posix_mq_release(e->pipe_id);
    if (e->kind == FD_IO_URING) kernel_io_uring_release(e->pipe_id);
    if (e->kind == FD_LANDLOCK)
        kernel_landlock_ruleset_release(e->pipe_id);
    if (e->kind == FD_BPF)
        kernel_bpf_object_release(e->pipe_id);
    if (e->kind == FD_SECCOMP)
        edge_seccomp_listener_release(e->pipe_id);
    if (e->kind == FD_ZCRX)
        kernel_io_uring_zcrx_export_release(e->pipe_id);
    if (e->kind == FD_NAMESPACE)
        edge_namespace_handle_release(
            (edge_namespace_kind_t)e->namespace_kind, e->namespace_id);
}

static int fd_sync_inode(edge_fd_t *e, int data_only) {
    if (!e || !e->used) return 0;
    /*
     * fsync and fdatasync target the inode, including changes made through a
     * different open file description. A descriptor-local dirty bit cannot
     * decide whether the shared filesystem object needs writeback.
     */
    if (e->kind == FD_VFS && e->sb) {
        if (vfs_sync_inode(e->sb, &e->inode, data_only) < 0) return -1;
    }
    e->dirty = 0;
    return 0;
}

static int fd_add_backing_object(edge_fd_t *e) {
    if (!e || !e->used) return -1;
    if (e->kind == FD_PIPE_R || e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW) {
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PIPES || !g_pipes[e->pipe_id].used) return -1;
        /*
         * A read/write FIFO description owns both endpoints. Keep endpoint
         * accounting in one branch so fork, dup, pidfd_getfd, and SCM_RIGHTS
         * cannot increment only the read side and later decrement both sides
         * on close. Linux pipe readiness follows file lifetime and must not
         * require a global descriptor-table scan from poll(2).
         */
        return kernel_pipe_endpoint_retain(
            &g_pipes[e->pipe_id],
            e->kind == FD_PIPE_R || e->kind == FD_PIPE_RW,
            e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW);
    }
    if (e->kind == FD_SOCKET) {
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS || !g_sockets[e->pipe_id].used) return -1;
        socket_add_ref(e->pipe_id);
        return 0;
    }
    if (e->kind == FD_PTY_MASTER) {
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS || !g_ptys[e->pipe_id].used) return -1;
        pty_add_ref(e->pipe_id, 1);
        return 0;
    }
    if (e->kind == FD_PTY_SLAVE) {
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS || !g_ptys[e->pipe_id].used) return -1;
        pty_add_ref(e->pipe_id, 0);
        return 0;
    }
    if (e->kind == FD_EVENTFD) {
        return kernel_eventfd_retain(e->pipe_id) == 0 ? 0 : -1;
    }
    if (e->kind == FD_TIMERFD) {
        return kernel_timerfd_retain(e->pipe_id) == 0 ? 0 : -1;
    }
    if (e->kind == FD_SIGNALFD) {
        return kernel_signalfd_retain(e->pipe_id) == 0 ? 0 : -1;
    }
    if (e->kind == FD_EPOLL) {
        return kernel_epoll_object_retain(e->pipe_id) == 0 ? 0 : -1;
    }
    if (e->kind == FD_INOTIFY) {
        return kernel_inotify_retain(e->pipe_id) == 0 ? 0 : -1;
    }
    if (e->kind == FD_FANOTIFY) {
        return kernel_fanotify_retain(e->pipe_id) == 0 ? 0 : -1;
    }
    if (e->kind == FD_USERFAULTFD) {
        return kernel_userfaultfd_retain(e->pipe_id) == 0 ? 0 : -1;
    }
    if (e->kind == FD_PERF_EVENT) {
        return kernel_perf_event_retain(e->pipe_id) == 0 ? 0 : -1;
    }
    if (e->kind == FD_MEMFD) {
        if (!memfd_get(e->pipe_id)) return -1;
        memfd_add_ref(e->pipe_id);
        return 0;
    }
    if (e->kind == FD_DMA_BUF)
        return edge_drm_prime_retain(e->pipe_id) == 0 ? 0 : -1;
    if (e->kind == FD_DRM_SYNC)
        return edge_virtgpu_sync_file_retain(e->pipe_id) == 0 ? 0 : -1;
    if (e->kind == FD_MOUNT)
        return kernel_mount_api_retain(e->pipe_id) == 0 ? 0 : -1;
    if (e->kind == FD_MQUEUE)
        return kernel_posix_mq_retain(e->pipe_id) == 0 ? 0 : -1;
    if (e->kind == FD_IO_URING)
        return kernel_io_uring_retain(e->pipe_id) == 0 ? 0 : -1;
    if (e->kind == FD_LANDLOCK)
        return kernel_landlock_ruleset_retain(e->pipe_id) == 0 ? 0 : -1;
    if (e->kind == FD_BPF)
        return kernel_bpf_object_retain(e->pipe_id) == 0 ? 0 : -1;
    if (e->kind == FD_SECCOMP)
        return edge_seccomp_listener_retain(e->pipe_id) == 0 ? 0 : -1;
    if (e->kind == FD_ZCRX)
        return kernel_io_uring_zcrx_export_retain(e->pipe_id) == 0 ? 0 : -1;
    if (e->kind == FD_NAMESPACE) {
        if (e->namespace_kind >= EDGE_NAMESPACE_KIND_COUNT ||
            edge_namespace_handle_retain(
                (edge_namespace_kind_t)e->namespace_kind,
                e->namespace_id) < 0)
            return -1;
        return 0;
    }
    return 0;
}

static void fd_proc_release(int pid) {
    task_t *t = task_by_pid_mutable_local(pid);
    edge_fd_proc_t *p = fd_proc_for_pid(pid, 0);
    int released_graphics_vt = 0;
    if (!p) return;
    if (__atomic_exchange_n(
            &p->detached, 1u, __ATOMIC_ACQ_REL))
        return;
    for (int line_id = 0; line_id <= EDGE_FB_VT_COUNT; ++line_id) {
        edge_console_line_t *line = console_line_state(line_id);
        if (!line) continue;
        if (line->kd_owner_pid == pid) {
            line->kd_owner_pid = 0;
            line->kd_mode = LINUX_KD_TEXT;
            line->kbd_mode = LINUX_K_XLATE;
            line->vt_mode = LINUX_VT_AUTO;
            line->vt_waitv = 0;
            line->vt_relsig = 0;
            line->vt_acqsig = 0;
            line->vt_frsig = 0;
            released_graphics_vt = 1;
        }
        if (line->primary_open_pid == pid) {
            line->primary_open_pid = 0;
            line->primary_open_sid = 0;
        }
    }
    {
        int reset_console_line[EDGE_FB_VT_COUNT + 1];
        int reset_pty_ids[EDGE_MAX_PTYS];
        int reset_pty_count = 0;
        memset(reset_console_line, 0, sizeof(reset_console_line));
        memset(reset_pty_ids, 0, sizeof(reset_pty_ids));

        if (t) {
            if (t->ctty_kind == PROCESS_CTTY_CONSOLE) {
                int line_id = console_line_valid(t->ctty_id) ? t->ctty_id : console_line_from_vt(t->ctty_id);
                reset_console_line[line_id] = 1;
            } else if (t->ctty_kind == PROCESS_CTTY_PTY) {
                int pty_id = t->ctty_id;
                if (pty_id >= 0 && pty_id < EDGE_MAX_PTYS) reset_pty_ids[pty_id] = 1;
            }
        }

        for (int i = 0; i < EDGE_MAX_FD; ++i) {
            edge_fd_t *e = &p->fds[i];
            if (!e->used) continue;
            if (e->kind == FD_CONSOLE) {
                int line_id = console_line_valid(e->pipe_id) ? e->pipe_id : console_line_from_vt(e->pipe_id);
                reset_console_line[line_id] = 1;
            }
            if (e->kind == FD_VFS && path_is_tty_device(e->path)) reset_console_line[console_line_from_path(e->path)] = 1;
            if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
                e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_PTYS) {
                reset_pty_ids[e->pipe_id] = 1;
            }
        }

        for (int line_id = 0; line_id <= EDGE_FB_VT_COUNT; ++line_id) {
            edge_console_line_t *line;
            if (!reset_console_line[line_id]) continue;
            if (console_line_referenced_elsewhere(pid, line_id)) continue;
            line = console_line_state(line_id);
            if (!line) continue;
            if (t && t->pgid > 0 && line->session.foreground_pgid == t->pgid) {
                line->session.foreground_pgid = 0;
            }
            console_line_reset(line);
        }
        for (int pty_id = 0; pty_id < EDGE_MAX_PTYS; ++pty_id) {
            if (!reset_pty_ids[pty_id]) continue;
            if (!g_ptys[pty_id].used) continue;
            if (t && t->pgid > 0 && g_ptys[pty_id].session.foreground_pgid == t->pgid) {
                g_ptys[pty_id].session.foreground_pgid = 0;
            }
            termios_init_sane(&g_ptys[pty_id].termios);
            reset_pty_count++;
        }
    }
    for (int i = 0; i < EDGE_MAX_FD; ++i) {
        edge_fd_t closing;
        if (fd_remove_open(p, i, &closing) == 0) {
            (void)fd_release_entry(&closing, t, 1, 1);
        } else {
            (void)fd_cancel_constructed_reserved(p, i);
        }
    }
    (void)fd_proc_registry_detach(p);
    p->pid = 0;
    fd_proc_table_release(p);
    if (released_graphics_vt &&
        !syscall_console_active_vt_in_graphics() &&
        !fb_user_mmap_active())
        fb_console_set_present_enabled(1);
}

static int fd_proc_has_pty_fd(int pid) {
    edge_fd_proc_t *p = fd_proc_for_pid(pid, 0);
    if (!p) return 0;
    for (int i = 0; i < EDGE_MAX_FD; ++i) {
        edge_fd_t *e = &p->fds[i];
        if (!e->used) continue;
        if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) return 1;
    }
    return 0;
}

void syscall_release_process_fds(int pid) {
    fd_proc_release(pid);
}

static void fd_ensure_console_stdio(edge_fd_proc_t *p, int line_id) {
    int ref;
    if (!p) return;
    if (!console_line_valid(line_id)) line_id = console_line_default();
    if (!fd_get(p, 0) && fd_reserve_exact(p, 0) == 0) {
        ref = file_ref_alloc(0);
        if (!ref) {
            fd_abort_reserved(p, 0);
            return;
        }
        p->fds[0].kind = FD_CONSOLE;
        p->fds[0].file_ref = ref;
        p->fds[0].flags = 0;
        p->fds[0].fd_flags = 0;
        p->fds[0].pipe_id = line_id;
        strncpy(p->fds[0].path, "/dev/console", sizeof(p->fds[0].path) - 1);
        (void)fd_publish(p, 0);
    }
    if (!fd_get(p, 1) && fd_reserve_exact(p, 1) == 0) {
        ref = file_ref_alloc(LINUX_O_WRONLY);
        if (!ref) {
            fd_abort_reserved(p, 1);
            return;
        }
        p->fds[1].kind = FD_CONSOLE;
        p->fds[1].file_ref = ref;
        p->fds[1].flags = LINUX_O_WRONLY;
        p->fds[1].fd_flags = 0;
        p->fds[1].pipe_id = line_id;
        strncpy(p->fds[1].path, "/dev/console", sizeof(p->fds[1].path) - 1);
        (void)fd_publish(p, 1);
    }
    if (!fd_get(p, 2) && fd_reserve_exact(p, 2) == 0) {
        ref = file_ref_alloc(LINUX_O_WRONLY);
        if (!ref) {
            fd_abort_reserved(p, 2);
            return;
        }
        p->fds[2].kind = FD_CONSOLE;
        p->fds[2].file_ref = ref;
        p->fds[2].flags = LINUX_O_WRONLY;
        p->fds[2].fd_flags = 0;
        p->fds[2].pipe_id = line_id;
        strncpy(p->fds[2].path, "/dev/console", sizeof(p->fds[2].path) - 1);
        (void)fd_publish(p, 2);
    }
}

static void fd_ensure_stdio(edge_fd_proc_t *p) {
    int default_line;
    task_t *cur;
    int ref;
    if (!p) return;
    default_line = console_line_default();
    cur = process_current_task();
    if (cur && cur->ctty_kind == PROCESS_CTTY_NONE) {
        /*
         * Detached daemons intentionally close or redirect stdio after setsid().
         * Do not synthesize a new controlling-console fd for them on their next
         * syscall: Linux leaves those descriptors closed unless userland opens
         * something explicitly, and many daemons assume reopened fd 0/1/2 are
         * /dev/null.  Reattaching /dev/console here lets background services
         * accidentally consume login-shell input.
         */
        if (!fd_get(p, 0) && fd_reserve_exact(p, 0) == 0) {
            ref = file_ref_alloc(0);
            if (!ref) {
                fd_abort_reserved(p, 0);
                return;
            }
            p->fds[0].kind = FD_VFS;
            p->fds[0].file_ref = ref;
            p->fds[0].flags = 0;
            p->fds[0].fd_flags = 0;
            strncpy(p->fds[0].path, "/dev/null", sizeof(p->fds[0].path) - 1);
            (void)fd_publish(p, 0);
        }
        if (!fd_get(p, 1) && fd_reserve_exact(p, 1) == 0) {
            ref = file_ref_alloc(LINUX_O_WRONLY);
            if (!ref) {
                fd_abort_reserved(p, 1);
                return;
            }
            p->fds[1].kind = FD_VFS;
            p->fds[1].file_ref = ref;
            p->fds[1].flags = LINUX_O_WRONLY;
            p->fds[1].fd_flags = 0;
            strncpy(p->fds[1].path, "/dev/null", sizeof(p->fds[1].path) - 1);
            (void)fd_publish(p, 1);
        }
        if (!fd_get(p, 2) && fd_reserve_exact(p, 2) == 0) {
            ref = file_ref_alloc(LINUX_O_WRONLY);
            if (!ref) {
                fd_abort_reserved(p, 2);
                return;
            }
            p->fds[2].kind = FD_VFS;
            p->fds[2].file_ref = ref;
            p->fds[2].flags = LINUX_O_WRONLY;
            p->fds[2].fd_flags = 0;
            strncpy(p->fds[2].path, "/dev/null", sizeof(p->fds[2].path) - 1);
            (void)fd_publish(p, 2);
        }
        return;
    }
    if (cur && cur->ctty_kind == PROCESS_CTTY_CONSOLE && console_line_valid(cur->ctty_id)) {
        default_line = cur->ctty_id;
    }
    fd_ensure_console_stdio(p, default_line);
}

static uint32_t fd_current_allocation_limit(void) {
    const task_t *current = process_current_task();
    uint64_t soft_limit;

    if (!current) return 0;
    soft_limit = __atomic_load_n(
        &current->rlimits[EDGE_LINUX_RLIMIT_NOFILE][0],
        __ATOMIC_ACQUIRE);
    return soft_limit < EDGE_MAX_FD ?
        (uint32_t)soft_limit : EDGE_MAX_FD;
}

static int fd_alloc(edge_fd_proc_t *p, int minfd) {
    uint32_t descriptor = 0;
    uint32_t exclusive_limit;
    uint64_t irq_flags;
    int result;

    if (!p) return -1;
    if (minfd < 0) minfd = 0;
    exclusive_limit = fd_current_allocation_limit();
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    result = kernel_fd_table_reserve_next_below_locked(
        &p->table_runtime, (uint32_t)minfd,
        exclusive_limit, &descriptor);
    if (result == 0) {
        /*
         * Reservation is deliberately separate from publication.  The
         * descriptor remains invisible while its file-description reference,
         * backing-object reference, flags, and payload are prepared.
         */
        memset(&p->fds[descriptor], 0, sizeof(p->fds[descriptor]));
    }
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    return result == 0 ? (int)descriptor : -1;
}

static int fd_reserve_exact(edge_fd_proc_t *p, int fd) {
    uint64_t irq_flags;
    int result;

    if (!p || fd < 0 || fd >= EDGE_MAX_FD) return -EBADF;
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    result = kernel_fd_table_reserve_exact_locked(
        &p->table_runtime, (uint32_t)fd);
    if (result == 0)
        memset(&p->fds[fd], 0, sizeof(p->fds[fd]));
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    return result;
}

static int fd_publish(edge_fd_proc_t *p, int fd) {
    edge_fd_t *entry;
    uint64_t irq_flags;
    int result;

    if (!p || fd < 0 || fd >= EDGE_MAX_FD) return -EBADF;
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    result = kernel_fd_table_publish_locked(
        &p->table_runtime, (uint32_t)fd);
    if (result == 0) {
        entry = &p->fds[fd];
        __atomic_store_n(&entry->used, 1, __ATOMIC_RELEASE);
        fd_async_input_watch_update(entry);
    }
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    return result;
}

static int fd_install_reserved(edge_fd_proc_t *p, int fd,
                               const edge_fd_t *entry) {
    edge_fd_t installation;
    uint64_t irq_flags;
    uint32_t status_flags;
    int result;

    if (!p || !entry || fd < 0 || fd >= EDGE_MAX_FD) return -EBADF;
    installation = *entry;
    installation.used = 0;
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    if (kernel_fd_table_state_locked(
            &p->table_runtime, (uint32_t)fd) !=
        KERNEL_FD_SLOT_RESERVED) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -EBADF;
    }
    if (installation.file_ref <= 0 ||
        kernel_file_description_status_load(
            file_ref_locator(installation.file_ref), &status_flags) < 0) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -EBADF;
    }
    installation.used = 1;
    kernel_fd_apply_status_flags(
        &installation, UINT32_MAX, status_flags);
    installation.used = 0;
    p->fds[fd] = installation;
    result = kernel_fd_table_publish_locked(
        &p->table_runtime, (uint32_t)fd);
    if (result < 0) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return result;
    }
    __atomic_store_n(&p->fds[fd].used, 1, __ATOMIC_RELEASE);
    fd_async_input_watch_update(&p->fds[fd]);
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    return 0;
}

static void fd_abort_reserved(edge_fd_proc_t *p, int fd) {
    uint64_t irq_flags;

    if (!p || fd < 0 || fd >= EDGE_MAX_FD) return;
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    if (kernel_fd_table_cancel_reservation_locked(
            &p->table_runtime, (uint32_t)fd) == 0)
        memset(&p->fds[fd], 0, sizeof(p->fds[fd]));
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
}

static int fd_snapshot_retain(edge_fd_proc_t *p, int fd,
                              edge_fd_t *snapshot) {
    uint64_t irq_flags;

    if (!p || !snapshot || fd < 0 || fd >= EDGE_MAX_FD) return -EBADF;
    memset(snapshot, 0, sizeof(*snapshot));
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &p->table_runtime, (uint32_t)fd) ||
        !__atomic_load_n(&p->fds[fd].used, __ATOMIC_ACQUIRE)) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -EBADF;
    }
    *snapshot = p->fds[fd];
    if (snapshot->file_ref <= 0 || file_ref_get(snapshot->file_ref) < 0) {
        memset(snapshot, 0, sizeof(*snapshot));
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -ENOMEM;
    }
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    if (fd_add_backing_object(snapshot) < 0) {
        (void)file_ref_put(snapshot->file_ref);
        memset(snapshot, 0, sizeof(*snapshot));
        return -EBADF;
    }
    return 0;
}

static int fd_remove_open(edge_fd_proc_t *p, int fd,
                          edge_fd_t *closing) {
    uint64_t irq_flags;

    if (!p || !closing || fd < 0 || fd >= EDGE_MAX_FD) return -EBADF;
    memset(closing, 0, sizeof(*closing));
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &p->table_runtime, (uint32_t)fd) ||
        !__atomic_load_n(&p->fds[fd].used, __ATOMIC_ACQUIRE)) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -EBADF;
    }
    *closing = p->fds[fd];
    if (kernel_fd_table_detach_open_locked(
            &p->table_runtime, (uint32_t)fd) < 0) {
        memset(closing, 0, sizeof(*closing));
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -EBADF;
    }
    fd_async_input_watch_remove(&p->fds[fd]);
    memset(&p->fds[fd], 0, sizeof(p->fds[fd]));
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    return 0;
}

static int fd_replace_exact(edge_fd_proc_t *p, int fd,
                            const edge_fd_t *replacement,
                            edge_fd_t *closing, int *replaced) {
    edge_fd_t installation;
    kernel_fd_slot_state_t state;
    uint64_t irq_flags;
    uint32_t status_flags;
    int result;

    if (!p || !replacement || !closing || !replaced ||
        fd < 0 || fd >= EDGE_MAX_FD)
        return -EBADF;
    installation = *replacement;
    installation.used = 0;
    memset(closing, 0, sizeof(*closing));
    *replaced = 0;
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    state = kernel_fd_table_state_locked(
        &p->table_runtime, (uint32_t)fd);
    if (state == KERNEL_FD_SLOT_RESERVED ||
        state == KERNEL_FD_SLOT_CLOSING) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -EBUSY;
    }
    if (installation.file_ref <= 0 ||
        kernel_file_description_status_load(
            file_ref_locator(installation.file_ref), &status_flags) < 0) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return -EBADF;
    }
    installation.used = 1;
    kernel_fd_apply_status_flags(
        &installation, UINT32_MAX, status_flags);
    installation.used = 0;
    if (state == KERNEL_FD_SLOT_OPEN) {
        *closing = p->fds[fd];
        result = kernel_fd_table_begin_close_locked(
            &p->table_runtime, (uint32_t)fd);
        if (result < 0) {
            memset(closing, 0, sizeof(*closing));
            kernel_fd_table_unlock(&p->table_runtime, irq_flags);
            return result;
        }
        fd_async_input_watch_remove(&p->fds[fd]);
        __atomic_store_n(&p->fds[fd].used, 0, __ATOMIC_RELEASE);
        *replaced = 1;
    } else {
        result = kernel_fd_table_reserve_exact_locked(
            &p->table_runtime, (uint32_t)fd);
        if (result < 0) {
            kernel_fd_table_unlock(&p->table_runtime, irq_flags);
            return result;
        }
    }
    p->fds[fd] = installation;
    result = state == KERNEL_FD_SLOT_OPEN
        ? kernel_fd_table_restore_open_locked(
            &p->table_runtime, (uint32_t)fd)
        : kernel_fd_table_publish_locked(
            &p->table_runtime, (uint32_t)fd);
    if (result < 0) {
        kernel_fd_table_unlock(&p->table_runtime, irq_flags);
        return result;
    }
    __atomic_store_n(&p->fds[fd].used, 1, __ATOMIC_RELEASE);
    fd_async_input_watch_update(&p->fds[fd]);
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    return 0;
}

static edge_fd_t *fd_get(edge_fd_proc_t *p, int fd) {
    edge_fd_t *entry = 0;
    uint64_t irq_flags;

    if (!p || fd < 0 || fd >= EDGE_MAX_FD) return 0;
    irq_flags = kernel_fd_table_lock(&p->table_runtime);
    if (kernel_fd_table_is_open_locked(
            &p->table_runtime, (uint32_t)fd) &&
        __atomic_load_n(&p->fds[fd].used, __ATOMIC_ACQUIRE))
        entry = &p->fds[fd];
    kernel_fd_table_unlock(&p->table_runtime, irq_flags);
    return entry;
}

static int fd_any_live_task_has_path(const char *path) {
    if (!path || !path[0]) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *t = process_task_by_index(i);
        edge_fd_proc_t *p;
        if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) continue;
        p = fd_proc_for_pid(t->fd_owner_pid > 0 ? t->fd_owner_pid : t->pid, 0);
        if (!p) continue;
        for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
            edge_fd_t *e = &p->fds[fd];
            if (!e->used || e->kind != FD_VFS) continue;
            if (strcmp(e->path, path) == 0) return 1;
        }
    }
    return 0;
}

int edge_procfs_fdinfo_snapshot(int pid, int fd, uint64_t *pos_out, uint32_t *flags_out, uint32_t *ino_out) {
    const task_t *t;
    edge_fd_proc_t *p;
    edge_fd_t *e;
    int owner_pid = pid;

    if (fd < 0 || fd >= EDGE_MAX_FD) return -1;
    t = process_get_task(pid);
    if (!t || t->state == TASK_UNUSED) return -1;
    if (t->fd_owner_pid > 0) owner_pid = t->fd_owner_pid;
    p = fd_proc_for_pid(owner_pid, 0);
    e = fd_get(p, fd);
    if (!e) return -1;
    if (pos_out) *pos_out = fd_description_offset(e);
    if (flags_out) {
        uint32_t flags = (uint32_t)e->flags;
        if (e->fd_flags & LINUX_FD_CLOEXEC) flags |= LINUX_O_CLOEXEC;
        *flags_out = flags;
    }
    if (ino_out) *ino_out = e->inode.ino ? e->inode.ino : (0xE0000000u | ((uint32_t)owner_pid << 8) | (uint32_t)fd);
    return 0;
}

int edge_procfs_fd_debug_snapshot(int pid, int fd, uint64_t *pos_out, uint32_t *flags_out,
                                  uint32_t *ino_out, int *kind_out, char *path_out,
                                  uint32_t path_out_sz) {
    const task_t *t;
    edge_fd_proc_t *p;
    edge_fd_t *e;
    int owner_pid = pid;

    if (fd < 0 || fd >= EDGE_MAX_FD) return -1;
    t = process_get_task(pid);
    if (!t || t->state == TASK_UNUSED) return -1;
    if (t->fd_owner_pid > 0) owner_pid = t->fd_owner_pid;
    p = fd_proc_for_pid(owner_pid, 0);
    e = fd_get(p, fd);
    if (!e) return -1;
    if (pos_out) *pos_out = fd_description_offset(e);
    if (flags_out) {
        uint32_t flags = (uint32_t)e->flags;
        if (e->fd_flags & LINUX_FD_CLOEXEC) flags |= LINUX_O_CLOEXEC;
        *flags_out = flags;
    }
    if (ino_out) *ino_out = e->inode.ino ? e->inode.ino : (0xE0000000u | ((uint32_t)owner_pid << 8) | (uint32_t)fd);
    if (kind_out) *kind_out = (int)e->kind;
    if (path_out && path_out_sz) {
        uint32_t i = 0;
        while (i + 1 < path_out_sz && e->path[i]) {
            path_out[i] = e->path[i];
            ++i;
        }
        path_out[i] = 0;
    }
    return 0;
}

int edge_procfs_fd_kind_target_snapshot(int pid, int fd, int *kind_out, int *target_out) {
    const task_t *t;
    edge_fd_proc_t *p;
    edge_fd_t *e;
    int owner_pid = pid;

    if (fd < 0 || fd >= EDGE_MAX_FD) return -1;
    t = process_get_task(pid);
    if (!t || t->state == TASK_UNUSED) return -1;
    if (t->fd_owner_pid > 0) owner_pid = t->fd_owner_pid;
    p = fd_proc_for_pid(owner_pid, 0);
    e = fd_get(p, fd);
    if (!e) return -1;
    if (kind_out) *kind_out = (int)e->kind;
    if (target_out) *target_out = e->pipe_id;
    return 0;
}

int arch_procfd_at(int32_t pid, uint32_t ordinal, uint32_t *fd_out) {
    const task_t *task;
    edge_fd_proc_t *process;
    int owner_pid;
    uint64_t irq_flags;
    int result = -1;

    if (pid <= 0 || !fd_out) return -1;
    task = process_get_task(pid);
    if (!task || task->state == TASK_UNUSED) return -1;
    owner_pid = task->fd_owner_pid > 0 ? task->fd_owner_pid : task->pid;
    fd_proc_registry_read_begin();
    process = fd_proc_for_pid(owner_pid, 0);
    if (!process || fd_proc_table_retain(process) < 0) {
        fd_proc_registry_read_end();
        return -1;
    }
    fd_proc_registry_read_end();
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    for (uint32_t descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
        if (!kernel_fd_table_is_open_locked(
                &process->table_runtime, descriptor) ||
            !__atomic_load_n(
                &process->fds[descriptor].used, __ATOMIC_ACQUIRE))
            continue;
        if (ordinal) {
            --ordinal;
            continue;
        }
        *fd_out = descriptor;
        result = 0;
        break;
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    fd_proc_table_release(process);
    return result;
}

int arch_proc_fd_snapshot(int32_t pid, int32_t descriptor,
                          kernel_fd_proc_snapshot_t *snapshot) {
    const task_t *task;
    edge_fd_proc_t *process;
    edge_fd_t *entry;
    int owner_pid;
    uint64_t irq_flags;

    if (pid <= 0 || descriptor < 0 || descriptor >= EDGE_MAX_FD ||
        !snapshot)
        return -EBADF;
    task = process_get_task(pid);
    if (!task || task->state == TASK_UNUSED) return -EBADF;
    owner_pid = task->fd_owner_pid > 0 ? task->fd_owner_pid : task->pid;
    fd_proc_registry_read_begin();
    process = fd_proc_for_pid(owner_pid, 0);
    if (!process || fd_proc_table_retain(process) < 0) {
        fd_proc_registry_read_end();
        return -EBADF;
    }
    fd_proc_registry_read_end();
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    if (!kernel_fd_table_is_open_locked(
            &process->table_runtime, (uint32_t)descriptor) ||
        !__atomic_load_n(
            &process->fds[descriptor].used, __ATOMIC_ACQUIRE)) {
        kernel_fd_table_unlock(&process->table_runtime, irq_flags);
        fd_proc_table_release(process);
        return -EBADF;
    }
    entry = &process->fds[descriptor];
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->offset = fd_description_offset(entry);
    snapshot->inode = entry->inode.ino ? entry->inode.ino :
        (0xE0000000u | ((uint32_t)owner_pid << 8) |
         (uint32_t)descriptor);
    snapshot->flags = (uint32_t)entry->flags;
    if (entry->fd_flags & LINUX_FD_CLOEXEC)
        snapshot->flags |= LINUX_O_CLOEXEC;
    if (entry->kind == FD_PIDFD) {
        snapshot->is_pidfd = 1;
        snapshot->pidfd_target = entry->pipe_id;
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    fd_proc_table_release(process);
    return 0;
}

static int gui_wake_trace_task(const task_t *t) {
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
           strcmp(t->name, "dbus-daemon") == 0;
#else
    (void)t;
    return 0;
#endif
}

static void fd_wake_fd_owner_tasks(int fd_owner_pid, task_t *cur, const char *source) {
    static int wake_trace_budget = EDGE_GUI_DEEP_TRACE ? 192 : 0;
    if (fd_owner_pid <= 0) return;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *ct = process_task_by_index(i);
        task_t *t = (task_t *)(uintptr_t)ct;
        int owner_pid;
        if (!t || t == cur || t->is_idle ||
            t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) {
            continue;
        }
        owner_pid = t->fd_owner_pid > 0 ? t->fd_owner_pid : t->pid;
        if (owner_pid != fd_owner_pid) continue;
        /*
         * Linux wait queues wake sleepers; they do not requeue every runnable
         * thread that happens to share the same files table.  EdgeOS still uses
         * a broad fd-owner scan until sockets/pipe objects grow real wait queue
         * entries, but the scan must only transition TASK_BLOCKED waiters.
         * Re-marking already-runnable GLib/DBus/XFCE helper threads on every
         * X11 socket wake keeps whole desktop thread groups runnable and makes
         * mouse/keyboard input feel far slower than fbconsole.
         */
        if (t->state == TASK_BLOCKED && t->fd_wait_active) {
            uint32_t cpu = scheduler_cpu_id();
            if (wake_trace_budget > 0 && gui_wake_trace_task(t)) {
                printf("[fdwake] src=%s owner=%d pid=%d cmd=%s sys=%llu ret=%lld fdwait=%u\n",
                       source ? source : "?",
                       fd_owner_pid, t->pid, t->name,
                       (unsigned long long)t->last_syscall_nr,
                       (long long)t->last_syscall_ret,
                       (unsigned)t->fd_wait_active);
                wake_trace_budget--;
            }
            scheduler_task_make_runnable(t, cpu);
        }
    }
}

static void fd_wake_socket_waiters_events(int sock_id, uint16_t events) {
    task_t *cur = process_current_task();
    static int wake_scan_trace_budget = EDGE_X11_TRACE ? 8 : 0;
    uint32_t changed = 0;
    int registered_woke;
    int waiter_overflow = 0;
    if (sock_id < 0) return;
    if (sock_id < EDGE_MAX_SOCKETS && g_sockets[sock_id].used) {
        /*
         * Mark only the readiness classes that changed before waking waiters.
         * Linux EPOLLET users can receive another read edge when fresh bytes
         * arrive while the fd is already readable, but a peer-drained write-space
         * edge must not masquerade as new readable data.  Keeping the generations
         * per poll mask avoids Xorg/GTK spinning on unchanged AF_UNIX sockets.
         */
        if (events & (LINUX_POLLIN | LINUX_POLLPRI |
                      LINUX_POLLRDNORM | LINUX_POLLRDBAND |
                      LINUX_POLLRDHUP))
            changed |= KERNEL_SOCKET_READINESS_READ_CHANGED;
        if (events & (LINUX_POLLOUT | LINUX_POLLWRNORM |
                      LINUX_POLLWRBAND))
            changed |= KERNEL_SOCKET_READINESS_WRITE_CHANGED;
        kernel_socket_readiness_advance(
            &g_sockets[sock_id].readiness, changed);
    }
    registered_woke = socket_waiter_wake_registered(sock_id, cur);
    if (sock_id >= 0 && sock_id < EDGE_MAX_SOCKETS) {
        uint64_t irq_flags = spin_lock_irqsave(&g_waiter_lock);
        waiter_overflow = g_socket_waiter_overflow[sock_id];
        spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    }
    /*
     * Do not use the fd-owner fallback for Linux AF_UNIX streams.  Xorg and GTK
     * processes share one files table across helper threads; a broad owner scan
     * wakes InputThread for every X11/DBus packet even when that thread's epoll
     * wait is really interested in evdev/pipe fds.  Blocking socket users now
     * register in the compact waiter table before sleeping, and poll/select/epoll
     * already do the same, so an AF_UNIX packet with no registered waiter should
     * not wake unrelated blocked threads.  Keep the legacy scan for inet sockets
     * until TCP/UDP have equally complete per-socket wait queues.
     */
    if (sock_id >= 0 && sock_id < EDGE_MAX_SOCKETS &&
        g_sockets[sock_id].used &&
        g_sockets[sock_id].domain == LINUX_AF_UNIX) {
        /*
         * Poll, select, epoll, and blocking I/O all register exact waiters.
         * No registered waiter means no task is currently sleeping on this
         * socket, so a readable transition must not scan every process table.
         * Retain the broad fallback only when registration overflowed.
         */
        if (!waiter_overflow) return;
    }
    /*
     * Prefer the compact per-socket waiter list for all other cases.  The
     * fd-owner fallback is only for stale/missing waiter registrations or the
     * AF_UNIX readable-file case above.
     */
    if (registered_woke > 0 &&
        (sock_id < 0 || sock_id >= EDGE_MAX_SOCKETS ||
         !waiter_overflow))
        return;
    fd_proc_registry_read_begin();
    for (int pi = 0; pi < EDGE_MAX_FD_PROCS; ++pi) {
        edge_fd_proc_t *fp = __atomic_load_n(
            &g_fd_procs[pi], __ATOMIC_ACQUIRE);
        if (!fp || !fp->pid ||
            __atomic_load_n(&fp->detached, __ATOMIC_ACQUIRE))
            continue;
        for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
            edge_fd_t *e = &fp->fds[fd];
            if (!e->used || e->kind != FD_SOCKET ||
                e->pipe_id != sock_id)
                continue;
            /*
             * A stream listener becoming readable is a wakeup source for
             * accept/select/poll/epoll waiters.  Linux has per-wait-queue
             * wakeups; EdgeOS keeps this small scan until sockets grow real
             * wait queues.
             */
            fd_wake_fd_owner_tasks(fp->pid, cur, "socket");
            if (registered_woke == 0 &&
                wake_scan_trace_budget-- > 0 &&
                sock_id >= 0 && sock_id < EDGE_MAX_SOCKETS &&
                g_sockets[sock_id].domain == LINUX_AF_UNIX) {
                printf("[sockwake] scan sid=%d fd_owner=%d fd=%d reg=%d peer=%d rx=%u\n",
                       sock_id, fp->pid, fd, registered_woke,
                       g_sockets[sock_id].unix_peer_id,
                       g_sockets[sock_id].rx_len);
            }
            break;
        }
    }
    fd_proc_registry_read_end();
}

static void fd_wake_socket_waiters(int sock_id) {
    fd_wake_socket_waiters_events(sock_id,
                                  LINUX_POLLIN | LINUX_POLLPRI |
                                  LINUX_POLLRDNORM | LINUX_POLLRDBAND |
                                  LINUX_POLLOUT | LINUX_POLLWRNORM |
                                  LINUX_POLLWRBAND | LINUX_POLLRDHUP);
}

static void fd_wake_pipe_waiters(int pipe_id) {
    task_t *cur = process_current_task();
    uint64_t irq_flags;
    int read_overflow;
    int write_overflow;
    int read_woke;
    int write_woke;
    int read_ready;
    int write_ready;
    if (pipe_id < 0) return;
    read_ready = pipe_read_ready_for_wakeup(pipe_id);
    write_ready = pipe_write_ready_for_wakeup(pipe_id);
    read_woke = pipe_waiter_wake_registered(g_pipe_read_waiter_pids, "read", pipe_id,
                                            pipe_read_ready_for_wakeup, cur);
    write_woke = pipe_waiter_wake_registered(g_pipe_write_waiter_pids, "write", pipe_id,
                                             pipe_write_ready_for_wakeup, cur);
    irq_flags = spin_lock_irqsave(&g_waiter_lock);
    read_overflow = pipe_id < EDGE_MAX_PIPES ?
        g_pipe_read_waiter_overflow[pipe_id] : 0;
    write_overflow = pipe_id < EDGE_MAX_PIPES ?
        g_pipe_write_waiter_overflow[pipe_id] : 0;
    spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    /*
     * Pipe waiters are directional just like Linux wait queues: a read waiter
     * wakes for data/EOF and a write waiter wakes for room/EPIPE.  Waking both
     * sides for every byte made Xorg and GLib helper threads runnable for pipe
     * transitions they did not poll for, which amplified XFCE startup latency.
     * Exact poll/select/epoll and blocking pipe I/O registrations cover the
     * supported cases.  Linux wait queues are still object based, though: if the
     * compact table filled or a wait was registered through a shared fd table
     * edge case, a pipe transition must not be lost until a long userspace
     * timeout.  Fall back to fd-owner waking only for processes that actually
     * hold a matching end of this pipe, and only when the corresponding side is
     * currently ready.
     */
    if ((read_ready && read_overflow) ||
        (write_ready && write_overflow)) {
        static int pipe_scan_trace_budget = EDGE_XFCE_BOOT_TRACE ? 64 : 0;
        fd_proc_registry_read_begin();
        for (int pi = 0; pi < EDGE_MAX_FD_PROCS; ++pi) {
            edge_fd_proc_t *fp = __atomic_load_n(
                &g_fd_procs[pi], __ATOMIC_ACQUIRE);
            int has_read_end = 0;
            int has_write_end = 0;
            if (!fp || !fp->pid ||
                __atomic_load_n(&fp->detached, __ATOMIC_ACQUIRE))
                continue;
            for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
                edge_fd_t *e = &fp->fds[fd];
                if (!e->used || e->pipe_id != pipe_id) continue;
                if (e->kind == FD_PIPE_R || e->kind == FD_PIPE_RW) has_read_end = 1;
                if (e->kind == FD_PIPE_W || e->kind == FD_PIPE_RW) has_write_end = 1;
                if (has_read_end && has_write_end) break;
            }
            if ((read_ready && has_read_end) || (write_ready && has_write_end)) {
                if (pipe_scan_trace_budget > 0) {
                    const task_t *owner = process_get_task(fp->pid);
                    edge_pipe_t *pp = (pipe_id >= 0 && pipe_id < EDGE_MAX_PIPES) ? &g_pipes[pipe_id] : 0;
                    printf("[pipewake] scan id=%d owner=%d cmd=%s rr=%d wr=%d count=%u r=%d w=%d budget=%d\n",
                           pipe_id, fp->pid, owner && owner->name[0] ? owner->name : "?",
                           read_ready, write_ready, pp ? pp->count : 0,
                           pp ? (int)pp->readers : -1,
                           pp ? (int)pp->writers : -1,
                           pipe_scan_trace_budget - 1);
                    pipe_scan_trace_budget--;
                }
                fd_wake_fd_owner_tasks(fp->pid, cur, "pipe");
            }
        }
        fd_proc_registry_read_end();
    }
    (void)read_woke;
    (void)write_woke;
}

static void fd_wake_eventfd_read_waiters(int eventfd_id) {
    task_t *cur = process_current_task();
    int registered_woke;
    if (eventfd_id < 0) return;
    registered_woke = eventfd_waiter_wake_registered(g_eventfd_read_waiter_pids,
                                                     "read", eventfd_id, cur);
    /*
     * GLib uses eventfd for per-thread wakeups inside XFCE processes.  A broad
     * fd-owner scan wakes every blocked thread sharing the same files table and
     * turns a single eventfd notification into a process-wide scheduling storm.
     * Poll/select/epoll and blocking eventfd I/O register exact waiters, so do
     * not fall back to waking unrelated owner tasks here.
     */
    (void)registered_woke;
}

static void fd_wake_eventfd_write_waiters(int eventfd_id) {
    task_t *cur = process_current_task();
    int registered_woke;
    if (eventfd_id < 0) return;
    registered_woke = eventfd_waiter_wake_registered(g_eventfd_write_waiter_pids,
                                                     "write", eventfd_id, cur);
    (void)registered_woke;
}

static void fd_wake_timerfd_waiters(int timerfd_id) {
    task_t *cur = process_current_task();
    if (timerfd_id < 0) return;
    fd_proc_registry_read_begin();
    for (int pi = 0; pi < EDGE_MAX_FD_PROCS; ++pi) {
        edge_fd_proc_t *fp = __atomic_load_n(
            &g_fd_procs[pi], __ATOMIC_ACQUIRE);
        if (!fp || !fp->pid ||
            __atomic_load_n(&fp->detached, __ATOMIC_ACQUIRE))
            continue;
        for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
            edge_fd_t *e = &fp->fds[fd];
            if (!e->used || e->kind != FD_TIMERFD || e->pipe_id != timerfd_id) continue;
            /*
             * timerfd readiness is deadline-driven, but timerfd_settime() can
             * arm or re-arm a descriptor from another thread.  Wake waiters so
             * they recompute the next deadline instead of sleeping on an old
             * timeout.  The timer expiry itself is handled by bounded sleep
             * deadlines in poll/select/epoll.
             */
            fd_wake_fd_owner_tasks(fp->pid, cur, "timerfd");
            break;
        }
    }
    fd_proc_registry_read_end();
}

static void fd_wake_pidfd_waiters(int target_pid) {
    task_t *cur = process_current_task();
    if (target_pid <= 0) return;
    fd_proc_registry_read_begin();
    for (int pi = 0; pi < EDGE_MAX_FD_PROCS; ++pi) {
        edge_fd_proc_t *fp = __atomic_load_n(
            &g_fd_procs[pi], __ATOMIC_ACQUIRE);
        if (!fp || !fp->pid ||
            __atomic_load_n(&fp->detached, __ATOMIC_ACQUIRE))
            continue;
        for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
            edge_fd_t *e = &fp->fds[fd];
            if (!e->used || e->kind != FD_PIDFD || e->pipe_id != target_pid) continue;
            /*
             * A pidfd becomes readable when the referenced task exits.  This is
             * a real Linux wait source, not a descriptor that should be
             * periodically polled.  Wake owners broadly until EdgeOS grows
             * per-file wait queues for all special fd kinds.
             */
            fd_wake_fd_owner_tasks(fp->pid, cur, "pidfd");
            break;
        }
    }
    fd_proc_registry_read_end();
}

static void fd_wake_unix_listener_for_pending_child(int child_sock_id) {
    if (child_sock_id < 0) return;
    for (int sid = 0; sid < EDGE_MAX_SOCKETS; ++sid) {
        edge_socket_t *listener = &g_sockets[sid];
        if (!listener->used || !listener->listening) continue;
        if (kernel_socket_accept_queue_contains(
                &listener->accept_queue, child_sock_id)) {
            /*
             * A client may send immediately after connect while the server is
             * still finishing startup.  The accepted child is not fd-owned until
             * accept() dequeues it, so readable child data must wake the listener
             * wait queue as well as the child socket's eventual reader.
             */
            fd_wake_socket_waiters_events(sid, LINUX_POLLIN | LINUX_POLLPRI);
            return;
        }
    }
}

static int pipe_alloc(void) {
    int result = kernel_pipe_object_allocate(g_pipes, EDGE_MAX_PIPES);
    if (result >= 0) {
        uint64_t irq_flags = spin_lock_irqsave(&g_waiter_lock);
        g_pipe_read_waiter_overflow[result] = 0;
        g_pipe_write_waiter_overflow[result] = 0;
        spin_unlock_irqrestore(&g_waiter_lock, irq_flags);
    }
    return result < 0 ? -1 : result;
}

static void pipe_x86_wake(void *context, uint32_t pipe_index) {
    (void)context;
    fd_wake_pipe_waiters((int)pipe_index);
}

static int pipe_x86_copy_to_user(void *context, uint64_t destination,
                                 const void *source, uint64_t size) {
    (void)context;
    return copy_to_user(destination, source, size);
}

static int pipe_x86_copy_from_user(void *context, void *destination,
                                   uint64_t source, uint64_t size) {
    (void)context;
    return copy_from_user(destination, source, size);
}

static void pipe_drop_reader(int pipe_id) {
    if (pipe_id < 0 || pipe_id >= EDGE_MAX_PIPES) return;
    edge_pipe_t *pp = &g_pipes[pipe_id];
    if (!pp->used) return;
    (void)kernel_pipe_endpoint_drop(
        pp, 1, 0, pipe_x86_wake, 0, (uint32_t)pipe_id);
    (void)kernel_pipe_object_release_if_unused(pp);
}

static void pipe_drop_writer(int pipe_id) {
    if (pipe_id < 0 || pipe_id >= EDGE_MAX_PIPES) return;
    edge_pipe_t *pp = &g_pipes[pipe_id];
    if (!pp->used) return;
    (void)kernel_pipe_endpoint_drop(
        pp, 0, 1, pipe_x86_wake, 0, (uint32_t)pipe_id);
    (void)kernel_pipe_object_release_if_unused(pp);
}

static void fd_clone_table_abort(edge_fd_proc_t *table) {
    if (!table) return;
    if (__atomic_exchange_n(
            &table->detached, 1u, __ATOMIC_ACQ_REL))
        return;
    for (int descriptor = 0; descriptor < EDGE_MAX_FD; ++descriptor) {
        edge_fd_t closing;
        if (fd_remove_open(table, descriptor, &closing) == 0) {
            (void)fd_release_entry(&closing, 0, 0, 0);
        } else {
            (void)fd_cancel_constructed_reserved(
                table, descriptor);
        }
    }
    (void)fd_proc_registry_detach(table);
    table->pid = 0;
    fd_proc_table_release(table);
}

static int fd_clone_table_contents(edge_fd_proc_t *source,
                                   edge_fd_proc_t *destination) {
    uint32_t inherited_limit;
    uint64_t irq_flags;

    if (!source || !destination) return -ENOMEM;
    irq_flags = kernel_fd_table_lock(&source->table_runtime);
    inherited_limit = kernel_fd_table_allocated_limit_locked(
        &source->table_runtime);
    kernel_fd_table_unlock(&source->table_runtime, irq_flags);
    for (uint32_t descriptor = 0;
         descriptor < inherited_limit; ++descriptor) {
        edge_fd_t copy;

        memset(&copy, 0, sizeof(copy));
        irq_flags = kernel_fd_table_lock(&source->table_runtime);
        if (!kernel_fd_table_is_open_locked(
                &source->table_runtime, (uint32_t)descriptor) ||
            !__atomic_load_n(
                &source->fds[descriptor].used, __ATOMIC_ACQUIRE)) {
            kernel_fd_table_unlock(
                &source->table_runtime, irq_flags);
            continue;
        }
        copy = source->fds[descriptor];
        if (copy.file_ref <= 0 || file_ref_get(copy.file_ref) < 0) {
            kernel_fd_table_unlock(&source->table_runtime, irq_flags);
            return -ENOMEM;
        }
        kernel_fd_table_unlock(&source->table_runtime, irq_flags);
        if (fd_add_backing_object(&copy) < 0) {
            (void)file_ref_put(copy.file_ref);
            return -ENOMEM;
        }
        if (fd_reserve_exact(destination, (int)descriptor) < 0 ||
            fd_install_reserved(destination, (int)descriptor, &copy) < 0) {
            fd_abort_reserved(destination, (int)descriptor);
            (void)fd_release_entry(&copy, 0, 0, 0);
            return -ENOMEM;
        }
    }
    {
        uint64_t destination_flags =
            kernel_fd_table_lock(&destination->table_runtime);

        if (inherited_limit > destination->table_runtime.limit)
            inherited_limit = destination->table_runtime.limit;
        if (destination->table_runtime.allocated_limit < inherited_limit)
            destination->table_runtime.allocated_limit = inherited_limit;
        kernel_fd_table_unlock(
            &destination->table_runtime, destination_flags);
    }
    return 0;
}

static int fd_clone_after_fork(int parent_pid, int child_pid) {
    edge_fd_proc_t *parent = fd_proc_for_pid(parent_pid, 0);
    edge_fd_proc_t *child;
    edge_fd_t parent_debug_copy;
    uint64_t irq_flags;
    if (!parent || child_pid <= 0) return -ENOMEM;
    /*
     * A fork child inherits the parent's descriptor table.  Creating the table
     * through fd_proc_for_pid() first synthesizes three stdio descriptions;
     * replacing those entries with the inherited table would leak their global
     * file references on every fork.  Allocate an empty table so every file
     * reference installed below is reachable and released at process exit.
    */
    child = fd_proc_for_pid_empty(child_pid, 1);
    if (!child) return -ENOMEM;
    irq_flags = kernel_fd_table_lock(&parent->table_runtime);
    parent_debug_copy = parent->fds[10];
    kernel_fd_table_unlock(&parent->table_runtime, irq_flags);
    fd_debug_slot_once("fork-parent-pre", parent_pid, 10, &parent_debug_copy);
    if (fd_clone_table_contents(parent, child) < 0) {
        fd_clone_table_abort(child);
        return -ENOMEM;
    }
    /* Clone all descriptors, not just stdio. */
    for (int i = 0; i < EDGE_MAX_FD; ++i) {
        if (!child->fds[i].used) continue;
        if (g_pipe_lifecycle_trace_budget > 0 && pipe_lifecycle_trace_task(task_by_pid_mutable_local(parent_pid)) &&
            (child->fds[i].kind == FD_PIPE_R || child->fds[i].kind == FD_PIPE_W ||
             child->fds[i].kind == FD_PIPE_RW)) {
            edge_pipe_t *pp = &g_pipes[child->fds[i].pipe_id];
            printf("[pipefd] fork parent=%d child=%d fd=%d kind=%s pipe=%d r=%d w=%d refs=%d budget=%d\n",
                   parent_pid, child_pid, i, fd_kind_name(child->fds[i].kind),
                   child->fds[i].pipe_id, pp->readers, pp->writers,
                   child->fds[i].file_ref, g_pipe_lifecycle_trace_budget - 1);
            g_pipe_lifecycle_trace_budget--;
        }
        fd_log_lifecycle("fork-clone-parent", parent_pid, i, &child->fds[i], child_pid);
        fd_log_lifecycle("fork-clone-child", child_pid, i, &child->fds[i], parent_pid);
    }
    fd_debug_slot_once("fork-child-post", child_pid, 10, &child->fds[10]);
    return 0;
}

static void tty_reset_defaults(void) {
    for (int i = 0; i <= EDGE_FB_VT_COUNT; ++i) console_line_reset(&g_console_lines[i]);
    g_active_vt = 1;
    g_tty_read_log_count = 0;
    g_tty_fg_fix_log_count = 0;
    g_tty_ioctl_log_count = 0;
}

static int tty_seen_pid(int *arr, int *count, int pid) {
    if (!arr || !count || pid <= 0) return 1;
    for (int i = 0; i < *count; ++i) {
        if (arr[i] == pid) return 1;
    }
    if (*count < 64) arr[(*count)++] = pid;
    return 0;
}

static const char *fd_kind_name(edge_fd_kind_t kind) {
    switch (kind) {
        case FD_CONSOLE: return "console";
        case FD_VFS: return "vfs";
        case FD_PIPE_R: return "pipe_r";
        case FD_PIPE_W: return "pipe_w";
        case FD_PIPE_RW: return "pipe_rw";
        case FD_SOCKET: return "socket";
        case FD_PTY_MASTER: return "pty_master";
        case FD_PTY_SLAVE: return "pty_slave";
        case FD_EVENTFD: return "eventfd";
        case FD_TIMERFD: return "timerfd";
        case FD_SIGNALFD: return "signalfd";
        case FD_EPOLL: return "epoll";
        case FD_PIDFD: return "pidfd";
        case FD_INOTIFY: return "inotify";
        case FD_FANOTIFY: return "fanotify";
        case FD_USERFAULTFD: return "userfaultfd";
        case FD_PERF_EVENT: return "perf_event";
        case FD_MEMFD: return "memfd";
        case FD_DMA_BUF: return "dma-buf";
        case FD_TUN: return "tun";
        case FD_NAMESPACE: return "namespace";
        case FD_MOUNT: return "mount";
        case FD_MQUEUE: return "mqueue";
        case FD_IO_URING: return "io_uring";
        case FD_LANDLOCK: return "landlock";
        case FD_BPF: return "bpf";
        case FD_SECCOMP: return "seccomp";
        case FD_DRM_SYNC: return "sync_file";
        default: return "none";
    }
}

static int path_is_console_tty(const char *path) {
    if (!path || !path[0]) return 0;
    if (strcmp(path, "/dev/tty") == 0) return 1;
    if (strcmp(path, "/dev/console") == 0) return 1;
    if (strncmp(path, "/dev/tty", 8) == 0) {
        const char *n = path + 8;
        if (!n[0]) return 0;
        for (const char *p = n; *p; ++p) {
            if (*p < '0' || *p > '9') return 0;
        }
        return 1;
    }
    return 0;
}

static int path_is_serial_tty(const char *path) {
    if (!path || !path[0]) return 0;
    return strcmp(path, "/dev/ttyS0") == 0;
}

static int path_can_be_controlling_tty(const char *path) {
    if (!path || !path[0]) return 0;
    if (strcmp(path, "/dev/console") == 0 ||
        strcmp(path, "/dev/tty") == 0 ||
        strcmp(path, "/dev/tty0") == 0)
        return 0;
    return path_is_console_tty(path) || path_is_serial_tty(path);
}

static int path_is_tty_device(const char *path) {
    return path_is_console_tty(path) || path_is_serial_tty(path);
}

static int path_is_devpts_slave(const char *path, int *pty_id_out) {
    int pty_id = 0;
    const char *n;
    if (!path || strncmp(path, "/dev/pts/", 9) != 0) return 0;
    n = path + 9;
    if (!n[0]) return 0;
    for (const char *q = n; *q; ++q) {
        if (*q < '0' || *q > '9') return 0;
        pty_id = pty_id * 10 + (*q - '0');
        if (pty_id >= EDGE_MAX_PTYS) return 0;
    }
    if (pty_id_out) *pty_id_out = pty_id;
    return 1;
}

static int console_line_from_fd_entry(const edge_fd_t *e) {
    if (!e) return console_line_active_vt();
    if (e->kind == FD_CONSOLE) return console_line_valid(e->pipe_id) ? e->pipe_id : console_line_from_vt(e->pipe_id);
    if (e->kind == FD_VFS && path_is_tty_device(e->path)) return console_line_from_path(e->path);
    return console_line_active_vt();
}

static int fd_proc_infer_console_line(edge_fd_proc_t *p) {
    if (!p) return -1;
    for (int fd = 0; fd <= 2; ++fd) {
        edge_fd_t *e = &p->fds[fd];
        int line_id;
        if (!e->used) continue;
        if (!(e->kind == FD_CONSOLE || (e->kind == FD_VFS && path_is_tty_device(e->path)))) continue;
        line_id = console_line_from_fd_entry(e);
        if (line_id == 0 && e->kind == FD_VFS && !path_is_serial_tty(e->path)) continue;
        return line_id;
    }
    return -1;
}

static int console_tty_path_supported(const char *path) {
    const char *n;
    int vt = 0;
    if (!path || !path[0]) return 0;
    if (strcmp(path, "/dev/tty") == 0) return 1;
    if (strcmp(path, "/dev/console") == 0) return 1;
    if (strcmp(path, "/dev/ttyS0") == 0) return 1;
    if (strcmp(path, "/dev/tty0") == 0) return 1;
    if (strncmp(path, "/dev/tty", 8) != 0) return 0;
    n = path + 8;
    if (!n[0]) return 0;
    for (const char *p = n; *p; ++p) {
        if (*p < '0' || *p > '9') return 0;
        vt = vt * 10 + (*p - '0');
        if (vt > EDGE_FB_VT_COUNT) return 0;
    }
    return vt >= 1 && vt <= EDGE_FB_VT_COUNT;
}

static int console_line_referenced_elsewhere(int owner_pid, int line_id) {
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *ot = process_task_by_index(i);
        edge_fd_proc_t *op;
        if (!ot || ot->state == TASK_UNUSED || ot->state == TASK_ZOMBIE) continue;
        if (ot->pid == owner_pid) continue;
        if (ot->ctty_kind == PROCESS_CTTY_CONSOLE &&
            console_line_from_vt(ot->ctty_id) == line_id) {
            return 1;
        }
        op = fd_proc_for_pid(ot->fd_owner_pid > 0 ? ot->fd_owner_pid : ot->pid, 0);
        if (!op) continue;
        for (int fd = 0; fd < EDGE_MAX_FD; ++fd) {
            edge_fd_t *e = &op->fds[fd];
            if (!e->used) continue;
            if (!(e->kind == FD_CONSOLE || (e->kind == FD_VFS && path_is_tty_device(e->path)))) continue;
            if (console_line_from_fd_entry(e) == line_id) return 1;
        }
    }
    return 0;
}

static void tty_session_caller_from_task(
    const task_t *task, int terminal_is_controlling,
    edge_linux_tty_session_caller_t *caller) {
    memset(caller, 0, sizeof(*caller));
    if (!task) return;
    caller->pid = task->pid;
    caller->sid = task->sid;
    caller->pgid = task->pgid;
    caller->effective_capabilities = task->capabilities.effective;
    caller->has_controlling_terminal =
        task->ctty_kind != PROCESS_CTTY_NONE;
    caller->terminal_is_controlling = terminal_is_controlling != 0;
}

static int tty_fd_is_controlling_terminal(const task_t *task,
                                          const edge_fd_t *entry) {
    int line_id;
    if (!task || !entry || task->ctty_kind == PROCESS_CTTY_NONE) return 0;
    if (entry->kind == FD_PTY_MASTER || entry->kind == FD_PTY_SLAVE) {
        return task->ctty_kind == PROCESS_CTTY_PTY &&
               task->ctty_id == entry->pipe_id;
    }
    if (task->ctty_kind != PROCESS_CTTY_CONSOLE) return 0;
    line_id = console_line_from_fd_entry(entry);
    return console_line_valid(line_id) &&
           console_line_from_vt(task->ctty_id) == line_id;
}

static edge_linux_tty_session_state_t *tty_session_state_from_entry(
    const edge_fd_t *entry) {
    if (!entry) return 0;
    if (entry->kind == FD_PTY_MASTER || entry->kind == FD_PTY_SLAVE) {
        if (entry->pipe_id < 0 || entry->pipe_id >= EDGE_MAX_PTYS ||
            !g_ptys[entry->pipe_id].used)
            return 0;
        return &g_ptys[entry->pipe_id].session;
    }
    {
        edge_console_line_t *line =
            console_line_state(console_line_from_fd_entry(entry));
        return line ? &line->session : 0;
    }
}

static int tty_process_group_session(int pgid, int *sid_out) {
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *task = process_task_by_index(i);
        if (!task || task->state == TASK_UNUSED || task->state == TASK_ZOMBIE)
            continue;
        if (task->pgid != pgid) continue;
        if (sid_out) *sid_out = task->sid;
        return 1;
    }
    return 0;
}

static void tty_notify_disassociated_process_group(int pgid);

static int tty_session_leader_alive(int sid) {
    if (sid <= 0) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *task = process_task_by_index(i);
        if (!task || task->state == TASK_UNUSED ||
            task->state == TASK_ZOMBIE)
            continue;
        if (task->pid == sid && task->sid == sid) return 1;
    }
    return 0;
}

static void tty_session_reclaim_stale(
    edge_linux_tty_session_state_t *state) {
    edge_linux_tty_session_transition_t transition;
    if (!state || state->session_id <= 0 ||
        tty_session_leader_alive(state->session_id))
        return;
    edge_linux_tty_session_release(
        state, state->session_id, &transition);
    if (transition.detach_whole_session)
        tty_notify_disassociated_process_group(
            transition.detached_foreground_pgid);
}

static void tty_clear_session_tasks(int sid) {
    if (sid <= 0) return;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *task = (task_t *)(uintptr_t)process_task_by_index(i);
        if (!task || task->state == TASK_UNUSED || task->state == TASK_ZOMBIE ||
            task->sid != sid)
            continue;
        task->ctty_kind = PROCESS_CTTY_NONE;
        task->ctty_id = -1;
    }
}

static void tty_notify_disassociated_process_group(int pgid) {
    if (pgid <= 0) return;
    (void)process_send_signal_pgid(pgid, LINUX_SIGHUP);
    (void)process_send_signal_pgid(pgid, LINUX_SIGCONT);
}

static void tty_session_release_task(task_t *task) {
    edge_linux_tty_session_state_t *state = 0;
    edge_linux_tty_session_transition_t transition;
    if (!task || task->pid != task->sid ||
        task->ctty_kind == PROCESS_CTTY_NONE)
        return;
    if (task->ctty_kind == PROCESS_CTTY_PTY) {
        if (task->ctty_id >= 0 && task->ctty_id < EDGE_MAX_PTYS &&
            g_ptys[task->ctty_id].used)
            state = &g_ptys[task->ctty_id].session;
    } else if (task->ctty_kind == PROCESS_CTTY_CONSOLE) {
        edge_console_line_t *line =
            console_line_state(console_line_from_vt(task->ctty_id));
        if (line) state = &line->session;
    }
    if (!state) return;
    edge_linux_tty_session_release(state, task->sid, &transition);
    if (!transition.detach_whole_session) return;
    tty_clear_session_tasks(transition.detached_session_id);
    tty_notify_disassociated_process_group(
        transition.detached_foreground_pgid);
}

int arch_tty_vhangup(void) {
    task_t *task = process_current_task();
    edge_linux_tty_session_state_t *state = 0;
    edge_linux_tty_session_transition_t transition;

    if (!task) return -ESRCH;
    if (task->ctty_kind == PROCESS_CTTY_PTY) {
        if (task->ctty_id >= 0 && task->ctty_id < EDGE_MAX_PTYS &&
            g_ptys[task->ctty_id].used)
            state = &g_ptys[task->ctty_id].session;
    } else if (task->ctty_kind == PROCESS_CTTY_CONSOLE) {
        edge_console_line_t *line =
            console_line_state(console_line_from_vt(task->ctty_id));
        if (line) state = &line->session;
    }
    if (!state) return 0;
    edge_linux_tty_session_hangup(state, &transition);
    if (!transition.detach_whole_session) return 0;
    tty_clear_session_tasks(transition.detached_session_id);
    tty_notify_disassociated_process_group(
        transition.detached_foreground_pgid);
    return 0;
}

static uint64_t open_console_tty_fd(edge_fd_proc_t *p, const char *path, int flags) {
    int fd;
    int line_id;
    int visible_line_id;
    int wants_ctty;
    int parked_duplicate = 0;
    edge_fd_t *e;
    task_t *cur;

    if (!p || !path || !path_is_tty_device(path)) return (uint64_t)-EINVAL;
    if (strcmp(path, "/dev/tty") == 0) return (uint64_t)-ENXIO;
    if (!console_tty_path_supported(path)) return (uint64_t)-ENXIO;

    line_id = console_line_from_path(path);
    if (!console_line_valid(line_id)) return (uint64_t)-ENXIO;

    cur = process_current_task();
    visible_line_id = line_id;
    wants_ctty = cur &&
                 cur->sid == cur->pid &&
                 cur->ctty_kind == PROCESS_CTTY_NONE &&
                 (flags & LINUX_O_NOCTTY) == 0 &&
                 (flags & LINUX_O_PATH) == 0 &&
                 path_can_be_controlling_tty(path);
    {
        static int tty_open_trace_budget = 12;
        if (tty_open_trace_budget > 0 &&
            (strcmp(path, "/dev/console") == 0 || strcmp(path, "/dev/tty1") == 0 ||
             strcmp(path, "/dev/ttyS0") == 0)) {
            printf("[tty-open] pid=%d task=%s path=%s line=%d default=%d active=%d flags=0x%x\n",
                   cur ? cur->pid : -1,
                   (cur && cur->name[0]) ? cur->name : "?",
                   path, line_id, console_line_default(), console_line_active_vt(),
                   (unsigned)flags);
            tty_open_trace_budget--;
        }
    }
    /*
     * /dev/console and /dev/tty1 can name the same visible Linux VT.  Opening
     * /dev/tty1 must still return the real active VT: Xorg opens that device
     * before switching it to KD_GRAPHICS, and redirecting it to an inactive
     * hidden line makes startxfce4 hang before the server owns the display.
     * Duplicate getty/input stealing has to be solved through foreground
     * process-group and VT-mode rules, not by changing the device being opened.
     */
    /*
     * Do not redirect an active VT open merely because another session has a
     * controlling terminal reference to it. Linux permits the open; ownership
     * checks happen when userspace asks for controlling-terminal semantics or
     * foreground input. Redirecting here breaks Xorg, which opens the active
     * VT from a new session during startxfce4.
     */
    (void)console_line_referenced_elsewhere;

    fd = fd_alloc(p, 0);
    if (fd < 0) return (uint64_t)-EMFILE;
    e = &p->fds[fd];
    e->file_ref = file_ref_alloc((uint32_t)flags);
    if (!e->file_ref) {
        fd_abort_reserved(p, fd);
        return (uint64_t)-ENFILE;
    }

    e->kind = FD_CONSOLE;
    e->flags = flags;
    e->fd_flags = (flags & LINUX_O_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    fd_description_set_offset(e, 0);
    e->pipe_id = line_id;
    strncpy(e->path, path, sizeof(e->path) - 1);
    e->path[sizeof(e->path) - 1] = 0;
    if (fd_publish(p, fd) < 0) {
        (void)file_ref_put(e->file_ref);
        fd_abort_reserved(p, fd);
        return (uint64_t)-EBADF;
    }

    if (wants_ctty &&
        !parked_duplicate &&
        visible_line_id == line_id &&
        line_id == console_line_active_vt()) {
        edge_console_line_t *line = console_line_state(line_id);
        if (line && line->primary_open_sid <= 0) {
            line->primary_open_pid = cur->pid;
            line->primary_open_sid = cur->sid;
        }
    }

    /*
     * Linux assigns a controlling terminal when a session leader without one
     * opens a terminal device without O_NOCTTY.  Getty/login relies on this
     * after setsid(): later /dev/tty opens must resolve back to the concrete
     * VT or serial line, not to the boot console default.  Keep this in the
     * kernel TTY layer; do not special-case rootfs paths or init systems here.
     */
    if (wants_ctty) {
        edge_linux_tty_session_caller_t caller;
        edge_console_line_t *line = console_line_state(line_id);
        tty_session_caller_from_task(cur, 0, &caller);
        if (line && edge_linux_tty_session_acquire_on_open(
                        &line->session, &caller,
                        (flags & LINUX_O_NOCTTY) != 0)) {
        cur->ctty_kind = PROCESS_CTTY_CONSOLE;
        cur->ctty_id = line_id;
        }
    }
    return (uint64_t)fd;
}

static int path_is_mouse_input(const char *path) {
    if (!path) return 0;
    return strcmp(path, "/dev/input/mice") == 0 || strcmp(path, "/dev/input/mouse0") == 0;
}

static int linux_input_index_name(char *out, uint32_t capacity,
                                  const char *prefix, uint32_t index) {
    char reverse[10];
    uint32_t length = 0;
    uint32_t digits = 0;

    if (!out || !capacity || !prefix) return -1;
    while (*prefix) {
        if (length + 1u >= capacity) return -1;
        out[length++] = *prefix++;
    }
    do {
        reverse[digits++] = (char)('0' + index % 10u);
        index /= 10u;
    } while (index && digits < sizeof(reverse));
    while (digits) {
        if (length + 1u >= capacity) return -1;
        out[length++] = reverse[--digits];
    }
    out[length] = 0;
    return 0;
}

static int path_is_event_input(const char *path) {
    if (!path) return 0;
    if (strncmp(path, "/dev/input/event", 16) != 0) return 0;
    path += 16;
    if (!*path) return 0;
    while (*path >= '0' && *path <= '9') ++path;
    return *path == 0;
}

static int path_input_event_index(const char *path) {
    int idx = 0;
    if (!path || strncmp(path, "/dev/input/event", 16) != 0) return -1;
    path += 16;
    if (!*path) return -1;
    while (*path >= '0' && *path <= '9') {
        idx = idx * 10 + (*path - '0');
        if (idx >= (int)EDGE_INPUT_DEVICE_MAX) return -1;
        ++path;
    }
    if (*path != 0) return -1;
    return idx;
}

static int path_is_uinput_device(const char *path) {
    return path && strcmp(path, "/dev/uinput") == 0;
}

static int path_is_dri_device(const char *path) {
    return edge_drm_path_is_device(path);
}

static int path_is_video_device(const char *path) {
    return uvc_path_kind(path);
}

static int path_is_kmsg_device(const char *path) {
    return path && strcmp(path, "/dev/kmsg") == 0;
}

static int path_is_rtc_device(const char *path) {
    return path && (strcmp(path, "/dev/rtc") == 0 || strcmp(path, "/dev/rtc0") == 0);
}

static int path_is_watchdog_device(const char *path) {
#ifdef CONFIG_WATCHDOG
    return path &&
           (strcmp(path, "/dev/watchdog") == 0 || strcmp(path, "/dev/watchdog0") == 0) &&
           watchdog_available();
#else
    (void)path;
    return 0;
#endif
}

static int linux_special_dev_path_supported(const char *path) {
    int pty_id = -1;
    if (!path || !path[0]) return 0;
    if (path_is_tty_device(path)) return console_tty_path_supported(path);
    if (path_is_devpts_slave(path, &pty_id)) {
        return pty_id >= 0 && pty_id < EDGE_MAX_PTYS && g_ptys[pty_id].used;
    }
    if (strcmp(path, "/dev/fb0") == 0) return 1;
    if (linux_misc_rdev_from_path(path) != 0) return 1;
    if (path_is_kmsg_device(path)) return 1;
    if (path_is_rtc_device(path)) return 1;
    if (path_is_watchdog_device(path)) return 1;
    if (path_is_audio_device(path)) return 1;
    if (path_is_alsa_device(path)) return 1;
    if (path_is_mouse_input(path) || path_is_event_input(path) ||
        path_is_uinput_device(path) || path_is_dri_device(path)) {
        return linux_graphics_input_rdev_from_path(path) != 0;
    }
    if (path_is_video_device(path)) return linux_graphics_input_rdev_from_path(path) != 0;
    return 0;
}

static int linux_special_dev_stat_from_path(
    const char *path, edge_x86_64_linux_stat_t *st) {
    uint64_t rdev;
    int pty_id = -1;
    if (!path || !st) return 0;
    if (strcmp(path, EDGE_LINUX_TUN_PATH) == 0) {
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(path);
        st->st_rdev = linux_makedev(10, 200);
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    if (path_is_tty_device(path) && console_tty_path_supported(path)) {
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(path);
        st->st_rdev = linux_tty_rdev_from_path(path);
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    if (path_is_devpts_slave(path, &pty_id)) {
        if (pty_id < 0 || pty_id >= EDGE_MAX_PTYS || !g_ptys[pty_id].used) return 0;
        st->st_dev = 1;
        st->st_ino = 0xD0FFF100u + (uint64_t)(uint32_t)pty_id;
        st->st_rdev = linux_makedev(136, (uint32_t)pty_id);
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    if (strcmp(path, "/dev/fb0") == 0) {
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(path);
        st->st_rdev = linux_makedev(29, 0);
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    if (path_is_rtc_device(path)) {
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(path);
        st->st_rdev = linux_makedev(254, 0);
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    rdev = linux_misc_rdev_from_path(path);
    if (rdev) {
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(path);
        st->st_rdev = rdev;
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    if (path_is_mouse_input(path) || path_is_event_input(path) ||
        path_is_uinput_device(path) || path_is_dri_device(path)) {
        rdev = linux_graphics_input_rdev_from_path(path);
        if (!rdev) return 0;
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(path);
        st->st_rdev = rdev;
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    if (path_is_video_device(path)) {
        rdev = linux_graphics_input_rdev_from_path(path);
        if (!rdev) return 0;
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(path);
        st->st_rdev = rdev;
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    if (path_is_audio_device(path)) {
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(path);
        st->st_rdev = linux_makedev(14, strcmp(path, "/dev/mixer") == 0 ? 0u : 3u);
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    if (path_is_alsa_device(path)) {
        int kind = alsa_path_kind(path);
        st->st_dev = 1;
        st->st_ino = linux_devnode_ino_from_path(path);
        st->st_rdev = linux_makedev(EDGE_ALSA_CARD_MAJOR, alsa_dev_minor_from_kind(kind));
        st->st_mode = (st->st_mode & 07777u) | LINUX_S_IFCHR;
        return 1;
    }
    return 0;
}

static int pty_alloc(void) {
    task_t *task = process_current_task();
    for (int i = 0; i < EDGE_MAX_PTYS; ++i) {
        edge_pty_t *pty = &g_ptys[i];
        if (pty->used) continue;
        memset(pty, 0, sizeof(*pty));
        pty->used = 1;
        pty->refs_master = 1;
        pty->refs_slave = 0;
        pty->unlocked = 0;
        pty->session.session_id = 0;
        pty->session.foreground_pgid = 0;
        termios_init_sane(&pty->termios);
        pty->winsz.ws_row = 25;
        pty->winsz.ws_col = 80;
        if (devpts_slave_create(
                &pty->slave_inode, (uint32_t)i,
                task ? task->fsuid : 0u) < 0) {
            memset(pty, 0, sizeof(*pty));
            return -ENOENT;
        }
        return i;
    }
    return -ENOMEM;
}

static void pty_add_ref(int pty_id, int is_master) {
    if (pty_id < 0 || pty_id >= EDGE_MAX_PTYS) return;
    if (!g_ptys[pty_id].used) return;
    if (is_master) g_ptys[pty_id].refs_master++;
    else g_ptys[pty_id].refs_slave++;
}

static void pty_maybe_assign_controlling_tty(int pty_id, int flags) {
    task_t *cur;
    edge_linux_tty_session_caller_t caller;

    if (pty_id < 0 || pty_id >= EDGE_MAX_PTYS || !g_ptys[pty_id].used) return;

    /*
     * Linux gives a session leader without a controlling terminal a ctty when
     * it opens a terminal device and did not request O_NOCTTY.  Pseudo-terminal
     * users such as xterm/openpty rely on this after setsid(): later /dev/tty
     * opens must resolve to this slave, not fail with ENXIO.  Keep this generic
     * in the tty layer; do not key it to a specific rootfs, package, or app.
     */
    cur = process_current_task();
    if (!cur ||
        cur->sid != cur->pid ||
        cur->ctty_kind != PROCESS_CTTY_NONE ||
        (flags & LINUX_O_NOCTTY) != 0) {
        return;
    }

    tty_session_caller_from_task(cur, 0, &caller);
    if (edge_linux_tty_session_acquire_on_open(
            &g_ptys[pty_id].session, &caller,
            (flags & LINUX_O_NOCTTY) != 0)) {
        cur->ctty_kind = PROCESS_CTTY_PTY;
        cur->ctty_id = pty_id;
    }
}

static int pty_ring_push(uint8_t *buf, uint32_t *wpos, uint32_t *count, uint8_t c) {
    if (!buf || !wpos || !count) return -1;
    if (*count >= EDGE_PTY_BUF_SIZE) return -1;
    buf[*wpos] = c;
    *wpos = (*wpos + 1) % EDGE_PTY_BUF_SIZE;
    (*count)++;
    return 0;
}

static void pty_console_redirect_write(void *context, char byte) {
    edge_pty_t *pty = (edge_pty_t *)context;

    if (!pty || pty < g_ptys || pty >= g_ptys + EDGE_MAX_PTYS ||
        !pty->used || pty->refs_master <= 0)
        return;
    if (byte == '\n' &&
        (pty->termios.c_oflag & (LINUX_OPOST | LINUX_ONLCR)) ==
            (LINUX_OPOST | LINUX_ONLCR))
        (void)pty_ring_push(pty->s2m_buf, &pty->s2m_wpos,
                            &pty->s2m_count, '\r');
    (void)pty_ring_push(pty->s2m_buf, &pty->s2m_wpos,
                        &pty->s2m_count, (uint8_t)byte);
}

static void pty_echo_to_master(edge_pty_t *pty, uint8_t c) {
    if (!pty) return;
    (void)pty_ring_push(pty->s2m_buf, &pty->s2m_wpos, &pty->s2m_count, c);
}

static void pty_echo_seq_to_master(edge_pty_t *pty, const char *s, int n) {
    if (!pty || !s || n <= 0) return;
    for (int i = 0; i < n; ++i) {
        if (pty_ring_push(pty->s2m_buf, &pty->s2m_wpos, &pty->s2m_count, (uint8_t)s[i]) < 0) break;
    }
}

static int pty_slave_input_have_canonical_line(const edge_pty_t *pty) {
    if (!pty) return 0;
    return kernel_pty_canonical_input_ready(
        pty->m2s_buf, pty->m2s_rpos, pty->m2s_count,
        EDGE_PTY_BUF_SIZE, pty->termios.c_cc[LINUX_VEOF]);
}

static uint64_t pty_slave_read_limit(const edge_pty_t *pty, uint64_t req, uint64_t avail) {
    uint32_t cnt, pos;
    uint8_t eofc;
    uint64_t n = 0;
    if (!pty) return 0;
    if ((pty->termios.c_lflag & LINUX_ICANON) == 0) {
        if (req > avail) req = avail;
        return req;
    }
    cnt = pty->m2s_count;
    pos = pty->m2s_rpos;
    eofc = pty->termios.c_cc[LINUX_VEOF];
    if (req > avail) req = avail;
    while (cnt > 0 && n < req) {
        uint8_t c = pty->m2s_buf[pos];
        n++;
        pos = (pos + 1) % EDGE_PTY_BUF_SIZE;
        cnt--;
        if (c == '\n' || c == eofc) break;
    }
    return n;
}

static void pty_drop_ref(int pty_id, int is_master) {
    edge_pty_t *pty;
    if (pty_id < 0 || pty_id >= EDGE_MAX_PTYS) return;
    pty = &g_ptys[pty_id];
    if (!pty->used) return;
    if (is_master) {
        if (pty->refs_master > 0) pty->refs_master--;
    } else {
        if (pty->refs_slave > 0) pty->refs_slave--;
    }
    if (pty->refs_master <= 0 && pty->refs_slave <= 0) {
        edge_linux_tty_console_redirect_release(pty);
        devpts_slave_destroy(&pty->slave_inode);
        memset(pty, 0, sizeof(*pty));
    }
}

static void pty_console_redirect_release_reference(void *context) {
    edge_pty_t *pty = (edge_pty_t *)context;

    if (!pty || pty < g_ptys || pty >= g_ptys + EDGE_MAX_PTYS) return;
    pty_drop_ref((int)(pty - g_ptys), 0);
}

static int fd_is_tty(const edge_fd_t *e) {
    if (!e) return 0;
    if (e->kind == FD_CONSOLE) return 1;
    if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) return 1;
    if (e->kind == FD_VFS && path_is_tty_device(e->path)) return 1;
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if (e->kind == FD_VFS &&
        (e->inode.mode & 0xf000u) == VFS_INODE_CHR &&
        bsd_bridge_cdev_is_tty(e->inode.rdev))
        return 1;
#endif
    return 0;
}

static int tty_ioctl_cmd_is_traced(uint32_t cmd) {
    return (cmd == LINUX_TCGETS ||
            cmd == LINUX_TCSETS || cmd == LINUX_TCSETSW || cmd == LINUX_TCSETSF ||
            cmd == LINUX_TIOCGPGRP || cmd == LINUX_TIOCSPGRP);
}

static int tty_ioctl_cmd_requires_tty(uint32_t cmd) {
    return (cmd == LINUX_TCGETS ||
            cmd == LINUX_TCSETS || cmd == LINUX_TCSETSW || cmd == LINUX_TCSETSF ||
            cmd == LINUX_TCSBRK || cmd == LINUX_TCXONC || cmd == LINUX_TCFLSH || cmd == LINUX_TCSBRKP ||
            cmd == LINUX_TIOCGPGRP || cmd == LINUX_TIOCSPGRP ||
            cmd == LINUX_TIOCGSID ||
            cmd == LINUX_TIOCGWINSZ || cmd == LINUX_TIOCSWINSZ ||
            cmd == LINUX_TIOCSCTTY || cmd == LINUX_TIOCNOTTY ||
            cmd == LINUX_VT_OPENQRY || cmd == LINUX_VT_GETMODE ||
            cmd == LINUX_VT_SETMODE || cmd == LINUX_VT_GETSTATE ||
            cmd == LINUX_VT_RELDISP || cmd == LINUX_VT_ACTIVATE ||
            cmd == LINUX_VT_WAITACTIVE || cmd == LINUX_KDSETMODE ||
            cmd == LINUX_KDGETMODE || cmd == LINUX_KDGKBMODE ||
            cmd == LINUX_KDSKBMODE || cmd == LINUX_KDMKTONE ||
            cmd == LINUX_GIO_FONT || cmd == LINUX_PIO_FONT ||
            cmd == LINUX_GIO_FONTX || cmd == LINUX_PIO_FONTX ||
            cmd == LINUX_PIO_FONTRESET || cmd == LINUX_KDFONTOP);
}

static const char *tty_ioctl_cmd_name(uint32_t cmd) {
    switch (cmd) {
        case LINUX_TCGETS: return "TCGETS";
        case LINUX_TCSETS: return "TCSETS";
        case LINUX_TCSETSW: return "TCSETSW";
        case LINUX_TCSETSF: return "TCSETSF";
        case LINUX_TCSBRK: return "TCSBRK";
        case LINUX_TCXONC: return "TCXONC";
        case LINUX_TCFLSH: return "TCFLSH";
        case LINUX_TCSBRKP: return "TCSBRKP";
        case LINUX_TIOCGPGRP: return "TIOCGPGRP";
        case LINUX_TIOCSPGRP: return "TIOCSPGRP";
        case LINUX_KDFONTOP: return "KDFONTOP";
        case LINUX_PIO_FONT: return "PIO_FONT";
        case LINUX_GIO_FONT: return "GIO_FONT";
        case LINUX_PIO_FONTX: return "PIO_FONTX";
        case LINUX_GIO_FONTX: return "GIO_FONTX";
        case LINUX_PIO_FONTRESET: return "PIO_FONTRESET";
        default: return "OTHER";
    }
}

static void tty_log_ioctl_once(task_t *cur, int fd, uint32_t cmd, const edge_fd_t *e, const char *result) {
#if EDGE_TTY_DEBUG
    int pid = cur ? cur->pid : process_getpid();
    const char *name = (cur && cur->name[0]) ? cur->name : "?";
    if (pid <= 0 || !result) return;
    if (tty_seen_pid(g_tty_ioctl_log_pids, &g_tty_ioctl_log_count, pid)) return;
    printf("[tty][ioctl] pid=%d task=%s cmd=%s fd=%d ftype=%s path=%s res=%s\n",
           pid,
           name,
           tty_ioctl_cmd_name(cmd),
           fd,
           e ? fd_kind_name(e->kind) : "none",
           (e && e->path[0]) ? e->path : "-",
           result);
#else
    (void)cur; (void)fd; (void)cmd; (void)e; (void)result;
#endif
}

static int fd_trace_interesting(const edge_fd_t *e, int fd) {
    if (fd >= 0 && fd <= 2) return 1;
    if (!e) return 0;
    if (e->kind == FD_CONSOLE) return 1;
    if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) return 1;
    if (e->kind == FD_VFS && path_is_tty_device(e->path)) return 1;
    return 0;
}

static void fd_log_lifecycle(const char *ev, int pid, int fd, const edge_fd_t *e, int extra) {
#if EDGE_TTY_DEBUG
    if (!ev || !e) return;
    if (!fd_trace_interesting(e, fd)) return;
    printf("[fd] %s pid=%d fd=%d ftype=%s path=%s extra=%d\n",
           ev, pid, fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-", extra);
#else
    (void)ev; (void)pid; (void)fd; (void)e; (void)extra;
#endif
}

static void fd_debug_slot_once(const char *tag, int pid, int fd, const edge_fd_t *e) {
#if EDGE_FD_FORK_DEBUG
    if (!tag || fd < 0) return;
    if (!e || !e->used) {
        printf("[fd][forkdbg] %s pid=%d fd=%d used=0\n", tag, pid, fd);
        return;
    }
    printf("[fd][forkdbg] %s pid=%d fd=%d used=1 kind=%s ref=%d path=%s\n",
           tag, pid, fd, fd_kind_name(e->kind), e->file_ref, e->path[0] ? e->path : "-");
#else
    (void)tag; (void)pid; (void)fd; (void)e;
#endif
}

static int tty_pgrp_alive(int pgid) {
    if (pgid <= 0) return 0;
    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        const task_t *t = process_task_by_index(i);
        if (!t || t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) continue;
        if (t->pgid == pgid) return 1;
    }
    return 0;
}

static void tty_log_read_once(task_t *cur, int fg_pgrp) {
#if EDGE_TTY_DEBUG
    if (!cur) return;
    if (tty_seen_pid(g_tty_read_log_pids, &g_tty_read_log_count, cur->pid)) return;
    printf("[tty] read pid=%d pgid=%d sid=%d fg_pgrp=%d st=%d onrq=%d\n",
           cur->pid, cur->pgid, cur->sid, fg_pgrp, (int)cur->state, (int)cur->on_runqueue);
#else
    (void)cur; (void)fg_pgrp;
#endif
}

static void tty_log_fg_fix_once(task_t *cur, int old_fg, int new_fg, const char *why) {
#if EDGE_TTY_DEBUG
    if (!cur || !why) return;
    if (tty_seen_pid(g_tty_fg_fix_log_pids, &g_tty_fg_fix_log_count, cur->pid)) return;
    printf("[tty] fg-fix pid=%d pgid=%d sid=%d fg:%d->%d reason=%s (SIGTTIN bypass compat)\n",
           cur->pid, cur->pgid, cur->sid, old_fg, new_fg, why);
#else
    (void)cur; (void)old_fg; (void)new_fg; (void)why;
#endif
}

static uint64_t tty_interrupt_current_ret(void) {
    /* Emulate EINTR delivery point; caller decides process behavior. */
    return (uint64_t)-EINTR;
}

static int signal_pending_restartable_syscall(void) {
    task_t *t = process_current_task();
    uint64_t available;
    if (!t) return 0;
    available = task_pending_signal_mask(t) &
        (~t->sigmask | EDGE_LINUX_SIGNAL_UNBLOCKABLE_MASK);
    for (uint32_t signal = 1; signal <= EDGE_LINUX_SIGNAL_MAX; ++signal) {
        edge_linux_signal_action_t *action;
        edge_linux_signal_default_disposition_t disposition;
        if (!(available & edge_linux_signal_mask_bit(signal))) continue;
        action = task_signal_action_local(t, signal);
        if (!action || action->handler == LINUX_SIG_IGN) continue;
        disposition = edge_linux_signal_default_disposition(signal);
        if (action->handler == LINUX_SIG_DFL) {
            if (disposition == EDGE_LINUX_SIGNAL_DEFAULT_IGNORE ||
                disposition == EDGE_LINUX_SIGNAL_DEFAULT_CONTINUE)
                continue;
            return 0;
        }
        return (action->flags & EDGE_LINUX_SA_RESTART) != 0;
    }
    return 0;
}

static int signal_pending_interrupt(void) {
    for (;;) {
        task_t *t = process_current_task();
        uint64_t available;
        int handled_stop = 0;
        task_timer_poll();
        if (!t) return 0;
        if (process_task_group_exit_requested(t, 0)) return 1;
        available = task_pending_signal_mask(t) &
            (~t->sigmask | EDGE_LINUX_SIGNAL_UNBLOCKABLE_MASK);
        for (uint32_t signal = 1; signal <= EDGE_LINUX_SIGNAL_MAX;
             ++signal) {
            edge_linux_signal_action_t *action;
            edge_linux_signal_default_disposition_t disposition;
            if (!(available & edge_linux_signal_mask_bit(signal))) continue;
            action = task_signal_action_local(t, signal);
            if (!action || action->handler == LINUX_SIG_IGN) continue;
            disposition = edge_linux_signal_default_disposition(signal);
            if (action->handler == LINUX_SIG_DFL &&
                (disposition == EDGE_LINUX_SIGNAL_DEFAULT_IGNORE ||
                 disposition == EDGE_LINUX_SIGNAL_DEFAULT_CONTINUE))
                continue;
            if (action->handler == LINUX_SIG_DFL &&
                disposition == EDGE_LINUX_SIGNAL_DEFAULT_STOP) {
                /*
                 * A default job-control stop does not make a Linux blocking
                 * syscall return EINTR after SIGCONT.  Consume the pending
                 * signal, stop the group at this safe kernel wait point, and
                 * resume the original wait with its existing deadline.
                 * Catchable stop signals still interrupt normally below.
                 */
                kernel_signal_runtime_state_t signal_state;
                if (task_signal_runtime_state(t, &signal_state) == 0)
                    (void)kernel_signal_pending_consume(
                        &signal_state, signal, 0, 0);
                process_stop_current_group((int)signal);
                scheduler_yield();
                handled_stop = 1;
                break;
            }
            return 1;
        }
        if (!handled_stop) return 0;
    }
}

static uint32_t task_pending_signal_bits(const task_t *t) {
    uint64_t pending = task_pending_signal_mask(t);
    return (uint32_t)pending | ((pending >> 32) ? UINT32_C(0x80000000) : 0u);
}
