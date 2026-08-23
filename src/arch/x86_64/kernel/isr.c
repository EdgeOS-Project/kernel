#include "arch/x86_64/isr.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/pic.h"
#include "arch/x86_64/page_table.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/syscall.h"
#include "arch/x86_64/user_layout.h"
#include "console.h"
#include "dev/fbdev.h"
#include "fb.h"
#include "serial_console.h"
#include "sys/process.h"
#include "sys/boottime.h"
#include "sys/scheduler.h"
#include "sys/syscall.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_ptrace.h"
#include "kernel/smp.h"
#include "kernel/process_runtime.h"
#include "kernel/mm_runtime.h"
#include "kernel/userfaultfd.h"
#include "fs/cgroupfs.h"
#include "mm/statistics.h"
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/cpu.h"
#endif
#ifdef CONFIG_APIC
#include "drivers/apic.h"
#endif
#include "string.h"
#include <stdint.h>

#define MAX_HANDLERS_PER_VECTOR 8
#define MAX_CONTEXT_HANDLERS_PER_VECTOR 8

static ISR g_interrupt_handlers[NO_INTERRUPT_HANDLERS][MAX_HANDLERS_PER_VECTOR];
static uint8_t g_interrupt_handler_count[NO_INTERRUPT_HANDLERS];
typedef struct {
    ISR_CONTEXT handler;
    void *context;
    volatile uint32_t active;
    volatile uint8_t state;
    uint16_t vector;
} isr_context_handler_t;
static isr_context_handler_t
    g_context_handlers[NO_INTERRUPT_HANDLERS][MAX_CONTEXT_HANDLERS_PER_VECTOR];
static uint32_t g_user_exception_log_budget = 32;
static uint32_t g_kernel_nontext_exception_budget = 8;
#ifndef EDGE_IRQ_PREEMPT_TRACE
#define EDGE_IRQ_PREEMPT_TRACE 0
#endif
static uint32_t g_user_timer_seen_log_budget = EDGE_IRQ_PREEMPT_TRACE ? 256 : 0;
static uint32_t g_user_timer_preempt_log_budget = EDGE_IRQ_PREEMPT_TRACE ? 256 : 0;

static int isr_preempt_trace_task(const task_t *task) {
    static const char chromium[] = "chromium";

    if (!task) return 0;
    for (uint32_t index = 0; index < sizeof(chromium) - 1u; ++index)
        if (task->name[index] != chromium[index]) return 0;
    return 1;
}

static int user_span_ok(uint64_t addr, uint64_t len);
static uint64 read_cr3(void);
static uint64 read_cr2(void);
static void dump_nearby_vmas(const char *tag, uint64_t addr);

static void dump_chromium_shared_metadata(void) {
    task_t *task = process_current_task();
    task_t *memory = task ? process_vm_task(task) : 0;
    uint32_t words[24];
    int dumped = 0;
    int live;

    if (!task || !memory) return;
    live = memory->user_vma_count;
    if ((uint32_t)live > memory->user_vma_capacity)
        live = (int)memory->user_vma_capacity;
    for (int index = 0; index < live && dumped < 8; ++index) {
        const edge_user_vma_t *mapping = &memory->user_vmas[index];
        const char *path;
        uint64_t bytes;

        if (!mapping->file_backed || mapping->end <= mapping->start)
            continue;
        path = process_user_mmap_file_path_for_slot(mapping->file_slot);
        if (!path || !strstr(path, ".org.chromium.Chromium.")) continue;
        bytes = mapping->end - mapping->start;
        if (bytes > sizeof(words)) bytes = sizeof(words);
        memset(words, 0, sizeof(words));
        if (process_read_user_memory(task->pid, mapping->start,
                                     words, bytes) < 0)
            continue;
        printf("[chromium-shm] pid=%d map=0x%x-0x%x prot=0x%x flags=0x%x slot=%u off=0x%x path=%s\n",
               task->pid, (uint32_t)mapping->start,
               (uint32_t)mapping->end, mapping->prot, mapping->flags,
               (uint32_t)mapping->file_slot,
               (uint32_t)mapping->file_off, path);
        printf("[chromium-shm] words=%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
               words[0], words[1], words[2], words[3], words[4], words[5],
               words[6], words[7], words[8], words[9], words[10], words[11],
               words[12], words[13], words[14], words[15], words[16],
               words[17], words[18], words[19], words[20], words[21],
               words[22], words[23]);
        process_user_mmap_debug_dump_addr(
            "CHROMIUM-SHM-PAGE", task, mapping->start);
        if (words[10] >= 64u && words[10] < bytes)
            process_user_mmap_debug_dump_addr(
                "CHROMIUM-SHM-FREE", task,
                mapping->start + words[10]);
        ++dumped;
    }
}

static void emergency_serial_puts(const char *s) {
    if (!s) return;
    while (*s) serial_console_write_emergency(*s++);
}

static void emergency_serial_hex64(uint64_t v) {
    static const char hex[] = "0123456789abcdef";
    int started = 0;
    emergency_serial_puts("0x");
    for (int i = 15; i >= 0; --i) {
        uint8_t n = (uint8_t)((v >> ((uint32_t)i * 4u)) & 0xFULL);
        if (n || started || i == 0) {
            serial_console_write_emergency(hex[n]);
            started = 1;
        }
    }
}

static void emergency_serial_exception(const char *tag, const REGISTERS *r, uint64_t cr2) {
    emergency_serial_puts("[early-exc] ");
    emergency_serial_puts(tag ? tag : "?");
    emergency_serial_puts(" int=");
    emergency_serial_hex64(r ? r->int_no : 0);
    emergency_serial_puts(" err=");
    emergency_serial_hex64(r ? r->err_code : 0);
    emergency_serial_puts(" rip=");
    emergency_serial_hex64(r ? r->rip : 0);
    emergency_serial_puts(" cr2=");
    emergency_serial_hex64(cr2);
    emergency_serial_puts(" cs=");
    emergency_serial_hex64(r ? r->cs : 0);
    emergency_serial_puts(" cr3=");
    emergency_serial_hex64(read_cr3());
    emergency_serial_puts("\n");
}

extern char _kernel_text_start;
extern char _kernel_text_end;
extern char _kernel_start;
extern char _kernel_end;

#define PTE_PRESENT 0x001ULL
#define PTE_WRITE   0x002ULL
#define PTE_USER    0x004ULL
#define PTE_PS      0x080ULL
#define USER_MIN_ADDR EDGE_USER_MIN_ADDR
#define USER_MAX_ADDR EDGE_USER_MAX_ADDR
#define USER_LOW_BASE_ISR X86_USER_LOW_BASE
#define USER_LOW_LIMIT_ISR X86_USER_LOW_LIMIT
#define USER_LOW_SIZE_ISR X86_USER_LOW_SIZE
#define USER_TEXT_BASE_ISR X86_USER_INTERP_BASE
#define USER_TEXT_SIZE_ISR X86_USER_FIXED_WINDOW_SIZE
#define USER_STACK_BASE_ISR X86_USER_STACK_BASE
#define USER_STACK_SIZE_ISR X86_USER_FIXED_WINDOW_SIZE
#define USER_HEAP_BASE_ISR X86_USER_HEAP_BASE
#define USER_HEAP_MAX_ISR USER_HEAP_MAX_DELTA
#define USER_HEAP_EXTRA_ISR USER_HEAP_PY_EXTRA_DELTA
#define USER_BIGPIE_BASE_ISR X86_USER_BIGPIE_BASE
#define USER_BIGPIE_SIZE_ISR X86_USER_BIGPIE_SIZE

char *exception_messages[32] = {
    "Division By Zero", "Debug", "Non Maskable Interrupt", "Breakpoint", "Overflow",
    "BOUND Range Exceeded", "Invalid Opcode", "Device Not Available (No Math Coprocessor)",
    "Double Fault", "Coprocessor Segment Overrun", "Invalid TSS", "Segment Not Present",
    "Stack-Segment Fault", "General Protection", "Page Fault", "Unknown Interrupt (intel reserved)",
    "x87 FPU Floating-Point Error (Math Fault)", "Alignment Check", "Machine Check",
    "SIMD Floating-Point Exception", "Virtualization Exception", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved"
};

/*
 * Synchronous user exceptions are thread-directed Linux signals.  Queueing
 * them through the normal signal path preserves catchable SIGILL/SIGFPE/
 * SIGSEGV behavior and lets a default-fatal disposition terminate the entire
 * thread group.  Killing only the faulting pthread leaves a multithreaded
 * process half alive, so its parent can wait forever after an intentional
 * abort such as Chromium's UD2 crash path.
 */
static void deliver_user_exception_signal(REGISTERS *reg, uint32_t signal,
                                          int32_t code,
                                          uint64_t fault_address) {
    struct edge_linux_siginfo information;

    if (!reg) return;
    memset(&information, 0, sizeof(information));
    information.signal_number = (int32_t)signal;
    information.code = code;
    memcpy(information.payload, &fault_address, sizeof(fault_address));
    if (process_send_signal_info(process_getpid(), (int)signal,
                                 &information) < 0) {
        scheduler_kill_current_group_and_yield(128 + (int)signal);
        return;
    }
    (void)edgeos_x86_64_deliver_signal_on_user_return(reg);
}

void isr_register_interrupt_handler(int num, ISR handler) {
    if (num < 0 || num >= NO_INTERRUPT_HANDLERS || !handler) return;
    for (uint8_t i = 0; i < g_interrupt_handler_count[num]; ++i) {
        if (g_interrupt_handlers[num][i] == handler) return;
    }
    if (g_interrupt_handler_count[num] >= MAX_HANDLERS_PER_VECTOR) return;
    g_interrupt_handlers[num][g_interrupt_handler_count[num]++] = handler;
}

static uint64_t isr_disable_interrupts(void) {
    uint64_t flags;

    __asm__ __volatile__("pushfq\n\tpopq %0\n\tcli" : "=r"(flags) :: "memory");
    return flags;
}

static void isr_restore_interrupts(uint64_t flags) {
    if (flags & (1ULL << 9))
        __asm__ __volatile__("sti" ::: "memory");
}

int isr_register_context_interrupt_handler(int num, ISR_CONTEXT handler,
                                           void *context, void **cookie) {
    uint64_t flags;

    if (num < 0 || num >= NO_INTERRUPT_HANDLERS || !handler || !cookie)
        return -1;
    flags = isr_disable_interrupts();
    for (uint8_t index = 0; index < MAX_CONTEXT_HANDLERS_PER_VECTOR;
         ++index) {
        isr_context_handler_t *entry = &g_context_handlers[num][index];
        uint8_t expected = 0;

        if (!__atomic_compare_exchange_n(&entry->state, &expected, 3,
            0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        entry->context = context;
        entry->vector = (uint16_t)num;
        __atomic_store_n(&entry->handler, handler, __ATOMIC_RELEASE);
        __atomic_store_n(&entry->state, 1, __ATOMIC_RELEASE);
        *cookie = entry;
        isr_restore_interrupts(flags);
        return 0;
    }
    isr_restore_interrupts(flags);
    return -1;
}

int isr_unregister_context_interrupt_handler(void *opaque_cookie) {
    isr_context_handler_t *cookie = opaque_cookie;
    uintptr_t first = (uintptr_t)&g_context_handlers[0][0];
    uintptr_t end = first + sizeof(g_context_handlers);
    uint64_t flags;
    uint8_t expected = 1;

    if (!cookie || (uintptr_t)cookie < first ||
        (uintptr_t)cookie >= end ||
        ((uintptr_t)cookie - first) % sizeof(*cookie) != 0)
        return -1;
    flags = isr_disable_interrupts();
    if (!__atomic_compare_exchange_n(&cookie->state, &expected, 2,
        0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        isr_restore_interrupts(flags);
        return -1;
    }
    __atomic_store_n(&cookie->handler, 0, __ATOMIC_RELEASE);
    isr_restore_interrupts(flags);
    while (__atomic_load_n(&cookie->active, __ATOMIC_ACQUIRE) != 0)
        __asm__ __volatile__("pause");
    cookie->context = 0;
    cookie->vector = 0;
    __atomic_store_n(&cookie->state, 0, __ATOMIC_RELEASE);
    return 0;
}

static void isr_dispatch_context_handlers(uint32_t vector) {
    if (vector >= NO_INTERRUPT_HANDLERS)
        return;
    for (uint8_t index = 0; index < MAX_CONTEXT_HANDLERS_PER_VECTOR;
         ++index) {
        isr_context_handler_t *entry = &g_context_handlers[vector][index];
        ISR_CONTEXT handler;

        __atomic_add_fetch(&entry->active, 1, __ATOMIC_ACQ_REL);
        handler = __atomic_load_n(&entry->state, __ATOMIC_ACQUIRE) == 1 ?
            __atomic_load_n(&entry->handler, __ATOMIC_ACQUIRE) : 0;
        if (handler) {
            handler(entry->context);
        }
        __atomic_sub_fetch(&entry->active, 1, __ATOMIC_ACQ_REL);
    }
}

int isr_interrupt_has_handler(int num) {
    if (num < 0 || num >= NO_INTERRUPT_HANDLERS) return 0;
    if (g_interrupt_handler_count[num] > 0)
        return 1;
    for (uint8_t index = 0; index < MAX_CONTEXT_HANDLERS_PER_VECTOR;
         ++index) {
        if (__atomic_load_n(&g_context_handlers[num][index].state,
                            __ATOMIC_ACQUIRE) == 1)
            return 1;
    }
    return 0;
}

void isr_end_interrupt(int num) {
#ifdef CONFIG_APIC
    apic_eoi();
#endif
    pic8259_eoi(num);
}

void isr_irq_handler(REGISTERS *reg) {
    if (reg && reg->int_no == APIC_TLB_VECTOR)
        edge_smp_handle_call(x86_smp_current_cpu_id());
    if (reg->int_no < NO_INTERRUPT_HANDLERS) {
        for (uint8_t i = 0; i < g_interrupt_handler_count[reg->int_no]; ++i) {
            ISR handler = g_interrupt_handlers[reg->int_no][i];
            if (handler) handler(reg);
        }
        isr_dispatch_context_handlers((uint32_t)reg->int_no);
    }
#ifdef CONFIG_APIC
    apic_eoi();
#endif
    pic8259_eoi((int)reg->int_no);
    /*
     * Timer IRQ preemption is intentionally narrow.  EdgeOS cannot schedule
     * away from arbitrary kernel IRQ frames yet: the interrupted task's kernel
     * stack owns the live interrupt frame, and earlier broad IRQ scheduling
     * corrupted continuations under daemon/package-manager pressure.  However,
     * user-mode timer frames are the Linux preemption point that GUI workloads
     * require.  Xorg/XFCE can spend long stretches in userspace between
     * syscalls; merely setting need_resched then waiting for the next syscall
     * can stretch a shell `sleep 2` into minutes and makes input feel frozen.
     *
     * Restrict this to IRQ0 and a ring-3 interrupted frame.  The ring check is
     * the authoritative safety gate here: if the timer interrupted user mode,
     * the live frame belongs to user execution even if task bookkeeping still
     * has in_syscall set from an emulated-syscall edge.  Do not key this off
     * stale in_syscall state, or one hot task can suppress preemption for an
     * entire X11 desktop and stretch normal sleeps/input dispatch into minutes.
     *
     * Do not broaden this to device IRQs or kernel-mode frames until EdgeOS has
     * dedicated interrupt stacks and the scheduler return-frame ownership model
     * has been audited.
     */
    if (reg && (reg->int_no == IRQ_BASE ||
                reg->int_no == APIC_TIMER_VECTOR ||
                reg->int_no == APIC_RESCHEDULE_VECTOR) &&
        (reg->cs & 0x3) == 0x3) {
        task_t *t = process_current_task();
        if (t && !t->is_idle && isr_preempt_trace_task(t) &&
            g_user_timer_seen_log_budget > 0) {
            --g_user_timer_seen_log_budget;
            printf("[irq-user] cpu=%u pid=%d cmd=%s rip=0x%x flags=0x%x need=%u in_sys=%u budget=%u\n",
                   x86_smp_current_cpu_id(),
                   t->pid, t->name, (uint32_t)reg->rip, (uint32_t)reg->rflags,
                   (unsigned)t->need_resched, (unsigned)t->in_syscall,
                   g_user_timer_seen_log_budget);
        }
        if (t && !t->is_idle && t->need_resched) {
            uint64_t pending = 0;
            int signal_work =
                kernel_current_signal_pending(&pending) == 0 && pending;
            int slice_status = signal_work ?
                (t->linux_thread.rseq.slice_granted ?
                    kernel_current_rseq_slice_interrupt(UINT64_MAX) : 0) :
                kernel_current_rseq_slice_interrupt(
                    boottime_monotonic_us());

            if (slice_status > 0) {
                t->need_resched = 0;
            } else {
                if (slice_status < 0)
                    (void)process_send_signal(t->pid, EDGE_LINUX_SIGSEGV);
                if (isr_preempt_trace_task(t) &&
                    g_user_timer_preempt_log_budget > 0) {
                    --g_user_timer_preempt_log_budget;
                    printf("[irq-preempt] cpu=%u pid=%d cmd=%s rip=0x%x in_sys=%u budget=%u\n",
                           x86_smp_current_cpu_id(),
                           t->pid, t->name, (uint32_t)reg->rip,
                           (unsigned)t->in_syscall,
                           g_user_timer_preempt_log_budget);
                }
                scheduler_yield_from_irq();
                /*
                 * The IRQ continuation resumes on the interrupted task's
                 * original kernel stack and still owns its userspace frame.
                 * Apply Linux rseq abort semantics before iret returns to the
                 * critical section.
                 */
                syscall_rseq_prepare_user_return(&reg->rip);
            }
        }
    }
    /*
     * Linux performs signal notify-resume work on every return to user mode,
     * not only after a syscall.  Without this hook, a CPU-bound task never
     * observes SIGKILL or a caught signal because its timer IRQ returns
     * directly through iretq.  Scheduling above eventually resumes on the
     * interrupted task's original kernel stack, so its live frame is again
     * current and can safely be rewritten for signal entry here.
     */
    if (reg && (reg->cs & 0x3) == 0x3) {
        uint64_t pending = 0;
        if (kernel_current_signal_pending(&pending) == 0 && pending)
            (void)edgeos_x86_64_deliver_signal_on_user_return(reg);
    }
}

static void print_registers(REGISTERS *reg) {
    printf("REGISTERS:\n");
    printf("err_code=%x\n", (uint32)reg->err_code);
    printf("rax=0x%x rbx=0x%x rcx=0x%x rdx=0x%x\n", (uint32)reg->rax, (uint32)reg->rbx, (uint32)reg->rcx, (uint32)reg->rdx);
    printf("rdi=0x%x rsi=0x%x rbp=0x%x rsp=0x%x\n", (uint32)reg->rdi, (uint32)reg->rsi, (uint32)reg->rbp, (uint32)reg->rsp);
    printf("r8=0x%x r9=0x%x r10=0x%x r11=0x%x\n", (uint32)reg->r8, (uint32)reg->r9, (uint32)reg->r10, (uint32)reg->r11);
    printf("r12=0x%x r13=0x%x r14=0x%x r15=0x%x\n", (uint32)reg->r12, (uint32)reg->r13, (uint32)reg->r14, (uint32)reg->r15);
    printf("rip=0x%x cs=0x%x ss=0x%x rflags=0x%x\n", (uint32)reg->rip, (uint32)reg->cs, (uint32)reg->ss, (uint32)reg->rflags);
}

static void print_task_context_brief(void) {
    task_t *t = process_current_task();
    if (!t) return;
    printf("TASK: pid=%d ppid=%d name=%s pgid=%d sid=%d ctty=%d ctty_id=%d\n",
           t->pid, t->ppid, t->name, t->pgid, t->sid, t->ctty_kind, t->ctty_id);
}

static int log_user_exception_brief(REGISTERS *reg) {
    task_t *t = process_current_task();
    uint8_t op[8] = {0};
    if (!reg || g_user_exception_log_budget == 0) return 0;
    g_user_exception_log_budget--;
    if (user_span_ok(reg->rip, sizeof(op))) {
        memcpy(op, (const void *)(uintptr_t)reg->rip, sizeof(op));
    }
    printf("[exception] user int=%u pid=%d name=%s rip=0x%x rsp=0x%x rflags=0x%x bytes=%x %x %x %x %x %x %x %x budget=%u\n",
           (uint32_t)reg->int_no,
           t ? t->pid : 0,
           t ? t->name : "(none)",
           (uint32_t)reg->rip,
           (uint32_t)reg->rsp,
           (uint32_t)reg->rflags,
           op[0], op[1], op[2], op[3], op[4], op[5], op[6], op[7],
           g_user_exception_log_budget);
    return 1;
}

static void log_user_exception_task_detail(void) {
    task_t *t = process_current_task();
    const task_t *leader;
    const edge_linux_signal_action_t *rtmin;
    const edge_linux_signal_action_t *chld;
    const edge_linux_signal_action_t *alrm;
    const edge_linux_signal_action_t *io;
    uint64_t pending;
    if (!t) return;
    leader = process_get_task(t->tgid > 0 ? t->tgid : t->pid);
    pending = t->signal_pending |
              (leader ? leader->signal_shared_pending : 0u);
    rtmin = &t->signal_actions[EDGE_LINUX_SIGRTMIN_KERNEL + 1u];
    chld = &t->signal_actions[EDGE_LINUX_SIGCHLD - 1u];
    alrm = &t->signal_actions[EDGE_LINUX_SIGALRM - 1u];
    io = &t->signal_actions[EDGE_LINUX_SIGIO - 1u];
    printf("[exception-task] pid=%d tgid=%d name=%s fs=0x%x sigmask=0x%x rt_handler=0x%x rt_flags=0x%x rt_restorer=0x%x rt_pending=%u clear_tid=0x%x fdwait=%u in_sys=%u\n",
           t->pid, t->tgid, t->name, (uint32_t)t->fs_base,
           (uint32_t)t->sigmask, (uint32_t)rtmin->handler,
           (uint32_t)rtmin->flags, (uint32_t)rtmin->restorer,
           (unsigned)((pending & edge_linux_signal_mask_bit(
                           EDGE_LINUX_SIGRTMIN_KERNEL + 2u)) != 0),
           (uint32_t)t->linux_thread.clear_child_tid,
           (unsigned)t->fd_wait_active, (unsigned)t->in_syscall);
    printf("[exception-signal] chld handler=0x%x flags=0x%x restorer=0x%x pending=%u mask=0x%x alrm handler=0x%x flags=0x%x restorer=0x%x pending=%u io handler=0x%x flags=0x%x restorer=0x%x pending=%u active_frame=0x%x active_rsp=0x%x\n",
           (uint32_t)chld->handler, (uint32_t)chld->flags,
           (uint32_t)chld->restorer,
           (unsigned)((pending & edge_linux_signal_mask_bit(
                           EDGE_LINUX_SIGCHLD)) != 0),
           (uint32_t)chld->mask,
           (uint32_t)alrm->handler, (uint32_t)alrm->flags,
           (uint32_t)alrm->restorer,
           (unsigned)((pending & edge_linux_signal_mask_bit(
                           EDGE_LINUX_SIGALRM)) != 0),
           (uint32_t)io->handler, (uint32_t)io->flags,
           (uint32_t)io->restorer,
           (unsigned)((pending & edge_linux_signal_mask_bit(
                           EDGE_LINUX_SIGIO)) != 0),
           (uint32_t)t->active_signal_frame,
           (uint32_t)t->active_signal_restorer_rsp);
    for (int i = 0; i < TASK_SYSCALL_HISTORY; ++i) {
        uint32_t idx = (t->syscall_history_pos + i) % TASK_SYSCALL_HISTORY;
        if (!t->syscall_history_nr[idx] && !t->syscall_history_ret[idx]) continue;
        printf("[exception-task] hist nr=%llu ret=%lld a1=0x%x a2=0x%x a3=0x%x a4=0x%x a5=0x%x a6=0x%x\n",
               (unsigned long long)t->syscall_history_nr[idx],
               (long long)t->syscall_history_ret[idx],
               (uint32_t)t->syscall_history_arg1[idx],
               (uint32_t)t->syscall_history_arg2[idx],
               (uint32_t)t->syscall_history_arg3[idx],
               (uint32_t)t->syscall_history_arg4[idx],
               (uint32_t)t->syscall_history_arg5[idx],
               (uint32_t)t->syscall_history_arg6[idx]);
    }
}

static int kernel_text_addr(uint64_t rip) {
    uint64_t start = (uint64_t)(uintptr_t)&_kernel_text_start;
    uint64_t end = (uint64_t)(uintptr_t)&_kernel_text_end;
    return rip >= start && rip < end;
}

static int kill_current_for_kernel_nontext_exception(REGISTERS *reg) {
    task_t *t;
    if (!reg || (reg->cs & 0x3) != 0 || kernel_text_addr(reg->rip)) return 0;

    t = process_current_task();
    if (!t || t->is_idle) return 0;

    /*
     * A ring-0 fault with RIP in .data/.bss is never a valid kernel
     * instruction fault.  In practice this means a user task returned through a
     * corrupted kernel continuation.  Do not spin the whole VM forever; retire
     * the current task and keep the machine alive so the shell/service manager
     * can continue and the original corruption remains visible in dmesg.
     */
    if (g_kernel_nontext_exception_budget > 0) {
        g_kernel_nontext_exception_budget--;
        emergency_serial_puts("[kernel-nontext-emerg] int=");
        emergency_serial_hex64(reg->int_no);
        emergency_serial_puts(" pid=");
        emergency_serial_hex64((uint64_t)(uint32_t)t->pid);
        emergency_serial_puts(" name=");
        emergency_serial_puts(t->name[0] ? t->name : "?");
        emergency_serial_puts(" rip=");
        emergency_serial_hex64(reg->rip);
        emergency_serial_puts(" rsp=");
        emergency_serial_hex64(reg->rsp);
        emergency_serial_puts(" cs=");
        emergency_serial_hex64(reg->cs);
        emergency_serial_puts(" cr2=");
        emergency_serial_hex64(read_cr2());
        emergency_serial_puts(" budget=");
        emergency_serial_hex64(g_kernel_nontext_exception_budget);
        emergency_serial_puts("\n");
    }
    scheduler_abandon_current_and_yield(-(int)reg->int_no);
    return 1;
}

static void dump_vma_for_addr(const char *tag, uint64_t addr) {
    task_t *t = process_current_task();
    task_t *mm = process_vm_task(t);
    if (!mm) return;
    printf("%s ", tag);
    printf("addr=0x%x%08x ", (uint32)(addr >> 32), (uint32)addr);
    for (uint32_t i = 0; i < mm->user_vma_count &&
                             i < mm->user_vma_capacity; ++i) {
        edge_user_vma_t *v = &mm->user_vmas[i];
        if (v->end <= v->start) continue;
        if (addr < v->start || addr >= v->end) continue;
        printf("start=0x%x%08x end=0x%x%08x ",
               (uint32)(v->start >> 32), (uint32)v->start,
               (uint32)(v->end >> 32), (uint32)v->end);
        printf("prot=0x%x flags=0x%x", v->prot, v->flags);
        if (v->file_backed) {
            const char *path = process_user_mmap_file_path_for_slot(v->file_slot);
            printf(" file=%s off=0x%x slot=%u",
                   path && path[0] ? path : "?",
                   (uint32)v->file_off,
                   (uint32)v->file_slot);
        }
        printf("\n");
        return;
    }
    printf("no-vma\n");
}

static uint64_t vma_distance_to_addr(const edge_user_vma_t *v, uint64_t addr) {
    if (!v || v->end <= v->start) return ~0ULL;
    if (addr >= v->start && addr < v->end) return 0;
    if (addr < v->start) return v->start - addr;
    return addr - v->end;
}

static void dump_nearby_vmas(const char *tag, uint64_t addr) {
    task_t *t = process_current_task();
    task_t *mm = process_vm_task(t);
    uint64_t best_dist[6];
    int best_idx[6];
    if (!mm) return;
    for (int i = 0; i < 6; ++i) {
        best_dist[i] = ~0ULL;
        best_idx[i] = -1;
    }
    for (uint32_t i = 0; i < mm->user_vma_count &&
                             i < mm->user_vma_capacity; ++i) {
        edge_user_vma_t *v = &mm->user_vmas[i];
        uint64_t d;
        if (v->end <= v->start) continue;
        d = vma_distance_to_addr(v, addr);
        for (int j = 0; j < 6; ++j) {
            if (d >= best_dist[j]) continue;
            for (int k = 5; k > j; --k) {
                best_dist[k] = best_dist[k - 1];
                best_idx[k] = best_idx[k - 1];
            }
            best_dist[j] = d;
            best_idx[j] = i;
            break;
        }
    }
    for (int j = 0; j < 6; ++j) {
        edge_user_vma_t *v;
        const char *path = 0;
        if (best_idx[j] < 0) continue;
        v = &mm->user_vmas[best_idx[j]];
        if (v->file_backed) path = process_user_mmap_file_path_for_slot(v->file_slot);
        printf("%s near[%d] dist=0x%x%08x start=0x%x%08x end=0x%x%08x prot=0x%x flags=0x%x file=%s off=0x%x len=0x%x\n",
               tag ? tag : "VMA",
               j,
               (uint32_t)(best_dist[j] >> 32), (uint32_t)best_dist[j],
               (uint32_t)(v->start >> 32), (uint32_t)v->start,
               (uint32_t)(v->end >> 32), (uint32_t)v->end,
               v->prot, v->flags,
               path && path[0] ? path : "-",
               (uint32_t)v->file_off, (uint32_t)v->file_len);
    }
}

static int user_span_ok(uint64_t addr, uint64_t len) {
    uint64_t end;
    uint64_t kstart = (uint64_t)(uintptr_t)&_kernel_start;
    uint64_t kend = (uint64_t)(uintptr_t)&_kernel_end;
    if (addr < USER_MIN_ADDR) return 0;
    if (addr >= USER_MAX_ADDR) return 0;
    if (len > USER_MAX_ADDR) return 0;
    end = addr + len;
    if (end < addr) return 0;
    if (end > USER_MAX_ADDR) return 0;
    if (len && kstart < kend && addr < kend && end > kstart) {
        int fixed_user =
            (end <= USER_LOW_LIMIT_ISR) ||
            (addr >= USER_TEXT_BASE_ISR && end <= USER_TEXT_BASE_ISR + USER_TEXT_SIZE_ISR) ||
            (addr >= USER_STACK_BASE_ISR && end <= USER_STACK_BASE_ISR + USER_STACK_SIZE_ISR) ||
            (addr >= USER_HEAP_BASE_ISR && end <= USER_HEAP_BASE_ISR + USER_HEAP_MAX_ISR + USER_HEAP_EXTRA_ISR) ||
            (addr >= USER_BIGPIE_BASE_ISR && end <= USER_BIGPIE_BASE_ISR + USER_BIGPIE_SIZE_ISR);
        if (!fixed_user) return 0;
    }
    return 1;
}

static int user_page_present(uint64_t va) {
    uint64 cr3 = read_cr3() & ~0xFFFULL;
    uint64 *pml4 = x86_page_table_alias(cr3);
    if (!pml4) return 0;
    uint64 pml4e = pml4[(va >> 39) & 0x1FF];
    uint64 *pdpt;
    uint64 pdpte;
    uint64 *pd;
    uint64 pde;
    uint64 *pt;
    uint64 pte;
    if (!(pml4e & PTE_PRESENT) || !(pml4e & PTE_USER)) return 0;
    pdpt = x86_page_table_alias(pml4e);
    if (!pdpt) return 0;
    pdpte = pdpt[(va >> 30) & 0x1FF];
    if (!(pdpte & PTE_PRESENT) || !(pdpte & PTE_USER)) return 0;
    if (pdpte & PTE_PS) return 1;
    pd = x86_page_table_alias(pdpte);
    if (!pd) return 0;
    pde = pd[(va >> 21) & 0x1FF];
    if (!(pde & PTE_PRESENT) || !(pde & PTE_USER)) return 0;
    if (pde & PTE_PS) return 1;
    pt = x86_page_table_alias(pde);
    if (!pt) return 0;
    pte = pt[(va >> 12) & 0x1FF];
    return (pte & PTE_PRESENT) && (pte & PTE_USER);
}

static int user_span_mapped(uint64_t addr, uint64_t len) {
    uint64_t end;
    uint64_t va;
    if (!user_span_ok(addr, len)) return 0;
    if (!len) return 1;
    end = addr + len - 1;
    for (va = addr & ~0xFFFULL; va <= end; va += 0x1000ULL) {
        /*
         * Exception logging runs while CR3 still points at the faulting task.
         * A VMA check alone is not enough for sparse/demand-backed mappings:
         * directly reading an unmapped user stack page from this debug path
         * recursively faults in kernel mode and hides the original XFCE fault.
         */
        if (!user_page_present(va)) return 0;
        if (va > UINT64_MAX - 0x1000ULL) break;
    }
    return 1;
}

static void dump_user_bytes(uint64_t addr, int count, const char *tag) {
    if (!user_span_mapped(addr, (uint64_t)count)) return;
    printf("%s: va=0x%x bytes=", tag, (uint32)addr);
    for (int i = 0; i < count; ++i) {
        const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)(addr + (uint64_t)i);
        printf("%x", (uint32)(*p));
        if (i + 1 < count) printf(" ");
    }
    printf("\n");
}

static void dump_user_qwords(uint64_t addr, int count, const char *tag) {
    if (!user_span_mapped(addr, (uint64_t)count * 8ULL)) return;
    printf("%s: va=0x%x", tag, (uint32)addr);
    for (int i = 0; i < count; ++i) {
        const volatile uint64_t *p = (const volatile uint64_t *)(uintptr_t)(addr + (uint64_t)i * 8ULL);
        printf(" q%d=0x%x", i, (uint32)(*p));
    }
    printf("\n");
}

static void dump_user_gpf_context(REGISTERS *reg) {
    task_t *t = process_current_task();
    uint64_t code_addr;
    if (!reg) return;

    /*
     * GTK/XFCE failures have shown up as #GP in otherwise executable shared
     * libraries.  For #PF we already log code and stack bytes; do the same for
     * #GP so the serial log can distinguish an ABI/call-frame problem from a
     * wrong file-backed text mapping.  Red flag: keep this read-only and gated
     * through present user PTE checks so exception logging does not recurse
     * into a second kernel fault while reporting the original crash.
     */
    code_addr = reg->rip >= 16 ? reg->rip - 16 : reg->rip;
    dump_user_bytes(code_addr, 48, "GPF-CODE");
    dump_user_qwords(reg->rsp, 12, "GPF-STACK");
    dump_user_qwords(reg->rbp, 8, "GPF-RBP");
    dump_user_qwords(reg->rbx, 8, "GPF-RBX");
    dump_user_qwords(reg->rcx, 8, "GPF-RCX");
    dump_user_qwords(reg->rdx, 8, "GPF-RDX");
    dump_user_qwords(reg->rdi, 8, "GPF-RDI");
    dump_user_qwords(reg->rsi, 8, "GPF-RSI");
    dump_user_qwords(reg->rax, 4, "GPF-RAX");
    if (t && t->fs_base) {
        dump_user_qwords(t->fs_base, 8, "GPF-FS");
        process_user_mmap_debug_dump_addr("GPF-MMAP-FS", t, t->fs_base);
        if (user_span_mapped(t->fs_base + 8, sizeof(uint64_t))) {
            uint64_t dtv = *(const volatile uint64_t *)(uintptr_t)(t->fs_base + 8);
            /*
             * musl stores the dynamic TLS vector at fs:8 on x86-64.  GUI
             * crashes in __tls_get_addr are otherwise hard to diagnose after
             * the fact, so dump the vector when it is already mapped.  This is
             * read-only exception telemetry and must not fault in the logger.
             */
            dump_user_qwords(dtv, 16, "GPF-FS-DTV");
            process_user_mmap_debug_dump_addr("GPF-MMAP-FS-DTV", t, dtv);
        }
    }
    process_user_mmap_debug_dump_addr("GPF-MMAP-RIP", t, reg->rip);
    process_user_mmap_debug_dump_addr("GPF-MMAP-RSP", t, reg->rsp);
    process_user_mmap_debug_dump_addr("GPF-MMAP-RBX", t, reg->rbx);
    process_user_mmap_debug_dump_addr("GPF-MMAP-RCX", t, reg->rcx);
    process_user_mmap_debug_dump_addr("GPF-MMAP-RDX", t, reg->rdx);
    process_user_mmap_debug_dump_addr("GPF-MMAP-RDI", t, reg->rdi);
}

static uint64 read_cr2(void) {
    uint64 v;
    __asm__ __volatile__("mov %%cr2, %0" : "=r"(v));
    return v;
}

static uint64 read_cr3(void) {
    uint64 v;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));
    return v;
}

static void dump_pte_for_va(uint64 va) {
    uint64 cr3 = read_cr3() & ~0xFFFULL;
    uint64 *pml4 = x86_page_table_alias(cr3);
    if (!pml4) {
        printf("PT: va=0x%x pml4=unmapped\n", (uint32)va);
        return;
    }
    uint64 pml4e = pml4[(va >> 39) & 0x1FF];
    if (!(pml4e & PTE_PRESENT)) {
        printf("PT: va=0x%x pml4e=not-present\n", (uint32)va);
        return;
    }

    uint64 *pdpt = x86_page_table_alias(pml4e);
    if (!pdpt) {
        printf("PT: va=0x%x pdpt=unmapped\n", (uint32)va);
        return;
    }
    uint64 pdpte = pdpt[(va >> 30) & 0x1FF];
    if (!(pdpte & PTE_PRESENT)) {
        printf("PT: va=0x%x pdpte=not-present pml4e_flags=0x%x\n", (uint32)va, (uint32)(pml4e & 0xFFFULL));
        return;
    }
    if (pdpte & PTE_PS) {
        printf("PT: va=0x%x 1G flags=0x%x P=%d U=%d W=%d\n",
               (uint32)va, (uint32)(pdpte & 0xFFFULL),
               (int)((pdpte & PTE_PRESENT) != 0), (int)((pdpte & PTE_USER) != 0), (int)((pdpte & PTE_WRITE) != 0));
        return;
    }

    uint64 *pd = x86_page_table_alias(pdpte);
    if (!pd) {
        printf("PT: va=0x%x pd=unmapped\n", (uint32)va);
        return;
    }
    uint64 pde = pd[(va >> 21) & 0x1FF];
    if (!(pde & PTE_PRESENT)) {
        printf("PT: va=0x%x pde=not-present pdpte_flags=0x%x\n", (uint32)va, (uint32)(pdpte & 0xFFFULL));
        return;
    }
    if (pde & PTE_PS) {
        printf("PT: va=0x%x 2M flags=0x%x P=%d U=%d W=%d\n",
               (uint32)va, (uint32)(pde & 0xFFFULL),
               (int)((pde & PTE_PRESENT) != 0), (int)((pde & PTE_USER) != 0), (int)((pde & PTE_WRITE) != 0));
        return;
    }

    uint64 *pt = x86_page_table_alias(pde);
    if (!pt) {
        printf("PT: va=0x%x pt=unmapped\n", (uint32)va);
        return;
    }
    uint64 pte = pt[(va >> 12) & 0x1FF];
    if (!(pte & PTE_PRESENT)) {
        printf("PT: va=0x%x pte=not-present pde_flags=0x%x\n", (uint32)va, (uint32)(pde & 0xFFFULL));
        return;
    }

    printf("PT: va=0x%x 4K flags=0x%x P=%d U=%d W=%d\n",
           (uint32)va, (uint32)(pte & 0xFFFULL),
           (int)((pte & PTE_PRESENT) != 0), (int)((pte & PTE_USER) != 0), (int)((pte & PTE_WRITE) != 0));
}

static void store_xmm_unaligned(int reg, void *dst) {
    switch (reg & 7) {
        case 0: __asm__ __volatile__("movdqu %%xmm0, (%0)" :: "r"(dst) : "memory"); break;
        case 1: __asm__ __volatile__("movdqu %%xmm1, (%0)" :: "r"(dst) : "memory"); break;
        case 2: __asm__ __volatile__("movdqu %%xmm2, (%0)" :: "r"(dst) : "memory"); break;
        case 3: __asm__ __volatile__("movdqu %%xmm3, (%0)" :: "r"(dst) : "memory"); break;
        case 4: __asm__ __volatile__("movdqu %%xmm4, (%0)" :: "r"(dst) : "memory"); break;
        case 5: __asm__ __volatile__("movdqu %%xmm5, (%0)" :: "r"(dst) : "memory"); break;
        case 6: __asm__ __volatile__("movdqu %%xmm6, (%0)" :: "r"(dst) : "memory"); break;
        case 7: __asm__ __volatile__("movdqu %%xmm7, (%0)" :: "r"(dst) : "memory"); break;
    }
}

static int emulate_user_gpf_sse(REGISTERS *reg) {
    const uint8_t *pc;
    uint8_t modrm;
    uint64_t addr;
    uint32_t disp32;
    int xmm_reg;
    if (!reg || (reg->cs & 0x3) != 0x3) return 0;
    if (!user_span_ok(reg->rip, 8)) return 0;
    pc = (const uint8_t *)(uintptr_t)reg->rip;
    if (pc[0] != 0x0F || pc[1] != 0x29) return 0; /* MOVAPS xmm -> m128 */
    modrm = pc[2];
    xmm_reg = (modrm >> 3) & 7;

    if (modrm == 0x44 && pc[3] == 0x24) {
        addr = reg->rsp + (uint64_t)(int8_t)pc[4];
        if (!user_span_ok(addr, 16)) return 0;
        store_xmm_unaligned(xmm_reg, (void *)(uintptr_t)addr);
        reg->rip += 5;
        return 1;
    }
    if (modrm == 0x04 && pc[3] == 0x24) {
        addr = reg->rsp;
        if (!user_span_ok(addr, 16)) return 0;
        store_xmm_unaligned(xmm_reg, (void *)(uintptr_t)addr);
        reg->rip += 4;
        return 1;
    }
    if ((modrm & 0xC7u) == 0x84u && pc[3] == 0x24) {
        /*
         * Same Linux-compatibility shim as the disp8 cases above, but for the
         * encoding generated by GLib/GObject on Alpine:
         *   0f 29 84 24 xx xx xx xx    movaps %xmmN, disp32(%rsp)
         *
         * EdgeOS still has a known user-stack alignment gap under heavy
         * pthread/XFCE startup.  Do not broaden this into arbitrary #GP
         * recovery; keep it limited to unaligned user MOVAPS stores to the
         * current stack while the underlying clone/signal alignment path is
         * being audited.
         */
        memcpy(&disp32, pc + 4, sizeof(disp32));
        addr = reg->rsp + (uint64_t)(int32_t)disp32;
        if (!user_span_ok(addr, 16)) return 0;
        store_xmm_unaligned(xmm_reg, (void *)(uintptr_t)addr);
        reg->rip += 8;
        return 1;
    }
    return 0;
}

void isr_exception_handler(REGISTERS *reg) {
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if (reg->int_no == 2u && bsd_x86_nmi_dispatch(reg))
        return;
    if (reg->int_no == 13u && (reg->cs & 0x3u) == 0u &&
        bsd_x86_msr_fault_recover(&reg->rip))
        return;
#endif
    if (reg->int_no == 1u &&
        scheduler_handle_context_watch(reg->rip, reg->cs, reg->rsp,
                                       reg->rdi, reg->rsi, reg->rdx,
                                       reg->rcx, reg->rax, reg->rbp))
        return;

    if (reg->int_no == 6) {
        if ((reg->cs & 0x3) == 0x3) {
            const uint8_t *pc = (const uint8_t *)(uintptr_t)reg->rip;
            /* x86 CET IBT ENDBR instructions are safe no-ops on CPUs without CET.
             * Some user binaries are built with -fcf-protection and would otherwise
             * fault with #UD on entry to many functions. */
            if (pc && pc[0] == 0xF3 && pc[1] == 0x0F && pc[2] == 0x1E &&
                (pc[3] == 0xFA || pc[3] == 0xFB)) {
                reg->rip += 4;
                return;
            }
            if (pc && pc[0] == 0x0F && pc[1] == 0x05) {
                ISR syscall_h = g_interrupt_handler_count[128] ? g_interrupt_handlers[128][0] : 0;
                reg->rcx = reg->rip + 2;
                reg->r11 = reg->rflags;
                reg->rip += 2;
                if (syscall_h) {
                    syscall_h(reg);
                    return;
                }
            }
        }
    }

    if ((reg->cs & 0x3) == 0x3 &&
        (reg->int_no == 1u || reg->int_no == 3u) &&
        edge_linux_ptrace_debug_stop(reg))
        return;

    if ((reg->cs & 0x3) == 0x3 &&
        (reg->int_no == 1u || reg->int_no == 3u)) {
        struct edge_linux_siginfo information;
        uint64_t fault_address = reg->rip;

        memset(&information, 0, sizeof(information));
        information.signal_number = EDGE_LINUX_PTRACE_SIGTRAP;
        /* Linux UAPI: TRAP_BRKPT=1 and TRAP_TRACE=2. */
        information.code = reg->int_no == 3u ? 1 : 2;
        if (reg->int_no == 3u && fault_address > 0)
            --fault_address;
        memcpy(information.payload, &fault_address,
               sizeof(fault_address));
        if (process_send_signal_info(process_getpid(), EDGE_LINUX_PTRACE_SIGTRAP,
                                     &information) < 0) {
            scheduler_kill_current_group_and_yield(
                128 + EDGE_LINUX_PTRACE_SIGTRAP);
            return;
        }
        (void)edgeos_x86_64_deliver_signal_on_user_return(reg);
        return;
    }

    if (reg->int_no == 14) {
        uint64 cr2 = read_cr2();
        uint64 ec = reg->err_code;
        uint64 p = ec & 1;
        uint64 wr = (ec >> 1) & 1;
        uint64 us = (ec >> 2) & 1;

        /* The exception frame and kernel GS are stable at this point.  Permit
         * TLB and device interrupts while resolving a user fault; otherwise a
         * sibling CPU changing the same mm waits for this CPU while this CPU
         * can simultaneously wait on the mm lock.  exception_common disables
         * interrupts again immediately before restoring the user frame. */
        if ((reg->cs & 0x3u) == 0x3u)
            __asm__ __volatile__("sti" ::: "memory");

        /*
         * A valid demand-backed user range can initially overlap a supervisor
         * identity PDE.  Its first read then arrives as a present user-mode
         * protection fault (P=1, W/R=0, U/S=1), not as a non-present fault.
         * Offer every user access fault to the userspace mapping resolver;
         * VMA and protection checks there still reject PROT_NONE and illegal
         * writes.  Restricting this to writes made freshly grown brk pages
         * readable only after a write and crashed applications that inspect
         * zero-filled allocator storage first.
         */
        if (!p || wr || us) {
            task_t *t = process_current_task();
            int userfault_context = -1;
            uint64_t userfault_ticket = 0;
            int userfault_status = 0;

            if (t && !p &&
                process_user_mmap_page_poisoned(t, cr2) > 0) {
                deliver_user_exception_signal(
                    reg, EDGE_LINUX_SIGBUS, 4, cr2);
                return;
            }
            if (t && (!p || wr) &&
                !kernel_userfaultfd_resolution_bypasses_fault(
                    arch_mm_current_address_space(), cr2)) {
                userfault_status = kernel_userfaultfd_page_fault(
                    arch_mm_current_address_space(), cr2, (int)wr,
                    (int)p,
                    (uint32_t)t->pid,
                    &userfault_context, &userfault_ticket);
            }
            if (userfault_status == KERNEL_UFFD_FAULT_SIGBUS) {
                deliver_user_exception_signal(
                    reg, EDGE_LINUX_SIGBUS, 2, cr2);
                return;
            }
            if (userfault_status == KERNEL_UFFD_FAULT_QUEUED) {
                t->userfaultfd_wait_active = 1;
                t->userfaultfd_wait_context = userfault_context;
                t->userfaultfd_wait_ticket = userfault_ticket;
                scheduler_task_set_blocked(t);
                if (!kernel_userfaultfd_fault_pending(
                        userfault_context, userfault_ticket))
                    scheduler_task_make_runnable(
                        t, x86_smp_current_cpu_id());
                scheduler_yield_from_irq();
                t->userfaultfd_wait_active = 0;
                t->userfaultfd_wait_context = -1;
                t->userfaultfd_wait_ticket = 0;
                if (!kernel_userfaultfd_fault_pending(
                        userfault_context, userfault_ticket)) {
                    process_account_minor_fault(t);
                    cgroupfs_memory_note_fault(t->cgroup_id, 0);
                    edge_mm_statistics_note_fault(0);
                }
                return;
            }
            int resolved = process_user_mmap_handle_fault(
                t, cr2, (int)wr);
            if (resolved) {
                int major = resolved > 1;

                if (major)
                    process_account_major_fault(t);
                else
                    process_account_minor_fault(t);
                cgroupfs_memory_note_fault(
                    t ? t->cgroup_id : 0u, major);
                edge_mm_statistics_note_fault(major);
                return;
            }
            if (process_consume_cgroup_memory_oom(t)) {
                scheduler_kill_current_group_and_yield(128 + 9);
                return;
            }
        }

        emergency_serial_exception("pf", reg, cr2);
        printf("PAGE FAULT: cr2=0x%x err=0x%x P=%d W/R=%d U/S=%d\n",
               (uint32)cr2, (uint32)ec, (int)p, (int)wr, (int)us);
        dump_pte_for_va(cr2);
        if (reg->rip) dump_pte_for_va(reg->rip);
        print_registers(reg);

        if ((reg->cs & 0x3) == 0x3 || us) {
            uint64_t fb_phys = 0, fb_off = 0;
            uint32_t fb_pages = 0;
            print_task_context_brief();
            log_user_exception_task_detail();
            dump_vma_for_addr("PF-VMA-CR2", cr2);
            dump_vma_for_addr("PF-VMA-RIP", reg->rip);
            dump_nearby_vmas("PF-VMA-NEAR-CR2", cr2);
            dump_nearby_vmas("PF-VMA-NEAR-RIP", reg->rip);
            if (user_span_ok(reg->rip, 32)) dump_user_bytes(reg->rip, 32, "PF-CODE");
            {
                task_t *fault_task = process_current_task();
                uint64_t return_addr = 0;

                if (fault_task &&
                    user_span_mapped(reg->rsp, sizeof(return_addr)) &&
                    process_read_user_memory(
                        fault_task->pid, reg->rsp, &return_addr,
                        sizeof(return_addr)) == 0) {
                    dump_user_qwords(reg->rsp, 8, "PF-STACK");
                    dump_vma_for_addr("PF-VMA-RETURN", return_addr);
                    dump_nearby_vmas("PF-VMA-NEAR-RETURN", return_addr);
                    process_user_mmap_debug_dump_addr("PF-MMAP-RETURN",
                                                      fault_task,
                                                      return_addr);
                    if (return_addr >= 16 &&
                        user_span_ok(return_addr - 16, 48)) {
                        dump_user_bytes(
                            return_addr - 16, 48, "PF-RETURN-CODE");
                    }
                }
            }
            if (user_span_ok(reg->rbp, 64)) dump_user_qwords(reg->rbp, 8, "PF-RBP");
            if (user_span_ok(reg->rax, 64)) {
                dump_user_qwords(reg->rax, 8, "PF-RAX");
                process_user_mmap_debug_dump_addr("PF-MMAP-RAX",
                                                  process_current_task(),
                                                  reg->rax);
            }
            if (reg->rax <= UINT64_MAX - 0x2c0 &&
                user_span_ok(reg->rax + 0x2c0, 64)) {
                dump_user_qwords(reg->rax + 0x2c0, 8, "PF-RAX-CLASS-TAIL");
                process_user_mmap_debug_dump_addr("PF-MMAP-RAX-CLASS-TAIL",
                                                  process_current_task(),
                                                  reg->rax + 0x2c0);
            }
            if (user_span_ok(reg->rbx, 64)) dump_user_qwords(reg->rbx, 8, "PF-RBX");
            if (user_span_ok(reg->rsi, 96)) dump_user_qwords(reg->rsi, 12, "PF-RSI");
            if (user_span_ok(reg->r8, 64)) dump_user_qwords(reg->r8, 8, "PF-R8");
            if (user_span_ok(reg->r9, 64)) dump_user_qwords(reg->r9, 8, "PF-R9");
            if (user_span_ok(reg->r11, 64)) dump_user_qwords(reg->r11, 8, "PF-R11");
            process_user_mmap_debug_dump_addr("PF-MMAP-CR2", process_current_task(), cr2);
            process_user_mmap_debug_dump_addr("PF-MMAP-RIP", process_current_task(), reg->rip);
            process_user_mmap_debug_dump_addr("PF-MMAP-RSP", process_current_task(), reg->rsp);
            if (fb_get_2m_phys_window(&fb_phys, &fb_pages, &fb_off)) {
                /*
                 * Xorg/fbdev failures often present as a user access into a
                 * supervisor-only 2 MiB identity PDE.  Print the active fbdev
                 * aperture next to the fault so the serial log shows whether
                 * userspace touched the fbdev alias, the raw backing page, or
                 * an unrelated low address.  Red flag: this is diagnostics only
                 * and must not make arbitrary kernel identity pages user-visible.
                 */
                printf("[fb-fault] phys=0x%x pages=%u off=0x%x alias=0x%x cr2_delta=0x%x\n",
                       (uint32_t)fb_phys, fb_pages, (uint32_t)fb_off,
                       (uint32_t)(EDGE_FBDEV_USER_BASE + fb_off),
                       (uint32_t)(cr2 - (fb_phys + fb_off)));
            }
            printf("[process] delivering SIGSEGV to pid=%d for user page fault\n",
                   process_getpid());
            deliver_user_exception_signal(
                reg, EDGE_LINUX_SIGSEGV, p ? 2 : 1, cr2);
            return;
        }
    }

    if (reg->int_no == 13) {
        emergency_serial_exception("gpf", reg, read_cr2());
        if (emulate_user_gpf_sse(reg)) return;
        if ((reg->cs & 0x3) == 0 && scheduler_fault_in_switch_window(reg->rip)) {
            if (g_kernel_nontext_exception_budget > 0) {
                task_t *t = process_current_task();
                g_kernel_nontext_exception_budget--;
                printf("[exception][ERR] scheduler switch GPF pid=%d name=%s rip=0x%x rsp=0x%x budget=%u\n",
                       t ? t->pid : -1,
                       t ? t->name : "(none)",
                       (uint32)reg->rip,
                       (uint32)reg->rsp,
                       g_kernel_nontext_exception_budget);
                print_registers(reg);
            }
            scheduler_abandon_current_and_yield(-13);
            return;
        }
        printf("GPF: rip=0x%x cs=0x%x err=0x%x\n", (uint32)reg->rip, (uint32)reg->cs, (uint32)reg->err_code);
        dump_pte_for_va(reg->rip);
        if ((reg->cs & 0x3) == 0x3) {
            print_task_context_brief();
            log_user_exception_task_detail();
            dump_vma_for_addr("GPF-VMA-RIP", reg->rip);
            dump_vma_for_addr("GPF-VMA-RDI", reg->rdi);
            dump_user_gpf_context(reg);
            print_registers(reg);
            printf("[process] delivering SIGSEGV to pid=%d for user GPF\n",
                   process_getpid());
            deliver_user_exception_signal(
                reg, EDGE_LINUX_SIGSEGV, 128, reg->rip);
            return;
        }
    }

    if (reg->int_no < 32) {
        if ((reg->cs & 0x3) == 0x3) {
            int log_detail = log_user_exception_brief(reg);
            emergency_serial_exception("user", reg, read_cr2());
            if (log_detail) printf("EXCEPTION: %s\n", exception_messages[reg->int_no]);
            if (log_detail && reg->int_no == 6) {
                print_task_context_brief();
                log_user_exception_task_detail();
                dump_vma_for_addr("UD-VMA-RIP", reg->rip);
                dump_nearby_vmas("UD-VMA-NEAR-RIP", reg->rip);
                process_user_mmap_debug_dump_addr("UD-MMAP-RIP", process_current_task(), reg->rip);
                dump_chromium_shared_metadata();
                if (reg->rip >= USER_MIN_ADDR + 8 && reg->rip + 16 < USER_MAX_ADDR) {
                    dump_user_bytes(reg->rip - 8, 24, "UD-CODE");
                } else {
                    dump_user_bytes(reg->rip, 16, "UD-CODE");
                }
                if (user_span_ok(reg->r12, 48)) dump_user_qwords(reg->r12, 6, "R12");
            }
            if (log_detail) {
                print_registers(reg);
                printf("[process] killing pid=%d due to user exception %d\n", process_getpid(), (int)reg->int_no);
            }
            switch (reg->int_no) {
                case 0:
                    deliver_user_exception_signal(
                        reg, EDGE_LINUX_SIGFPE, 1, reg->rip);
                    break;
                case 6:
                    deliver_user_exception_signal(
                        reg, EDGE_LINUX_SIGILL, 1, reg->rip);
                    break;
                case 16:
                case 19:
                    deliver_user_exception_signal(
                        reg, EDGE_LINUX_SIGFPE, 7, reg->rip);
                    break;
                case 17:
                    deliver_user_exception_signal(
                        reg, EDGE_LINUX_SIGBUS, 1, reg->rip);
                    break;
                default:
                    deliver_user_exception_signal(
                        reg, EDGE_LINUX_SIGSEGV, 128, reg->rip);
                    break;
            }
            return;
        }
        if (kill_current_for_kernel_nontext_exception(reg)) return;
        printf("EXCEPTION: %s\n", exception_messages[reg->int_no]);
        print_registers(reg);
        for (;;) ;
    }
    if (reg->int_no < NO_INTERRUPT_HANDLERS) {
        for (uint8_t i = 0; i < g_interrupt_handler_count[reg->int_no]; ++i) {
            ISR handler = g_interrupt_handlers[reg->int_no][i];
            if (handler) handler(reg);
        }
    }
}
