#include "sys/user_exec.h"

#include "stdio.h"
#include "string.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_ptrace.h"
#include "kernel/linux_vdso.h"
#include "sys/process.h"
#include "arch/x86_64/syscall.h"
#include "arch/x86_64/user_layout.h"

extern void gdt_set_tss_rsp0(uint64_t rsp0);
extern void isr_return_from_frame(void);

static uint64_t user_exec_entropy64(void) {
    uint32_t lo, hi;
    uint64_t tsc;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    tsc = ((uint64_t)hi << 32) | lo;
    tsc ^= (uint64_t)(uintptr_t)&tsc;
    tsc ^= tsc << 13;
    tsc ^= tsc >> 7;
    tsc ^= tsc << 17;
    return tsc;
}

__attribute__((noreturn)) static void user_frame_enter(edge_trap_frame_t *frame) {
    __asm__ __volatile__(
        "cli\n\tmov %0, %%rsp\n\tjmp isr_return_from_frame\n"
        :
        : "r"(frame)
        : "memory");
    for (;;) __asm__ __volatile__("hlt");
}

void user_exec_set_kernel_rsp0(uint64_t rsp0) {
    gdt_set_tss_rsp0(rsp0);
}

static int user_copy_to_current(uint64_t destination, const void *source,
                                uint64_t length) {
    return process_write_user_memory(process_getpid(), destination, source,
                                     length);
}

static int user_push_u64(uintptr_t *sp, uint64_t v) {
    if (!sp || *sp < 8) return -1;
    *sp -= sizeof(uint64_t);
    return user_copy_to_current((uint64_t)*sp, &v, sizeof(v));
}

static __attribute__((noreturn)) void user_exec_enter(
    const user_exec_image_t *img, task_t *cur, uint64_t stack_pointer) {
    edge_trap_frame_t frame;

    user_exec_set_kernel_rsp0(cur->kernel_stack_top);
    edgeos_x86_64_set_user_gs_base(cur->gs_base);
    memset(&frame, 0, sizeof(frame));
    frame.rip = img->entry;
    frame.cs = USER_CS;
    frame.rflags = 0x202u;
    frame.rsp = stack_pointer;
    frame.ss = USER_DS;
    edge_linux_ptrace_exec_stop(&frame);
    {
        int64_t exec_result = 0;
        edge_linux_ptrace_syscall_exit(&frame, &exec_result);
        frame.rax = (uint64_t)exec_result;
    }
    user_frame_enter(&frame);
}

static uint32_t payload_string_length(const char *string) {
    uint32_t length = 0;
    if (!string) return LINUX_EXEC_STRING_MAX;
    while (length < LINUX_EXEC_STRING_MAX && string[length]) ++length;
    return length;
}

static int user_write_u64_forward(uint64_t *cursor, uint64_t limit,
                                  uint64_t value) {
    if (!cursor || *cursor > limit || limit - *cursor < sizeof(value))
        return -1;
    if (user_copy_to_current(*cursor, &value, sizeof(value)) < 0)
        return -1;
    *cursor += sizeof(value);
    return 0;
}

int user_exec_run_payload(const user_exec_image_t *img,
                          const linux_exec_payload_t *payload,
                          kernel_exec_payload_handle_t *payload_handle) {
    static const char platform[] = "x86_64";
    const uint64_t auxiliary_pairs = 21u;
    task_t *cur;
    uint64_t stack_top;
    uint64_t strings_bytes = 0;
    uint64_t argv_bytes = 0;
    uint64_t strings_start;
    uint64_t string_cursor;
    uint64_t platform_address;
    uint64_t random_address;
    uint64_t vector_bytes;
    uint64_t stack_pointer;
    uint64_t vector_cursor;
    uint64_t execfn;
    uint64_t vdso_base;
    uint8_t random_bytes[16];

    if (!img || !payload || !payload_handle || !payload->argc ||
        payload->argc > LINUX_EXEC_POINTER_MAX ||
        payload->envc > LINUX_EXEC_POINTER_MAX - payload->argc)
        return -1;
    cur = process_current_task();
    if (!cur) return -1;
    vdso_base = linux_vdso_map(cur->cr3);
    if (!vdso_base) return -1;

    for (uint32_t index = 0; index < payload->argc; ++index) {
        const char *string = linux_exec_payload_argument(payload, index);
        uint32_t length = payload_string_length(string);
        if (length == LINUX_EXEC_STRING_MAX) return -1;
        strings_bytes += (uint64_t)length + 1u;
        argv_bytes += (uint64_t)length + 1u;
    }
    for (uint32_t index = 0; index < payload->envc; ++index) {
        const char *string = linux_exec_payload_environment(payload, index);
        uint32_t length = payload_string_length(string);
        if (length == LINUX_EXEC_STRING_MAX) return -1;
        strings_bytes += (uint64_t)length + 1u;
    }
    if (strings_bytes + ((uint64_t)payload->argc + payload->envc + 2u) *
            sizeof(uint64_t) > LINUX_EXEC_BYTES_MAX)
        return -1;

    stack_top = img->user_stack_top;
    if (strings_bytes >= stack_top - X86_USER_STACK_BASE) return -1;
    strings_start = stack_top - strings_bytes;
    if (strings_start < X86_USER_STACK_BASE + sizeof(platform)) return -1;
    platform_address = strings_start - sizeof(platform);
    if (platform_address < X86_USER_STACK_BASE + sizeof(random_bytes))
        return -1;
    random_address = (platform_address - sizeof(random_bytes)) & ~15ULL;
    vector_bytes = ((uint64_t)payload->argc + payload->envc + 3u +
                    auxiliary_pairs * 2u) * sizeof(uint64_t);
    if (random_address < X86_USER_STACK_BASE + vector_bytes) return -1;
    stack_pointer = (random_address - vector_bytes) & ~15ULL;
    if (stack_pointer < X86_USER_STACK_BASE) return -1;

    string_cursor = strings_start;
    execfn = strings_start;
    for (uint32_t index = 0; index < payload->argc; ++index) {
        const char *string = linux_exec_payload_argument(payload, index);
        uint32_t length = payload_string_length(string) + 1u;
        if (user_copy_to_current(string_cursor, string, length) < 0)
            return -1;
        string_cursor += length;
    }
    for (uint32_t index = 0; index < payload->envc; ++index) {
        const char *string = linux_exec_payload_environment(payload, index);
        uint32_t length = payload_string_length(string) + 1u;
        if (user_copy_to_current(string_cursor, string, length) < 0)
            return -1;
        string_cursor += length;
    }
    if (user_copy_to_current(platform_address, platform,
                             sizeof(platform)) < 0)
        return -1;
    {
        uint64_t first = user_exec_entropy64();
        uint64_t second = user_exec_entropy64() ^
                          ((uint64_t)cur->pid << 32) ^ stack_pointer;
        memcpy(random_bytes, &first, sizeof(first));
        memcpy(random_bytes + sizeof(first), &second, sizeof(second));
        if (user_copy_to_current(random_address, random_bytes,
                                 sizeof(random_bytes)) < 0)
            return -1;
    }

#define WRITE_STACK(value) \
    do { \
        if (user_write_u64_forward(&vector_cursor, random_address, \
                                   (uint64_t)(value)) < 0) \
            return -1; \
    } while (0)

    vector_cursor = stack_pointer;
    WRITE_STACK(payload->argc);
    string_cursor = strings_start;
    for (uint32_t index = 0; index < payload->argc; ++index) {
        const char *string = linux_exec_payload_argument(payload, index);
        uint32_t length = payload_string_length(string) + 1u;
        WRITE_STACK(string_cursor);
        string_cursor += length;
    }
    WRITE_STACK(0);
    for (uint32_t index = 0; index < payload->envc; ++index) {
        const char *string = linux_exec_payload_environment(payload, index);
        uint32_t length = payload_string_length(string) + 1u;
        WRITE_STACK(string_cursor);
        string_cursor += length;
    }
    WRITE_STACK(0);
    WRITE_STACK(3);  WRITE_STACK(img->at_phdr);       /* AT_PHDR */
    WRITE_STACK(4);  WRITE_STACK(56);                 /* AT_PHENT */
    WRITE_STACK(5);  WRITE_STACK(img->at_phnum);      /* AT_PHNUM */
    WRITE_STACK(6);  WRITE_STACK(4096);               /* AT_PAGESZ */
    WRITE_STACK(7);  WRITE_STACK(img->at_base);       /* AT_BASE */
    WRITE_STACK(9);  WRITE_STACK(img->at_entry);      /* AT_ENTRY */
    WRITE_STACK(11); WRITE_STACK(cur->uid);           /* AT_UID */
    WRITE_STACK(12); WRITE_STACK(cur->euid);          /* AT_EUID */
    WRITE_STACK(13); WRITE_STACK(cur->gid);           /* AT_GID */
    WRITE_STACK(14); WRITE_STACK(cur->egid);          /* AT_EGID */
    WRITE_STACK(15); WRITE_STACK(platform_address);   /* AT_PLATFORM */
    WRITE_STACK(16); WRITE_STACK(0);                  /* AT_HWCAP */
    WRITE_STACK(17); WRITE_STACK(100);                /* AT_CLKTCK */
    WRITE_STACK(23); WRITE_STACK(img->secure_exec);   /* AT_SECURE */
    WRITE_STACK(25); WRITE_STACK(random_address);     /* AT_RANDOM */
    WRITE_STACK(26); WRITE_STACK(0);                  /* AT_HWCAP2 */
    WRITE_STACK(31); WRITE_STACK(execfn);             /* AT_EXECFN */
    WRITE_STACK(EDGE_LINUX_AT_RSEQ_FEATURE_SIZE);
    WRITE_STACK(EDGE_LINUX_RSEQ_FEATURE_SIZE);
    WRITE_STACK(EDGE_LINUX_AT_RSEQ_ALIGN);
    WRITE_STACK(EDGE_LINUX_RSEQ_ALIGN);
    WRITE_STACK(33); WRITE_STACK(vdso_base);          /* AT_SYSINFO_EHDR */
    WRITE_STACK(0);  WRITE_STACK(0);                  /* AT_NULL */
#undef WRITE_STACK

    if (vector_cursor > random_address || (stack_pointer & 15u) != 0)
        return -1;
    (void)argv_bytes;
    kernel_exec_payload_release(payload_handle);
    user_exec_enter(img, cur, stack_pointer);
}

int user_exec_run(const user_exec_image_t *img, int argc, char **argv, int envc, char **envp) {
    if (!img) return -1;

    task_t *cur = process_current_task();
    if (!cur) return -1;

    if (argc < 0) argc = 0;
    if (argc > EDGE_EXEC_ARG_MAX) argc = EDGE_EXEC_ARG_MAX;

    uintptr_t sp = (uintptr_t)img->user_stack_top;
    uint64_t user_argv_ptrs[EDGE_EXEC_ARG_MAX + 1];
    uint64_t user_envp_ptrs[EDGE_EXEC_ENV_MAX + 1];
    uint64_t user_random_ptr;
    uint64_t user_execfn_ptr;
    uint64_t user_platform_ptr;
    int real_argc = 0;
    int real_envc = 0;
    uint8_t random_bytes[16];
    uint64_t vdso_base;

    vdso_base = linux_vdso_map(cur->cr3);
    if (!vdso_base) return -1;

    for (int i = 0; i < argc; ++i) {
        if (!argv || !argv[i]) break;
        real_argc++;
    }
    if (envc < 0) envc = 0;
    if (envc > EDGE_EXEC_ENV_MAX) envc = EDGE_EXEC_ENV_MAX;
    for (int i = 0; i < envc; ++i) {
        if (!envp || !envp[i]) break;
        real_envc++;
    }

    for (int i = real_argc - 1; i >= 0; --i) {
        int n = strlen(argv[i]) + 1;
        sp -= (uintptr_t)n;
        if (user_copy_to_current((uint64_t)sp, argv[i], (uint32_t)n) < 0)
            return -1;
        user_argv_ptrs[i] = (uint64_t)sp;
    }
    user_argv_ptrs[real_argc] = 0;
    for (int i = real_envc - 1; i >= 0; --i) {
        int n = strlen(envp[i]) + 1;
        sp -= (uintptr_t)n;
        if (user_copy_to_current((uint64_t)sp, envp[i], (uint32_t)n) < 0)
            return -1;
        user_envp_ptrs[i] = (uint64_t)sp;
    }
    user_envp_ptrs[real_envc] = 0;
    {
        const char platform[] = "x86_64";
        sp -= sizeof(platform);
        if (user_copy_to_current((uint64_t)sp, platform,
                                 sizeof(platform)) < 0)
            return -1;
        user_platform_ptr = (uint64_t)sp;
    }
    {
        const char *execfn = (real_argc > 0 && argv && argv[0]) ? argv[0] : "";
        int n = strlen(execfn) + 1;
        sp -= (uintptr_t)n;
        if (user_copy_to_current((uint64_t)sp, execfn, (uint32_t)n) < 0)
            return -1;
        user_execfn_ptr = (uint64_t)sp;
    }
    {
        uint64_t a = user_exec_entropy64();
        uint64_t b = user_exec_entropy64() ^ ((uint64_t)cur->pid << 32) ^ (uint64_t)sp;
        memcpy(random_bytes, &a, sizeof(a));
        memcpy(random_bytes + sizeof(a), &b, sizeof(b));
        sp -= sizeof(random_bytes);
        if (user_copy_to_current((uint64_t)sp, random_bytes,
                                 sizeof(random_bytes)) < 0)
            return -1;
        user_random_ptr = (uint64_t)sp;
    }

    {
        /*
         * The AMD64 process-entry ABI requires a 16-byte-aligned initial
         * stack.  A normal call then leaves the callee's entry stack eight
         * bytes below that boundary, and its standard frame prologue restores
         * 16-byte alignment for aligned SSE spills.  Real hardware raises
         * #GP for a misaligned movaps even though some TCG configurations are
         * permissive, so keep this calculation tied to the complete vector.
         */
        int qwords = 45 + real_argc + real_envc;
        sp &= ~(uintptr_t)0xFULL;
        if ((qwords & 1) != 0) {
            if (sp < sizeof(uint64_t)) return -1;
            sp -= sizeof(uint64_t);
        }
    }
    /* Build Linux-style initial stack:
     * [argc][argv...][NULL][envp...][NULL][auxv...][AT_NULL]
     */
    if (user_push_u64(&sp, 0) < 0) return -1; /* AT_NULL a_val */
    if (user_push_u64(&sp, 0) < 0) return -1; /* AT_NULL a_type */
    if (user_push_u64(&sp, vdso_base) < 0) return -1;
    if (user_push_u64(&sp, 33) < 0) return -1; /* AT_SYSINFO_EHDR */
    if (user_push_u64(&sp, EDGE_LINUX_RSEQ_ALIGN) < 0) return -1;
    if (user_push_u64(&sp, EDGE_LINUX_AT_RSEQ_ALIGN) < 0) return -1;
    if (user_push_u64(&sp, EDGE_LINUX_RSEQ_FEATURE_SIZE) < 0) return -1;
    if (user_push_u64(&sp, EDGE_LINUX_AT_RSEQ_FEATURE_SIZE) < 0) return -1;
    if (user_push_u64(&sp, user_execfn_ptr) < 0) return -1;
    if (user_push_u64(&sp, 31) < 0) return -1; /* AT_EXECFN */
    if (user_push_u64(&sp, 0) < 0) return -1;
    if (user_push_u64(&sp, 26) < 0) return -1; /* AT_HWCAP2 */
    if (user_push_u64(&sp, user_random_ptr) < 0) return -1;
    if (user_push_u64(&sp, 25) < 0) return -1; /* AT_RANDOM */
    if (user_push_u64(&sp, img->secure_exec) < 0) return -1;
    if (user_push_u64(&sp, 23) < 0) return -1; /* AT_SECURE */
    if (user_push_u64(&sp, 100) < 0) return -1;
    if (user_push_u64(&sp, 17) < 0) return -1; /* AT_CLKTCK */
    if (user_push_u64(&sp, 0) < 0) return -1;
    if (user_push_u64(&sp, 16) < 0) return -1; /* AT_HWCAP */
    if (user_push_u64(&sp, user_platform_ptr) < 0) return -1;
    if (user_push_u64(&sp, 15) < 0) return -1; /* AT_PLATFORM */
    if (user_push_u64(&sp, cur->egid) < 0) return -1;
    if (user_push_u64(&sp, 14) < 0) return -1; /* AT_EGID */
    if (user_push_u64(&sp, cur->gid) < 0) return -1;
    if (user_push_u64(&sp, 13) < 0) return -1; /* AT_GID */
    if (user_push_u64(&sp, cur->euid) < 0) return -1;
    if (user_push_u64(&sp, 12) < 0) return -1; /* AT_EUID */
    if (user_push_u64(&sp, cur->uid) < 0) return -1;
    if (user_push_u64(&sp, 11) < 0) return -1; /* AT_UID */
    if (user_push_u64(&sp, 4096) < 0) return -1;
    if (user_push_u64(&sp, 6) < 0) return -1;  /* AT_PAGESZ */
    if (user_push_u64(&sp, img->at_base) < 0) return -1;
    if (user_push_u64(&sp, 7) < 0) return -1;  /* AT_BASE */
    if (user_push_u64(&sp, img->at_entry) < 0) return -1;
    if (user_push_u64(&sp, 9) < 0) return -1;  /* AT_ENTRY */
    if (user_push_u64(&sp, img->at_phnum) < 0) return -1;
    if (user_push_u64(&sp, 5) < 0) return -1;  /* AT_PHNUM */
    if (user_push_u64(&sp, 56) < 0) return -1;
    if (user_push_u64(&sp, 4) < 0) return -1;  /* AT_PHENT */
    if (user_push_u64(&sp, img->at_phdr) < 0) return -1;
    if (user_push_u64(&sp, 3) < 0) return -1;  /* AT_PHDR */
    if (user_push_u64(&sp, 0) < 0) return -1;  /* envp terminator */
    for (int i = real_envc - 1; i >= 0; --i) {
        if (user_push_u64(&sp, user_envp_ptrs[i]) < 0) return -1;
    }
    for (int i = real_argc; i >= 0; --i) {
        if (user_push_u64(&sp, user_argv_ptrs[i]) < 0) return -1;
    }
    if (user_push_u64(&sp, (uint64_t)real_argc) < 0) return -1;
    if ((sp & 0xFULL) != 0) return -1;

    if (0) {
        const uint64_t *stk = (const uint64_t *)(uintptr_t)sp;
        printf("[uexec-stack] pid=%d entry=0x%x rsp=0x%x at_base=0x%x at_entry=0x%x at_phdr=0x%x at_phnum=%d argc=%d envc=%d\n",
               cur->pid, (uint32_t)img->entry, (uint32_t)sp, (uint32_t)img->at_base,
               (uint32_t)img->at_entry, (uint32_t)img->at_phdr, (int)img->at_phnum,
               real_argc, real_envc);
        printf("[uexec-stack] qwords: 0=0x%x 1=0x%x 2=0x%x 3=0x%x 4=0x%x 5=0x%x 6=0x%x 7=0x%x\n",
               (uint32_t)stk[0], (uint32_t)stk[1], (uint32_t)stk[2], (uint32_t)stk[3],
               (uint32_t)stk[4], (uint32_t)stk[5], (uint32_t)stk[6], (uint32_t)stk[7]);
        printf("[uexec-code] entry: %x %x %x %x %x %x %x %x  phdr: %x %x %x %x %x %x %x %x\n",
               ((const uint8_t *)(uintptr_t)img->entry)[0], ((const uint8_t *)(uintptr_t)img->entry)[1],
               ((const uint8_t *)(uintptr_t)img->entry)[2], ((const uint8_t *)(uintptr_t)img->entry)[3],
               ((const uint8_t *)(uintptr_t)img->entry)[4], ((const uint8_t *)(uintptr_t)img->entry)[5],
               ((const uint8_t *)(uintptr_t)img->entry)[6], ((const uint8_t *)(uintptr_t)img->entry)[7],
               ((const uint8_t *)(uintptr_t)img->at_phdr)[0], ((const uint8_t *)(uintptr_t)img->at_phdr)[1],
               ((const uint8_t *)(uintptr_t)img->at_phdr)[2], ((const uint8_t *)(uintptr_t)img->at_phdr)[3],
               ((const uint8_t *)(uintptr_t)img->at_phdr)[4], ((const uint8_t *)(uintptr_t)img->at_phdr)[5],
               ((const uint8_t *)(uintptr_t)img->at_phdr)[6], ((const uint8_t *)(uintptr_t)img->at_phdr)[7]);
    }
    if (0 && img->at_phdr < X86_USER_LOW_LIMIT &&
        img->at_base == X86_USER_INTERP_BASE) {
        const volatile uint32_t *h = (const volatile uint32_t *)(uintptr_t)0x0000000000400388ULL;
        printf("[uexec-xorg] entry=0x%x rsp=0x%x at_base=0x%x at_entry=0x%x at_phdr=0x%x phnum=%d hash=%x %x %x %x %x %x %x %x\n",
               (uint32_t)img->entry, (uint32_t)sp, (uint32_t)img->at_base,
               (uint32_t)img->at_entry, (uint32_t)img->at_phdr, (int)img->at_phnum,
               h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    }

    user_exec_enter(img, cur, (uint64_t)sp);
}
