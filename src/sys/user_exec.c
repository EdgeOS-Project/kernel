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

static int user_push_word(uintptr_t *stack_pointer, uint64_t value,
                          uint8_t word_size) {
    if (!stack_pointer || (word_size != 4u && word_size != 8u) ||
        *stack_pointer < word_size ||
        (word_size == 4u && value > UINT32_MAX))
        return -1;
    *stack_pointer -= word_size;
    if (word_size == 4u) {
        uint32_t compat = (uint32_t)value;
        return user_copy_to_current(
            (uint64_t)*stack_pointer, &compat, sizeof(compat));
    }
    return user_copy_to_current(
        (uint64_t)*stack_pointer, &value, sizeof(value));
}

static const char *user_exec_platform(edge_linux_task_abi_t abi,
                                      uint32_t *size) {
    static const char native_platform[] = "x86_64";
    static const char ia32_platform[] = "i686";
    const char *platform = abi == EDGE_LINUX_TASK_ABI_IA32 ?
        ia32_platform : native_platform;

    if (size) *size = abi == EDGE_LINUX_TASK_ABI_IA32 ?
        sizeof(ia32_platform) : sizeof(native_platform);
    return platform;
}

static __attribute__((noreturn)) void user_exec_enter(
    const user_exec_image_t *img, task_t *cur, uint64_t stack_pointer) {
    edge_trap_frame_t frame;

    user_exec_set_kernel_rsp0(cur->kernel_stack_top);
    edgeos_x86_64_set_user_gs_base(cur->gs_base);
    memset(&frame, 0, sizeof(frame));
    frame.rip = img->entry;
    frame.cs = img->linux_abi == EDGE_LINUX_TASK_ABI_IA32 ?
        USER32_CS : USER_CS;
    frame.rflags = 0x202u;
    frame.rsp = stack_pointer;
    frame.ss = img->linux_abi == EDGE_LINUX_TASK_ABI_IA32 ?
        USER32_DS : USER_DS;
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

static int user_write_word_forward(uint64_t *cursor, uint64_t limit,
                                   uint64_t value, uint8_t word_size) {
    if (!cursor || (word_size != 4u && word_size != 8u) ||
        *cursor > limit || limit - *cursor < word_size ||
        (word_size == 4u && value > UINT32_MAX))
        return -1;
    if (word_size == 4u) {
        uint32_t compat = (uint32_t)value;
        if (user_copy_to_current(*cursor, &compat, sizeof(compat)) < 0)
            return -1;
    } else if (user_copy_to_current(*cursor, &value, sizeof(value)) < 0) {
        return -1;
    }
    *cursor += word_size;
    return 0;
}

int user_exec_run_payload(const user_exec_image_t *img,
                          const linux_exec_payload_t *payload,
                          kernel_exec_payload_handle_t *payload_handle) {
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
    uint8_t word_size;
    uint8_t random_bytes[16];
    const char *platform;
    uint32_t platform_size;

    if (!img || !payload || !payload_handle || !payload->argc ||
        payload->argc > LINUX_EXEC_POINTER_MAX ||
        payload->envc > LINUX_EXEC_POINTER_MAX - payload->argc)
        return -1;
    cur = process_current_task();
    if (!cur) return -1;
    word_size = edge_linux_task_abi_word_size(img->linux_abi);
    platform = user_exec_platform(img->linux_abi, &platform_size);
    vdso_base = img->linux_abi == EDGE_LINUX_TASK_ABI_NATIVE64 ?
        linux_vdso_map(cur->cr3) : 0;
    if (img->linux_abi == EDGE_LINUX_TASK_ABI_NATIVE64 && !vdso_base)
        return -1;

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
            word_size > LINUX_EXEC_BYTES_MAX)
        return -1;

    stack_top = img->user_stack_top;
    if (strings_bytes >= stack_top - X86_USER_STACK_BASE) return -1;
    strings_start = stack_top - strings_bytes;
    if (strings_start < X86_USER_STACK_BASE + platform_size) return -1;
    platform_address = strings_start - platform_size;
    if (platform_address < X86_USER_STACK_BASE + sizeof(random_bytes))
        return -1;
    random_address = (platform_address - sizeof(random_bytes)) & ~15ULL;
    vector_bytes = ((uint64_t)payload->argc + payload->envc + 3u +
                    auxiliary_pairs * 2u) * word_size;
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
                             platform_size) < 0)
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
        if (user_write_word_forward(&vector_cursor, random_address, \
                                    (uint64_t)(value), word_size) < 0) \
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
    WRITE_STACK(4);  WRITE_STACK(img->at_phent ? img->at_phent : 56u); /* AT_PHENT */
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
    uint8_t word_size;
    const char *platform;
    uint32_t platform_size;

    word_size = edge_linux_task_abi_word_size(img->linux_abi);
    platform = user_exec_platform(img->linux_abi, &platform_size);
    vdso_base = img->linux_abi == EDGE_LINUX_TASK_ABI_NATIVE64 ?
        linux_vdso_map(cur->cr3) : 0;
    if (img->linux_abi == EDGE_LINUX_TASK_ABI_NATIVE64 && !vdso_base)
        return -1;

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
        sp -= platform_size;
        if (user_copy_to_current((uint64_t)sp, platform,
                                 platform_size) < 0)
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
        uintptr_t vector_bytes =
            (uintptr_t)(45 + real_argc + real_envc) * word_size;
        if (sp < vector_bytes) return -1;
        sp = ((sp - vector_bytes) & ~(uintptr_t)0xfull) + vector_bytes;
    }
    /* Build Linux-style initial stack:
     * [argc][argv...][NULL][envp...][NULL][auxv...][AT_NULL]
     */
#define PUSH_WORD(value) \
    do { \
        if (user_push_word(&sp, (uint64_t)(value), word_size) < 0) return -1; \
    } while (0)
    PUSH_WORD(0); /* AT_NULL a_val */
    PUSH_WORD(0); /* AT_NULL a_type */
    PUSH_WORD(vdso_base);
    PUSH_WORD(33); /* AT_SYSINFO_EHDR */
    PUSH_WORD(EDGE_LINUX_RSEQ_ALIGN);
    PUSH_WORD(EDGE_LINUX_AT_RSEQ_ALIGN);
    PUSH_WORD(EDGE_LINUX_RSEQ_FEATURE_SIZE);
    PUSH_WORD(EDGE_LINUX_AT_RSEQ_FEATURE_SIZE);
    PUSH_WORD(user_execfn_ptr);
    PUSH_WORD(31); /* AT_EXECFN */
    PUSH_WORD(0);
    PUSH_WORD(26); /* AT_HWCAP2 */
    PUSH_WORD(user_random_ptr);
    PUSH_WORD(25); /* AT_RANDOM */
    PUSH_WORD(img->secure_exec);
    PUSH_WORD(23); /* AT_SECURE */
    PUSH_WORD(100);
    PUSH_WORD(17); /* AT_CLKTCK */
    PUSH_WORD(0);
    PUSH_WORD(16); /* AT_HWCAP */
    PUSH_WORD(user_platform_ptr);
    PUSH_WORD(15); /* AT_PLATFORM */
    PUSH_WORD(cur->egid);
    PUSH_WORD(14); /* AT_EGID */
    PUSH_WORD(cur->gid);
    PUSH_WORD(13); /* AT_GID */
    PUSH_WORD(cur->euid);
    PUSH_WORD(12); /* AT_EUID */
    PUSH_WORD(cur->uid);
    PUSH_WORD(11); /* AT_UID */
    PUSH_WORD(4096);
    PUSH_WORD(6);  /* AT_PAGESZ */
    PUSH_WORD(img->at_base);
    PUSH_WORD(7);  /* AT_BASE */
    PUSH_WORD(img->at_entry);
    PUSH_WORD(9);  /* AT_ENTRY */
    PUSH_WORD(img->at_phnum);
    PUSH_WORD(5);  /* AT_PHNUM */
    PUSH_WORD(img->at_phent ? img->at_phent : 56u);
    PUSH_WORD(4);  /* AT_PHENT */
    PUSH_WORD(img->at_phdr);
    PUSH_WORD(3);  /* AT_PHDR */
    PUSH_WORD(0);  /* envp terminator */
    for (int i = real_envc - 1; i >= 0; --i) {
        PUSH_WORD(user_envp_ptrs[i]);
    }
    for (int i = real_argc; i >= 0; --i) {
        PUSH_WORD(user_argv_ptrs[i]);
    }
    PUSH_WORD(real_argc);
#undef PUSH_WORD
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
