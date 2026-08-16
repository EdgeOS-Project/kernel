/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS common Linux exec payload and initial-stack construction. */

#include <stdint.h>
#include "kernel/user_stack.h"
#include "kernel/arch_cpu.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_vdso.h"
#include "mm/arch_vm.h"

#define STACK_INITIAL_BYTES (64u * 1024u)
#define STACK_LIMIT_BYTES (8u * 1024u * 1024u)
#define PAGE_SIZE 4096u
#define AT_NULL 0u
#define AT_PAGESZ 6u
#define AT_PHDR 3u
#define AT_PHENT 4u
#define AT_PHNUM 5u
#define AT_BASE 7u
#define AT_ENTRY 9u
#define AT_UID 11u
#define AT_EUID 12u
#define AT_GID 13u
#define AT_EGID 14u
#define AT_CLKTCK 17u
#define AT_SECURE 23u
#define AT_RANDOM 25u
#define AT_HWCAP2 26u
#define AT_EXECFN 31u
#define AT_HWCAP 16u
#define AT_SYSINFO_EHDR 33u
#define AUXV_PAIR_COUNT 20u

typedef const char *(*stack_string_at_t)(const void *context, uint32_t index);

typedef struct {
    const char *const *vector;
} stack_vector_context_t;

static uint64_t align_down16(uint64_t value) { return value & ~15ULL; }
static uint64_t align_down_page(uint64_t value) {
    return value & ~(uint64_t)(PAGE_SIZE - 1u);
}

static uint32_t string_length_limited(const char *string, uint32_t limit) {
    uint32_t length = 0;
    if (!string) return limit;
    while (length < limit && string[length]) ++length;
    return length;
}

static const char *payload_argv_at(const void *context, uint32_t index) {
    return linux_exec_payload_argument((const linux_exec_payload_t *)context,
                                       index);
}

static const char *payload_env_at(const void *context, uint32_t index) {
    return linux_exec_payload_environment(
        (const linux_exec_payload_t *)context, index);
}

static const char *vector_at(const void *context, uint32_t index) {
    const stack_vector_context_t *vectors =
        (const stack_vector_context_t *)context;
    return vectors->vector[index];
}

static int stack_write_u64(uint64_t address_space, uint64_t *cursor,
                           uint64_t value) {
    if (arch_copy_to_user(address_space, *cursor, &value, sizeof(value)) < 0)
        return -EDGE_LINUX_EFAULT;
    *cursor += sizeof(value);
    return 0;
}

static int stack_build(uint64_t address_space,
                       const void *argv_context, stack_string_at_t argv_at,
                       uint32_t argc,
                       const void *env_context, stack_string_at_t env_at,
                       uint32_t envc,
                       uint64_t at_phdr, uint64_t at_phnum,
                       uint64_t at_entry, uint64_t at_base,
                       const linux_user_stack_identity_t *identity,
                       linux_user_stack_result_t *result) {
    uint64_t stack_top = arch_cpu_user_stack_top();
    uint64_t strings_bytes = 0;
    uint64_t argv_bytes = 0;
    uint64_t strings_start;
    uint64_t random_address;
    uint64_t vector_bytes;
    uint64_t stack_pointer;
    uint64_t stack_low;
    uint64_t string_cursor;
    uint64_t vector_cursor;
    uint64_t execfn;
    uint64_t vdso_base;
    uint8_t random[16];
    uint64_t seed;

    if (!address_space || !argv_context || !argv_at || !argc ||
        (envc && (!env_context || !env_at)) || !identity || !result ||
        argc > LINUX_EXEC_POINTER_MAX ||
        envc > LINUX_EXEC_POINTER_MAX - argc)
        return -EDGE_LINUX_EINVAL;
    vdso_base = linux_vdso_map(address_space);
    if (!vdso_base) return -EDGE_LINUX_ENOMEM;
    for (uint32_t i = 0; i < argc; ++i) {
        const char *string = argv_at(argv_context, i);
        uint32_t length = string_length_limited(string, LINUX_EXEC_STRING_MAX);
        if (length == LINUX_EXEC_STRING_MAX) return -EDGE_LINUX_E2BIG;
        strings_bytes += (uint64_t)length + 1u;
        argv_bytes += (uint64_t)length + 1u;
    }
    for (uint32_t i = 0; i < envc; ++i) {
        const char *string = env_at(env_context, i);
        uint32_t length = string_length_limited(string, LINUX_EXEC_STRING_MAX);
        if (length == LINUX_EXEC_STRING_MAX) return -EDGE_LINUX_E2BIG;
        strings_bytes += (uint64_t)length + 1u;
    }
    if (strings_bytes + ((uint64_t)argc + envc + 2u) * sizeof(uint64_t) >
        LINUX_EXEC_BYTES_MAX)
        return -EDGE_LINUX_E2BIG;

    strings_start = stack_top - strings_bytes;
    random_address = align_down16(strings_start - sizeof(random));
    vector_bytes = ((uint64_t)argc + envc + 3u +
                    AUXV_PAIR_COUNT * 2u) * sizeof(uint64_t);
    stack_pointer = align_down16(random_address - vector_bytes);
    stack_low = align_down_page(stack_pointer);
    if (stack_top - stack_low < STACK_INITIAL_BYTES)
        stack_low = stack_top - STACK_INITIAL_BYTES;
    if (stack_top - stack_low > STACK_LIMIT_BYTES) return -EDGE_LINUX_E2BIG;

    for (uint64_t va = stack_low; va < stack_top; va += PAGE_SIZE) {
        void *page = arch_vm_alloc_page();
        if (!page || arch_vm_map_user_page(
                address_space, va, (uint64_t)(uintptr_t)page,
                ARCH_VM_PROT_READ | ARCH_VM_PROT_WRITE) < 0) {
            if (page) arch_vm_free_page(page);
            return -EDGE_LINUX_ENOMEM;
        }
    }

    string_cursor = strings_start;
    execfn = strings_start;
    for (uint32_t i = 0; i < argc; ++i) {
        const char *string = argv_at(argv_context, i);
        uint32_t length = string_length_limited(string, LINUX_EXEC_STRING_MAX) + 1u;
        if (arch_copy_to_user(address_space, string_cursor, string, length) < 0)
            return -EDGE_LINUX_EFAULT;
        string_cursor += length;
    }
    for (uint32_t i = 0; i < envc; ++i) {
        const char *string = env_at(env_context, i);
        uint32_t length = string_length_limited(string, LINUX_EXEC_STRING_MAX) + 1u;
        if (arch_copy_to_user(address_space, string_cursor, string, length) < 0)
            return -EDGE_LINUX_EFAULT;
        string_cursor += length;
    }

    seed = arch_cpu_cycle_counter();
    for (uint32_t i = 0; i < sizeof(random); ++i) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        random[i] = (uint8_t)seed;
    }
    if (arch_copy_to_user(address_space, random_address, random,
                          sizeof(random)) < 0)
        return -EDGE_LINUX_EFAULT;

    vector_cursor = stack_pointer;
    if (stack_write_u64(address_space, &vector_cursor, argc) < 0)
        return -EDGE_LINUX_EFAULT;
    string_cursor = strings_start;
    for (uint32_t i = 0; i < argc; ++i) {
        const char *string = argv_at(argv_context, i);
        uint32_t length = string_length_limited(string, LINUX_EXEC_STRING_MAX) + 1u;
        if (stack_write_u64(address_space, &vector_cursor, string_cursor) < 0)
            return -EDGE_LINUX_EFAULT;
        string_cursor += length;
    }
    if (stack_write_u64(address_space, &vector_cursor, 0) < 0)
        return -EDGE_LINUX_EFAULT;
    for (uint32_t i = 0; i < envc; ++i) {
        const char *string = env_at(env_context, i);
        uint32_t length = string_length_limited(string, LINUX_EXEC_STRING_MAX) + 1u;
        if (stack_write_u64(address_space, &vector_cursor, string_cursor) < 0)
            return -EDGE_LINUX_EFAULT;
        string_cursor += length;
    }
    if (stack_write_u64(address_space, &vector_cursor, 0) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_PHDR) < 0 ||
        stack_write_u64(address_space, &vector_cursor, at_phdr) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_PHENT) < 0 ||
        stack_write_u64(address_space, &vector_cursor, 56u) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_PHNUM) < 0 ||
        stack_write_u64(address_space, &vector_cursor, at_phnum) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_ENTRY) < 0 ||
        stack_write_u64(address_space, &vector_cursor, at_entry) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_BASE) < 0 ||
        stack_write_u64(address_space, &vector_cursor, at_base) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_PAGESZ) < 0 ||
        stack_write_u64(address_space, &vector_cursor, PAGE_SIZE) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_UID) < 0 ||
        stack_write_u64(address_space, &vector_cursor, identity->uid) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_EUID) < 0 ||
        stack_write_u64(address_space, &vector_cursor, identity->euid) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_GID) < 0 ||
        stack_write_u64(address_space, &vector_cursor, identity->gid) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_EGID) < 0 ||
        stack_write_u64(address_space, &vector_cursor, identity->egid) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_CLKTCK) < 0 ||
        stack_write_u64(address_space, &vector_cursor, 100u) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_SECURE) < 0 ||
        stack_write_u64(address_space, &vector_cursor,
                        identity->secure_exec ? 1u : 0u) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_RANDOM) < 0 ||
        stack_write_u64(address_space, &vector_cursor, random_address) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_EXECFN) < 0 ||
        stack_write_u64(address_space, &vector_cursor, execfn) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_HWCAP) < 0 ||
        stack_write_u64(address_space, &vector_cursor, arch_cpu_user_hwcap()) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_HWCAP2) < 0 ||
        stack_write_u64(address_space, &vector_cursor, arch_cpu_user_hwcap2()) < 0 ||
        stack_write_u64(address_space, &vector_cursor,
                        EDGE_LINUX_AT_RSEQ_FEATURE_SIZE) < 0 ||
        stack_write_u64(address_space, &vector_cursor,
                        EDGE_LINUX_RSEQ_FEATURE_SIZE) < 0 ||
        stack_write_u64(address_space, &vector_cursor,
                        EDGE_LINUX_AT_RSEQ_ALIGN) < 0 ||
        stack_write_u64(address_space, &vector_cursor,
                        EDGE_LINUX_RSEQ_ALIGN) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_SYSINFO_EHDR) < 0 ||
        stack_write_u64(address_space, &vector_cursor, vdso_base) < 0 ||
        stack_write_u64(address_space, &vector_cursor, AT_NULL) < 0 ||
        stack_write_u64(address_space, &vector_cursor, 0) < 0)
        return -EDGE_LINUX_EFAULT;

    result->stack_pointer = stack_pointer;
    result->stack_low = stack_low;
    result->arg_start = strings_start;
    result->arg_end = strings_start + argv_bytes;
    result->env_start = result->arg_end;
    result->env_end = stack_top;
    return 0;
}

int linux_user_stack_build_payload(uint64_t address_space,
                                   const linux_exec_payload_t *payload,
                                   uint64_t at_phdr, uint64_t at_phnum,
                                   uint64_t at_entry, uint64_t at_base,
                                   linux_user_stack_result_t *result) {
    const linux_user_stack_identity_t identity = { 0 };
    return linux_user_stack_build_payload_with_identity(
        address_space, payload, &identity, at_phdr, at_phnum,
        at_entry, at_base, result);
}

int linux_user_stack_build_payload_with_identity(
    uint64_t address_space, const linux_exec_payload_t *payload,
    const linux_user_stack_identity_t *identity,
    uint64_t at_phdr, uint64_t at_phnum,
    uint64_t at_entry, uint64_t at_base,
    linux_user_stack_result_t *result) {
    if (!payload || !payload->argc) return -EDGE_LINUX_EINVAL;
    return stack_build(address_space, payload, payload_argv_at, payload->argc,
                       payload, payload_env_at, payload->envc,
                       at_phdr, at_phnum, at_entry, at_base,
                       identity, result);
}

int linux_user_stack_build_vectors(uint64_t address_space,
                                   const char *const argv[], uint32_t argc,
                                   const char *const envp[], uint32_t envc,
                                   uint64_t at_phdr, uint64_t at_phnum,
                                   uint64_t at_entry, uint64_t at_base,
                                   uint64_t *sp_out) {
    stack_vector_context_t argv_context = { argv };
    stack_vector_context_t env_context = { envp };
    const linux_user_stack_identity_t identity = { 0 };
    linux_user_stack_result_t result;
    int status;
    if (!sp_out) return -EDGE_LINUX_EINVAL;
    status = stack_build(address_space, &argv_context, vector_at, argc,
                         &env_context, vector_at, envc,
                         at_phdr, at_phnum, at_entry, at_base,
                         &identity, &result);
    if (status < 0) return status;
    *sp_out = result.stack_pointer;
    return 0;
}

int linux_user_stack_build(uint64_t address_space, const char *argv0,
                           uint64_t at_phdr, uint64_t at_phnum,
                           uint64_t at_entry, uint64_t at_base,
                           uint64_t *sp_out) {
    static const char env_path[] =
        "PATH=/usr/libexec/rc/bin:/bin:/sbin:/usr/bin:/usr/sbin";
    static const char env_home[] = "HOME=/";
    static const char env_term[] = "TERM=linux";
    const char *argv[1] = { argv0 };
    const char *envp[3] = { env_path, env_home, env_term };
    if (!argv0) return -EDGE_LINUX_EINVAL;
    return linux_user_stack_build_vectors(address_space, argv, 1, envp, 3,
                                          at_phdr, at_phnum, at_entry,
                                          at_base, sp_out);
}
