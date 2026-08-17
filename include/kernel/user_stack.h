/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_USER_STACK_H
#define EDGEOS_KERNEL_USER_STACK_H

#include <stdint.h>

/* Linux permits at most 32 pages in one argument string. */
#define LINUX_EXEC_STRING_MAX (32u * 4096u)
/* An 8 MiB stack limit yields Linux's 2 MiB aggregate exec payload limit. */
#define LINUX_EXEC_BYTES_MAX (2u * 1024u * 1024u)
#define LINUX_EXEC_POINTER_MAX (LINUX_EXEC_BYTES_MAX / sizeof(uint64_t))

typedef struct {
    uint32_t argc;
    uint32_t envc;
    uint32_t bytes_used;
    uint32_t offsets[LINUX_EXEC_POINTER_MAX];
    char bytes[LINUX_EXEC_BYTES_MAX];
} linux_exec_payload_t;

typedef struct {
    uint64_t stack_pointer;
    uint64_t stack_low;
    uint64_t arg_start;
    uint64_t arg_end;
    uint64_t env_start;
    uint64_t env_end;
} linux_user_stack_result_t;

typedef struct {
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
    uint8_t secure_exec;
} linux_user_stack_identity_t;

typedef int (*linux_exec_copy_from_user_fn)(void *context,
                                            void *destination,
                                            uint64_t source,
                                            uint64_t length);

void linux_exec_payload_reset(linux_exec_payload_t *payload);
int linux_exec_payload_capture_vector_with(
    linux_exec_payload_t *payload, void *copy_context,
    linux_exec_copy_from_user_fn copy_from_user, uint64_t user_vector,
    int environment);
int linux_exec_payload_append(linux_exec_payload_t *payload,
                              const char *string, int environment,
                              uint32_t *offset_out);
const char *linux_exec_payload_argument(const linux_exec_payload_t *payload,
                                        uint32_t index);
const char *linux_exec_payload_environment(const linux_exec_payload_t *payload,
                                           uint32_t index);
int linux_exec_payload_prepend_script(linux_exec_payload_t *payload,
                                      const char *interpreter,
                                      const char *interpreter_argument,
                                      const char *script_path);
int linux_exec_payload_ensure_argv0(linux_exec_payload_t *payload,
                                    const char *path);

int linux_user_stack_build(uint64_t address_space, const char *argv0,
                           uint64_t at_phdr, uint64_t at_phnum,
                           uint64_t at_entry, uint64_t at_base,
                           uint64_t *sp_out);
int linux_user_stack_build_vectors(uint64_t address_space,
                                   const char *const argv[], uint32_t argc,
                                   const char *const envp[], uint32_t envc,
                                   uint64_t at_phdr, uint64_t at_phnum,
                                   uint64_t at_entry, uint64_t at_base,
                                   uint64_t *sp_out);
int linux_user_stack_build_payload(uint64_t address_space,
                                   const linux_exec_payload_t *payload,
                                   uint64_t at_phdr, uint64_t at_phnum,
                                   uint64_t at_entry, uint64_t at_base,
                                   linux_user_stack_result_t *result);
int linux_user_stack_build_payload_with_identity(
    uint64_t address_space, const linux_exec_payload_t *payload,
    const linux_user_stack_identity_t *identity,
    uint64_t at_phdr, uint64_t at_phnum,
    uint64_t at_entry, uint64_t at_base,
    linux_user_stack_result_t *result);

#endif
