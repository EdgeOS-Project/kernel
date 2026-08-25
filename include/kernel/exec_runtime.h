/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent exec runtime interface.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux exec policy is architecture-independent. Architecture runtimes
 * receive a shared transaction only for native image mapping, address-space
 * replacement, descriptor mechanics, and entry-register construction.
 */

#ifndef EDGEOS_KERNEL_EXEC_RUNTIME_H
#define EDGEOS_KERNEL_EXEC_RUNTIME_H

#include <stdint.h>
#include "kernel/credentials.h"
#include "kernel/exec_payload.h"
#include "vfs/vfs.h"

typedef struct kernel_exec_request {
    /* Canonical kernel pathname resolved by shared Linux syscall policy. */
    char *path;
    /* Optional open file used by execveat(AT_EMPTY_PATH) and procfd exec. */
    const vfs_inode_t *inode;
    vfs_superblock_t *superblock;
    /* Optional memory descriptor used when no VFS inode backs execveat. */
    int32_t memory_descriptor;
    uint64_t argv_user;
    uint64_t envp_user;
    uint8_t vector_word_size;
    uint8_t memory_descriptor_supplied;
    uint8_t nofollow;
} kernel_exec_request_t;

typedef struct kernel_exec_descriptor_source {
    vfs_inode_t inode;
    vfs_superblock_t *superblock;
    uint8_t active;
} kernel_exec_descriptor_source_t;

typedef uint64_t kernel_exec_file_handle_t;

#define KERNEL_EXEC_FILE_HANDLE_NONE 0u

#define KERNEL_EXEC_PATH_CAPACITY 4096u
#define KERNEL_EXEC_ARCHITECTURE_STATE_BYTES 1024u

typedef struct kernel_exec_file {
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint8_t mount_nosuid;
    uint8_t mount_noexec;
} kernel_exec_file_t;

typedef struct kernel_exec_credentials {
    linux_credential_state_t identity;
    uint32_t parent_death_signal;
    uint8_t no_new_privs;
    uint8_t dumpable;
} kernel_exec_credentials_t;

typedef struct kernel_exec_reset_configuration {
    uint8_t detach_signal_handlers;
    uint8_t reset_signal_dispositions;
    uint8_t disable_signal_altstack;
    uint8_t reset_thread_state;
    uint8_t reset_membarrier;
    uint8_t reset_architecture_tls;
    uint8_t reset_floating_point;
} kernel_exec_reset_configuration_t;

typedef union kernel_exec_architecture_state {
    uint64_t alignment;
    uint8_t bytes[KERNEL_EXEC_ARCHITECTURE_STATE_BYTES];
} kernel_exec_architecture_state_t;

typedef struct kernel_exec_state {
    void *task;
    char *path;
    char *script_path;
    uint32_t path_capacity;
    int32_t owner_pid;
    int32_t process_id;
    kernel_exec_payload_handle_t payload_handle;
    linux_exec_payload_t *payload;
    kernel_exec_file_t file;
    kernel_exec_credentials_t credentials;
    kernel_exec_descriptor_source_t descriptor_source;
    kernel_exec_architecture_state_t architecture;
    uint8_t image_prepared;
    uint8_t point_of_no_return;
    uint8_t image_committed;
    uint8_t files_unshared;
    uint8_t credentials_prepared;
    uint8_t secure_exec;
} kernel_exec_state_t;

int kernel_exec_descriptor_source_acquire(
    int32_t descriptor, kernel_exec_descriptor_source_t *source);
void kernel_exec_descriptor_source_release(
    kernel_exec_descriptor_source_t *source);

/*
 * Common code owns pathname and shebang policy, argument capture, executable
 * permission checks, credential transitions, and the complete exec commit
 * order. Backends implement only native task access, VFS/ELF mechanics,
 * address-space replacement, descriptor-table mechanics, and user entry.
 */
int process_exec_arch_initialize(kernel_exec_state_t *state);
int process_exec_arch_supply_file(kernel_exec_state_t *state,
                                  const vfs_inode_t *inode,
                                  vfs_superblock_t *superblock);
int process_exec_arch_current_file(vfs_inode_t *inode,
                                   vfs_superblock_t **superblock);
int process_exec_arch_copy_from_user(void *context, void *destination,
                                    uint64_t source, uint64_t size);
int process_exec_arch_resolve(kernel_exec_state_t *state, int nofollow);
int process_exec_arch_probe_image(kernel_exec_state_t *state);
int process_exec_arch_read_image(kernel_exec_state_t *state,
                                 void *destination, uint32_t capacity);
int process_exec_arch_prepare_image(kernel_exec_state_t *state);
int process_exec_arch_unshare_files(kernel_exec_state_t *state);
/*
 * Remove every other thread in the caller's thread group before replacing
 * the shared address space. The backend must either fail without changing
 * task state or complete the operation so exec can cross its commit point.
 */
int process_exec_arch_de_thread(kernel_exec_state_t *state);
int process_exec_arch_commit_image(kernel_exec_state_t *state);
int process_exec_arch_reset_state(
    kernel_exec_state_t *state,
    const kernel_exec_reset_configuration_t *configuration);
int process_exec_arch_get_credentials(
    kernel_exec_state_t *state, kernel_exec_credentials_t *credentials);
int process_exec_arch_set_credentials(
    kernel_exec_state_t *state,
    const kernel_exec_credentials_t *credentials);
int process_exec_arch_set_identity(kernel_exec_state_t *state,
                                   const char *command_name);
int process_exec_arch_close_on_exec(kernel_exec_state_t *state);
void process_exec_arch_wake_vfork_parent(kernel_exec_state_t *state);
int process_exec_arch_enter(kernel_exec_state_t *state);
void process_exec_arch_abort(kernel_exec_state_t *state);
int process_exec_arch_fatal(kernel_exec_state_t *state, int status);

int kernel_exec_file_create(vfs_superblock_t *superblock,
                            const vfs_inode_t *inode,
                            kernel_exec_file_handle_t *handle);
int kernel_exec_file_retain(kernel_exec_file_handle_t handle);
void kernel_exec_file_release(kernel_exec_file_handle_t handle);
int kernel_exec_file_snapshot(kernel_exec_file_handle_t handle,
                              vfs_superblock_t **superblock,
                              vfs_inode_t *inode);

int64_t kernel_process_exec(const kernel_exec_request_t *request);

#endif
