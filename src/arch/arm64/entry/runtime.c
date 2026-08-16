/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 entry adapters for the common Linux process runtime. */

#include "kernel/arch_user.h"
#include "arch/arm64/linux_abi.h"
#include "arch/arm64/syscall.h"
#include "arch/arm64/user_enter.h"
#include "arch/arm64/vm.h"
#include "kernel/linux_errno.h"

int edge_arm64_linux_stat_to_user(
    void *context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_destination, const kernel_file_metadata_t *metadata) {
    edge_arm64_linux_stat_t result = {0};
    if (!copy_to_user || !user_destination || !metadata)
        return -EDGE_LINUX_EFAULT;
    if (metadata->size > INT64_MAX || metadata->blocks > INT64_MAX ||
        metadata->block_size > INT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    result.device = metadata->device;
    result.inode = metadata->inode;
    result.mode = metadata->mode;
    result.links = metadata->links;
    result.uid = metadata->uid;
    result.gid = metadata->gid;
    result.rdev = metadata->rdev;
    result.size = (int64_t)metadata->size;
    result.block_size = (int32_t)metadata->block_size;
    result.blocks = (int64_t)metadata->blocks;
    result.access_time_seconds = metadata->access_time.seconds;
    result.access_time_nanoseconds = metadata->access_time.nanoseconds;
    result.modification_time_seconds =
        metadata->modification_time.seconds;
    result.modification_time_nanoseconds =
        metadata->modification_time.nanoseconds;
    result.change_time_seconds = metadata->change_time.seconds;
    result.change_time_nanoseconds = metadata->change_time.nanoseconds;
    return copy_to_user(context, user_destination, &result, sizeof(result)) < 0 ?
           -EDGE_LINUX_EFAULT : 0;
}

uint16_t arch_user_elf_machine(void) {
    return 183u; /* ELF EM_AARCH64. */
}

void arch_syscall_register(arch_syscall_handler_t handler) {
    edgeos_arm64_syscall_register(handler);
}

__attribute__((noreturn)) void arch_user_enter(uint64_t address_space,
                                               uint64_t entry,
                                               uint64_t stack_pointer,
                                               uint64_t kernel_stack_pointer) {
    edgeos_arm64_address_space_activate(address_space);
    edgeos_arm64_enter_user(
                            edgeos_arm64_address_space_ttbr_value(address_space),
                            entry, stack_pointer,
                            kernel_stack_pointer);
}

__attribute__((noreturn)) void arch_user_resume(uint64_t address_space,
                                                const arch_user_frame_t *frame,
                                                uint64_t kernel_stack_pointer) {
    edgeos_arm64_address_space_activate(address_space);
    edgeos_arm64_resume_user(
                             edgeos_arm64_address_space_ttbr_value(address_space),
                             frame, kernel_stack_pointer);
}
