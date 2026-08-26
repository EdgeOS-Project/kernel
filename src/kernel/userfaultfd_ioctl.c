/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux userfaultfd ioctl service.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/credentials.h"
#include "kernel/mm_runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/task_scratch.h"
#include "kernel/userfaultfd.h"
#include "kernel/userfaultfd_runtime.h"
#include "string.h"

#define KERNEL_UFFDIO_REGISTER   0xc020aa00u
#define KERNEL_UFFDIO_UNREGISTER 0x8010aa01u
#define KERNEL_UFFDIO_WAKE       0x8010aa02u
#define KERNEL_UFFDIO_COPY       0xc028aa03u
#define KERNEL_UFFDIO_ZEROPAGE   0xc020aa04u
#define KERNEL_UFFDIO_MOVE       0xc028aa05u
#define KERNEL_UFFDIO_WRITEPROTECT 0xc018aa06u
#define KERNEL_UFFDIO_CONTINUE   0xc020aa07u
#define KERNEL_UFFDIO_POISON     0xc020aa08u
#define KERNEL_UFFDIO_API        0xc018aa3fu
#define KERNEL_UFFD_PAGE_SIZE 4096u

static int userfaultfd_copy_from_user(
    const kernel_ioctl_request_t *request, void *destination,
    uint64_t source, uint64_t size) {
    if (!request || !request->copy_from_user || !source)
        return -EDGE_LINUX_EFAULT;
    return request->copy_from_user(
        request->copy_context, destination, source, size) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int userfaultfd_copy_to_user(
    const kernel_ioctl_request_t *request, uint64_t destination,
    const void *source, uint64_t size) {
    if (!request || !request->copy_to_user || !destination)
        return -EDGE_LINUX_EFAULT;
    return request->copy_to_user(
        request->copy_context, destination, source, size) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int userfaultfd_fill_page(
    const kernel_ioctl_request_t *request, uint64_t address_space,
    uint64_t destination, uint64_t source, int zero) {
    kernel_task_scratch_t *scratch = arch_task_scratch_current();
    uint8_t *page;
    int resident;
    int poisoned;

    if (!scratch) return -EDGE_LINUX_ENOMEM;
    page = scratch->xattr_scratch;
    poisoned = arch_mm_address_space_page_poisoned(
        address_space, destination);
    if (poisoned < 0) return poisoned;
    if (poisoned) return -EDGE_LINUX_EEXIST;
    resident = arch_mm_address_space_page_resident(
        address_space, destination);
    if (resident < 0) return resident;
    if (resident) return -EDGE_LINUX_EEXIST;
    if (zero)
        memset(page, 0, KERNEL_UFFD_PAGE_SIZE);
    else if (userfaultfd_copy_from_user(
                 request, page, source, KERNEL_UFFD_PAGE_SIZE) < 0)
        return -EDGE_LINUX_EFAULT;
    return arch_mm_address_space_copy(
        address_space, destination, page, KERNEL_UFFD_PAGE_SIZE,
        KERNEL_MM_PROCESS_VM_WRITE);
}

int64_t kernel_userfaultfd_ioctl(const kernel_ioctl_request_t *request) {
    kernel_userfaultfd_state_t state;
    int context_id;
    int status;

    if (!request) return -EDGE_LINUX_EIO;
    context_id = kernel_userfaultfd_descriptor_id(request->descriptor);
    if (context_id < 0) return -EDGE_LINUX_ENOTTY;
    if (!request->argument) return -EDGE_LINUX_EFAULT;
    if (kernel_userfaultfd_query(context_id, &state) < 0)
        return -EDGE_LINUX_EBADF;

    if (request->command == KERNEL_UFFDIO_API) {
        kernel_uffdio_api_t api;
        linux_credential_state_t credentials;
        status = userfaultfd_copy_from_user(
            request, &api, request->argument, sizeof(api));
        if (status < 0) return status;
        if (api.features & KERNEL_UFFD_FEATURE_EVENT_FORK) {
            if (kernel_current_credentials_get(&credentials) < 0)
                return -EDGE_LINUX_ESRCH;
            if (!(credentials.capabilities.effective &
                  (1ULL << EDGE_LINUX_CAP_SYS_PTRACE))) {
                memset(&api, 0, sizeof(api));
                if (userfaultfd_copy_to_user(
                        request, request->argument,
                        &api, sizeof(api)) < 0)
                    return -EDGE_LINUX_EFAULT;
                return -EDGE_LINUX_EPERM;
            }
        }
        status = kernel_userfaultfd_negotiate(context_id, &api);
        if (userfaultfd_copy_to_user(
                request, request->argument, &api, sizeof(api)) < 0)
            return -EDGE_LINUX_EFAULT;
        return status;
    }

    if (!state.api_ready) return -EDGE_LINUX_EINVAL;
    if (request->command == KERNEL_UFFDIO_REGISTER) {
        kernel_uffdio_register_t registration;
        uint64_t backing_page_size;
        uint8_t backing_page_shift = 0u;
        int huge_backing;
        int shmem_backing;
        memset(&registration, 0, sizeof(registration));
        status = userfaultfd_copy_from_user(
            request, &registration, request->argument,
            sizeof(registration) - sizeof(registration.ioctls));
        if (status < 0) return status;
        status = arch_mm_address_space_range_mapped(
            state.address_space,
            registration.range.start, registration.range.length);
        if (status < 0) return status;
        status = arch_mm_address_space_shmem_page_size(
            state.address_space, registration.range.start,
            registration.range.length, &backing_page_size);
        shmem_backing = status == 0;
        if (status < 0) {
            if (registration.mode & KERNEL_UFFD_REGISTER_MODE_MINOR)
                return status;
            backing_page_size = KERNEL_UFFD_PAGE_SIZE;
        }
        if (!backing_page_size ||
            (backing_page_size & (backing_page_size - 1u)))
            return -EDGE_LINUX_EINVAL;
        while ((UINT64_C(1) << backing_page_shift) < backing_page_size)
            ++backing_page_shift;
        if ((registration.range.start | registration.range.length) &
            (backing_page_size - 1u))
            return -EDGE_LINUX_EINVAL;
        huge_backing = backing_page_size > KERNEL_UFFD_PAGE_SIZE;
        if ((registration.mode & KERNEL_UFFD_REGISTER_MODE_MISSING) &&
            shmem_backing &&
            !(state.features & (huge_backing ?
              KERNEL_UFFD_FEATURE_MISSING_HUGETLBFS :
              KERNEL_UFFD_FEATURE_MISSING_SHMEM)))
            return -EDGE_LINUX_EINVAL;
        if ((registration.mode & KERNEL_UFFD_REGISTER_MODE_MINOR) &&
            !(state.features & (huge_backing ?
              KERNEL_UFFD_FEATURE_MINOR_HUGETLBFS :
              KERNEL_UFFD_FEATURE_MINOR_SHMEM)))
            return -EDGE_LINUX_EINVAL;
        if (huge_backing &&
            (registration.mode & KERNEL_UFFD_REGISTER_MODE_WP))
            return -EDGE_LINUX_EINVAL;
        status = kernel_userfaultfd_register_backing(
            context_id, &registration, backing_page_shift);
        if (status < 0) return status;
        if (huge_backing) {
            registration.ioctls &=
                ~(UINT64_C(1) << KERNEL_UFFDIO_ZEROPAGE_NUMBER);
            registration.ioctls &=
                ~(UINT64_C(1) << KERNEL_UFFDIO_MOVE_NUMBER);
            registration.ioctls &=
                ~(UINT64_C(1) << KERNEL_UFFDIO_POISON_NUMBER);
        }
        status = userfaultfd_copy_to_user(
            request, request->argument, &registration,
            sizeof(registration));
        if (status < 0) {
            (void)kernel_userfaultfd_unregister(
                context_id, &registration.range);
            return status;
        }
        return 0;
    }

    if (request->command == KERNEL_UFFDIO_UNREGISTER ||
        request->command == KERNEL_UFFDIO_WAKE) {
        kernel_uffdio_range_t range;
        status = userfaultfd_copy_from_user(
            request, &range, request->argument, sizeof(range));
        if (status < 0) return status;
        status = arch_mm_address_space_range_mapped(
            state.address_space, range.start, range.length);
        if (status < 0) return status;
        if (request->command == KERNEL_UFFDIO_UNREGISTER) {
            uint64_t writeprotect_address_space = 0;
            status = kernel_userfaultfd_unregister_validate(
                context_id, &range, &writeprotect_address_space);
            if (status < 0) return status;
            status = kernel_userfaultfd_writeprotect_intersects(
                context_id, &range, &writeprotect_address_space);
            if (status < 0) return status;
            if (status > 0) {
                status = arch_mm_address_space_write_protect(
                    writeprotect_address_space, range.start,
                    range.length, 0);
                if (status < 0) return status;
            }
            return kernel_userfaultfd_unregister(context_id, &range);
        }
        status = kernel_userfaultfd_validate_resolution(
            context_id, &range, 0, &state.address_space);
        if (status < 0) return status;
        (void)kernel_userfaultfd_resolve(context_id, &range);
        return 0;
    }

    if (request->command == KERNEL_UFFDIO_COPY) {
        kernel_uffdio_copy_t copy;
        kernel_uffdio_range_t range;
        uint64_t completed = 0;
        memset(&copy, 0, sizeof(copy));
        status = userfaultfd_copy_from_user(
            request, &copy, request->argument,
            sizeof(copy) - sizeof(copy.copied));
        if (status < 0) return status;
        range.start = copy.destination;
        range.length = copy.length;
        if (copy.source > UINT64_MAX - copy.length)
            return -EDGE_LINUX_EINVAL;
        status = arch_mm_address_space_range_mapped(
            state.address_space, range.start, range.length);
        if (status < 0) return status;
        status = kernel_userfaultfd_validate_resolution(
            context_id, &range, copy.mode, &state.address_space);
        if (status < 0) return status;
        if (copy.mode & KERNEL_UFFDIO_COPY_MODE_WP) {
            status = kernel_userfaultfd_writeprotect_validate(
                context_id, &range,
                KERNEL_UFFDIO_WRITEPROTECT_MODE_WP,
                &state.address_space);
            if (status < 0) {
                (void)kernel_userfaultfd_cancel_resolution(
                    context_id, &range);
                return status == -EDGE_LINUX_ENOENT ?
                    -EDGE_LINUX_EINVAL : status;
            }
        }
        while (completed < copy.length) {
            kernel_uffdio_range_t page_range = {
                .start = copy.destination + completed,
                .length = KERNEL_UFFD_PAGE_SIZE,
            };
            status = userfaultfd_fill_page(
                request, state.address_space,
                page_range.start, copy.source + completed, 0);
            if (status < 0) break;
            if (copy.mode & KERNEL_UFFDIO_COPY_MODE_WP) {
                status = arch_mm_address_space_write_protect(
                    state.address_space, page_range.start,
                    page_range.length, 1);
                if (status < 0) break;
                status = kernel_userfaultfd_writeprotect_commit(
                    context_id, &page_range,
                    KERNEL_UFFDIO_WRITEPROTECT_MODE_WP |
                    KERNEL_UFFDIO_WRITEPROTECT_MODE_DONTWAKE);
                if (status < 0) {
                    (void)arch_mm_address_space_write_protect(
                        state.address_space, page_range.start,
                        page_range.length, 0);
                    break;
                }
            }
            completed += KERNEL_UFFD_PAGE_SIZE;
            if (!(copy.mode & KERNEL_UFFDIO_MODE_DONTWAKE))
                (void)kernel_userfaultfd_resolve(
                    context_id, &page_range);
        }
        copy.copied = completed ? (int64_t)completed : status;
        if (completed < copy.length)
            (void)kernel_userfaultfd_cancel_resolution(
                context_id, &range);
        else if (copy.mode & KERNEL_UFFDIO_MODE_DONTWAKE)
            (void)kernel_userfaultfd_cancel_resolution(
                context_id, &range);
        if (userfaultfd_copy_to_user(
                request, request->argument, &copy, sizeof(copy)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (completed == copy.length) return 0;
        return completed ? -EDGE_LINUX_EAGAIN : status;
    }

    if (request->command == KERNEL_UFFDIO_ZEROPAGE) {
        kernel_uffdio_zeropage_t zero;
        uint64_t completed = 0;
        memset(&zero, 0, sizeof(zero));
        status = userfaultfd_copy_from_user(
            request, &zero, request->argument,
            sizeof(zero) - sizeof(zero.zeroed));
        if (status < 0) return status;
        if (zero.mode & ~KERNEL_UFFDIO_MODE_DONTWAKE)
            return -EDGE_LINUX_EINVAL;
        status = arch_mm_address_space_range_mapped(
            state.address_space, zero.range.start, zero.range.length);
        if (status < 0) return status;
        status = kernel_userfaultfd_validate_resolution(
            context_id, &zero.range, zero.mode, &state.address_space);
        if (status < 0) return status;
        while (completed < zero.range.length) {
            kernel_uffdio_range_t page_range = {
                .start = zero.range.start + completed,
                .length = KERNEL_UFFD_PAGE_SIZE,
            };
            status = userfaultfd_fill_page(
                request, state.address_space,
                page_range.start, 0, 1);
            if (status < 0) break;
            completed += KERNEL_UFFD_PAGE_SIZE;
            if (!(zero.mode & KERNEL_UFFDIO_MODE_DONTWAKE))
                (void)kernel_userfaultfd_resolve(
                    context_id, &page_range);
        }
        zero.zeroed = completed ? (int64_t)completed : status;
        if (completed < zero.range.length)
            (void)kernel_userfaultfd_cancel_resolution(
                context_id, &zero.range);
        else if (zero.mode & KERNEL_UFFDIO_MODE_DONTWAKE)
            (void)kernel_userfaultfd_cancel_resolution(
                context_id, &zero.range);
        if (userfaultfd_copy_to_user(
                request, request->argument, &zero, sizeof(zero)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (completed == zero.range.length) return 0;
        return completed ? -EDGE_LINUX_EAGAIN : status;
    }

    if (request->command == KERNEL_UFFDIO_CONTINUE) {
        kernel_uffdio_continue_t continuation;
        uint64_t completed = 0;
        uint64_t backing_page_size;

        memset(&continuation, 0, sizeof(continuation));
        status = userfaultfd_copy_from_user(
            request, &continuation, request->argument,
            sizeof(continuation) - sizeof(continuation.mapped));
        if (status < 0) return status;
        if (!continuation.range.length ||
            continuation.range.start >
                UINT64_MAX - continuation.range.length ||
            (continuation.mode &
             ~(KERNEL_UFFDIO_CONTINUE_MODE_DONTWAKE |
               KERNEL_UFFDIO_CONTINUE_MODE_WP)))
            return -EDGE_LINUX_EINVAL;
        status = arch_mm_address_space_range_mapped(
            state.address_space, continuation.range.start,
            continuation.range.length);
        if (status < 0) return status;
        status = arch_mm_address_space_shmem_range_supported(
            state.address_space, continuation.range.start,
            continuation.range.length);
        if (status < 0) return status;
        status = arch_mm_address_space_shmem_page_size(
            state.address_space, continuation.range.start,
            continuation.range.length, &backing_page_size);
        if (status < 0) return status;
        if ((continuation.range.start | continuation.range.length) &
            (backing_page_size - 1u))
            return -EDGE_LINUX_EINVAL;
        status = kernel_userfaultfd_continue_validate(
            context_id, &continuation.range, continuation.mode,
            &state.address_space);
        if (status < 0) return status;
        if (continuation.mode & KERNEL_UFFDIO_CONTINUE_MODE_WP) {
            status = kernel_userfaultfd_writeprotect_validate(
                context_id, &continuation.range,
                KERNEL_UFFDIO_WRITEPROTECT_MODE_WP,
                &state.address_space);
            if (status < 0) {
                (void)kernel_userfaultfd_cancel_resolution(
                    context_id, &continuation.range);
                return status == -EDGE_LINUX_ENOENT ?
                    -EDGE_LINUX_EINVAL : status;
            }
        }
        __sync_synchronize();
        while (completed < continuation.range.length) {
            kernel_uffdio_range_t page_range = {
                .start = continuation.range.start + completed,
                .length = KERNEL_UFFD_PAGE_SIZE,
            };
            status = arch_mm_address_space_shmem_page_state(
                state.address_space, page_range.start);
            if (status <= 0) {
                status = status < 0 ? status : -EDGE_LINUX_EFAULT;
                break;
            }
            status = arch_mm_address_space_page_resident(
                state.address_space, page_range.start);
            if (status < 0) break;
            if (status > 0) {
                status = -EDGE_LINUX_EEXIST;
                break;
            }
            status = kernel_mm_resolve_user_page(
                state.address_space, page_range.start,
                KERNEL_MM_PROT_READ);
            if (status <= 0) {
                status = status < 0 ? status : -EDGE_LINUX_EFAULT;
                break;
            }
            if (continuation.mode & KERNEL_UFFDIO_CONTINUE_MODE_WP) {
                status = arch_mm_address_space_write_protect(
                    state.address_space, page_range.start,
                    page_range.length, 1);
                if (status < 0) break;
                status = kernel_userfaultfd_writeprotect_commit(
                    context_id, &page_range,
                    KERNEL_UFFDIO_WRITEPROTECT_MODE_WP |
                    KERNEL_UFFDIO_WRITEPROTECT_MODE_DONTWAKE);
                if (status < 0) {
                    (void)arch_mm_address_space_write_protect(
                        state.address_space, page_range.start,
                        page_range.length, 0);
                    break;
                }
            }
            completed += KERNEL_UFFD_PAGE_SIZE;
            if (!(continuation.mode &
                  KERNEL_UFFDIO_CONTINUE_MODE_DONTWAKE))
                (void)kernel_userfaultfd_continue_resolve(
                    context_id, &page_range);
        }
        continuation.mapped = completed ? (int64_t)completed : status;
        if (completed < continuation.range.length ||
            (continuation.mode &
             KERNEL_UFFDIO_CONTINUE_MODE_DONTWAKE))
            (void)kernel_userfaultfd_cancel_resolution(
                context_id, &continuation.range);
        if (userfaultfd_copy_to_user(
                request, request->argument, &continuation,
                sizeof(continuation)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (completed == continuation.range.length) return 0;
        return completed ? -EDGE_LINUX_EAGAIN : status;
    }

    if (request->command == KERNEL_UFFDIO_MOVE) {
        kernel_uffdio_move_t move;
        kernel_uffdio_range_t destination_range;
        uint64_t completed = 0;

        memset(&move, 0, sizeof(move));
        status = userfaultfd_copy_from_user(
            request, &move, request->argument,
            sizeof(move) - sizeof(move.moved));
        if (status < 0) return status;
        if (!move.length ||
            ((move.source | move.destination | move.length) &
             (KERNEL_UFFD_PAGE_SIZE - 1u)) ||
            move.source > UINT64_MAX - move.length ||
            move.destination > UINT64_MAX - move.length ||
            (move.mode & ~(KERNEL_UFFDIO_MOVE_MODE_DONTWAKE |
                           KERNEL_UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES)))
            return -EDGE_LINUX_EINVAL;
        destination_range.start = move.destination;
        destination_range.length = move.length;
        status = arch_mm_address_space_range_mapped(
            state.address_space, move.source, move.length);
        if (status < 0) return status;
        status = arch_mm_address_space_range_mapped(
            state.address_space, move.destination, move.length);
        if (status < 0) return status;
        status = kernel_userfaultfd_validate_resolution(
            context_id, &destination_range, 0, &state.address_space);
        if (status < 0) return status;
        status = arch_mm_address_space_move_validate(
            state.address_space, move.source, move.destination,
            move.length);
        if (status < 0) {
            (void)kernel_userfaultfd_cancel_resolution(
                context_id, &destination_range);
            return status;
        }
        while (completed < move.length) {
            kernel_uffdio_range_t page_range = {
                .start = move.destination + completed,
                .length = KERNEL_UFFD_PAGE_SIZE,
            };
            status = arch_mm_address_space_move_page(
                state.address_space, move.source + completed,
                move.destination + completed,
                (move.mode &
                 KERNEL_UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES) != 0u);
            if (status < 0) break;
            completed += KERNEL_UFFD_PAGE_SIZE;
            if (!(move.mode & KERNEL_UFFDIO_MOVE_MODE_DONTWAKE))
                (void)kernel_userfaultfd_resolve(
                    context_id, &page_range);
        }
        move.moved = completed ? (int64_t)completed : status;
        if (completed < move.length ||
            (move.mode & KERNEL_UFFDIO_MOVE_MODE_DONTWAKE))
            (void)kernel_userfaultfd_cancel_resolution(
                context_id, &destination_range);
        if (userfaultfd_copy_to_user(
                request, request->argument, &move, sizeof(move)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (completed == move.length) return 0;
        return completed ? -EDGE_LINUX_EAGAIN : status;
    }

    if (request->command == KERNEL_UFFDIO_POISON) {
        kernel_uffdio_poison_t poison;
        uint64_t completed = 0;

        memset(&poison, 0, sizeof(poison));
        status = userfaultfd_copy_from_user(
            request, &poison, request->argument,
            sizeof(poison) - sizeof(poison.updated));
        if (status < 0) return status;
        if (!poison.range.length ||
            ((poison.range.start | poison.range.length) &
             (KERNEL_UFFD_PAGE_SIZE - 1u)) ||
            poison.range.start > UINT64_MAX - poison.range.length ||
            (poison.mode & ~KERNEL_UFFDIO_POISON_MODE_DONTWAKE))
            return -EDGE_LINUX_EINVAL;
        status = arch_mm_address_space_range_mapped(
            state.address_space, poison.range.start,
            poison.range.length);
        if (status < 0) return status;
        status = kernel_userfaultfd_validate_resolution(
            context_id, &poison.range, poison.mode,
            &state.address_space);
        if (status < 0) return status;
        while (completed < poison.range.length) {
            kernel_uffdio_range_t page_range = {
                .start = poison.range.start + completed,
                .length = KERNEL_UFFD_PAGE_SIZE,
            };
            status = arch_mm_address_space_poison_page(
                state.address_space, page_range.start);
            if (status < 0) break;
            completed += KERNEL_UFFD_PAGE_SIZE;
            if (!(poison.mode & KERNEL_UFFDIO_POISON_MODE_DONTWAKE))
                (void)kernel_userfaultfd_resolve(
                    context_id, &page_range);
        }
        poison.updated = completed ? (int64_t)completed : status;
        if (completed < poison.range.length ||
            (poison.mode & KERNEL_UFFDIO_POISON_MODE_DONTWAKE))
            (void)kernel_userfaultfd_cancel_resolution(
                context_id, &poison.range);
        if (userfaultfd_copy_to_user(
                request, request->argument, &poison,
                sizeof(poison)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (completed == poison.range.length) return 0;
        return completed ? -EDGE_LINUX_EAGAIN : status;
    }

    if (request->command == KERNEL_UFFDIO_WRITEPROTECT) {
        kernel_uffdio_writeprotect_t writeprotect;
        int enable;

        status = userfaultfd_copy_from_user(
            request, &writeprotect, request->argument,
            sizeof(writeprotect));
        if (status < 0) return status;
        status = arch_mm_address_space_range_mapped(
            state.address_space, writeprotect.range.start,
            writeprotect.range.length);
        if (status < 0) return status;
        status = kernel_userfaultfd_writeprotect_validate(
            context_id, &writeprotect.range, writeprotect.mode,
            &state.address_space);
        if (status < 0) return status;
        enable = (writeprotect.mode &
                  KERNEL_UFFDIO_WRITEPROTECT_MODE_WP) != 0;
        status = arch_mm_address_space_write_protect(
            state.address_space, writeprotect.range.start,
            writeprotect.range.length, enable);
        if (status < 0) return status;
        status = kernel_userfaultfd_writeprotect_commit(
            context_id, &writeprotect.range, writeprotect.mode);
        if (status < 0)
            (void)arch_mm_address_space_write_protect(
                state.address_space, writeprotect.range.start,
                writeprotect.range.length, !enable);
        return status;
    }

    return -EDGE_LINUX_ENOTTY;
}
