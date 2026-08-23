/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux userfaultfd ioctl service.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/task_scratch.h"
#include "kernel/userfaultfd.h"
#include "kernel/userfaultfd_runtime.h"
#include "string.h"

#define KERNEL_UFFDIO_REGISTER   0xc020aa00u
#define KERNEL_UFFDIO_UNREGISTER 0x8010aa01u
#define KERNEL_UFFDIO_WAKE       0x8010aa02u
#define KERNEL_UFFDIO_COPY       0xc028aa03u
#define KERNEL_UFFDIO_ZEROPAGE   0xc020aa04u
#define KERNEL_UFFDIO_WRITEPROTECT 0xc018aa06u
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

    if (!scratch) return -EDGE_LINUX_ENOMEM;
    page = scratch->xattr_scratch;
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
        status = userfaultfd_copy_from_user(
            request, &api, request->argument, sizeof(api));
        if (status < 0) return status;
        status = kernel_userfaultfd_negotiate(context_id, &api);
        if (userfaultfd_copy_to_user(
                request, request->argument, &api, sizeof(api)) < 0)
            return -EDGE_LINUX_EFAULT;
        return status;
    }

    if (!state.api_ready) return -EDGE_LINUX_EINVAL;
    if (request->command == KERNEL_UFFDIO_REGISTER) {
        kernel_uffdio_register_t registration;
        memset(&registration, 0, sizeof(registration));
        status = userfaultfd_copy_from_user(
            request, &registration, request->argument,
            sizeof(registration) - sizeof(registration.ioctls));
        if (status < 0) return status;
        status = arch_mm_address_space_range_mapped(
            state.address_space,
            registration.range.start, registration.range.length);
        if (status < 0) return status;
        status = kernel_userfaultfd_register(context_id, &registration);
        if (status < 0) return status;
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
