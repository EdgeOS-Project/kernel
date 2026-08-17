/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Architecture-neutral Linux ALSA userspace transfer adapter.
 */

#ifndef EDGEOS_DEV_ALSA_USER_IO_H
#define EDGEOS_DEV_ALSA_USER_IO_H

#include <stdint.h>

typedef int (*edge_alsa_copy_from_user_fn)(
    void *context, void *destination, uint64_t source, uint32_t length);
typedef int (*edge_alsa_copy_to_user_fn)(
    void *context, uint64_t destination, const void *source,
    uint32_t length);

int64_t alsa_read_user(
    const char *path, uint64_t destination, uint64_t length,
    void *scratch, uint32_t scratch_capacity,
    edge_alsa_copy_to_user_fn copy_to_user_fn, void *copy_context);
int64_t alsa_write_user(
    const char *path, uint64_t source, uint64_t length,
    void *scratch, uint32_t scratch_capacity,
    edge_alsa_copy_from_user_fn copy_from_user_fn, void *copy_context);
int64_t alsa_ioctl_user(
    const char *path, uint32_t command, uint64_t argument,
    void *scratch, uint32_t scratch_capacity,
    edge_alsa_copy_from_user_fn copy_from_user_fn,
    edge_alsa_copy_to_user_fn copy_to_user_fn,
    void *copy_context, int *handled);

#endif
