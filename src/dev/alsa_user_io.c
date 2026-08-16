/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Architecture-neutral Linux ALSA userspace transfer adapter.
 */

#include "dev/alsa.h"
#include "dev/alsa_user_io.h"

#define EDGE_ALSA_EFAULT 14
#define EDGE_ALSA_EINVAL 22

static int alsa_user_copy_from(
    edge_alsa_copy_from_user_fn copy_fn, void *context,
    void *destination, uint64_t source, uint32_t length) {
    if (!copy_fn || !source) return -1;
    return copy_fn(context, destination, source, length);
}

static int alsa_user_copy_to(
    edge_alsa_copy_to_user_fn copy_fn, void *context,
    uint64_t destination, const void *source, uint32_t length) {
    if (!copy_fn || !destination) return -1;
    return copy_fn(context, destination, source, length);
}

int64_t alsa_read_user(
    const char *path, uint64_t destination, uint64_t length,
    void *scratch, uint32_t scratch_capacity,
    edge_alsa_copy_to_user_fn copy_to_user_fn, void *copy_context) {
    uint64_t done = 0;

    if (alsa_path_kind(path) != EDGE_ALSA_NODE_PCM_CAPTURE)
        return -EDGE_ALSA_EINVAL;
    if ((!destination && length) || !scratch || !scratch_capacity)
        return -EDGE_ALSA_EFAULT;
    while (done < length) {
        uint32_t chunk = (uint32_t)(
            length - done > scratch_capacity ?
            scratch_capacity : length - done);
        int result = alsa_read(path, scratch, chunk);

        if (result < 0) return done ? (int64_t)done : result;
        if (!result) break;
        if (alsa_user_copy_to(
                copy_to_user_fn, copy_context, destination + done,
                scratch, (uint32_t)result) < 0)
            return done ? (int64_t)done : -EDGE_ALSA_EFAULT;
        done += (uint32_t)result;
        if ((uint32_t)result < chunk) break;
    }
    return (int64_t)done;
}

int64_t alsa_write_user(
    const char *path, uint64_t source, uint64_t length,
    void *scratch, uint32_t scratch_capacity,
    edge_alsa_copy_from_user_fn copy_from_user_fn, void *copy_context) {
    uint64_t done = 0;

    if (alsa_path_kind(path) != EDGE_ALSA_NODE_PCM_PLAYBACK)
        return -EDGE_ALSA_EINVAL;
    if ((!source && length) || !scratch || !scratch_capacity)
        return -EDGE_ALSA_EFAULT;
    while (done < length) {
        uint32_t chunk = (uint32_t)(
            length - done > scratch_capacity ?
            scratch_capacity : length - done);
        int result;

        if (alsa_user_copy_from(
                copy_from_user_fn, copy_context, scratch,
                source + done, chunk) < 0)
            return done ? (int64_t)done : -EDGE_ALSA_EFAULT;
        result = alsa_write(path, scratch, chunk);
        if (result < 0) return done ? (int64_t)done : result;
        if (!result) break;
        done += (uint32_t)result;
        if ((uint32_t)result < chunk) break;
    }
    return (int64_t)done;
}

static int64_t alsa_user_transfer_frames(
    const char *path, uint32_t command, uint64_t argument,
    void *scratch, uint32_t scratch_capacity,
    edge_alsa_copy_from_user_fn copy_from_user_fn,
    edge_alsa_copy_to_user_fn copy_to_user_fn,
    void *copy_context) {
    struct edge_snd_xferi transfer;
    uint64_t byte_count;
    uint64_t done = 0;
    int capture = alsa_ioctl_nr(command) == 0x51;

    if (!argument || !scratch || !scratch_capacity)
        return -EDGE_ALSA_EINVAL;
    if (capture &&
        alsa_path_kind(path) != EDGE_ALSA_NODE_PCM_CAPTURE)
        return -EDGE_ALSA_EINVAL;
    if (!capture &&
        alsa_path_kind(path) != EDGE_ALSA_NODE_PCM_PLAYBACK)
        return -EDGE_ALSA_EINVAL;
    if (alsa_user_copy_from(
            copy_from_user_fn, copy_context, &transfer, argument,
            sizeof(transfer)) < 0)
        return -EDGE_ALSA_EFAULT;
    if (transfer.frames >
        UINT64_MAX / EDGE_ALSA_PCM_FRAME_BYTES)
        return -EDGE_ALSA_EINVAL;
    byte_count =
        (uint64_t)transfer.frames * EDGE_ALSA_PCM_FRAME_BYTES;
    while (done < byte_count) {
        uint32_t chunk = (uint32_t)(
            byte_count - done > scratch_capacity ?
            scratch_capacity : byte_count - done);
        int result;

        if (!capture &&
            alsa_user_copy_from(
                copy_from_user_fn, copy_context, scratch,
                (uint64_t)(uintptr_t)transfer.buf + done, chunk) < 0)
            return -EDGE_ALSA_EFAULT;
        result = capture ?
            alsa_read(path, scratch, chunk) :
            alsa_write(path, scratch, chunk);
        if (result < 0) {
            transfer.result = done ?
                (edge_snd_pcm_sframes_t)(
                    done / EDGE_ALSA_PCM_FRAME_BYTES) : result;
            (void)alsa_user_copy_to(
                copy_to_user_fn, copy_context, argument, &transfer,
                sizeof(transfer));
            return done ? 0 : result;
        }
        if (capture && result > 0 &&
            alsa_user_copy_to(
                copy_to_user_fn, copy_context,
                (uint64_t)(uintptr_t)transfer.buf + done,
                scratch, (uint32_t)result) < 0)
            return -EDGE_ALSA_EFAULT;
        if (!result) break;
        done += (uint32_t)result;
        if ((uint32_t)result < chunk) break;
    }
    transfer.result = (edge_snd_pcm_sframes_t)(
        done / EDGE_ALSA_PCM_FRAME_BYTES);
    if (alsa_user_copy_to(
            copy_to_user_fn, copy_context, argument, &transfer,
            sizeof(transfer)) < 0)
        return -EDGE_ALSA_EFAULT;
    return 0;
}

int64_t alsa_ioctl_user(
    const char *path, uint32_t command, uint64_t argument,
    void *scratch, uint32_t scratch_capacity,
    edge_alsa_copy_from_user_fn copy_from_user_fn,
    edge_alsa_copy_to_user_fn copy_to_user_fn,
    void *copy_context, int *handled) {
    uint32_t size;
    int result;

    if (handled) *handled = 0;
    if (alsa_path_kind(path) == EDGE_ALSA_NODE_NONE)
        return 0;
    if (handled) *handled = 1;
    if (alsa_ioctl_type(command) == 'A' &&
        (alsa_ioctl_nr(command) == 0x50 ||
         alsa_ioctl_nr(command) == 0x51))
        return alsa_user_transfer_frames(
            path, command, argument, scratch, scratch_capacity,
            copy_from_user_fn, copy_to_user_fn, copy_context);

    size = alsa_ioctl_arg_size(command);
    if (size > scratch_capacity || (size && !scratch))
        return -EDGE_ALSA_EINVAL;
    if (size && alsa_user_copy_from(
            copy_from_user_fn, copy_context, scratch, argument, size) < 0)
        return -EDGE_ALSA_EFAULT;
    result = alsa_ioctl_kernel(
        path, command, size ? scratch : 0);
    if (result < 0) return result;
    if (size && alsa_ioctl_type(command) == 'U' &&
        alsa_ioctl_nr(command) == 0x10) {
        struct edge_snd_ctl_elem_list *list =
            (struct edge_snd_ctl_elem_list *)scratch;

        if (list->pids && list->used) {
            for (uint32_t index = 0; index < list->used; ++index) {
                struct edge_snd_ctl_elem_id id;

                if (alsa_ctl_elem_id_for_index(
                        list->offset + index, &id) < 0)
                    return -EDGE_ALSA_EINVAL;
                if (alsa_user_copy_to(
                        copy_to_user_fn, copy_context,
                        list->pids +
                            (uint64_t)index * sizeof(id),
                        &id, sizeof(id)) < 0)
                    return -EDGE_ALSA_EFAULT;
            }
        }
    }
    if (size && alsa_user_copy_to(
            copy_to_user_fn, copy_context, argument, scratch, size) < 0)
        return -EDGE_ALSA_EFAULT;
    return 0;
}
