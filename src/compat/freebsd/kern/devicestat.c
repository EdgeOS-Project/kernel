/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD device statistics backed by lock-free EdgeOS counters. */

#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/bio.h"
#include "sys/devicestat.h"

static uint32_t g_devstat_next_device;

struct devstat *
devstat_new_entry(const void *device_name, int unit_number,
    uint32_t block_size, devstat_support_flags flags,
    devstat_type_flags device_type, devstat_priority priority)
{
    struct devstat *statistics;

    if (!device_name || unit_number < 0 || block_size == 0)
        return 0;
    statistics = bsd_malloc(sizeof(*statistics), M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!statistics)
        return 0;
    statistics->allocated = 1;
    statistics->device_number =
        __atomic_fetch_add(&g_devstat_next_device, 1, __ATOMIC_RELAXED);
    bsd_strlcpy(statistics->device_name, device_name,
        sizeof(statistics->device_name));
    statistics->unit_number = unit_number;
    statistics->block_size = block_size;
    statistics->flags = flags;
    statistics->device_type = device_type;
    statistics->priority = priority;
    statistics->id = statistics;
    return statistics;
}

void
devstat_remove_entry(struct devstat *statistics)
{
    if (!statistics)
        return;
    statistics->allocated = 0;
    bsd_free(statistics, M_DEVBUF);
}

void
devstat_start_transaction(struct devstat *statistics,
    const struct bintime *now)
{
    (void)now;
    if (!statistics)
        return;
    __atomic_fetch_add(&statistics->sequence0, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&statistics->start_count, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&statistics->sequence1, 1, __ATOMIC_RELEASE);
}

void
devstat_start_transaction_bio(struct devstat *statistics, struct bio *bio)
{
    (void)bio;
    devstat_start_transaction(statistics, 0);
}

void
devstat_start_transaction_bio_t0(struct devstat *statistics,
    struct bio *bio)
{
    devstat_start_transaction_bio(statistics, bio);
}

void
devstat_end_transaction(struct devstat *statistics, uint32_t bytes,
    devstat_tag_type tag_type, devstat_trans_flags flags,
    const struct bintime *now, const struct bintime *then)
{
    unsigned int index = (unsigned int)flags;

    (void)now;
    (void)then;
    if (!statistics || index >= DEVSTAT_N_TRANS_FLAGS)
        return;
    __atomic_fetch_add(&statistics->sequence0, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&statistics->bytes[index], bytes, __ATOMIC_RELAXED);
    __atomic_fetch_add(&statistics->operations[index], 1, __ATOMIC_RELAXED);
    if ((unsigned int)tag_type < 3)
        __atomic_fetch_add(&statistics->tag_types[tag_type], 1,
            __ATOMIC_RELAXED);
    __atomic_fetch_add(&statistics->end_count, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&statistics->sequence1, 1, __ATOMIC_RELEASE);
}

void
devstat_end_transaction_bio(struct devstat *statistics,
    const struct bio *bio)
{
    devstat_trans_flags flags = DEVSTAT_NO_DATA;
    uint32_t bytes = 0;

    if (bio) {
        if (bio->bio_cmd == BIO_READ)
            flags = DEVSTAT_READ;
        else if (bio->bio_cmd == BIO_WRITE)
            flags = DEVSTAT_WRITE;
        else if (bio->bio_cmd == BIO_DELETE)
            flags = DEVSTAT_FREE;
        if (bio->bio_bcount > bio->bio_resid)
            bytes = (uint32_t)(bio->bio_bcount - bio->bio_resid);
    }
    devstat_end_transaction(statistics, bytes, DEVSTAT_TAG_NONE,
        flags, 0, 0);
}

void
devstat_end_transaction_bio_bt(struct devstat *statistics,
    const struct bio *bio, const struct bintime *now)
{
    (void)now;
    devstat_end_transaction_bio(statistics, bio);
}
