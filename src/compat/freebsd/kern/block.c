/* SPDX-License-Identifier: MPL-2.0 */
/* Shared FreeBSD BIO and disk-publication runtime. */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <stdarg.h>

#include "compat/freebsd/edgeos/block.h"
#include "compat/freebsd/edgeos/cdev.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/slicer.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/geom/geom.h"
#include "compat/freebsd/geom/geom_disk.h"
#include "compat/freebsd/sys/bio.h"
#ifdef BSD_BRIDGE_HOST_TEST
struct devstat;
void devstat_start_transaction_bio(struct devstat *, struct bio *);
void devstat_end_transaction_bio(struct devstat *, const struct bio *);
void devstat_remove_entry(struct devstat *);
#else
#include "sys/devicestat.h"
#endif

#ifndef BSD_BRIDGE_HOST_TEST
#include "block/block.h"
#endif

#define BSD_BLOCK_EIO 5
#define BSD_BLOCK_ENXIO 6
#define BSD_BLOCK_ENOMEM 12
#define BSD_BLOCK_EBUSY 16
#define BSD_BLOCK_EINVAL 22
#define BSD_BLOCK_EROFS 30
#define BSD_BLOCK_WAIT_TICKS 30000
#define BSD_BLOCK_NAME_CAPACITY 32
#define BSD_BLOCK_BIOQ_BATCH_SIZE 128

typedef struct bsd_disk_slice_context {
    struct disk *disk;
    uint64_t base_sector;
    uint64_t sector_count;
    uint8_t read_only;
    char name[BSD_BLOCK_NAME_CAPACITY];
} bsd_disk_slice_context_t;

typedef struct bsd_flash_slicer_kind {
    const char *attribute;
    unsigned int type;
} bsd_flash_slicer_kind_t;

static const bsd_flash_slicer_kind_t g_flash_slicer_kinds[] = {
    { "NAND::device", FLASH_SLICES_TYPE_NAND },
    { "CFI::device", FLASH_SLICES_TYPE_CFI },
    { "SPI::device", FLASH_SLICES_TYPE_SPI },
    { "MMC::device", FLASH_SLICES_TYPE_MMC },
};

int printf(const char *format, ...);

static bsd_block_backend_ops_t g_block_operations;
static uint8_t g_block_init_state;
static char g_unmapped_buffer_marker;
static volatile uint32_t g_topology_lock_state;
static struct g_geom *g_geom_list;
static struct g_provider *g_provider_list;
static struct g_class *g_class_list;
char *unmapped_buf = &g_unmapped_buffer_marker;

#ifndef BSD_BRIDGE_HOST_TEST
typedef struct bsd_default_block_publication {
    bsd_block_description_t description;
    block_device_t *device;
    char name[BLOCK_NAME_MAX];
} bsd_default_block_publication_t;

static int
default_block_read(block_device_t *device, uint32_t lba,
    uint32_t sector_count, void *output)
{
    bsd_default_block_publication_t *publication =
        device ? device->ctx : 0;

    if (!publication || !publication->description.read)
        return -1;
    return publication->description.read(
        publication->description.device_context, lba, sector_count, output);
}

static int
default_block_write(block_device_t *device, uint32_t lba,
    uint32_t sector_count, const void *input)
{
    bsd_default_block_publication_t *publication =
        device ? device->ctx : 0;

    if (!publication || !publication->description.write)
        return -1;
    return publication->description.write(
        publication->description.device_context, lba, sector_count, input);
}

static int
default_block_flush(block_device_t *device)
{
    bsd_default_block_publication_t *publication =
        device ? device->ctx : 0;

    if (!publication || !publication->description.flush)
        return 0;
    return publication->description.flush(
        publication->description.device_context);
}

static int
default_block_publish(const bsd_block_description_t *description,
    void **publication_out, void *context)
{
    bsd_default_block_publication_t *publication;
    block_ops_t operations;
    int index;

    (void)context;
    if (!description || !publication_out || !description->name ||
        !description->read || !description->sector_size ||
        !description->sector_count ||
        description->sector_count > UINT32_MAX)
        return BSD_BLOCK_EINVAL;
    publication = bsd_malloc(sizeof(*publication), M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!publication)
        return BSD_BLOCK_ENOMEM;
    publication->description = *description;
    if (bsd_strlcpy(publication->name, description->name,
        sizeof(publication->name)) >= sizeof(publication->name)) {
        bsd_free(publication, M_DEVBUF);
        return BSD_BLOCK_EINVAL;
    }
    publication->description.name = publication->name;
    operations.read_sectors = default_block_read;
    operations.write_sectors =
        description->write ? default_block_write : 0;
    operations.flush = description->flush ? default_block_flush : 0;
    index = block_register(publication->name, description->sector_size,
        (uint32_t)description->sector_count, 0, publication, operations);
    if (index < 0) {
        bsd_free(publication, M_DEVBUF);
        return BSD_BLOCK_EBUSY;
    }
    publication->device = block_get(index);
    if (!publication->device) {
        block_device_t *device = block_find(publication->name);

        if (device)
            (void)block_unregister(device);
        bsd_free(publication, M_DEVBUF);
        return BSD_BLOCK_EIO;
    }
    block_set_max_transfer_sectors(publication->device,
        description->max_transfer_sectors);
    *publication_out = publication;
    bsd_bridge_devtmpfs_changed();
    return 0;
}

static int
default_block_unpublish(void *publication_value, void *context)
{
    bsd_default_block_publication_t *publication = publication_value;

    (void)context;
    if (!publication || !publication->device)
        return BSD_BLOCK_EINVAL;
    if (block_unregister(publication->device) != 0)
        return BSD_BLOCK_EBUSY;
    bsd_bridge_devtmpfs_changed();
    bsd_free(publication, M_DEVBUF);
    return 0;
}

static int
default_block_resize(void *publication_value, uint64_t sector_count,
    void *context)
{
    bsd_default_block_publication_t *publication = publication_value;

    (void)context;
    if (!publication || !publication->device || !sector_count ||
        sector_count > UINT32_MAX)
        return BSD_BLOCK_EINVAL;
    if (block_resize(publication->device, (uint32_t)sector_count) != 0)
        return BSD_BLOCK_EBUSY;
    publication->description.sector_count = sector_count;
    bsd_bridge_devtmpfs_changed();
    return 0;
}
#endif

int
bsd_block_initialize(const bsd_block_backend_ops_t *operations)
{
    uint8_t expected = 0;

    if (!operations || !operations->publish || !operations->unpublish ||
        !operations->resize)
        return -1;
    if (!__atomic_compare_exchange_n(&g_block_init_state, &expected, 1, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -1;
    g_block_operations = *operations;
    __atomic_store_n(&g_block_init_state, 2, __ATOMIC_RELEASE);
    return 0;
}

int
bsd_block_ensure_initialized(void)
{
    uint8_t state =
        __atomic_load_n(&g_block_init_state, __ATOMIC_ACQUIRE);

    if (state == 2)
        return 0;
    if (state == 1) {
        do {
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
            state = __atomic_load_n(&g_block_init_state, __ATOMIC_ACQUIRE);
        } while (state == 1);
        return state == 2 ? 0 : -1;
    }
#ifdef BSD_BRIDGE_HOST_TEST
    return -1;
#else
    {
        bsd_block_backend_ops_t operations = {
            .publish = default_block_publish,
            .unpublish = default_block_unpublish,
            .resize = default_block_resize,
        };

        if (bsd_block_initialize(&operations) == 0)
            return 0;
    }
    return bsd_block_is_initialized() ? 0 : -1;
#endif
}

int
bsd_block_is_initialized(void)
{
    return __atomic_load_n(&g_block_init_state, __ATOMIC_ACQUIRE) == 2;
}

void
g_reset_bio(struct bio *bio)
{
    if (bio)
        bsd_memset(bio, 0, sizeof(*bio));
}

struct bio *
g_new_bio(void)
{
    return bsd_malloc(sizeof(struct bio), M_DEVBUF, M_NOWAIT | M_ZERO);
}

struct bio *
g_alloc_bio(void)
{
    return bsd_malloc(sizeof(struct bio), M_DEVBUF, M_WAITOK | M_ZERO);
}

void
g_destroy_bio(struct bio *bio)
{
    if (bio)
        bsd_free(bio, M_DEVBUF);
}

void
g_io_deliver(struct bio *bio, int error)
{
    if (!bio)
        return;
    if (error != 0) {
        bio->bio_error = error;
        bio->bio_flags |= BIO_ERROR;
        if (bio->bio_resid == 0)
            bio->bio_resid = bio->bio_length;
    }
    biodone(bio);
}

void
g_topology_lock(void)
{
    uint32_t expected;

    for (;;) {
        expected = 0;
        if (__atomic_compare_exchange_n(&g_topology_lock_state, &expected,
            1u, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return;
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

int
g_topology_try_lock(void)
{
    uint32_t expected = 0;

    return __atomic_compare_exchange_n(&g_topology_lock_state, &expected,
        1u, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

void
g_topology_unlock(void)
{
    if (__atomic_exchange_n(&g_topology_lock_state, 0u,
        __ATOMIC_RELEASE) == 0)
        __builtin_trap();
}

int
g_topology_locked(void)
{
    return __atomic_load_n(&g_topology_lock_state, __ATOMIC_ACQUIRE) != 0;
}

void
g_topology_assert(void)
{
    if (!g_topology_locked())
        __builtin_trap();
}

static char *
geom_format_name(const char *format, va_list arguments)
{
    char *name = 0;

    if (!format || bsd_vasprintf(&name, M_DEVBUF, format, arguments) < 0)
        return 0;
    return name;
}

struct g_geom *
g_new_geom(struct g_class *geom_class, const char *name)
{
    struct g_geom *geom;

    if (!geom_class || !name || !name[0])
        return 0;
    geom = bsd_malloc(sizeof(*geom), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!geom)
        return 0;
    geom->name = bsd_strdup(name, M_DEVBUF);
    if (!geom->name) {
        bsd_free(geom, M_DEVBUF);
        return 0;
    }
    geom->class = geom_class;
    geom->start = geom_class->start;
    geom->access = geom_class->access;
    geom->ioctl = geom_class->ioctl;
    geom->bridge_next = g_geom_list;
    g_geom_list = geom;
    return geom;
}

struct g_geom *
g_new_geomf(struct g_class *geom_class, const char *format, ...)
{
    struct g_geom *geom;
    char *name;
    va_list arguments;

    va_start(arguments, format);
    name = geom_format_name(format, arguments);
    va_end(arguments);
    if (!name)
        return 0;
    geom = g_new_geom(geom_class, name);
    bsd_free(name, M_DEVBUF);
    return geom;
}

struct g_provider *
g_new_providerf(struct g_geom *geom, const char *format, ...)
{
    struct g_provider *provider;
    char *name;
    va_list arguments;

    if (!geom)
        return 0;
    va_start(arguments, format);
    name = geom_format_name(format, arguments);
    va_end(arguments);
    if (!name)
        return 0;
    provider = bsd_malloc(sizeof(*provider), M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!provider) {
        bsd_free(name, M_DEVBUF);
        return 0;
    }
    provider->name = name;
    provider->geom = geom;
    provider->error = BSD_BLOCK_ENXIO;
    provider->bridge_geom_next = geom->bridge_providers;
    geom->bridge_providers = provider;
    provider->bridge_global_next = g_provider_list;
    g_provider_list = provider;
    return provider;
}

struct g_provider *
g_provider_by_name(const char *name)
{
    struct g_provider *provider;

    if (!name)
        return 0;
    for (provider = g_provider_list; provider;
        provider = provider->bridge_global_next) {
        if (bsd_strcmp(provider->name, name) == 0)
            return provider;
    }
    return 0;
}

static int
geom_provider_transfer(void *device_context, uint64_t lba,
    uint32_t sector_count, void *buffer, int write)
{
    struct g_provider *provider = device_context;
    struct bio bio;
    uint64_t offset;
    uint64_t length;
    int error;

    if (!provider || !provider->geom || !provider->geom->start ||
        provider->error != 0 || !provider->sectorsize ||
        !sector_count || !buffer)
        return -1;
    if (lba > UINT64_MAX / provider->sectorsize ||
        sector_count > UINT64_MAX / provider->sectorsize)
        return -1;
    offset = lba * provider->sectorsize;
    length = (uint64_t)sector_count * provider->sectorsize;
    if (provider->mediasize <= 0 ||
        offset > (uint64_t)provider->mediasize ||
        length > (uint64_t)provider->mediasize - offset ||
        length > (uint64_t)LONG_MAX)
        return -1;
    g_reset_bio(&bio);
    bio.bio_cmd = write ? BIO_WRITE : BIO_READ;
    bio.bio_to = provider;
    bio.bio_offset = (int64_t)offset;
    bio.bio_pblkno = (int64_t)lba;
    bio.bio_bcount = (long)length;
    bio.bio_length = (int64_t)length;
    bio.bio_resid = (long)length;
    bio.bio_data = buffer;
    provider->geom->start(&bio);
    error = biowait(&bio, write ? "geomw" : "geomr");
    return error == 0 && bio.bio_resid == 0 ? 0 : -1;
}

static int
geom_provider_read(void *device_context, uint64_t lba,
    uint32_t sector_count, void *output)
{
    return geom_provider_transfer(device_context, lba, sector_count,
        output, 0);
}

static int
geom_provider_write(void *device_context, uint64_t lba,
    uint32_t sector_count, const void *input)
{
    return geom_provider_transfer(device_context, lba, sector_count,
        (void *)(uintptr_t)input, 1);
}

static int
geom_provider_flush(void *device_context)
{
    struct g_provider *provider = device_context;
    struct bio bio;
    int error;

    if (!provider || !provider->geom || !provider->geom->start ||
        provider->error != 0)
        return -1;
    g_reset_bio(&bio);
    bio.bio_cmd = BIO_FLUSH;
    bio.bio_to = provider;
    provider->geom->start(&bio);
    error = biowait(&bio, "geomf");
    return error == 0 ? 0 : -1;
}

void
g_error_provider(struct g_provider *provider, int error)
{
    bsd_block_description_t description;
    void *publication = 0;
    uint64_t sector_count;
    int publish_error;

    if (!provider)
        return;
    provider->error = error;
    if (error != 0 || provider->bridge_publication)
        return;
    if (bsd_block_ensure_initialized() != 0 || !provider->geom ||
        !provider->geom->start || !provider->name ||
        !provider->sectorsize || provider->mediasize <= 0 ||
        (uint64_t)provider->mediasize % provider->sectorsize != 0) {
        provider->error = BSD_BLOCK_EINVAL;
        return;
    }
    sector_count = (uint64_t)provider->mediasize / provider->sectorsize;
    description = (bsd_block_description_t) {
        .name = provider->name,
        .sector_size = provider->sectorsize,
        .sector_count = sector_count,
        .max_transfer_sectors = BSD_BLOCK_BIOQ_BATCH_SIZE,
        .read = geom_provider_read,
        .write = geom_provider_write,
        .flush = geom_provider_flush,
        .device_context = provider,
    };
    publish_error = g_block_operations.publish(&description, &publication,
        g_block_operations.context);
    if (publish_error != 0 || !publication) {
        provider->error = publish_error != 0 ? publish_error : BSD_BLOCK_EIO;
        return;
    }
    provider->bridge_publication = publication;
    provider->error = 0;
}

void
g_resize_provider(struct g_provider *provider, off_t size)
{
    uint64_t sector_count;
    int error;

    if (!provider || !provider->bridge_publication ||
        !provider->sectorsize || size <= 0 ||
        (uint64_t)size % provider->sectorsize != 0) {
        if (provider)
            provider->error = BSD_BLOCK_EINVAL;
        return;
    }
    sector_count = (uint64_t)size / provider->sectorsize;
    error = g_block_operations.resize(provider->bridge_publication,
        sector_count, g_block_operations.context);
    if (error == 0)
        provider->mediasize = size;
    provider->error = error;
}

void
g_orphan_provider(struct g_provider *provider, int error)
{
    int unpublish_error;

    if (!provider || error == 0)
        return;
    provider->error = error;
    provider->flags |= G_PF_ORPHAN;
    if (provider->bridge_publication) {
        unpublish_error = g_block_operations.unpublish(
            provider->bridge_publication, g_block_operations.context);
        if (unpublish_error != 0) {
            provider->error = unpublish_error;
            return;
        }
        provider->bridge_publication = 0;
    }
    if (provider->geom && provider->geom->class &&
        provider->geom->class->providergone)
        provider->geom->class->providergone(provider);
}

static int
geom_run_event(g_event_t *function, void *argument)
{
    int acquired = 0;

    if (!function)
        return BSD_BLOCK_EINVAL;
    if (!g_topology_locked()) {
        g_topology_lock();
        acquired = 1;
    }
    function(argument, 0);
    if (acquired)
        g_topology_unlock();
    return 0;
}

int
g_post_event(g_event_t *function, void *argument, int flags, ...)
{
    (void)flags;
    return geom_run_event(function, argument);
}

int
g_waitfor_event(g_event_t *function, void *argument, int flags, ...)
{
    (void)flags;
    return geom_run_event(function, argument);
}

int
g_handleattr_int(struct bio *bio, const char *attribute, int value)
{
    if (!bio || !attribute || !bio->bio_attribute ||
        bsd_strcmp(bio->bio_attribute, attribute) != 0)
        return 0;
    if (!bio->bio_data || bio->bio_length != (int64_t)sizeof(value)) {
        g_io_deliver(bio, BSD_BLOCK_EINVAL);
        return 1;
    }
    bsd_memcpy(bio->bio_data, &value, sizeof(value));
    bio->bio_completed = sizeof(value);
    bio->bio_resid = 0;
    g_io_deliver(bio, 0);
    return 1;
}

void
g_print_bio(const char *prefix, const struct bio *bio,
    const char *suffix_format, ...)
{
    const char *command = "UNKNOWN";
    const char *provider_name = "unknown";
    va_list arguments;

    if (!bio)
        return;
    if (bio->bio_to && bio->bio_to->name)
        provider_name = bio->bio_to->name;
    switch (bio->bio_cmd) {
    case BIO_READ:
        command = "READ";
        break;
    case BIO_WRITE:
        command = "WRITE";
        break;
    case BIO_DELETE:
        command = "DELETE";
        break;
    case BIO_GETATTR:
        command = "GETATTR";
        break;
    case BIO_FLUSH:
        command = "FLUSH";
        break;
    case BIO_CMD0:
        command = "CMD0";
        break;
    case BIO_CMD1:
        command = "CMD1";
        break;
    case BIO_CMD2:
        command = "CMD2";
        break;
    }
    printf("%s%s[%s offset=%lld length=%lld]", prefix ? prefix : "",
        provider_name, command, (long long)bio->bio_offset,
        (long long)bio->bio_length);
    if (suffix_format && suffix_format[0]) {
        va_start(arguments, suffix_format);
        bsd_vprintf(suffix_format, arguments);
        va_end(arguments);
    }
    printf("\n");
}

int
g_modevent(module_t module, int event, void *data)
{
    struct g_class *geom_class = data;
    struct g_class **link;

    (void)module;
    if (!geom_class || !geom_class->name ||
        geom_class->version != G_VERSION)
        return BSD_BLOCK_EINVAL;
    switch (event) {
    case MOD_LOAD:
        if (geom_class->bridge_registered)
            return 0;
        geom_class->bridge_next = g_class_list;
        g_class_list = geom_class;
        geom_class->bridge_registered = 1;
        if (geom_class->init)
            ((void (*)(struct g_class *))geom_class->init)(geom_class);
        return 0;
    case MOD_UNLOAD:
        for (struct g_geom *geom = g_geom_list; geom;
            geom = geom->bridge_next) {
            if (geom->class == geom_class)
                return BSD_BLOCK_EBUSY;
        }
        for (link = &g_class_list; *link;
            link = &(*link)->bridge_next) {
            if (*link == geom_class) {
                *link = geom_class->bridge_next;
                break;
            }
        }
        if (geom_class->fini)
            ((void (*)(struct g_class *))geom_class->fini)(geom_class);
        geom_class->bridge_next = 0;
        geom_class->bridge_registered = 0;
        return 0;
    default:
        return BSD_BLOCK_EINVAL;
    }
}

static void
geom_remove_provider(struct g_provider *provider)
{
    struct g_provider **link;

    for (link = &g_provider_list; *link;
        link = &(*link)->bridge_global_next) {
        if (*link == provider) {
            *link = provider->bridge_global_next;
            break;
        }
    }
}

void
g_wither_geom(struct g_geom *geom, int error)
{
    struct g_provider *provider;
    struct g_geom **geom_link;

    if (!geom)
        return;
    geom->flags |= G_GEOM_WITHER;
    while ((provider = geom->bridge_providers) != 0) {
        geom->bridge_providers = provider->bridge_geom_next;
        provider->flags |= G_PF_WITHER;
        provider->error = error;
        if (provider->bridge_publication) {
            int unpublish_error = g_block_operations.unpublish(
                provider->bridge_publication, g_block_operations.context);

            if (unpublish_error != 0) {
                provider->error = unpublish_error;
                provider->bridge_geom_next = geom->bridge_providers;
                geom->bridge_providers = provider;
                return;
            }
            provider->bridge_publication = 0;
        }
        if (geom->class && geom->class->providergone)
            geom->class->providergone(provider);
        geom_remove_provider(provider);
        bsd_free(provider->name, M_DEVBUF);
        bsd_free(provider, M_DEVBUF);
    }
    for (geom_link = &g_geom_list; *geom_link;
        geom_link = &(*geom_link)->bridge_next) {
        if (*geom_link == geom) {
            *geom_link = geom->bridge_next;
            break;
        }
    }
    bsd_free(geom->name, M_DEVBUF);
    bsd_free(geom, M_DEVBUF);
}

void
biodone(struct bio *bio)
{
    uint16_t old_flags;

    if (!bio)
        return;
    old_flags = __atomic_fetch_or(&bio->bio_flags, BIO_DONE,
        __ATOMIC_RELEASE);
    if ((old_flags & BIO_DONE) != 0)
        return;
    if (bio->bio_done)
        bio->bio_done(bio);
    bsd_wakeup(bio);
}

void
biofinish(struct bio *bio, void *statistics, int error)
{
    (void)statistics;
    if (!bio)
        return;
    if (error) {
        bio->bio_error = error;
        bio->bio_resid = bio->bio_bcount;
        bio->bio_flags |= BIO_ERROR;
    }
    biodone(bio);
}

int
biowait(struct bio *bio, const char *wait_message)
{
    if (!bio)
        return BSD_BLOCK_EINVAL;
    for (int ticks = 0; ticks < BSD_BLOCK_WAIT_TICKS; ++ticks) {
        if ((__atomic_load_n(&bio->bio_flags, __ATOMIC_ACQUIRE) &
            BIO_DONE) != 0)
            return bio->bio_error;
        (void)bsd_msleep(bio, 0, 0, wait_message, 1);
    }
    return BSD_BLOCK_EIO;
}

void
bioq_init(struct bio_queue_head *queue)
{
    if (!queue)
        return;
    TAILQ_INIT(&queue->queue);
    queue->last_offset = 0;
    queue->insert_point = 0;
    queue->total = 0;
    queue->batched = 0;
}

void
bioq_flush(struct bio_queue_head *queue, struct devstat *statistics, int error)
{
    struct bio *bio;

    if (!queue)
        return;
    while ((bio = bioq_takefirst(queue)) != 0)
        biofinish(bio, statistics, error);
}

void
bioq_insert_head(struct bio_queue_head *queue, struct bio *bio)
{
    if (!queue || !bio || (bio->bio_flags & BIO_ONQUEUE) != 0)
        return;
    if (!queue->insert_point)
        queue->last_offset = bio->bio_offset;
    TAILQ_INSERT_HEAD(&queue->queue, bio, bio_queue);
    bio->bio_flags |= BIO_ONQUEUE;
    queue->total++;
    queue->batched = 0;
}

void
bioq_insert_tail(struct bio_queue_head *queue, struct bio *bio)
{
    if (!queue || !bio || (bio->bio_flags & BIO_ONQUEUE) != 0)
        return;
    TAILQ_INSERT_TAIL(&queue->queue, bio, bio_queue);
    bio->bio_flags |= BIO_ONQUEUE;
    queue->insert_point = bio;
    queue->last_offset = bio->bio_offset;
    queue->total++;
    queue->batched = 0;
}

void
bioq_remove(struct bio_queue_head *queue, struct bio *bio)
{
    if (!queue || !bio || (bio->bio_flags & BIO_ONQUEUE) == 0)
        return;
    if (!queue->insert_point) {
        if (bio == TAILQ_FIRST(&queue->queue))
            queue->last_offset = bio->bio_offset + bio->bio_length;
    } else if (bio == queue->insert_point) {
        queue->insert_point = 0;
    }
    TAILQ_REMOVE(&queue->queue, bio, bio_queue);
    bio->bio_flags &= (uint16_t)~BIO_ONQUEUE;
    if (queue->total > 0)
        queue->total--;
    if (TAILQ_EMPTY(&queue->queue))
        queue->batched = 0;
}

static uint64_t
bioq_sort_key(const struct bio_queue_head *queue, const struct bio *bio)
{
    return (uint64_t)(bio->bio_offset - queue->last_offset);
}

void
bioq_disksort(struct bio_queue_head *queue, struct bio *bio)
{
    struct bio *current;
    struct bio *previous = 0;
    uint64_t key;

    if (!queue || !bio || (bio->bio_flags & BIO_ONQUEUE) != 0)
        return;
    if ((bio->bio_flags & BIO_ORDERED) != 0 ||
        (bio->bio_cmd != BIO_READ && bio->bio_cmd != BIO_WRITE &&
        bio->bio_cmd != BIO_DELETE) ||
        queue->batched > BSD_BLOCK_BIOQ_BATCH_SIZE) {
        bioq_insert_tail(queue, bio);
        return;
    }

    key = bioq_sort_key(queue, bio);
    current = TAILQ_FIRST(&queue->queue);
    if (queue->insert_point) {
        previous = queue->insert_point;
        current = TAILQ_NEXT(queue->insert_point, bio_queue);
    }
    while (current && key >= bioq_sort_key(queue, current)) {
        previous = current;
        current = TAILQ_NEXT(current, bio_queue);
    }
    if (!previous)
        TAILQ_INSERT_HEAD(&queue->queue, bio, bio_queue);
    else
        TAILQ_INSERT_AFTER(&queue->queue, previous, bio, bio_queue);
    bio->bio_flags |= BIO_ONQUEUE;
    queue->total++;
    queue->batched++;
}

struct bio *
bioq_first(struct bio_queue_head *queue)
{
    return queue ? TAILQ_FIRST(&queue->queue) : 0;
}

struct bio *
bioq_takefirst(struct bio_queue_head *queue)
{
    struct bio *bio;

    if (!queue)
        return 0;
    bio = TAILQ_FIRST(&queue->queue);
    if (!bio)
        return 0;
    bioq_remove(queue, bio);
    return bio;
}

static int
disk_transfer(void *device_context, uint64_t lba, uint32_t sector_count,
    void *buffer, int write)
{
    struct disk *disk = device_context;
    struct bio bio;
    uint64_t offset;
    uint64_t length;
    int error;

    if (!disk || disk->d_bridge_destroyed || !disk->d_strategy ||
        !disk->d_sectorsize || !sector_count || !buffer)
        return -1;
    if (write && (disk->d_flags & DISKFLAG_WRITE_PROTECT) != 0)
        return -1;
    if (lba > UINT64_MAX / disk->d_sectorsize ||
        sector_count > UINT64_MAX / disk->d_sectorsize)
        return -1;
    offset = lba * disk->d_sectorsize;
    length = (uint64_t)sector_count * disk->d_sectorsize;
    if (disk->d_mediasize <= 0 || offset > (uint64_t)disk->d_mediasize ||
        length > (uint64_t)disk->d_mediasize - offset ||
        length > (uint64_t)LONG_MAX)
        return -1;

    g_reset_bio(&bio);
    bio.bio_cmd = write ? BIO_WRITE : BIO_READ;
    bio.bio_disk = disk;
    bio.bio_offset = (int64_t)offset;
    bio.bio_pblkno = (int64_t)lba;
    bio.bio_bcount = (long)length;
    bio.bio_length = (int64_t)length;
    bio.bio_resid = 0;
    bio.bio_data = buffer;
    devstat_start_transaction_bio(disk->d_devstat, &bio);
    disk->d_strategy(&bio);
    error = biowait(&bio, write ? "bsdw" : "bsdr");
    bio.bio_completed = bio.bio_bcount - bio.bio_resid;
    devstat_end_transaction_bio(disk->d_devstat, &bio);
    return error == 0 && bio.bio_resid == 0 ? 0 : -1;
}

static int
disk_read(void *device_context, uint64_t lba, uint32_t sector_count,
    void *output)
{
    return disk_transfer(device_context, lba, sector_count, output, 0);
}

static int
disk_write(void *device_context, uint64_t lba, uint32_t sector_count,
    const void *input)
{
    return disk_transfer(device_context, lba, sector_count,
        (void *)(uintptr_t)input, 1);
}

static int
disk_flush(void *device_context)
{
    struct disk *disk = device_context;
    struct bio bio;
    int error;

    if (!disk || disk->d_bridge_destroyed || !disk->d_strategy)
        return -1;
    g_reset_bio(&bio);
    bio.bio_cmd = BIO_FLUSH;
    bio.bio_disk = disk;
    disk->d_strategy(&bio);
    error = biowait(&bio, "bsdf");
    return error == 0 ? 0 : -1;
}

static int
disk_slice_flush(void *device_context)
{
    bsd_disk_slice_context_t *slice = device_context;

    return slice && slice->disk ? disk_flush(slice->disk) : -1;
}

static int
disk_slice_transfer(void *device_context, uint64_t lba,
    uint32_t sector_count, void *buffer, int write)
{
    bsd_disk_slice_context_t *slice = device_context;

    if (!slice || !slice->disk || !sector_count ||
        lba >= slice->sector_count ||
        sector_count > slice->sector_count - lba ||
        slice->base_sector > UINT64_MAX - lba ||
        (write && slice->read_only))
        return -1;
    return disk_transfer(slice->disk, slice->base_sector + lba,
        sector_count, buffer, write);
}

static int
disk_slice_read(void *device_context, uint64_t lba, uint32_t sector_count,
    void *output)
{
    return disk_slice_transfer(device_context, lba, sector_count, output, 0);
}

static int
disk_slice_write(void *device_context, uint64_t lba, uint32_t sector_count,
    const void *input)
{
    return disk_slice_transfer(device_context, lba, sector_count,
        (void *)(uintptr_t)input, 1);
}

static int
disk_provider_name(const struct disk *disk, char *name, size_t capacity)
{
    int length;

    if (!disk || !disk->d_name || !disk->d_name[0] || !name || !capacity)
        return BSD_BLOCK_EINVAL;
    length = bsd_snprintf(name, capacity, "%s%u", disk->d_name,
        disk->d_unit);
    return length < 0 || (size_t)length >= capacity ?
        BSD_BLOCK_EINVAL : 0;
}

static int
disk_get_flash_device(struct disk *disk, const char *attribute,
    device_t *device)
{
    struct bio bio;
    int error;

    if (!disk || !disk->d_getattr || !attribute || !device)
        return BSD_BLOCK_ENXIO;
    g_reset_bio(&bio);
    bio.bio_cmd = BIO_GETATTR;
    bio.bio_disk = disk;
    bio.bio_attribute = attribute;
    bio.bio_data = (char *)(void *)device;
    bio.bio_length = sizeof(*device);
    error = disk->d_getattr(&bio);
    if (error != 0 || bio.bio_completed != bio.bio_length)
        return error != 0 ? error : BSD_BLOCK_EIO;
    return 0;
}

static int
disk_slice_valid(const struct disk *disk, const struct flash_slice *slice)
{
    uint64_t base;
    uint64_t size;

    if (!disk || !slice || !slice->label || !slice->label[0] ||
        slice->base < 0 || slice->size <= 0 ||
        (slice->flags & ~FLASH_SLICES_FLAG_RO) != 0)
        return 0;
    base = (uint64_t)slice->base;
    size = (uint64_t)slice->size;
    if (base % disk->d_sectorsize != 0 ||
        size % disk->d_sectorsize != 0 ||
        base > (uint64_t)disk->d_mediasize ||
        size > (uint64_t)disk->d_mediasize - base)
        return 0;
    return 1;
}

static int
disk_unpublish_slices(struct disk *disk)
{
    int error;

    if (!disk)
        return BSD_BLOCK_EINVAL;
    while (disk->d_bridge_slice_count != 0) {
        unsigned int index = disk->d_bridge_slice_count - 1;

        error = g_block_operations.unpublish(
            disk->d_bridge_slice_publications[index],
            g_block_operations.context);
        if (error != 0)
            return error;
        bsd_free(disk->d_bridge_slice_contexts[index], M_DEVBUF);
        disk->d_bridge_slice_contexts[index] = 0;
        disk->d_bridge_slice_publications[index] = 0;
        disk->d_bridge_slice_count--;
    }
    return 0;
}

static int
disk_publish_slice(struct disk *disk, const char *provider,
    const struct flash_slice *slice)
{
    bsd_disk_slice_context_t *context;
    bsd_block_description_t description;
    uint32_t max_transfer;
    void *publication = 0;
    int length;
    int error;

    if (!disk_slice_valid(disk, slice) ||
        disk->d_bridge_slice_count >= BSD_DISK_MAX_SLICES)
        return BSD_BLOCK_EINVAL;
    context = bsd_malloc(sizeof(*context), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!context)
        return BSD_BLOCK_ENOMEM;
    length = bsd_snprintf(context->name, sizeof(context->name),
        FLASH_SLICES_FMT, provider, slice->label);
    if (length < 0 || (size_t)length >= sizeof(context->name)) {
        bsd_free(context, M_DEVBUF);
        return BSD_BLOCK_EINVAL;
    }
    for (unsigned int index = 0; index < disk->d_bridge_slice_count;
        ++index) {
        const bsd_disk_slice_context_t *existing =
            disk->d_bridge_slice_contexts[index];

        if (existing && bsd_strcmp(existing->name, context->name) == 0) {
            bsd_free(context, M_DEVBUF);
            return BSD_BLOCK_EINVAL;
        }
    }
    context->disk = disk;
    context->base_sector = (uint64_t)slice->base / disk->d_sectorsize;
    context->sector_count = (uint64_t)slice->size / disk->d_sectorsize;
    context->read_only =
        (slice->flags & FLASH_SLICES_FLAG_RO) != 0 ||
        (disk->d_flags & DISKFLAG_WRITE_PROTECT) != 0;
    max_transfer = disk->d_maxsize / disk->d_sectorsize;
    if (!max_transfer)
        max_transfer = 1;
    description = (bsd_block_description_t) {
        .name = context->name,
        .sector_size = disk->d_sectorsize,
        .sector_count = context->sector_count,
        .max_transfer_sectors = max_transfer,
        .read = disk_slice_read,
        .write = context->read_only ? 0 : disk_slice_write,
        .flush = (disk->d_flags & DISKFLAG_CANFLUSHCACHE) != 0 ?
            disk_slice_flush : 0,
        .device_context = context,
    };
    error = g_block_operations.publish(&description, &publication,
        g_block_operations.context);
    if (error != 0 || !publication) {
        bsd_free(context, M_DEVBUF);
        return error != 0 ? error : BSD_BLOCK_EIO;
    }
    disk->d_bridge_slice_contexts[disk->d_bridge_slice_count] = context;
    disk->d_bridge_slice_publications[disk->d_bridge_slice_count] =
        publication;
    disk->d_bridge_slice_count++;
    return 0;
}

static int
disk_publish_slices(struct disk *disk)
{
    struct flash_slice slices[FLASH_SLICES_MAX_NUM];
    char provider[BSD_BLOCK_NAME_CAPACITY];
    int error;

    if (!disk || !disk->d_getattr)
        return 0;
    error = disk_provider_name(disk, provider, sizeof(provider));
    if (error != 0)
        return error;
    for (size_t kind_index = 0;
        kind_index < sizeof(g_flash_slicer_kinds) /
        sizeof(g_flash_slicer_kinds[0]); ++kind_index) {
        const bsd_flash_slicer_kind_t *kind =
            &g_flash_slicer_kinds[kind_index];
        flash_slicer_t slicer = bsd_flash_slicer_lookup(kind->type);
        device_t device = 0;
        int slice_count = 0;

        if (!slicer ||
            disk_get_flash_device(disk, kind->attribute, &device) != 0)
            continue;
        bsd_memset(slices, 0, sizeof(slices));
        error = slicer(device, provider, slices, &slice_count);
        if (error != 0)
            continue;
        if (slice_count < 0 || slice_count > FLASH_SLICES_MAX_NUM) {
            error = BSD_BLOCK_EINVAL;
            goto rollback;
        }
        for (int slice_index = 0; slice_index < slice_count; ++slice_index) {
            error = disk_publish_slice(disk, provider,
                &slices[slice_index]);
            if (error != 0)
                goto rollback;
        }
        return 0;
    }
    return 0;

rollback:
    (void)disk_unpublish_slices(disk);
    return error;
}

struct disk *
disk_alloc(void)
{
    struct disk *disk = bsd_malloc(sizeof(struct disk), M_DEVBUF,
        M_WAITOK | M_ZERO);

    return disk;
}

static void
disk_gone_task(void *context, int pending)
{
    struct disk *disk = context;

    (void)pending;
    if (disk && !disk->d_bridge_destroyed && disk->d_gone)
        disk->d_gone(disk);
}

void
disk_create(struct disk *disk, int version)
{
    bsd_block_description_t description;
    char name[BSD_BLOCK_NAME_CAPACITY];
    uint64_t sector_count;
    uint32_t max_transfer;
    void *publication = 0;
    int name_length;
    int error;

    if (!disk || disk->d_bridge_destroyed || disk->d_bridge_published)
        return;
    if (bsd_block_ensure_initialized() != 0 || version != DISK_VERSION ||
        !disk->d_name || !disk->d_name[0] || !disk->d_strategy ||
        !disk->d_sectorsize || disk->d_mediasize <= 0 ||
        (uint64_t)disk->d_mediasize % disk->d_sectorsize != 0) {
        disk->d_bridge_error = BSD_BLOCK_EINVAL;
        return;
    }
    name_length = disk_provider_name(disk, name, sizeof(name));
    if (name_length != 0) {
        disk->d_bridge_error = BSD_BLOCK_EINVAL;
        return;
    }
    sector_count = (uint64_t)disk->d_mediasize / disk->d_sectorsize;
    max_transfer = disk->d_maxsize / disk->d_sectorsize;
    if (!max_transfer)
        max_transfer = 1;
    description = (bsd_block_description_t) {
        .name = name,
        .sector_size = disk->d_sectorsize,
        .sector_count = sector_count,
        .max_transfer_sectors = max_transfer,
        .read = disk_read,
        .write = (disk->d_flags & DISKFLAG_WRITE_PROTECT) != 0 ?
            0 : disk_write,
        .flush = (disk->d_flags & DISKFLAG_CANFLUSHCACHE) != 0 ?
            disk_flush : 0,
        .device_context = disk,
    };
    if (disk->d_open) {
        error = disk->d_open(disk);
        if (error != 0) {
            disk->d_bridge_error = error;
            return;
        }
        disk->d_bridge_opened = 1;
        disk->d_flags |= DISKFLAG_OPEN;
    }
    error = g_block_operations.publish(&description, &publication,
        g_block_operations.context);
    if (error != 0 || !publication) {
        disk->d_bridge_error = error != 0 ? error : BSD_BLOCK_EIO;
        if (disk->d_bridge_opened && disk->d_close) {
            (void)disk->d_close(disk);
            disk->d_bridge_opened = 0;
            disk->d_flags &= ~DISKFLAG_OPEN;
        }
        return;
    }
    disk->d_bridge_publication = publication;
    disk->d_bridge_error = 0;
    disk->d_bridge_published = 1;
    error = disk_publish_slices(disk);
    if (error != 0)
        disk->d_bridge_error = error;
}

void
disk_destroy(struct disk *disk)
{
    int error = 0;

    if (!disk)
        return;
    error = disk_unpublish_slices(disk);
    if (error != 0) {
        disk->d_bridge_error = error;
        return;
    }
    if (disk->d_bridge_published) {
        error = g_block_operations.unpublish(
            disk->d_bridge_publication, g_block_operations.context);
        if (error != 0) {
            disk->d_bridge_error = error;
            disk->d_bridge_destroyed = 1;
            disk->d_drv1 = 0;
            return;
        }
    }
    disk->d_bridge_publication = 0;
    disk->d_bridge_published = 0;
    if (disk->d_bridge_opened && disk->d_close) {
        error = disk->d_close(disk);
        if (error != 0)
            disk->d_bridge_error = error;
    }
    disk->d_bridge_opened = 0;
    disk->d_flags &= ~DISKFLAG_OPEN;
    disk->d_bridge_destroyed = 1;
    devstat_remove_entry(disk->d_devstat);
    disk->d_devstat = 0;
    bsd_free(disk, M_DEVBUF);
}

void
disk_gone(struct disk *disk)
{
    int error;

    if (!disk || disk->d_bridge_destroyed || disk->d_bridge_gone)
        return;
    disk->d_bridge_gone = 1;
    error = disk_unpublish_slices(disk);
    if (error != 0) {
        disk->d_bridge_error = error;
        disk->d_bridge_gone = 0;
        return;
    }
    if (disk->d_bridge_published) {
        error = g_block_operations.unpublish(
            disk->d_bridge_publication, g_block_operations.context);
        if (error != 0) {
            disk->d_bridge_error = error;
            disk->d_bridge_gone = 0;
            return;
        }
        disk->d_bridge_publication = 0;
        disk->d_bridge_published = 0;
    }
    if (!disk->d_gone)
        return;
    TASK_INIT(&disk->d_bridge_gone_task, 0, disk_gone_task, disk);
    if (!taskqueue_thread ||
        taskqueue_enqueue(taskqueue_thread, &disk->d_bridge_gone_task) != 0)
        disk->d_bridge_error = BSD_BLOCK_EBUSY;
}

int
disk_resize(struct disk *disk, int flags)
{
    uint64_t sector_count;
    int error;

    (void)flags;
    if (!disk || !disk->d_bridge_published || !disk->d_sectorsize ||
        disk->d_mediasize <= 0 ||
        (uint64_t)disk->d_mediasize % disk->d_sectorsize != 0)
        return BSD_BLOCK_EINVAL;
    error = disk_unpublish_slices(disk);
    if (error != 0) {
        disk->d_bridge_error = error;
        return error;
    }
    sector_count = (uint64_t)disk->d_mediasize / disk->d_sectorsize;
    error = g_block_operations.resize(disk->d_bridge_publication,
        sector_count, g_block_operations.context);
    if (error == 0)
        error = disk_publish_slices(disk);
    else
        (void)disk_publish_slices(disk);
    disk->d_bridge_error = error;
    return error;
}

void
disk_err(struct bio *bio, const char *message, int error, int blocks_done)
{
    (void)error;
    (void)blocks_done;
    printf("[bsd-block] %s%d: %s error=%d\n",
        bio && bio->bio_disk && bio->bio_disk->d_name ?
        bio->bio_disk->d_name : "disk",
        bio && bio->bio_disk ? bio->bio_disk->d_unit : 0,
        message ? message : "I/O", bio ? bio->bio_error : BSD_BLOCK_EIO);
}
