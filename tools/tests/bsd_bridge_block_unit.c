/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared FreeBSD disk-publication runtime. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/block.h"
#include "compat/freebsd/edgeos/module.h"
#include "compat/freebsd/edgeos/slicer.h"
#include "compat/freebsd/geom/geom.h"
#include "compat/freebsd/geom/geom_disk.h"
#include "compat/freebsd/sys/bio.h"
#include "compat/freebsd/sys/buf.h"
#include "compat/freebsd/sys/taskqueue.h"

#define TEST_PAGE_SIZE 4096U
#define TEST_MAX_PUBLICATIONS 16

typedef struct test_publication {
    bsd_block_description_t description;
    char name[32];
    uint64_t sector_count;
    int active;
} test_publication_t;

typedef struct test_backend {
    test_publication_t publications[TEST_MAX_PUBLICATIONS];
    int publication_record_count;
    int publish_count;
    int unpublish_count;
    int resize_count;
    int reject_publish;
    int reject_resize;
    int reject_unpublish;
} test_backend_t;

static int g_strategy_count;
static int g_done_count;
static uint8_t g_last_write;
static int g_open_count;
static int g_close_count;
static int g_queue_done_count;
static int64_t g_last_lba;
static int g_geom_read_count;
static int g_geom_write_count;
static int g_geom_flush_count;
static device_t g_slice_device = (device_t)(uintptr_t)0x1234;
static int g_geom_flashmap_version_seen;

struct mtx;
struct devstat;

struct taskqueue *taskqueue_thread;

void
bsd_static_record_register(enum bsd_static_record_kind kind,
    const void *record)
{
    const struct bsd_module_static_record *module_record = record;

    if (kind != BSD_STATIC_MODULE_METADATA || !module_record ||
        module_record->kind != BSD_MODULE_VERSION ||
        strcmp(module_record->name, "geom_flashmap") != 0)
        return;
    assert(module_record->minimum == 0);
    assert(module_record->preferred == 0);
    assert(module_record->maximum == 0);
    g_geom_flashmap_version_seen++;
}

void
devstat_start_transaction_bio(struct devstat *statistics, struct bio *bio)
{
    (void)statistics;
    (void)bio;
}

void
devstat_end_transaction_bio(struct devstat *statistics,
    const struct bio *bio)
{
    (void)statistics;
    (void)bio;
}

void
devstat_remove_entry(struct devstat *statistics)
{
    (void)statistics;
}

int
taskqueue_enqueue(struct taskqueue *queue, struct task *task)
{
    (void)queue;
    if (!task || !task->ta_func)
        return 22;
    task->ta_func(task->ta_context, 0);
    return 0;
}

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)page_count * TEST_PAGE_SIZE) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

int
bsd_msleep(const void *channel, struct mtx *mutex, int priority,
    const char *wait_message, int timeout_ticks)
{
    (void)channel;
    (void)mutex;
    (void)priority;
    (void)wait_message;
    (void)timeout_ticks;
    return 0;
}

void
bsd_wakeup(const void *channel)
{
    (void)channel;
}

static int
test_publish(const bsd_block_description_t *description,
    void **publication, void *context)
{
    test_backend_t *backend = context;
    test_publication_t *record;

    backend->publish_count++;
    if (backend->reject_publish)
        return 16;
    assert(description != 0);
    assert(publication != 0);
    assert(backend->publication_record_count < TEST_MAX_PUBLICATIONS);
    record = &backend->publications[backend->publication_record_count++];
    assert(strlen(description->name) < sizeof(record->name));
    strcpy(record->name, description->name);
    record->description = *description;
    record->description.name = record->name;
    record->sector_count = description->sector_count;
    record->active = 1;
    *publication = record;
    return 0;
}

static int
test_unpublish(void *publication, void *context)
{
    test_backend_t *backend = context;
    test_publication_t *record = publication;

    assert(record >= &backend->publications[0]);
    assert(record < &backend->publications[TEST_MAX_PUBLICATIONS]);
    assert(record->active);
    if (backend->reject_unpublish)
        return 16;
    record->active = 0;
    backend->unpublish_count++;
    return 0;
}

static int
test_resize(void *publication, uint64_t sector_count, void *context)
{
    test_backend_t *backend = context;
    test_publication_t *record = publication;

    assert(record >= &backend->publications[0]);
    assert(record < &backend->publications[TEST_MAX_PUBLICATIONS]);
    assert(record->active);
    backend->resize_count++;
    if (backend->reject_resize)
        return 16;
    record->sector_count = sector_count;
    return 0;
}

static test_publication_t *
test_find_publication(test_backend_t *backend, const char *name)
{
    for (int index = backend->publication_record_count - 1;
        index >= 0; --index) {
        test_publication_t *record = &backend->publications[index];

        if (record->active && strcmp(record->name, name) == 0)
            return record;
    }
    return 0;
}

static void
test_done(struct bio *bio)
{
    assert(bio != 0);
    g_done_count++;
}

static void
test_queue_done(struct bio *bio)
{
    assert(bio != 0);
    assert((bio->bio_flags & BIO_ONQUEUE) == 0);
    g_queue_done_count++;
}

static void
test_strategy(struct bio *bio)
{
    uint8_t *data;

    assert(bio != 0);
    assert(bio->bio_disk != 0);
    assert(bio->bio_bcount > 0);
    data = (uint8_t *)(void *)bio->bio_data;
    g_strategy_count++;
    g_last_lba = bio->bio_pblkno;
    if (bio->bio_cmd == BIO_READ)
        memset(data, 0x5a, (size_t)bio->bio_bcount);
    else if (bio->bio_cmd == BIO_WRITE)
        g_last_write = data[0];
    else
        bio->bio_error = 95;
    bio->bio_resid = bio->bio_error ? bio->bio_bcount : 0;
    biodone(bio);
}

static void
test_geom_start(struct bio *bio)
{
    assert(bio != 0);
    assert(bio->bio_to != 0);
    switch (bio->bio_cmd) {
    case BIO_READ:
        assert(bio->bio_data != 0);
        assert(bio->bio_length > 0);
        memset(bio->bio_data, 0x6b, (size_t)bio->bio_length);
        g_geom_read_count++;
        break;
    case BIO_WRITE:
        assert(bio->bio_data != 0);
        assert(bio->bio_length > 0);
        g_last_write = ((const uint8_t *)bio->bio_data)[0];
        g_geom_write_count++;
        break;
    case BIO_FLUSH:
        assert(bio->bio_length == 0);
        g_geom_flush_count++;
        break;
    default:
        g_io_deliver(bio, 95);
        return;
    }
    bio->bio_resid = 0;
    g_io_deliver(bio, 0);
}

static void
test_geom_provider(test_backend_t *backend)
{
    struct g_class geom_class = {
        .name = "NVDIMM",
        .version = G_VERSION,
        .start = test_geom_start,
    };
    struct g_geom *geom;
    struct g_provider *provider;
    struct g_geom *invalid_geom;
    struct g_provider *invalid_provider;
    test_publication_t *publication;
    int publish_count;
    uint8_t buffer[1024] = {0};

    assert(!g_topology_locked());
    assert(g_topology_try_lock());
    assert(g_topology_locked());
    assert(!g_topology_try_lock());
    g_topology_assert();

    geom = g_new_geomf(&geom_class, "spa%u", 7u);
    assert(geom != 0);
    provider = g_new_providerf(geom, "spa%u", 7u);
    assert(provider != 0);
    assert(g_provider_by_name("spa7") == provider);
    provider->sectorsize = 512;
    provider->mediasize = 4096;
    g_error_provider(provider, 0);
    assert(provider->error == 0);
    publication = test_find_publication(backend, "spa7");
    assert(publication != 0);
    assert(publication->description.flush != 0);
    assert(publication->description.read(
        publication->description.device_context, 1, 2, buffer) == 0);
    assert(g_geom_read_count == 1);
    assert(buffer[0] == 0x6b && buffer[sizeof(buffer) - 1] == 0x6b);
    buffer[0] = 0x4d;
    assert(publication->description.write(
        publication->description.device_context, 3, 1, buffer) == 0);
    assert(g_geom_write_count == 1);
    assert(g_last_write == 0x4d);
    assert(publication->description.flush(
        publication->description.device_context) == 0);
    assert(g_geom_flush_count == 1);
    assert(publication->description.read(
        publication->description.device_context, 8, 1, buffer) == -1);

    g_resize_provider(provider, 8192);
    assert(provider->error == 0);
    assert(provider->mediasize == 8192);
    assert(publication->sector_count == 16);
    backend->reject_resize = 1;
    g_resize_provider(provider, 16384);
    assert(provider->error == 16);
    assert(provider->mediasize == 8192);
    backend->reject_resize = 0;
    g_error_provider(provider, 0);
    assert(provider->error == 0);

    backend->reject_unpublish = 1;
    g_wither_geom(geom, 6);
    assert(g_provider_by_name("spa7") == provider);
    assert(provider->error == 16);
    backend->reject_unpublish = 0;
    g_wither_geom(geom, 6);
    assert(g_provider_by_name("spa7") == 0);
    assert(test_find_publication(backend, "spa7") == 0);

    invalid_geom = g_new_geom(&geom_class, "invalid");
    assert(invalid_geom != 0);
    invalid_provider = g_new_providerf(invalid_geom, "invalid%u", 0u);
    assert(invalid_provider != 0);
    invalid_provider->sectorsize = 512;
    invalid_provider->mediasize = 513;
    publish_count = backend->publish_count;
    g_error_provider(invalid_provider, 0);
    assert(invalid_provider->error == 22);
    assert(backend->publish_count == publish_count);
    g_wither_geom(invalid_geom, 6);
    assert(g_provider_by_name("invalid0") == 0);
    g_topology_unlock();
    assert(!g_topology_locked());
}

static int
test_flash_getattr(struct bio *bio)
{
    assert(bio != 0);
    if (!bio->bio_attribute ||
        strcmp(bio->bio_attribute, "MMC::device") != 0)
        return -1;
    assert(bio->bio_length == sizeof(g_slice_device));
    memcpy(bio->bio_data, &g_slice_device, sizeof(g_slice_device));
    bio->bio_completed = bio->bio_length;
    return 0;
}

static int
test_flash_slicer(device_t device, const char *provider,
    struct flash_slice *slices, int *slice_count)
{
    assert(device == g_slice_device);
    assert(strcmp(provider, "mmcsd0") == 0);
    assert(slices != 0);
    assert(slice_count != 0);
    slices[0].base = 512;
    slices[0].size = 1024;
    slices[0].label = "enh";
    slices[0].flags = FLASH_SLICES_FLAG_NONE;
    slices[1].base = 2048;
    slices[1].size = 512;
    slices[1].label = "boot";
    slices[1].flags = FLASH_SLICES_FLAG_RO;
    *slice_count = 2;
    return 0;
}

static int
test_open(struct disk *disk)
{
    assert(disk != 0);
    g_open_count++;
    return 0;
}

static int
test_close(struct disk *disk)
{
    assert(disk != 0);
    g_close_count++;
    return 0;
}

static void
test_bio_queue(void)
{
    struct bio_queue_head queue;
    struct bio first;
    struct bio second;
    struct bio third;
    struct bio wrapped;
    struct bio next;
    struct bio barrier;
    struct bio after_barrier;
    struct bio flush_one;
    struct bio flush_two;

    g_reset_bio(&first);
    g_reset_bio(&second);
    g_reset_bio(&third);
    g_reset_bio(&wrapped);
    g_reset_bio(&next);
    g_reset_bio(&barrier);
    g_reset_bio(&after_barrier);
    g_reset_bio(&flush_one);
    g_reset_bio(&flush_two);
    assert(unmapped_buf != 0);
    bioq_init(&queue);
    assert(bioq_first(&queue) == 0);
    bioq_insert_tail(&queue, &first);
    bioq_insert_tail(&queue, &second);
    assert(queue.total == 2);
    assert((first.bio_flags & BIO_ONQUEUE) != 0);
    assert(bioq_first(&queue) == &first);
    bioq_remove(&queue, &first);
    assert((first.bio_flags & BIO_ONQUEUE) == 0);
    assert(queue.total == 1);
    bioq_remove(&queue, &first);
    assert(queue.total == 1);
    assert(bioq_takefirst(&queue) == &second);
    assert(bioq_takefirst(&queue) == 0);
    assert(queue.total == 0);

    first.bio_cmd = BIO_READ;
    first.bio_offset = 100;
    first.bio_length = 10;
    second.bio_cmd = BIO_WRITE;
    second.bio_offset = 50;
    second.bio_length = 10;
    third.bio_cmd = BIO_DELETE;
    third.bio_offset = 200;
    third.bio_length = 10;
    bioq_disksort(&queue, &first);
    bioq_disksort(&queue, &second);
    bioq_disksort(&queue, &third);
    assert(bioq_takefirst(&queue) == &second);
    assert(queue.last_offset == 60);

    wrapped.bio_cmd = BIO_READ;
    wrapped.bio_offset = 20;
    wrapped.bio_length = 10;
    next.bio_cmd = BIO_READ;
    next.bio_offset = 70;
    next.bio_length = 10;
    bioq_disksort(&queue, &wrapped);
    bioq_disksort(&queue, &next);
    assert(bioq_takefirst(&queue) == &next);
    assert(bioq_takefirst(&queue) == &first);
    assert(bioq_takefirst(&queue) == &third);
    assert(bioq_takefirst(&queue) == &wrapped);
    assert(queue.total == 0);

    barrier.bio_cmd = BIO_FLUSH;
    barrier.bio_offset = 400;
    after_barrier.bio_cmd = BIO_READ;
    after_barrier.bio_offset = 1;
    bioq_disksort(&queue, &barrier);
    bioq_disksort(&queue, &after_barrier);
    assert(bioq_takefirst(&queue) == &barrier);
    assert(bioq_takefirst(&queue) == &after_barrier);

    flush_one.bio_cmd = BIO_READ;
    flush_one.bio_bcount = 512;
    flush_one.bio_done = test_queue_done;
    flush_two.bio_cmd = BIO_WRITE;
    flush_two.bio_bcount = 1024;
    flush_two.bio_done = test_queue_done;
    bioq_insert_tail(&queue, &flush_one);
    bioq_insert_tail(&queue, &flush_two);
    g_queue_done_count = 0;
    bioq_flush(&queue, 0, 5);
    assert(g_queue_done_count == 2);
    assert(queue.total == 0);
    assert(bioq_first(&queue) == 0);
    assert(flush_one.bio_error == 5);
    assert(flush_one.bio_resid == 512);
    assert((flush_one.bio_flags & (BIO_ERROR | BIO_DONE)) ==
        (BIO_ERROR | BIO_DONE));
    assert(flush_two.bio_error == 5);
    assert(flush_two.bio_resid == 1024);
    bioq_flush(&queue, 0, 5);
    assert(g_queue_done_count == 2);
}

int
main(void)
{
    bsd_allocator_ops_t allocator_operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    test_backend_t backend = {0};
    bsd_block_backend_ops_t block_operations = {
        .publish = test_publish,
        .unpublish = test_unpublish,
        .resize = test_resize,
        .context = &backend,
    };
    struct disk *disk;
    struct disk *failed_disk;
    struct disk *slice_disk;
    struct bio completed;
    test_publication_t *parent;
    test_publication_t *enhanced;
    test_publication_t *boot;
    uint8_t buffer[1024] = {0};

    assert(g_geom_flashmap_version_seen == 1);
    assert(bsd_allocator_initialize(&allocator_operations) == 0);
    assert(bsd_block_initialize(&block_operations) == 0);
    assert(bsd_block_is_initialized());
    assert(bsd_block_ensure_initialized() == 0);
    assert(bsd_block_initialize(&block_operations) == -1);

    test_bio_queue();
    g_reset_bio(&completed);
    completed.bio_done = test_done;
    completed.bio_bcount = 512;
    completed.bio_resid = 512;
    biodone(&completed);
    biodone(&completed);
    assert(g_done_count == 1);
    assert(biowait(&completed, "done") == 0);

    disk = disk_alloc();
    assert(disk != 0);
    disk->d_name = "vtbd";
    disk->d_unit = 3;
    disk->d_open = test_open;
    disk->d_close = test_close;
    disk->d_strategy = test_strategy;
    disk->d_sectorsize = 512;
    disk->d_mediasize = 4096;
    disk->d_maxsize = 1024;
    disk_create(disk, DISK_VERSION);
    assert(disk->d_bridge_published);
    assert(disk->d_bridge_error == 0);
    assert(g_open_count == 1);
    parent = test_find_publication(&backend, "vtbd3");
    assert(parent != 0);
    assert(parent->description.sector_size == 512);
    assert(parent->description.sector_count == 8);
    assert(parent->description.max_transfer_sectors == 2);
    assert(parent->description.read(parent->description.device_context,
        1, 2, buffer) == 0);
    assert(buffer[0] == 0x5a && buffer[sizeof(buffer) - 1] == 0x5a);
    buffer[0] = 0xa5;
    assert(parent->description.write(parent->description.device_context,
        2, 1, buffer) == 0);
    assert(g_last_write == 0xa5);
    assert(g_strategy_count == 2);
    assert(parent->description.read(parent->description.device_context,
        8, 1, buffer) == -1);

    disk->d_mediasize = 8192;
    assert(disk_resize(disk, 0) == 0);
    assert(parent->sector_count == 16);
    backend.reject_resize = 1;
    disk->d_mediasize = 16384;
    assert(disk_resize(disk, 0) == 16);
    assert(parent->sector_count == 16);
    backend.reject_resize = 0;
    disk_destroy(disk);
    assert(backend.unpublish_count == 1);
    assert(g_close_count == 1);

    backend.reject_publish = 1;
    failed_disk = disk_alloc();
    assert(failed_disk != 0);
    failed_disk->d_name = "fail";
    failed_disk->d_open = test_open;
    failed_disk->d_close = test_close;
    failed_disk->d_strategy = test_strategy;
    failed_disk->d_sectorsize = 512;
    failed_disk->d_mediasize = 4096;
    disk_create(failed_disk, DISK_VERSION);
    assert(!failed_disk->d_bridge_published);
    assert(failed_disk->d_bridge_error == 16);
    assert(g_open_count == 2);
    assert(g_close_count == 2);
    disk_destroy(failed_disk);
    assert(backend.publish_count == 2);
    assert(backend.unpublish_count == 1);

    backend.reject_publish = 0;
    flash_register_slicer(test_flash_slicer, FLASH_SLICES_TYPE_MMC, true);
    assert(bsd_flash_slicer_lookup(FLASH_SLICES_TYPE_MMC) ==
        test_flash_slicer);
    slice_disk = disk_alloc();
    assert(slice_disk != 0);
    slice_disk->d_name = "mmcsd";
    slice_disk->d_getattr = test_flash_getattr;
    slice_disk->d_strategy = test_strategy;
    slice_disk->d_sectorsize = 512;
    slice_disk->d_mediasize = 4096;
    slice_disk->d_maxsize = 1024;
    disk_create(slice_disk, DISK_VERSION);
    assert(slice_disk->d_bridge_published);
    assert(slice_disk->d_bridge_error == 0);
    assert(slice_disk->d_bridge_slice_count == 2);
    parent = test_find_publication(&backend, "mmcsd0");
    enhanced = test_find_publication(&backend, "mmcsd0s.enh");
    boot = test_find_publication(&backend, "mmcsd0s.boot");
    assert(parent != 0 && enhanced != 0 && boot != 0);
    assert(enhanced->description.sector_count == 2);
    assert(enhanced->description.write != 0);
    assert(enhanced->description.read(
        enhanced->description.device_context, 0, 1, buffer) == 0);
    assert(g_last_lba == 1);
    assert(enhanced->description.write(
        enhanced->description.device_context, 1, 1, buffer) == 0);
    assert(g_last_lba == 2);
    assert(enhanced->description.read(
        enhanced->description.device_context, 2, 1, buffer) == -1);
    assert(boot->description.sector_count == 1);
    assert(boot->description.write == 0);
    assert(boot->description.read(boot->description.device_context,
        0, 1, buffer) == 0);
    assert(g_last_lba == 4);

    slice_disk->d_mediasize = 8192;
    assert(disk_resize(slice_disk, 0) == 0);
    assert(slice_disk->d_bridge_slice_count == 2);
    assert(parent->sector_count == 16);
    enhanced = test_find_publication(&backend, "mmcsd0s.enh");
    boot = test_find_publication(&backend, "mmcsd0s.boot");
    assert(enhanced != 0 && boot != 0);
    disk_destroy(slice_disk);
    assert(backend.unpublish_count == 6);
    assert(test_find_publication(&backend, "mmcsd0") == 0);
    assert(test_find_publication(&backend, "mmcsd0s.enh") == 0);
    assert(test_find_publication(&backend, "mmcsd0s.boot") == 0);
    flash_register_slicer(0, FLASH_SLICES_TYPE_MMC, true);
    assert(bsd_flash_slicer_lookup(FLASH_SLICES_TYPE_MMC) == 0);

    test_geom_provider(&backend);

    return 0;
}
