/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared CAM and SCSI block gateway. */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/cam/cam_ccb.h"
#include "compat/freebsd/cam/cam_periph.h"
#include "compat/freebsd/cam/cam_sim.h"
#include "compat/freebsd/cam/cam_xpt_sim.h"
#include "compat/freebsd/cam/scsi/scsi_all.h"
#include "compat/freebsd/cam/scsi/scsi_message.h"
#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/block.h"
#include "compat/freebsd/edgeos/cam.h"
#include "compat/freebsd/edgeos/slicer.h"
#include "compat/freebsd/edgeos/sync.h"
#include "compat/freebsd/machine/bus.h"
#include "compat/freebsd/sys/bio.h"
#include "compat/freebsd/vm/vm.h"
#include <sys/memdesc.h>

#define TEST_PAGE_SIZE 4096u
#define TEST_SECTOR_SIZE 512u
#define TEST_MAX_SECTORS 256u

typedef struct test_backend {
    bsd_block_description_t description;
    char name[32];
    uint64_t sectors;
    int published;
    int unpublished;
    int resized;
} test_backend_t;

typedef struct test_sim {
    struct mtx mutex;
    uint32_t sectors;
    uint32_t capacity_attempts;
    uint32_t targets_seen;
    uint32_t reset_count;
    int inject_unit_attention;
    int is_ata;
    uint8_t storage[TEST_MAX_SECTORS * TEST_SECTOR_SIZE];
} test_sim_t;

static int g_thread_token;
static int g_async_count;
static target_id_t g_async_target = CAM_TARGET_WILDCARD;

struct devstat;
struct taskqueue;
struct task;

struct taskqueue *taskqueue_thread;

flash_slicer_t
bsd_flash_slicer_lookup(unsigned int type)
{
    (void)type;
    return 0;
}

int
taskqueue_enqueue(struct taskqueue *queue, struct task *task)
{
    (void)queue;
    (void)task;
    return 0;
}

struct memdesc
memdesc_bio(struct bio *bio)
{
    return memdesc_vaddr(bio, bio ? sizeof(*bio) : 0);
}

int
bus_dmamap_load_mem(bus_dma_tag_t tag, bus_dmamap_t map,
    struct memdesc *memory, bus_dmamap_callback_t *callback,
    void *callback_argument, int flags)
{
    (void)tag;
    (void)map;
    (void)memory;
    (void)flags;
    callback(callback_argument, 0, 0, 0);
    return 0;
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

static void *
test_current_thread(void *context)
{
    (void)context;
    return &g_thread_token;
}

static int
test_can_block(void *thread, void *context)
{
    (void)thread;
    (void)context;
    return 0;
}

static void
test_thread_noop(void *thread, void *context)
{
    (void)thread;
    (void)context;
}

static void
test_yield(void *context)
{
    (void)context;
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

uint64_t
bsd_kthread_wakeup_generation(const void *channel)
{
    (void)channel;
    return 0;
}

int
bsd_kthread_sleep_generation(const void *channel, uint64_t generation,
    int timeout_ticks)
{
    (void)channel;
    (void)generation;
    (void)timeout_ticks;
    return 0;
}

static int
test_publish(const bsd_block_description_t *description,
    void **publication, void *context)
{
    test_backend_t *backend = context;

    assert(description != 0 && publication != 0);
    assert(strlen(description->name) < sizeof(backend->name));
    strcpy(backend->name, description->name);
    backend->description = *description;
    backend->description.name = backend->name;
    backend->sectors = description->sector_count;
    backend->published++;
    *publication = backend;
    return 0;
}

static int
test_unpublish(void *publication, void *context)
{
    test_backend_t *backend = context;

    assert(publication == backend);
    backend->unpublished++;
    return 0;
}

static int
test_resize(void *publication, uint64_t sectors, void *context)
{
    test_backend_t *backend = context;

    assert(publication == backend);
    backend->sectors = sectors;
    backend->resized++;
    return 0;
}

static uint32_t
test_be32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
        ((uint32_t)data[2] << 8) | data[3];
}

static void
test_store_be32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static void
test_store_ata_word(void *data, uint32_t word, uint16_t value)
{
    uint8_t *bytes = data;

    bytes[word * 2u] = (uint8_t)value;
    bytes[word * 2u + 1u] = (uint8_t)(value >> 8);
}

static uint64_t
test_ata_lba(const struct ata_cmd *command)
{
    uint64_t lba = command->lba_low |
        ((uint64_t)command->lba_mid << 8) |
        ((uint64_t)command->lba_high << 16);

    if (command->flags & CAM_ATAIO_48BIT) {
        lba |= (uint64_t)command->lba_low_exp << 24;
        lba |= (uint64_t)command->lba_mid_exp << 32;
        lba |= (uint64_t)command->lba_high_exp << 40;
    } else {
        lba |= (uint64_t)(command->device & 0x0fu) << 24;
    }
    return lba;
}

static void
test_complete(union ccb *ccb, cam_status status)
{
    ccb->ccb_h.status = status;
    xpt_done(ccb);
}

static void
test_sim_action(struct cam_sim *sim, union ccb *ccb)
{
    test_sim_t *state = cam_sim_softc(sim);
    uint8_t *command;
    uint32_t lba;
    uint32_t sectors;

    if (ccb->ccb_h.func_code == XPT_PATH_INQ) {
        ccb->cpi.max_target = state->is_ata ? 0 : 1;
        ccb->cpi.max_lun = 0;
        ccb->cpi.initiator_id = state->is_ata ? 0 : 1;
        ccb->cpi.maxio = 128u * 1024u;
        ccb->cpi.protocol = state->is_ata ? PROTO_ATA : PROTO_SCSI;
        ccb->cpi.transport = state->is_ata ? XPORT_SATA : XPORT_SPI;
        test_complete(ccb, CAM_REQ_CMP);
        return;
    }
    if (state->is_ata && ccb->ccb_h.func_code == XPT_RESET_BUS) {
        state->reset_count++;
        test_complete(ccb, CAM_REQ_CMP);
        return;
    }
    if (state->is_ata) {
        const struct ata_cmd *ata = &ccb->ataio.cmd;
        uint64_t ata_lba;
        uint32_t ata_sectors;

        assert(ccb->ccb_h.func_code == XPT_ATA_IO);
        assert(ccb->ccb_h.target_id == 0);
        state->targets_seen |= 1u;
        ccb->ataio.resid = 0;
        if (ata->command == ATA_ATA_IDENTIFY) {
            assert(ccb->ataio.dxfer_len == sizeof(struct ata_params));
            memset(ccb->ataio.data_ptr, 0, ccb->ataio.dxfer_len);
            test_store_ata_word(ccb->ataio.data_ptr, 49,
                ATA_SUPPORT_DMA | ATA_SUPPORT_LBA);
            test_store_ata_word(ccb->ataio.data_ptr, 60,
                (uint16_t)state->sectors);
            test_store_ata_word(ccb->ataio.data_ptr, 61,
                (uint16_t)(state->sectors >> 16));
            test_store_ata_word(ccb->ataio.data_ptr, 83,
                0x4000u | ATA_SUPPORT_ADDRESS48);
            test_store_ata_word(ccb->ataio.data_ptr, 100,
                (uint16_t)state->sectors);
            test_store_ata_word(ccb->ataio.data_ptr, 101,
                (uint16_t)(state->sectors >> 16));
            test_complete(ccb, CAM_REQ_CMP);
            return;
        }
        assert(ata->command == ATA_READ_DMA48 ||
            ata->command == ATA_WRITE_DMA48);
        assert((ata->flags & (CAM_ATAIO_48BIT | CAM_ATAIO_DMA)) ==
            (CAM_ATAIO_48BIT | CAM_ATAIO_DMA));
        ata_lba = test_ata_lba(ata);
        ata_sectors = ata->sector_count |
            ((uint32_t)ata->sector_count_exp << 8);
        if (!ata_sectors)
            ata_sectors = 65536u;
        assert(ata_lba + ata_sectors <= state->sectors);
        assert(ccb->ataio.dxfer_len ==
            ata_sectors * TEST_SECTOR_SIZE);
        if (ata->command == ATA_READ_DMA48)
            memcpy(ccb->ataio.data_ptr,
                state->storage + ata_lba * TEST_SECTOR_SIZE,
                ccb->ataio.dxfer_len);
        else
            memcpy(state->storage + ata_lba * TEST_SECTOR_SIZE,
                ccb->ataio.data_ptr, ccb->ataio.dxfer_len);
        test_complete(ccb, CAM_REQ_CMP);
        return;
    }
    assert(ccb->ccb_h.func_code == XPT_SCSI_IO);
    assert(ccb->ccb_h.target_id < 32);
    state->targets_seen |= 1u << ccb->ccb_h.target_id;
    command = ccb->csio.cdb_io.cdb_bytes;
    ccb->csio.scsi_status = SCSI_STATUS_OK;
    ccb->csio.resid = 0;
    switch (command[0]) {
    case REPORT_LUNS:
        assert(ccb->csio.dxfer_len >= 16);
        memset(ccb->csio.data_ptr, 0, ccb->csio.dxfer_len);
        test_store_be32(ccb->csio.data_ptr, 8);
        ccb->csio.resid = ccb->csio.dxfer_len - 16;
        break;
    case INQUIRY: {
        struct scsi_inquiry_data *identity =
            (struct scsi_inquiry_data *)ccb->csio.data_ptr;

        assert(ccb->csio.dxfer_len >= sizeof(*identity));
        memset(identity, 0, sizeof(*identity));
        identity->device = T_DIRECT;
        memcpy(identity->vendor, "EdgeOS  ", 8);
        memcpy(identity->product, "CAM Test Disk   ", 16);
        break;
    }
    case READ_CAPACITY:
        state->capacity_attempts++;
        if (state->inject_unit_attention) {
            state->inject_unit_attention = 0;
            ccb->csio.scsi_status = SCSI_STATUS_CHECK_COND;
            ccb->csio.sense_data.bytes[0] = SSD_CURRENT_ERROR;
            ccb->csio.sense_data.bytes[2] = SSD_KEY_UNIT_ATTENTION;
            ccb->csio.sense_data.bytes[7] = 10;
            ccb->csio.sense_data.bytes[12] = 0x29;
            ccb->csio.sense_resid =
                sizeof(ccb->csio.sense_data) - 18u;
            test_complete(ccb,
                CAM_SCSI_STATUS_ERROR | CAM_AUTOSNS_VALID);
            return;
        }
        assert(ccb->csio.dxfer_len >= 8);
        test_store_be32(ccb->csio.data_ptr, state->sectors - 1u);
        test_store_be32(ccb->csio.data_ptr + 4, TEST_SECTOR_SIZE);
        break;
    case READ_10:
    case WRITE_10:
        lba = test_be32(command + 2);
        sectors = ((uint32_t)command[7] << 8) | command[8];
        assert(sectors != 0 && lba + sectors <= state->sectors);
        assert(ccb->csio.dxfer_len == sectors * TEST_SECTOR_SIZE);
        if (command[0] == READ_10)
            memcpy(ccb->csio.data_ptr,
                state->storage + lba * TEST_SECTOR_SIZE,
                ccb->csio.dxfer_len);
        else
            memcpy(state->storage + lba * TEST_SECTOR_SIZE,
                ccb->csio.data_ptr, ccb->csio.dxfer_len);
        break;
    default:
        ccb->csio.scsi_status = SCSI_STATUS_CHECK_COND;
        break;
    }
    test_complete(ccb, CAM_REQ_CMP);
}

static void
test_sim_poll(struct cam_sim *sim)
{
    assert(sim != 0);
}

static void
test_async(void *argument, uint32_t code, struct cam_path *path,
    void *event_argument)
{
    struct ccb_getdev *device = event_argument;

    (void)argument;
    assert(code == AC_FOUND_DEVICE);
    assert(path != 0);
    assert(device != 0);
    assert(device->ccb_h.func_code == XPT_GDEV_TYPE);
    assert(device->ccb_h.target_id == xpt_path_target_id(path));
    assert(device->protocol == PROTO_SCSI);
    assert(SID_TYPE(&device->inq_data) == T_DIRECT);
    g_async_target = device->ccb_h.target_id;
    g_async_count++;
}

int
main(void)
{
    bsd_allocator_ops_t allocator = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    bsd_sync_ops_t sync = {
        .current_thread = test_current_thread,
        .can_block = test_can_block,
        .prepare_block = test_thread_noop,
        .block_current = test_thread_noop,
        .wake_thread = test_thread_noop,
        .yield_thread = test_yield,
    };
    test_backend_t backend = {0};
    bsd_block_backend_ops_t block = {
        .publish = test_publish,
        .unpublish = test_unpublish,
        .resize = test_resize,
        .context = &backend,
    };
    test_sim_t state = {
        .sectors = 128,
        .inject_unit_attention = 1,
    };
    test_sim_t ata_state = {
        .sectors = TEST_MAX_SECTORS,
        .is_ata = 1,
    };
    struct cam_devq *queue;
    struct cam_sim *sim;
    struct cam_path *path = 0;
    struct cam_periph *periph;
    union ccb async_request;
    union ccb advanced_request;
    union ccb geometry_request;
    union ccb scan_request;
    struct ccb_scsiio start_stop_request;
    struct scsi_read_capacity_data_long capacity;
    char path_string[64];
    uint8_t buffer[TEST_SECTOR_SIZE * 2];

    assert(bsd_allocator_initialize(&allocator) == 0);
    assert(bsd_sync_initialize(&sync) == 0);
    assert(bsd_block_initialize(&block) == 0);
    mtx_init(&state.mutex, "cam-test", 0, MTX_DEF);
    queue = cam_simq_alloc(16);
    assert(queue != 0);
    sim = cam_sim_alloc(test_sim_action, test_sim_poll, "camtest",
        &state, 0, &state.mutex, 16, 0, queue);
    assert(sim != 0);
    assert(xpt_bus_register(sim, 0, 0) == CAM_SUCCESS);
    assert(bsd_cam_sim_count() == 1);
    assert(bsd_cam_disk_count() == 0);

    {
        struct scsi_sense_data sense;
        struct scsi_sense_data_fixed *fixed;
        struct scsi_sense_data_desc *descriptor;
        uint8_t encoded[4];

        scsi_set_sense_data(&sense, SSD_TYPE_NONE, 1,
            SSD_KEY_ILLEGAL_REQUEST, 0x24, 0, SSD_ELEM_NONE);
        fixed = (struct scsi_sense_data_fixed *)&sense;
        assert(fixed->error_code == SSD_CURRENT_ERROR);
        assert(fixed->add_sense_code == 0x24);
        assert(scsi_get_sense_key(&sense, SSD_MIN_SIZE, 0) ==
            SSD_KEY_ILLEGAL_REQUEST);

        scsi_set_sense_data(&sense, SSD_TYPE_DESC, 0,
            SSD_KEY_NOT_READY, 0x04, 1, SSD_ELEM_NONE);
        descriptor = (struct scsi_sense_data_desc *)&sense;
        assert(descriptor->error_code == SSD_DESC_DEFERRED_ERROR);
        assert(descriptor->add_sense_code == 0x04);
        assert(descriptor->add_sense_code_qual == 1);
        assert(scsi_get_sense_key(&sense, sizeof(*descriptor), 0) ==
            SSD_KEY_NOT_READY);
        assert(scsi_get_sense_key(&sense, 0, 0) == -1);

        scsi_ulto4b(0x89abcdefu, encoded);
        assert(scsi_4btoul(encoded) == 0x89abcdefu);
    }

    memset(&geometry_request, 0, sizeof(geometry_request));
    geometry_request.ccg.block_size = TEST_SECTOR_SIZE;
    geometry_request.ccg.volume_size = TEST_MAX_SECTORS;
    cam_calc_geometry(&geometry_request.ccg, 1);
    assert(geometry_request.ccb_h.status == CAM_REQ_CMP);
    assert(geometry_request.ccg.heads == 64);
    assert(geometry_request.ccg.secs_per_track == 32);
    geometry_request.ccg.block_size = 0;
    cam_calc_geometry(&geometry_request.ccg, 1);
    assert(geometry_request.ccb_h.status == CAM_REQ_CMP_ERR);

    assert(xpt_create_path(&path, 0, cam_sim_path(sim),
        CAM_TARGET_WILDCARD, CAM_LUN_WILDCARD) == CAM_REQ_CMP);
    memset(&async_request, 0, sizeof(async_request));
    xpt_setup_ccb(&async_request.ccb_h, path, 5);
    async_request.ccb_h.func_code = XPT_SASYNC_CB;
    async_request.csa.event_enable = AC_FOUND_DEVICE;
    async_request.csa.callback = test_async;
    xpt_action(&async_request);
    assert((async_request.ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP);
    xpt_free_path(path);

    memset(state.storage + 4u * TEST_SECTOR_SIZE, 0x5a,
        sizeof(buffer));
    assert(bsd_cam_scan_pending() == 0);
    assert(g_async_count == 1);
    assert(g_async_target == 0);
    assert(state.capacity_attempts == 2);
    assert(state.targets_seen == 1u);
    assert(bsd_cam_disk_count() == 1);
    assert(backend.published == 1);
    assert(strcmp(backend.name, "da0") == 0);
    assert(backend.description.sector_size == TEST_SECTOR_SIZE);
    assert(backend.description.sector_count == 128);
    assert(backend.description.max_transfer_sectors == 256);
    assert(xpt_create_path(&path, 0, cam_sim_path(sim), 0, 0) ==
        CAM_REQ_CMP);
    xpt_path_lock(path);
    periph = cam_periph_find(path, "da");
    assert(periph != 0);
    assert(strcmp(periph->periph_name, "da") == 0);
    assert(periph->unit_number == 0);
    assert(periph->path != 0);
    assert(periph->sim == sim);
    assert(periph->refcount == 1);
    assert(cam_periph_find(path, "ada") == 0);
    xpt_path_unlock(path);

    assert(strcmp(xpt_path_string(path, path_string,
        sizeof(path_string)), "camtest0:0:0:0") == 0);
    memset(&advanced_request, 0, sizeof(advanced_request));
    memset(&capacity, 0, sizeof(capacity));
    xpt_setup_ccb(&advanced_request.ccb_h, path, CAM_PRIORITY_NORMAL);
    advanced_request.ccb_h.func_code = XPT_DEV_ADVINFO;
    advanced_request.cdai.buftype = CDAI_TYPE_RCAPLONG;
    advanced_request.cdai.buf = (uint8_t *)&capacity;
    advanced_request.cdai.bufsiz = sizeof(capacity);
    xpt_action(&advanced_request);
    assert((advanced_request.ccb_h.status & CAM_STATUS_MASK) ==
        CAM_REQ_CMP);
    assert(advanced_request.cdai.provsiz == sizeof(capacity));
    assert(scsi_8btou64(capacity.addr) == 127);
    assert(scsi_4btoul(capacity.length) == TEST_SECTOR_SIZE);

    memset(&start_stop_request, 0, sizeof(start_stop_request));
    scsi_start_stop(&start_stop_request, 3, 0, MSG_SIMPLE_Q_TAG,
        1, 1, 1, SSD_FULL_SIZE, 5000);
    assert(start_stop_request.ccb_h.func_code == XPT_SCSI_IO);
    assert(start_stop_request.ccb_h.retry_count == 3);
    assert(start_stop_request.ccb_h.flags ==
        (CAM_DIR_NONE | CAM_HIGH_POWER));
    assert(start_stop_request.ccb_h.timeout == 5000);
    assert(start_stop_request.tag_action == MSG_SIMPLE_Q_TAG);
    assert(start_stop_request.cdb_io.cdb_bytes[0] == START_STOP_UNIT);
    assert(start_stop_request.cdb_io.cdb_bytes[1] == SSS_IMMED);
    assert(start_stop_request.cdb_io.cdb_bytes[4] ==
        (SSS_START | SSS_LOEJ));

    memset(&scan_request, 0, sizeof(scan_request));
    xpt_setup_ccb(&scan_request.ccb_h, path, CAM_PRIORITY_NORMAL);
    scan_request.ccb_h.func_code = XPT_SCAN_TGT;
    sim->scan_pending = 0;
    xpt_action(&scan_request);
    assert((scan_request.ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP);
    assert(sim->scan_pending == 1);
    assert(bsd_cam_scan_pending() == 0);
    xpt_free_path(path);
    memset(buffer, 0, sizeof(buffer));
    assert(backend.description.read(backend.description.device_context,
        4, 2, buffer) == 0);
    for (size_t index = 0; index < sizeof(buffer); ++index)
        assert(buffer[index] == 0x5a);
    memset(buffer, 0xa5, sizeof(buffer));
    assert(backend.description.write(backend.description.device_context,
        8, 2, buffer) == 0);
    assert(memcmp(state.storage + 8u * TEST_SECTOR_SIZE, buffer,
        sizeof(buffer)) == 0);

    state.sectors = TEST_MAX_SECTORS;
    sim->scan_pending = 1;
    assert(bsd_cam_scan_pending() == 0);
    assert(backend.resized == 1);
    assert(backend.sectors == TEST_MAX_SECTORS);
    assert(bsd_cam_disk_count() == 1);

    assert(xpt_bus_deregister(cam_sim_path(sim)) == CAM_SUCCESS);
    assert(bsd_cam_sim_count() == 0);
    assert(bsd_cam_disk_count() == 0);
    assert(backend.unpublished == 1);
    cam_sim_free(sim, 1);
    mtx_destroy(&state.mutex);

    mtx_init(&ata_state.mutex, "cam-ata-test", 0, MTX_DEF);
    queue = cam_simq_alloc(16);
    assert(queue != 0);
    sim = cam_sim_alloc(test_sim_action, test_sim_poll, "atatest",
        &ata_state, 0, &ata_state.mutex, 16, 0, queue);
    assert(sim != 0);
    assert(xpt_bus_register(sim, 0, 0) == CAM_SUCCESS);
    memset(ata_state.storage + 12u * TEST_SECTOR_SIZE, 0x3c,
        sizeof(buffer));
    assert(bsd_cam_scan_pending() == 0);
    assert(ata_state.reset_count == 1);
    assert(ata_state.targets_seen == 1u);
    assert(bsd_cam_disk_count() == 1);
    assert(backend.published == 2);
    assert(strcmp(backend.name, "ada0") == 0);
    assert(backend.description.sector_size == TEST_SECTOR_SIZE);
    assert(backend.description.sector_count == TEST_MAX_SECTORS);
    assert(backend.description.max_transfer_sectors == 256);
    assert(xpt_create_path(&path, 0, cam_sim_path(sim), 0, 0) ==
        CAM_REQ_CMP);
    xpt_path_lock(path);
    periph = cam_periph_find(path, "ada");
    assert(periph != 0);
    assert(strcmp(periph->periph_name, "ada") == 0);
    assert(periph->unit_number == 0);
    assert(periph->sim == sim);
    assert(cam_periph_find(path, "da") == 0);
    xpt_path_unlock(path);
    xpt_free_path(path);
    memset(buffer, 0, sizeof(buffer));
    assert(backend.description.read(backend.description.device_context,
        12, 2, buffer) == 0);
    for (size_t index = 0; index < sizeof(buffer); ++index)
        assert(buffer[index] == 0x3c);
    memset(buffer, 0xc3, sizeof(buffer));
    assert(backend.description.write(backend.description.device_context,
        16, 2, buffer) == 0);
    assert(memcmp(ata_state.storage + 16u * TEST_SECTOR_SIZE, buffer,
        sizeof(buffer)) == 0);
    sim->scan_pending = 1;
    assert(bsd_cam_scan_pending() == 0);
    assert(ata_state.reset_count == 1);
    assert(xpt_bus_deregister(cam_sim_path(sim)) == CAM_SUCCESS);
    assert(bsd_cam_disk_count() == 0);
    assert(backend.unpublished == 2);
    cam_sim_free(sim, 1);
    mtx_destroy(&ata_state.mutex);
    return 0;
}
