/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Shared CAM transport and disk publication gateway for imported BSD
 * storage drivers.
 */

#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef BSD_BRIDGE_HOST_TEST
#include <stdio.h>
#include <stdlib.h>
#else
#include "console.h"
#endif

#include "compat/freebsd/cam/cam.h"
#include "compat/freebsd/cam/cam_ccb.h"
#include "compat/freebsd/cam/cam_periph.h"
#include "compat/freebsd/cam/cam_sim.h"
#include "compat/freebsd/cam/cam_xpt_internal.h"
#include "compat/freebsd/cam/cam_xpt_sim.h"
#include "compat/freebsd/cam/scsi/scsi_all.h"
#include "compat/freebsd/cam/scsi/scsi_message.h"
#include "compat/freebsd/edgeos/cam.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/root_mount.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/geom/geom_disk.h"
#include "compat/freebsd/machine/bus.h"
#include "compat/freebsd/sys/bio.h"
#ifdef BSD_BRIDGE_HOST_TEST
#define panic(...) abort()
#else
#include "compat/freebsd/sys/kassert.h"
#endif
#include "compat/freebsd/vm/vm.h"
#include <sys/memdesc.h>
#include "compat/freebsd/sys/sbuf.h"
#ifndef BSD_BRIDGE_HOST_TEST
#include "compat/freebsd/sys/taskqueue.h"
#endif

#define BSD_CAM_ENOENT 2
#define BSD_CAM_EIO 5
#define BSD_CAM_ENXIO 6
#define BSD_CAM_ENOMEM 12
#define BSD_CAM_EBUSY 16
#define BSD_CAM_EINVAL 22
#define BSD_CAM_EOVERFLOW 75
#define BSD_CAM_ERESTART 85
#define BSD_CAM_ETIMEDOUT 110
#define BSD_CAM_MAX_TARGETS 256u
#define BSD_CAM_REPORT_LUNS_BYTES 4096u
#define BSD_CAM_POLL_LIMIT 10000000u
#define BSD_CAM_WAIT_TICKS 3000u
#define BSD_CAM_DEFAULT_MAX_IO (1024u * 1024u)
#define BSD_CAM_COMMAND_ATTEMPTS 4u

typedef struct bsd_cam_disk {
    struct bsd_cam_disk *next;
    struct cam_sim *sim;
    struct cam_path *path;
    struct disk *disk;
    target_id_t target;
    lun_id_t lun;
    uint64_t sectors;
    uint32_t sector_size;
    uint32_t generation;
    cam_proto protocol;
    uint8_t ata_lba48;
    struct cam_periph periph;
} bsd_cam_disk_t;

static volatile uint32_t g_cam_guard;
static struct cam_sim *g_cam_sims;
static bsd_cam_disk_t *g_cam_disks;
static struct cam_periph *g_cam_peripherals;
static uint32_t g_cam_global_async_events;
static void (*g_cam_global_async_callback)(
    void *, uint32_t, struct cam_path *, void *);
static void *g_cam_global_async_argument;
static path_id_t g_next_path_id;
static uint32_t g_next_scsi_disk_unit;
static uint32_t g_next_ata_disk_unit;
static uint32_t g_cam_boot_holds;
#ifndef BSD_BRIDGE_HOST_TEST
static struct root_hold_token *g_cam_boot_token;
#endif
struct cam_periph *xpt_periph;

static void cam_relax(void);
static bsd_cam_disk_t *cam_find_disk(struct cam_sim *sim,
    target_id_t target, lun_id_t lun);
static void cam_store_be32(uint8_t *data, uint32_t value);
static void cam_store_be64(uint8_t *data, uint64_t value);

void
cam_strvis(uint8_t *destination, const uint8_t *source,
    int source_length, int destination_length)
{
    int output = 0;

    if (!destination || destination_length <= 0)
        return;
    if (!source || source_length <= 0) {
        destination[0] = 0;
        return;
    }
    for (int index = 0; index < source_length &&
        output < destination_length - 1; ++index) {
        uint8_t character = source[index];

        destination[output++] = character >= 0x20 && character <= 0x7e ?
            character : (uint8_t)' ';
    }
    while (output > 0 && destination[output - 1] == ' ')
        output--;
    destination[output] = 0;
}

const char *
scsi_op_desc(uint16_t opcode, struct scsi_inquiry_data *inquiry)
{
    (void)inquiry;
    switch (opcode) {
    case TEST_UNIT_READY: return "Test Unit Ready";
    case REQUEST_SENSE: return "Request Sense";
    case INQUIRY: return "Inquiry";
    case READ_6: return "Read(6)";
    case WRITE_6: return "Write(6)";
    case MODE_SELECT_6: return "Mode Select(6)";
    case MODE_SENSE_6: return "Mode Sense(6)";
    case START_STOP_UNIT: return "Start Stop Unit";
    case PREVENT_ALLOW: return "Prevent Allow Medium Removal";
    case READ_CAPACITY: return "Read Capacity(10)";
    case READ_10: return "Read(10)";
    case WRITE_10: return "Write(10)";
    case VERIFY_10: return "Verify(10)";
    case SYNCHRONIZE_CACHE: return "Synchronize Cache(10)";
    case UNMAP: return "Unmap";
    case MODE_SELECT_10: return "Mode Select(10)";
    case MODE_SENSE_10: return "Mode Sense(10)";
    case READ_16: return "Read(16)";
    case WRITE_16: return "Write(16)";
    case WRITE_SAME_16: return "Write Same(16)";
    case REPORT_LUNS: return "Report LUNs";
    case READ_12: return "Read(12)";
    case WRITE_12: return "Write(12)";
    case SERVICE_ACTION_IN: return "Service Action In";
    default: return "Vendor Specific Command";
    }
}

#ifndef BSD_BRIDGE_HOST_TEST
static void cam_scan_task(void *argument, int pending);

static struct task g_cam_scan_task =
    TASK_INITIALIZER(0, cam_scan_task, 0);
static struct taskqueue *g_cam_scan_queue;
static uint8_t g_cam_scan_queue_state;

static int
cam_scan_queue_ensure(void)
{
    uint8_t expected = 0;
    uint8_t state =
        __atomic_load_n(&g_cam_scan_queue_state, __ATOMIC_ACQUIRE);

    if (state == 2)
        return 0;
    if (state == 1) {
        do {
            cam_relax();
            state = __atomic_load_n(
                &g_cam_scan_queue_state, __ATOMIC_ACQUIRE);
        } while (state == 1);
        return state == 2 ? 0 : BSD_CAM_ENOMEM;
    }
    if (!__atomic_compare_exchange_n(&g_cam_scan_queue_state, &expected, 1,
        0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return cam_scan_queue_ensure();
    g_cam_scan_queue = taskqueue_create("cam_scan", M_WAITOK,
        taskqueue_thread_enqueue, &g_cam_scan_queue);
    if (!g_cam_scan_queue ||
        taskqueue_start_threads(&g_cam_scan_queue, 1, 0,
            "cam_scan") != 0) {
        if (g_cam_scan_queue)
            taskqueue_free(g_cam_scan_queue);
        g_cam_scan_queue = 0;
        __atomic_store_n(&g_cam_scan_queue_state, 3, __ATOMIC_RELEASE);
        return BSD_CAM_ENOMEM;
    }
    __atomic_store_n(&g_cam_scan_queue_state, 2, __ATOMIC_RELEASE);
    return 0;
}
#endif

static void
cam_schedule_scan(void)
{
#ifndef BSD_BRIDGE_HOST_TEST
    if (cam_scan_queue_ensure() == 0)
        (void)taskqueue_enqueue(g_cam_scan_queue, &g_cam_scan_task);
    else if (taskqueue_thread)
        (void)taskqueue_enqueue(taskqueue_thread, &g_cam_scan_task);
#endif
}

static void
cam_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void
cam_guard_lock(void)
{
    while (__atomic_test_and_set(&g_cam_guard, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_cam_guard, __ATOMIC_RELAXED))
            cam_relax();
    }
}

static void
cam_guard_unlock(void)
{
    __atomic_clear(&g_cam_guard, __ATOMIC_RELEASE);
}

static struct cam_sim *
cam_find_sim(path_id_t path_id)
{
    struct cam_sim *sim;

    cam_guard_lock();
    for (sim = g_cam_sims; sim; sim = sim->bridge_next) {
        if (sim->registered && sim->path_id == path_id)
            break;
    }
    if (sim)
        sim->refcount++;
    cam_guard_unlock();
    return sim;
}

struct cam_sim *
xpt_path_sim(struct cam_path *path)
{
    return path ? path->sim : 0;
}

void
xpt_path_inq(struct ccb_pathinq *inquiry, struct cam_path *path)
{
    if (!inquiry)
        return;
    bsd_memset(inquiry, 0, sizeof(*inquiry));
    xpt_setup_ccb(&inquiry->ccb_h, path, CAM_PRIORITY_NONE);
    inquiry->ccb_h.func_code = XPT_PATH_INQ;
    xpt_action((union ccb *)inquiry);
}

void
xpt_print(struct cam_path *path, const char *format, ...)
{
    va_list arguments;

    if (path && path->sim)
        bsd_printf("%s%u:%u:%u:%llu: ",
            cam_sim_name(path->sim), cam_sim_unit(path->sim),
            cam_sim_bus(path->sim), path->target_id,
            (unsigned long long)path->lun_id);
    va_start(arguments, format);
    bsd_vprintf(format, arguments);
    va_end(arguments);
}

void
xpt_print_path(struct cam_path *path)
{
    xpt_print(path, "%s", "");
}

char *
xpt_path_string(struct cam_path *path, char *buffer, size_t buffer_length)
{
    if (!buffer || buffer_length == 0)
        return buffer;
    if (!path || !path->sim) {
        (void)bsd_snprintf(buffer, buffer_length, "(nopath)");
        return buffer;
    }
    (void)bsd_snprintf(buffer, buffer_length, "%s%u:%u:%u:%llu",
        path->sim->sim_name, path->sim->unit_number, path->path_id,
        path->target_id, (unsigned long long)path->lun_id);
    return buffer;
}

void
xpt_sim_poll(struct cam_sim *sim)
{
    if (sim && sim->sim_poll)
        sim->sim_poll(sim);
}

static void
cam_put_sim(struct cam_sim *sim)
{
    if (!sim)
        return;
    cam_guard_lock();
    if (sim->refcount > 0)
        sim->refcount--;
    cam_guard_unlock();
}

struct cam_devq *
cam_simq_alloc(uint32_t max_sim_transactions)
{
    struct cam_devq *queue;

    if (!max_sim_transactions)
        return 0;
    queue = bsd_malloc(sizeof(*queue), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (queue)
        queue->openings = max_sim_transactions;
    return queue;
}

void
cam_simq_free(struct cam_devq *queue)
{
    if (queue)
        bsd_free(queue, M_DEVBUF);
}

struct cam_sim *
cam_sim_alloc(sim_action_func action, sim_poll_func poll, const char *name,
    void *softc, uint32_t unit, struct mtx *mutex,
    int max_dev_transactions, int max_tagged_dev_transactions,
    struct cam_devq *queue)
{
    struct cam_sim *sim;

    if (!action || !name || !mutex || !queue ||
        max_dev_transactions <= 0 || max_tagged_dev_transactions < 0)
        return 0;
    sim = bsd_malloc(sizeof(*sim), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!sim)
        return 0;
    sim->sim_action = action;
    sim->sim_poll = poll;
    sim->sim_name = name;
    sim->softc = softc;
    sim->unit_number = unit;
    sim->mtx = mutex;
    sim->max_dev_openings = max_dev_transactions;
    sim->max_tagged_dev_openings = max_tagged_dev_transactions;
    sim->devq = queue;
    sim->path_id = CAM_XPT_PATH_ID;
    sim->refcount = 1;
    return sim;
}

void
cam_sim_hold(struct cam_sim *sim)
{
    if (!sim)
        return;
    cam_guard_lock();
    sim->refcount++;
    cam_guard_unlock();
}

void
cam_sim_release(struct cam_sim *sim)
{
    cam_put_sim(sim);
}

void
cam_sim_free(struct cam_sim *sim, int free_devq)
{
    struct cam_devq *queue;

    if (!sim || sim->registered)
        return;
    cam_guard_lock();
    if (sim->refcount != 1) {
        cam_guard_unlock();
        return;
    }
    sim->refcount = 0;
    queue = sim->devq;
    sim->devq = 0;
    cam_guard_unlock();
    if (free_devq)
        cam_simq_free(queue);
    bsd_free(sim, M_DEVBUF);
}

int
xpt_bus_register(struct cam_sim *sim, device_t parent, uint32_t bus)
{
    struct cam_sim *cursor;

    if (!sim || sim->registered)
        return BSD_CAM_EINVAL;
    cam_guard_lock();
    for (cursor = g_cam_sims; cursor; cursor = cursor->bridge_next) {
        if (cursor == sim) {
            cam_guard_unlock();
            return BSD_CAM_EBUSY;
        }
    }
    sim->path_id = g_next_path_id++;
    sim->bus_id = bus;
    sim->parent = parent;
    sim->registered = 1;
    sim->scan_pending = 1;
    sim->bridge_next = g_cam_sims;
    g_cam_sims = sim;
    cam_guard_unlock();
    printf("[bsd-cam] %s%u bus registered\n",
        sim->sim_name, sim->unit_number);
    cam_schedule_scan();
    return CAM_SUCCESS;
}

static void
cam_unpublish_sim_disks(struct cam_sim *sim)
{
    for (;;) {
        bsd_cam_disk_t **cursor;
        bsd_cam_disk_t *entry = 0;

        cam_guard_lock();
        for (cursor = &g_cam_disks; *cursor;
             cursor = &(*cursor)->next) {
            if ((*cursor)->sim == sim) {
                entry = *cursor;
                *cursor = entry->next;
                break;
            }
        }
        cam_guard_unlock();
        if (!entry)
            break;
        if (entry->disk)
            disk_destroy(entry->disk);
        xpt_free_path(entry->path);
        bsd_free(entry, M_DEVBUF);
    }
}

int
xpt_bus_deregister(path_id_t path_id)
{
    struct cam_sim **cursor;
    struct cam_sim *sim = 0;

    cam_guard_lock();
    for (cursor = &g_cam_sims; *cursor; cursor = &(*cursor)->bridge_next) {
        if ((*cursor)->path_id == path_id) {
            sim = *cursor;
            *cursor = sim->bridge_next;
            sim->bridge_next = 0;
            sim->registered = 0;
            sim->scan_pending = 0;
            sim->transport_ready = 0;
            break;
        }
    }
    cam_guard_unlock();
    if (!sim)
        return BSD_CAM_ENOENT;
    cam_unpublish_sim_disks(sim);
    cam_guard_lock();
    if (sim->refcount != 1) {
        cam_guard_unlock();
        return BSD_CAM_EBUSY;
    }
    cam_guard_unlock();
    sim->path_id = CAM_XPT_PATH_ID;
    return CAM_SUCCESS;
}

cam_status
xpt_create_path(struct cam_path **path_out, void *periph, path_id_t path_id,
    target_id_t target_id, lun_id_t lun_id)
{
    struct cam_path *path;
    struct cam_sim *sim;

    (void)periph;
    if (!path_out)
        return CAM_REQ_INVALID;
    *path_out = 0;
    sim = cam_find_sim(path_id);
    if (!sim)
        return CAM_PATH_INVALID;
    path = bsd_malloc(sizeof(*path), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!path) {
        cam_put_sim(sim);
        return CAM_RESRC_UNAVAIL;
    }
    path->sim = sim;
    path->path_id = path_id;
    path->target_id = target_id;
    path->lun_id = lun_id;
    path->device = &path->device_storage;
    mtx_init(&path->fallback_mtx, "CAM path", 0, MTX_DEF);
    *path_out = path;
    return CAM_REQ_CMP;
}

void
xpt_free_path(struct cam_path *path)
{
    if (!path)
        return;
    cam_put_sim(path->sim);
    mtx_destroy(&path->fallback_mtx);
    bsd_free(path, M_DEVBUF);
}

struct mtx *
xpt_path_mtx(struct cam_path *path)
{
    if (!path)
        return 0;
    if (path->sim && path->sim->mtx)
        return path->sim->mtx;
    return &path->fallback_mtx;
}

struct cam_periph *
cam_periph_find(struct cam_path *path, char *name)
{
    struct cam_periph *generic;
    bsd_cam_disk_t *entry;
    struct cam_periph *periph = 0;

    if (!path)
        return 0;
    cam_guard_lock();
    for (generic = g_cam_peripherals; generic;
        generic = generic->bridge_next) {
        if (generic->path->sim != path->sim ||
            generic->path->target_id != path->target_id ||
            generic->path->lun_id != path->lun_id)
            continue;
        if (name && bsd_strcmp(generic->periph_name, name) != 0)
            continue;
        periph = generic;
        break;
    }
    if (periph) {
        cam_guard_unlock();
        return periph;
    }
    for (entry = g_cam_disks; entry; entry = entry->next) {
        if (entry->sim != path->sim || entry->target != path->target_id ||
            entry->lun != path->lun_id)
            continue;
        if (name && bsd_strcmp(entry->periph.periph_name, name) != 0 &&
            bsd_strcmp(name, "pass") != 0)
            continue;
        periph = &entry->periph;
        break;
    }
    cam_guard_unlock();
    return periph;
}

cam_status
cam_periph_alloc(periph_ctor_t *constructor,
    periph_oninv_t *invalidate, periph_dtor_t *destructor,
    periph_start_t *start, char *name, cam_periph_type type,
    struct cam_path *path, ac_callback_t *callback, ac_code code,
    void *argument)
{
    struct cam_periph *periph;
    cam_status status;

    (void)callback;
    (void)code;
    if (!constructor || !name || !path ||
        cam_periph_find(path, name) != 0)
        return CAM_REQ_INVALID;
    periph = bsd_malloc(sizeof(*periph), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!periph)
        return CAM_RESRC_UNAVAIL;
    status = xpt_create_path(&periph->path, periph,
        path->path_id, path->target_id, path->lun_id);
    if (status != CAM_REQ_CMP) {
        bsd_free(periph, M_DEVBUF);
        return status;
    }
    periph->periph_start = start;
    periph->periph_oninval = invalidate;
    periph->periph_dtor = destructor;
    periph->periph_name = name;
    periph->sim = path->sim;
    periph->type = type;
    periph->scheduled_priority = CAM_PRIORITY_NONE;
    periph->immediate_priority = CAM_PRIORITY_NONE;
    periph->refcount = 1;
    cam_guard_lock();
    periph->bridge_next = g_cam_peripherals;
    g_cam_peripherals = periph;
    cam_guard_unlock();
    status = constructor(periph, argument);
    if (status == CAM_REQ_CMP)
        return status;
    cam_guard_lock();
    if (g_cam_peripherals == periph)
        g_cam_peripherals = periph->bridge_next;
    else {
        struct cam_periph *cursor = g_cam_peripherals;

        while (cursor && cursor->bridge_next != periph)
            cursor = cursor->bridge_next;
        if (cursor)
            cursor->bridge_next = periph->bridge_next;
    }
    cam_guard_unlock();
    xpt_free_path(periph->path);
    bsd_free(periph, M_DEVBUF);
    return status;
}

int
cam_periph_acquire(struct cam_periph *periph)
{
    if (!periph)
        return BSD_CAM_EINVAL;
    cam_guard_lock();
    if (!periph->path || periph->refcount == 0) {
        cam_guard_unlock();
        return BSD_CAM_ENOENT;
    }
    if (periph->refcount == UINT32_MAX) {
        cam_guard_unlock();
        return BSD_CAM_EOVERFLOW;
    }
    periph->refcount++;
    cam_guard_unlock();
    return 0;
}

void
cam_periph_release(struct cam_periph *periph)
{
    if (!periph)
        return;
    cam_guard_lock();
    if (periph->refcount > 1)
        periph->refcount--;
    cam_guard_unlock();
}

int
cam_periph_hold(struct cam_periph *periph, int priority)
{
    (void)priority;
    if (!periph || (periph->flags & CAM_PERIPH_INVALID) != 0)
        return BSD_CAM_ENXIO;
    if (cam_periph_acquire(periph) != 0)
        return BSD_CAM_ENXIO;
    periph->flags |= CAM_PERIPH_LOCKED;
    return 0;
}

void
cam_periph_unhold(struct cam_periph *periph)
{
    if (!periph)
        return;
    periph->flags &= ~CAM_PERIPH_LOCKED;
    cam_periph_release(periph);
}

union ccb *
cam_periph_getccb(struct cam_periph *periph, uint32_t priority)
{
    union ccb *ccb;
    struct mtx *mutex;
    int owned;

    if (!periph || !periph->path)
        return 0;
    mutex = xpt_path_mtx(periph->path);
    owned = mutex && mtx_owned(mutex);
    if (owned)
        mtx_unlock(mutex);
    ccb = xpt_alloc_ccb();
    if (owned)
        mtx_lock(mutex);
    if (!ccb)
        return 0;
    xpt_setup_ccb(&ccb->ccb_h, periph->path, priority);
    ccb->ccb_h.ppriv_ptr0 = periph;
    periph->periph_allocated++;
    return ccb;
}

int
cam_periph_runccb(union ccb *ccb,
    int (*error_routine)(union ccb *, cam_flags, uint32_t),
    cam_flags camflags, uint32_t sense_flags, struct devstat *stats)
{
    struct mtx *mutex;
    uint32_t timeout_ticks;
    int error = 0;

    (void)stats;
    if (!ccb || !ccb->ccb_h.path)
        return BSD_CAM_EINVAL;
    mutex = xpt_path_mtx(ccb->ccb_h.path);
    if (!mutex || !mtx_owned(mutex))
        return BSD_CAM_EINVAL;
    timeout_ticks = ccb->ccb_h.timeout;
    if (timeout_ticks == 0 || timeout_ticks == CAM_TIME_INFINITY)
        timeout_ticks = BSD_CAM_WAIT_TICKS;
    ccb->ccb_h.cbfcnp = 0;

    xpt_action(ccb);
    for (;;) {
        uint32_t waited = 0;

        while (!__atomic_load_n(&ccb->ccb_h.bridge_done,
            __ATOMIC_ACQUIRE) && waited < timeout_ticks) {
            uint64_t generation;

            mtx_unlock(mutex);
            generation = bsd_kthread_wakeup_generation(ccb);
            if (!__atomic_load_n(&ccb->ccb_h.bridge_done,
                __ATOMIC_ACQUIRE))
                (void)bsd_kthread_sleep_generation(
                    ccb, generation, 1);
            mtx_lock(mutex);
            waited++;
        }
        if (!__atomic_load_n(&ccb->ccb_h.bridge_done,
            __ATOMIC_ACQUIRE)) {
            error = BSD_CAM_ETIMEDOUT;
            break;
        }
        if ((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP)
            break;
        if (!error_routine) {
            error = BSD_CAM_EIO;
            break;
        }
        error = error_routine(ccb, camflags, sense_flags);
        if (error != BSD_CAM_ERESTART)
            break;
    }
    if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0) {
        (void)cam_release_devq(ccb->ccb_h.path, 0, 0, 0, 0);
        ccb->ccb_h.status &= ~CAM_DEV_QFRZN;
    }
    return error;
}

int
cam_periph_error(union ccb *ccb, cam_flags camflags,
    uint32_t sense_flags)
{
    (void)camflags;
    (void)sense_flags;
    if (!ccb)
        return BSD_CAM_EINVAL;
    if ((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP)
        return 0;
    return BSD_CAM_EIO;
}

void
xpt_schedule(struct cam_periph *periph, uint32_t priority)
{
    union ccb *ccb;

    if (!periph || !periph->periph_start ||
        (periph->flags & CAM_PERIPH_INVALID) != 0)
        return;
    periph->scheduled_priority = priority;
    ccb = cam_periph_getccb(periph, priority);
    if (!ccb)
        return;
    periph->scheduled_priority = CAM_PRIORITY_NONE;
    periph->periph_start(periph, ccb);
    xpt_free_ccb(ccb);
    if (periph->periph_allocated > 0)
        periph->periph_allocated--;
}

void
xpt_announce_periph(struct cam_periph *periph,
    const char *additional_text)
{
    if (!periph)
        return;
    printf("[bsd-cam] %s%u attached%s%s\n", periph->periph_name,
        periph->unit_number, additional_text ? ": " : "",
        additional_text ? additional_text : "");
}

device_t
xpt_path_sim_device(const struct cam_path *path)
{
    return path && path->sim ? path->sim->parent : 0;
}

void
cam_periph_async(struct cam_periph *periph, uint32_t code,
    struct cam_path *path, void *argument)
{
    (void)path;
    (void)argument;
    if (!periph)
        return;
    if ((code & AC_LOST_DEVICE) != 0) {
        periph->flags |= CAM_PERIPH_INVALID;
        if (periph->periph_oninval)
            periph->periph_oninval(periph);
    }
}

void
xpt_setup_ccb(struct ccb_hdr *header, struct cam_path *path,
    uint32_t priority)
{
    (void)priority;
    if (!header)
        return;
    header->path = path;
    header->path_id = path ? path->path_id : CAM_XPT_PATH_ID;
    header->target_id = path ? path->target_id : CAM_TARGET_WILDCARD;
    header->target_lun = path ? path->lun_id : CAM_LUN_WILDCARD;
    header->pinfo.priority = priority;
    header->pinfo.index = CAM_UNQUEUED_INDEX;
    header->status = CAM_REQ_INPROG;
    header->bridge_done = 0;
}

static void
cam_complete_immediate(union ccb *ccb, cam_status status)
{
    ccb->ccb_h.status = status;
    xpt_done(ccb);
}

static void
cam_dev_advinfo(union ccb *ccb)
{
    struct scsi_read_capacity_data_long capacity;
    bsd_cam_disk_t *entry;
    uint64_t sectors = 0;
    uint32_t sector_size = 0;
    size_t transfer;

    if ((ccb->cdai.flags & CDAI_FLAG_STORE) != 0 ||
        ccb->cdai.buftype != CDAI_TYPE_RCAPLONG || !ccb->cdai.buf ||
        ccb->cdai.bufsiz < 0) {
        cam_complete_immediate(ccb, CAM_REQ_INVALID);
        return;
    }
    cam_guard_lock();
    entry = cam_find_disk(ccb->ccb_h.path->sim, ccb->ccb_h.target_id,
        ccb->ccb_h.target_lun);
    if (entry) {
        sectors = entry->sectors;
        sector_size = entry->sector_size;
    }
    cam_guard_unlock();
    if (!entry) {
        cam_complete_immediate(ccb, CAM_DEV_NOT_THERE);
        return;
    }
    bsd_memset(&capacity, 0, sizeof(capacity));
    if (sectors != 0)
        cam_store_be64(capacity.addr, sectors - 1u);
    cam_store_be32(capacity.length, sector_size);
    ccb->cdai.provsiz = sizeof(capacity);
    transfer = (size_t)ccb->cdai.bufsiz;
    if (transfer > sizeof(capacity))
        transfer = sizeof(capacity);
    if (transfer != 0)
        bsd_memcpy(ccb->cdai.buf, &capacity, transfer);
    cam_complete_immediate(ccb, CAM_REQ_CMP);
}

void
xpt_action(union ccb *ccb)
{
    struct cam_sim *sim;
    int unlock = 0;

    if (!ccb || !ccb->ccb_h.path || !(sim = ccb->ccb_h.path->sim) ||
        !sim->registered) {
        if (ccb)
            cam_complete_immediate(ccb, CAM_NO_HBA);
        return;
    }
    ccb->ccb_h.bridge_done = 0;
    if (ccb->ccb_h.func_code == XPT_SASYNC_CB) {
        sim->async_events = ccb->csa.event_enable;
        sim->async_callback = ccb->csa.callback;
        sim->async_callback_arg = ccb->csa.callback_arg;
        cam_complete_immediate(ccb, CAM_REQ_CMP);
        return;
    }
    if (ccb->ccb_h.func_code == XPT_SCAN_BUS ||
        ccb->ccb_h.func_code == XPT_SCAN_TGT ||
        ccb->ccb_h.func_code == XPT_SCAN_LUN) {
        sim->scan_pending = 1;
        cam_schedule_scan();
        cam_complete_immediate(ccb, CAM_REQ_CMP);
        return;
    }
    if (ccb->ccb_h.func_code == XPT_DEV_ADVINFO) {
        cam_dev_advinfo(ccb);
        return;
    }
    if (sim->mtx && !mtx_owned(sim->mtx)) {
        mtx_lock(sim->mtx);
        unlock = 1;
    }
    sim->sim_action(sim, ccb);
    if (unlock)
        mtx_unlock(sim->mtx);
}

void
xpt_done(union ccb *ccb)
{
    if (!ccb)
        return;
    __atomic_store_n(&ccb->ccb_h.bridge_done, 1u, __ATOMIC_RELEASE);
    bsd_wakeup(ccb);
    if (ccb->ccb_h.cbfcnp)
        ccb->ccb_h.cbfcnp(0, ccb);
}

void
xpt_done_direct(union ccb *ccb)
{
    xpt_done(ccb);
}

uint32_t
xpt_freeze_simq(struct cam_sim *sim, unsigned int count)
{
    uint32_t previous;

    if (!sim)
        return 0;
    previous = sim->frozen;
    if (UINT32_MAX - sim->frozen < count)
        sim->frozen = UINT32_MAX;
    else
        sim->frozen += count;
    return previous;
}

void
xpt_release_simq(struct cam_sim *sim, int run_queue)
{
    (void)run_queue;
    if (sim && sim->frozen)
        sim->frozen--;
}

uint32_t
xpt_freeze_devq(struct cam_path *path, unsigned int count)
{
    uint32_t previous;

    if (!path)
        return 0;
    previous = path->frozen;
    if (UINT32_MAX - path->frozen < count)
        path->frozen = UINT32_MAX;
    else
        path->frozen += count;
    return previous;
}

void
xpt_release_devq(struct cam_path *path, unsigned int count, int run_queue)
{
    (void)run_queue;
    if (!path)
        return;
    if (count >= path->frozen)
        path->frozen = 0;
    else
        path->frozen -= count;
}

void
cam_freeze_devq(struct cam_path *path)
{
    (void)xpt_freeze_devq(path, 1);
}

uint32_t
cam_release_devq(struct cam_path *path, uint32_t release_flags,
    uint32_t opening_reduction, uint32_t timeout, int getcount_only)
{
    uint32_t frozen;

    (void)release_flags;
    (void)opening_reduction;
    (void)timeout;
    if (!path)
        return 0;
    frozen = path->frozen;
    if (!getcount_only)
        xpt_release_devq(path, frozen, 1);
    return frozen;
}

void
xpt_async(uint32_t code, struct cam_path *path, void *argument)
{
    struct cam_sim *sim;

    if (!path || !(sim = path->sim))
        return;
    if ((code & (AC_INQ_CHANGED | AC_LOST_DEVICE | AC_BUS_RESET)) != 0) {
        sim->scan_pending = 1;
        cam_schedule_scan();
    }
    if (sim->async_callback && (sim->async_events & code) != 0)
        sim->async_callback(sim->async_callback_arg, code, path, argument);
    if (g_cam_global_async_callback &&
        (g_cam_global_async_events & code) != 0)
        g_cam_global_async_callback(
            g_cam_global_async_argument, code, path, argument);
}

cam_status
xpt_register_async(int event,
    void (*callback)(void *, uint32_t, struct cam_path *, void *),
    void *callback_argument, struct cam_path *path)
{
    union ccb request;

    if (!path) {
        g_cam_global_async_events = (uint32_t)event;
        g_cam_global_async_callback = callback;
        g_cam_global_async_argument = callback_argument;
        return CAM_REQ_CMP;
    }
    bsd_memset(&request, 0, sizeof(request));
    xpt_setup_ccb(&request.ccb_h, path, CAM_PRIORITY_NORMAL);
    request.ccb_h.func_code = XPT_SASYNC_CB;
    request.csa.event_enable = (uint32_t)event;
    request.csa.callback = callback;
    request.csa.callback_arg = callback_argument;
    xpt_action(&request);
    return (cam_status)(request.ccb_h.status & CAM_STATUS_MASK);
}

void
xpt_hold_boot(void)
{
    cam_guard_lock();
#ifndef BSD_BRIDGE_HOST_TEST
    if (g_cam_boot_holds == 0)
        g_cam_boot_token = root_mount_hold("CAM discovery");
#endif
    if (g_cam_boot_holds != UINT32_MAX)
        g_cam_boot_holds++;
    cam_guard_unlock();
}

void
xpt_release_boot(void)
{
#ifndef BSD_BRIDGE_HOST_TEST
    struct root_hold_token *token = 0;
#endif

    cam_guard_lock();
    if (g_cam_boot_holds != 0)
        g_cam_boot_holds--;
#ifndef BSD_BRIDGE_HOST_TEST
    if (g_cam_boot_holds == 0) {
        token = g_cam_boot_token;
        g_cam_boot_token = 0;
    }
#endif
    cam_guard_unlock();
#ifndef BSD_BRIDGE_HOST_TEST
    if (token)
        root_mount_rel(token);
#endif
}

union ccb *
xpt_alloc_ccb_nowait(void)
{
    return bsd_malloc(sizeof(union ccb), M_DEVBUF, M_NOWAIT | M_ZERO);
}

union ccb *
xpt_alloc_ccb(void)
{
    return bsd_malloc(sizeof(union ccb), M_DEVBUF, M_WAITOK | M_ZERO);
}

void
xpt_free_ccb(union ccb *ccb)
{
    if (ccb)
        bsd_free(ccb, M_DEVBUF);
}

void
xpt_rescan(union ccb *ccb)
{
    if (ccb && ccb->ccb_h.path && ccb->ccb_h.path->sim) {
        ccb->ccb_h.path->sim->scan_pending = 1;
        cam_schedule_scan();
    }
    if (ccb) {
        xpt_free_path(ccb->ccb_h.path);
        ccb->ccb_h.path = 0;
        xpt_free_ccb(ccb);
    }
}

lun_id_t
xpt_path_lun_id(const struct cam_path *path)
{
    return path ? path->lun_id : CAM_LUN_WILDCARD;
}

path_id_t
xpt_path_path_id(const struct cam_path *path)
{
    return path ? path->path_id : CAM_XPT_PATH_ID;
}

target_id_t
xpt_path_target_id(const struct cam_path *path)
{
    return path ? path->target_id : CAM_TARGET_WILDCARD;
}

struct memdesc
memdesc_ccb(union ccb *ccb)
{
    void *data;
    uint32_t length;
    uint16_t segment_count;

    if (!ccb)
        return memdesc_vaddr(0, 0);
    switch (ccb->ccb_h.func_code) {
    case XPT_SCSI_IO:
    case XPT_CONT_TARGET_IO:
        data = ccb->csio.data_ptr;
        length = ccb->csio.dxfer_len;
        segment_count = ccb->csio.sglist_cnt;
        break;
    case XPT_NVME_IO:
    case XPT_NVME_ADMIN:
        data = ccb->nvmeio.data_ptr;
        length = ccb->nvmeio.dxfer_len;
        segment_count = ccb->nvmeio.sglist_cnt;
        break;
    case XPT_ATA_IO:
        data = ccb->ataio.data_ptr;
        length = ccb->ataio.dxfer_len;
        segment_count = 0;
        break;
    default:
        panic("%s: unsupported function code %u", __func__,
            ccb->ccb_h.func_code);
    }
    switch (ccb->ccb_h.flags & CAM_DATA_MASK) {
    case CAM_DATA_VADDR:
        return memdesc_vaddr(data, length);
    case CAM_DATA_PADDR:
        return memdesc_paddr((vm_paddr_t)(uintptr_t)data, length);
    case CAM_DATA_SG:
        return memdesc_vlist(data, segment_count);
    case CAM_DATA_SG_PADDR:
        return memdesc_plist(data, segment_count);
    case CAM_DATA_BIO:
        return memdesc_bio(data);
    default:
        panic("%s: unsupported data flags %#x", __func__,
            ccb->ccb_h.flags);
    }
}

int
bus_dmamap_load_ccb(bus_dma_tag_t tag, bus_dmamap_t map,
    union ccb *ccb, bus_dmamap_callback_t *callback,
    void *callback_argument, int flags)
{
    struct memdesc memory;

    if (!ccb || !callback)
        return BSD_CAM_EINVAL;
    if ((ccb->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_NONE) {
        callback(callback_argument, 0, 0, 0);
        return 0;
    }
    memory = memdesc_ccb(ccb);
    return bus_dmamap_load_mem(tag, map, &memory, callback,
        callback_argument, flags);
}

void
xpt_path_sbuf(struct cam_path *path, struct sbuf *buffer)
{
    if (!buffer)
        return;
    if (!path || !path->sim) {
        sbuf_printf(buffer, "(nopath): ");
        return;
    }
    sbuf_printf(buffer, "(%s%u:%u:%u:%llu): ",
        cam_sim_name(path->sim), cam_sim_unit(path->sim),
        cam_sim_bus(path->sim), path->target_id,
        (unsigned long long)path->lun_id);
}

void
cam_calc_geometry(struct ccb_calc_geometry *geometry, int extended)
{
    uint32_t sectors_per_cylinder;
    uint64_t blocks_per_megabyte;
    uint64_t size_megabytes;

    if (!geometry)
        return;
    if (!geometry->block_size) {
        geometry->ccb_h.status = CAM_REQ_CMP_ERR;
        return;
    }
    blocks_per_megabyte = (1024u * 1024u) / geometry->block_size;
    if (!blocks_per_megabyte) {
        geometry->ccb_h.status = CAM_REQ_CMP_ERR;
        return;
    }
    size_megabytes = geometry->volume_size / blocks_per_megabyte;
    if (extended && size_megabytes > 1024u) {
        geometry->heads = 255;
        geometry->secs_per_track = 63;
    } else {
        geometry->heads = 64;
        geometry->secs_per_track = 32;
    }
    sectors_per_cylinder =
        (uint32_t)geometry->heads * geometry->secs_per_track;
    if (!sectors_per_cylinder) {
        geometry->ccb_h.status = CAM_REQ_CMP_ERR;
        return;
    }
    geometry->cylinders =
        geometry->volume_size / sectors_per_cylinder > UINT32_MAX ?
        UINT32_MAX :
        (uint32_t)(geometry->volume_size / sectors_per_cylinder);
    geometry->ccb_h.status = CAM_REQ_CMP;
}

void
scsi_command_string(struct ccb_scsiio *request, struct sbuf *buffer)
{
    uint8_t operation;

    if (!request || !buffer)
        return;
    operation = (request->ccb_h.flags & CAM_CDB_POINTER) != 0 ?
        request->cdb_io.cdb_ptr[0] : request->cdb_io.cdb_bytes[0];
    sbuf_printf(buffer, "CDB 0x%02x ", operation);
}

void
scsi_set_sense_data(struct scsi_sense_data *sense_data,
    scsi_sense_data_type sense_format, int current_error, int sense_key,
    int asc, int ascq, ...)
{
    va_list arguments;

    if (!sense_data)
        return;
    bsd_memset(sense_data, 0, sizeof(*sense_data));
    if (sense_format == SSD_TYPE_DESC) {
        struct scsi_sense_data_desc *sense =
            (struct scsi_sense_data_desc *)sense_data;

        sense->error_code = current_error ?
            SSD_DESC_CURRENT_ERROR : SSD_DESC_DEFERRED_ERROR;
        sense->sense_key = (uint8_t)sense_key & SSD_KEY;
        sense->add_sense_code = (uint8_t)asc;
        sense->add_sense_code_qual = (uint8_t)ascq;
    } else {
        struct scsi_sense_data_fixed *sense =
            (struct scsi_sense_data_fixed *)sense_data;

        sense->error_code = current_error ?
            SSD_CURRENT_ERROR : SSD_DEFERRED_ERROR;
        sense->flags = (uint8_t)sense_key & SSD_KEY;
        sense->add_sense_code = (uint8_t)asc;
        sense->add_sense_code_qual = (uint8_t)ascq;
        sense->extra_len = 6;
    }

    va_start(arguments, ascq);
    for (;;) {
        scsi_sense_elem_type element =
            (scsi_sense_elem_type)va_arg(arguments, int);
        int length;
        const uint8_t *data;

        if (element == SSD_ELEM_NONE)
            break;
        if (element <= SSD_ELEM_NONE || element >= SSD_ELEM_MAX)
            break;
        length = va_arg(arguments, int);
        data = va_arg(arguments, const uint8_t *);
        if (length <= 0 || !data || sense_format == SSD_TYPE_DESC)
            continue;

        struct scsi_sense_data_fixed *sense =
            (struct scsi_sense_data_fixed *)sense_data;
        switch (element) {
        case SSD_ELEM_SKS:
            if ((unsigned int)length > sizeof(sense->sense_key_spec))
                length = sizeof(sense->sense_key_spec);
            bsd_memcpy(sense->sense_key_spec, data, (size_t)length);
            if (sense->extra_len < 10)
                sense->extra_len = 10;
            break;
        case SSD_ELEM_COMMAND:
            if ((unsigned int)length > sizeof(sense->cmd_spec_info)) {
                data += length - sizeof(sense->cmd_spec_info);
                length = sizeof(sense->cmd_spec_info);
            }
            bsd_memcpy(sense->cmd_spec_info +
                sizeof(sense->cmd_spec_info) - (size_t)length,
                data, (size_t)length);
            break;
        case SSD_ELEM_INFO:
            if ((unsigned int)length > sizeof(sense->info)) {
                data += length - sizeof(sense->info);
                length = sizeof(sense->info);
            }
            bsd_memcpy(sense->info + sizeof(sense->info) -
                (size_t)length, data, (size_t)length);
            sense->error_code |= 0x80u;
            break;
        case SSD_ELEM_FRU:
            sense->fru = data[0];
            if (sense->extra_len < 7)
                sense->extra_len = 7;
            break;
        case SSD_ELEM_STREAM:
            sense->flags |= data[0] &
                (SSD_ILI | SSD_EOM | SSD_FILEMARK);
            break;
        default:
            break;
        }
    }
    va_end(arguments);
}

int
scsi_get_sense_key(struct scsi_sense_data *sense_data,
    unsigned int sense_len, int show_errors)
{
    uint8_t response;

    (void)show_errors;
    if (!sense_data || sense_len == 0)
        return -1;
    response = sense_data->error_code & SSD_ERRCODE;
    if (response == SSD_CURRENT_ERROR ||
        response == SSD_DEFERRED_ERROR) {
        const struct scsi_sense_data_fixed *sense =
            (const struct scsi_sense_data_fixed *)sense_data;

        if (sense_len <= offsetof(struct scsi_sense_data_fixed, flags))
            return -1;
        return sense->flags & SSD_KEY;
    }
    if (response == SSD_DESC_CURRENT_ERROR ||
        response == SSD_DESC_DEFERRED_ERROR) {
        const struct scsi_sense_data_desc *sense =
            (const struct scsi_sense_data_desc *)sense_data;

        if (sense_len <= offsetof(struct scsi_sense_data_desc, sense_key))
            return -1;
        return sense->sense_key & SSD_KEY;
    }
    return -1;
}

void
scsi_start_stop(struct ccb_scsiio *request, uint32_t retries,
    void (*completion)(struct cam_periph *, union ccb *),
    uint8_t tag_action, int start, int load_eject, int immediate,
    uint8_t sense_length, uint32_t timeout)
{
    struct scsi_start_stop_unit *command;
    uint32_t flags = CAM_DIR_NONE;

    if (!request)
        return;
    command = (struct scsi_start_stop_unit *)request->cdb_io.cdb_bytes;
    bsd_memset(command, 0, sizeof(*command));
    command->opcode = START_STOP_UNIT;
    if (start) {
        command->how |= SSS_START;
        flags |= CAM_HIGH_POWER;
    }
    if (load_eject)
        command->how |= SSS_LOEJ;
    if (immediate)
        command->byte2 |= SSS_IMMED;
    cam_fill_csio(request, retries, completion, flags, tag_action, 0, 0,
        sense_length, sizeof(*command), timeout);
}

void
scsi_start_stop_pc(struct ccb_scsiio *request, uint32_t retries,
    void (*completion)(struct cam_periph *, union ccb *),
    uint8_t tag_action, int start, int load_eject, int immediate,
    uint8_t power_condition, uint8_t sense_length, uint32_t timeout)
{
    struct scsi_start_stop_unit *command;
    uint32_t flags = CAM_DIR_NONE;

    if (!request)
        return;
    command = (struct scsi_start_stop_unit *)request->cdb_io.cdb_bytes;
    bsd_memset(command, 0, sizeof(*command));
    command->opcode = START_STOP_UNIT;
    if (start) {
        command->how |= SSS_START;
        flags |= CAM_HIGH_POWER;
    }
    if (load_eject)
        command->how |= SSS_LOEJ;
    command->how |= power_condition & SSS_PC_MASK;
    if (immediate)
        command->byte2 |= SSS_IMMED;
    cam_fill_csio(request, retries, completion, flags, tag_action, 0, 0,
        sense_length, sizeof(*command), timeout);
}

void
scsi_sense_print(struct ccb_scsiio *request)
{
    uint8_t response;
    uint8_t key = 0;
    uint8_t asc = 0;
    uint8_t ascq = 0;

    if (!request)
        return;
    response = request->sense_data.error_code & SSD_ERRCODE;
    if (response == SSD_CURRENT_ERROR ||
        response == SSD_DEFERRED_ERROR) {
        const struct scsi_sense_data_fixed *sense =
            (const struct scsi_sense_data_fixed *)&request->sense_data;

        key = sense->flags & SSD_KEY;
        asc = sense->add_sense_code;
        ascq = sense->add_sense_code_qual;
    } else if (response == SSD_DESC_CURRENT_ERROR ||
        response == SSD_DESC_DEFERRED_ERROR) {
        const struct scsi_sense_data_desc *sense =
            (const struct scsi_sense_data_desc *)&request->sense_data;

        key = sense->sense_key & SSD_KEY;
        asc = sense->add_sense_code;
        ascq = sense->add_sense_code_qual;
    }
    xpt_print(request->ccb_h.path,
        "SCSI status %#x, sense key %#x, ASC %#x, ASCQ %#x\n",
        request->scsi_status, key, asc, ascq);
}

static int
cam_poll_request(union ccb *ccb)
{
    struct cam_sim *sim = ccb->ccb_h.path->sim;

#ifdef BSD_BRIDGE_HOST_TEST
    for (uint32_t attempt = 0; attempt < BSD_CAM_POLL_LIMIT; ++attempt) {
        int unlock = 0;

        if (__atomic_load_n(&ccb->ccb_h.bridge_done, __ATOMIC_ACQUIRE))
            return 0;
        if (sim->sim_poll) {
            if (sim->mtx && !mtx_owned(sim->mtx)) {
                mtx_lock(sim->mtx);
                unlock = 1;
            }
            sim->sim_poll(sim);
            if (unlock)
                mtx_unlock(sim->mtx);
        }
        if (__atomic_load_n(&ccb->ccb_h.bridge_done, __ATOMIC_ACQUIRE))
            return 0;
        cam_relax();
    }
#else
    (void)sim;
    for (uint32_t attempt = 0; attempt < BSD_CAM_WAIT_TICKS; ++attempt) {
        uint64_t generation;

        if (__atomic_load_n(&ccb->ccb_h.bridge_done, __ATOMIC_ACQUIRE))
            return 0;
        generation = bsd_kthread_wakeup_generation(ccb);
        if (__atomic_load_n(&ccb->ccb_h.bridge_done, __ATOMIC_ACQUIRE))
            return 0;
        /*
         * Normal CAM traffic is completed by the driver's interrupt path.
         * A SIM poll callback is reserved for crash-dump style operation
         * where scheduling and interrupts are unavailable.  Polling here
         * would also violate drivers such as MFI whose poll callback invokes
         * an interrupt routine that acquires the SIM mutex itself.
         */
        (void)bsd_kthread_sleep_generation(ccb, generation, 1);
    }
#endif
    return BSD_CAM_EIO;
}

static int
cam_scsi_execute_once(struct cam_path *path, const uint8_t *cdb,
    uint8_t cdb_length, uint32_t direction, void *data, uint32_t data_length,
    union ccb *request)
{
    bsd_memset(request, 0, sizeof(*request));
    xpt_setup_ccb(&request->ccb_h, path, 5);
    request->ccb_h.func_code = XPT_SCSI_IO;
    request->ccb_h.flags = direction | CAM_DATA_VADDR;
    request->ccb_h.timeout = CAM_TIME_INFINITY;
    request->csio.data_ptr = data;
    request->csio.dxfer_len = data_length;
    request->csio.sense_len = sizeof(request->csio.sense_data);
    request->csio.cdb_len = cdb_length;
    request->csio.tag_action = MSG_SIMPLE_Q_TAG;
    bsd_memcpy(request->csio.cdb_io.cdb_bytes, cdb, cdb_length);
    xpt_action(request);
    if (cam_poll_request(request) != 0)
        return BSD_CAM_ETIMEDOUT;
    if (request->csio.resid > data_length)
        return BSD_CAM_EIO;
    return 0;
}

static int
cam_sense_values(const struct scsi_sense_data *sense, uint32_t sense_length,
    uint8_t *key, uint8_t *asc, uint8_t *ascq)
{
    const uint8_t *bytes = sense->bytes;
    uint8_t response;

    if (!sense || !sense_length || !key || !asc || !ascq)
        return BSD_CAM_EINVAL;
    response = bytes[0] & SSD_ERRCODE;
    if (response == SSD_DESC_CURRENT_ERROR ||
        response == SSD_DESC_DEFERRED_ERROR) {
        if (sense_length < 4u)
            return BSD_CAM_EIO;
        *key = bytes[1] & SSD_KEY;
        *asc = bytes[2];
        *ascq = bytes[3];
        return 0;
    }
    if (response != SSD_CURRENT_ERROR &&
        response != SSD_DEFERRED_ERROR)
        return BSD_CAM_EIO;
    if (sense_length < 3u)
        return BSD_CAM_EIO;
    *key = bytes[2] & SSD_KEY;
    *asc = sense_length > 12u ? bytes[12] : 0;
    *ascq = sense_length > 13u ? bytes[13] : 0;
    return 0;
}

static int
cam_request_sense(struct cam_path *path, uint8_t *key, uint8_t *asc,
    uint8_t *ascq)
{
    struct scsi_sense_data sense;
    union ccb request;
    uint8_t command[6] = {REQUEST_SENSE, 0, 0, 0, sizeof(sense), 0};
    uint32_t received;

    bsd_memset(&sense, 0, sizeof(sense));
    if (cam_scsi_execute_once(path, command, sizeof(command), CAM_DIR_IN,
        &sense, sizeof(sense), &request) != 0 ||
        (request.ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP ||
        request.csio.scsi_status != SCSI_STATUS_OK)
        return BSD_CAM_EIO;
    received = sizeof(sense) - request.csio.resid;
    return cam_sense_values(&sense, received, key, asc, ascq);
}

static int
cam_scsi_retryable(struct cam_path *path, const uint8_t *cdb,
    const union ccb *request)
{
    uint32_t status = request->ccb_h.status & CAM_STATUS_MASK;
    uint32_t sense_length;
    uint8_t key = 0;
    uint8_t asc = 0;
    uint8_t ascq = 0;

    if (status == CAM_BUSY || status == CAM_SCSI_BUSY ||
        status == CAM_REQUEUE_REQ || status == CAM_SCSI_BUS_RESET ||
        status == CAM_REQ_ABORTED)
        return 1;
    if (status != CAM_SCSI_STATUS_ERROR ||
        request->csio.scsi_status != SCSI_STATUS_CHECK_COND)
        return 0;
    sense_length = request->csio.sense_len >= request->csio.sense_resid ?
        request->csio.sense_len - request->csio.sense_resid : 0;
    if (!(request->ccb_h.status & CAM_AUTOSNS_VALID) ||
        cam_sense_values(&request->csio.sense_data, sense_length,
        &key, &asc, &ascq) != 0) {
        if (cdb[0] == REQUEST_SENSE ||
            cam_request_sense(path, &key, &asc, &ascq) != 0)
            return 0;
    }
    (void)asc;
    (void)ascq;
    return key == SSD_KEY_NO_SENSE ||
        key == SSD_KEY_RECOVERED_ERROR ||
        key == SSD_KEY_NOT_READY ||
        key == SSD_KEY_UNIT_ATTENTION ||
        key == SSD_KEY_ABORTED_COMMAND;
}

static int
cam_scsi_execute(struct cam_path *path, const uint8_t *cdb,
    uint8_t cdb_length, uint32_t direction, void *data, uint32_t data_length,
    uint32_t *residual)
{
    union ccb request;

    if (!path || !cdb || !cdb_length || cdb_length > CAM_MAX_CDBLEN ||
        (data_length && !data))
        return BSD_CAM_EINVAL;
    for (uint32_t attempt = 0; attempt < BSD_CAM_COMMAND_ATTEMPTS;
         ++attempt) {
        int error = cam_scsi_execute_once(path, cdb, cdb_length,
            direction, data, data_length, &request);

        if (error != 0)
            return error;
        if (residual)
            *residual = request.csio.resid;
        if ((request.ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP &&
            request.csio.scsi_status == SCSI_STATUS_OK)
            return 0;
        if (attempt + 1u == BSD_CAM_COMMAND_ATTEMPTS ||
            !cam_scsi_retryable(path, cdb, &request))
            return BSD_CAM_EIO;
    }
    return BSD_CAM_EIO;
}

static int
cam_ata_retryable(const union ccb *request)
{
    uint32_t status = request->ccb_h.status & CAM_STATUS_MASK;

    return status == CAM_BUSY || status == CAM_REQUEUE_REQ ||
        status == CAM_REQ_ABORTED || status == CAM_SCSI_BUS_RESET;
}

static int
cam_ata_execute(struct cam_path *path, const struct ata_cmd *command,
    uint32_t direction, void *data, uint32_t data_length,
    uint32_t *residual)
{
    union ccb request;
    uint32_t status;

    if (!path || !command || (data_length && !data))
        return BSD_CAM_EINVAL;
    for (uint32_t attempt = 0; attempt < BSD_CAM_COMMAND_ATTEMPTS;
         ++attempt) {
        bsd_memset(&request, 0, sizeof(request));
        xpt_setup_ccb(&request.ccb_h, path, 5);
        request.ccb_h.func_code = XPT_ATA_IO;
        request.ccb_h.flags = direction | CAM_DATA_VADDR;
        request.ccb_h.timeout = CAM_TIME_INFINITY;
        request.ataio.cmd = *command;
        request.ataio.data_ptr = data;
        request.ataio.dxfer_len = data_length;
        xpt_action(&request);
        if (cam_poll_request(&request) != 0 ||
            request.ataio.resid > data_length)
            return BSD_CAM_EIO;
        if (residual)
            *residual = request.ataio.resid;
        status = request.ccb_h.status & CAM_STATUS_MASK;
        if (status == CAM_REQ_CMP)
            return 0;
        if (status == CAM_SEL_TIMEOUT || status == CAM_DEV_NOT_THERE)
            return BSD_CAM_ENOENT;
        if (request.ccb_h.status & CAM_DEV_QFRZN)
            xpt_release_devq(path, 1, 1);
        if (attempt + 1u == BSD_CAM_COMMAND_ATTEMPTS ||
            !cam_ata_retryable(&request))
            return BSD_CAM_EIO;
    }
    return BSD_CAM_EIO;
}

static void
cam_ata_28bit_command(struct ata_cmd *command, uint8_t opcode,
    uint64_t lba, uint32_t sector_count)
{
    bsd_memset(command, 0, sizeof(*command));
    command->flags = CAM_ATAIO_DMA;
    command->command = opcode;
    command->lba_low = (uint8_t)lba;
    command->lba_mid = (uint8_t)(lba >> 8);
    command->lba_high = (uint8_t)(lba >> 16);
    command->device = ATA_DEV_LBA | ((uint8_t)(lba >> 24) & 0x0fu);
    command->sector_count = (uint8_t)sector_count;
}

static void
cam_ata_48bit_command(struct ata_cmd *command, uint8_t opcode,
    uint64_t lba, uint32_t sector_count)
{
    bsd_memset(command, 0, sizeof(*command));
    command->flags = CAM_ATAIO_48BIT | CAM_ATAIO_DMA;
    command->command = opcode;
    command->lba_low = (uint8_t)lba;
    command->lba_mid = (uint8_t)(lba >> 8);
    command->lba_high = (uint8_t)(lba >> 16);
    command->device = ATA_DEV_LBA;
    command->lba_low_exp = (uint8_t)(lba >> 24);
    command->lba_mid_exp = (uint8_t)(lba >> 32);
    command->lba_high_exp = (uint8_t)(lba >> 40);
    command->sector_count = (uint8_t)sector_count;
    command->sector_count_exp = (uint8_t)(sector_count >> 8);
}

static uint16_t
cam_ata_ident_word(const struct ata_params *identity, uint32_t word)
{
    const uint8_t *bytes = (const uint8_t *)identity;

    return (uint16_t)bytes[word * 2u] |
        ((uint16_t)bytes[word * 2u + 1u] << 8);
}

static int
cam_ata_ident_geometry(const struct ata_params *identity, uint64_t *sectors,
    uint32_t *sector_size, uint8_t *lba48)
{
    uint16_t command2;
    uint16_t physical;
    uint64_t count;
    uint64_t logical_words;

    if (!identity || !sectors || !sector_size || !lba48)
        return BSD_CAM_EINVAL;
    command2 = cam_ata_ident_word(identity, 83);
    *lba48 = (command2 & 0xc000u) == 0x4000u &&
        (command2 & ATA_SUPPORT_ADDRESS48) != 0;
    if (*lba48) {
        count = cam_ata_ident_word(identity, 100) |
            ((uint64_t)cam_ata_ident_word(identity, 101) << 16) |
            ((uint64_t)cam_ata_ident_word(identity, 102) << 32) |
            ((uint64_t)cam_ata_ident_word(identity, 103) << 48);
    } else {
        count = cam_ata_ident_word(identity, 60) |
            ((uint64_t)cam_ata_ident_word(identity, 61) << 16);
    }
    if (!count)
        return BSD_CAM_EIO;
    physical = cam_ata_ident_word(identity, 106);
    if ((physical & ATA_PSS_VALID_MASK) == ATA_PSS_VALID_VALUE &&
        (physical & ATA_PSS_LSSABOVE512)) {
        logical_words = cam_ata_ident_word(identity, 117) |
            ((uint64_t)cam_ata_ident_word(identity, 118) << 16);
        if (!logical_words || logical_words > UINT32_MAX / 2u)
            return BSD_CAM_EOVERFLOW;
        *sector_size = (uint32_t)(logical_words * 2u);
    } else {
        *sector_size = 512u;
    }
    if (*sector_size < 512u || count > INT64_MAX / *sector_size)
        return BSD_CAM_EOVERFLOW;
    *sectors = count;
    return 0;
}

static uint32_t
cam_be32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
        ((uint32_t)data[2] << 8) | data[3];
}

static uint64_t
cam_be64(const uint8_t *data)
{
    return ((uint64_t)cam_be32(data) << 32) | cam_be32(data + 4);
}

static void
cam_store_be16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

static void
cam_store_be32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static void
cam_store_be64(uint8_t *data, uint64_t value)
{
    cam_store_be32(data, (uint32_t)(value >> 32));
    cam_store_be32(data + 4, (uint32_t)value);
}

static void
cam_disk_strategy(struct bio *bio)
{
    bsd_cam_disk_t *entry;
    struct ata_cmd ata_command;
    uint8_t command[16];
    uint64_t lba;
    uint32_t count;
    uint32_t direction;
    uint32_t residual = 0;
    int error;

    if (!bio || !bio->bio_disk ||
        !(entry = bio->bio_disk->d_drv1) || bio->bio_offset < 0 ||
        bio->bio_bcount <= 0 || (uint64_t)bio->bio_bcount > UINT32_MAX ||
        !entry->sector_size ||
        (uint64_t)bio->bio_offset % entry->sector_size != 0 ||
        (uint64_t)bio->bio_bcount % entry->sector_size != 0) {
        if (bio)
            biofinish(bio, 0, BSD_CAM_EINVAL);
        return;
    }
    lba = (uint64_t)bio->bio_offset / entry->sector_size;
    count = (uint32_t)((uint64_t)bio->bio_bcount / entry->sector_size);
    if (!count || lba >= entry->sectors ||
        count > entry->sectors - lba ||
        (bio->bio_cmd != BIO_READ && bio->bio_cmd != BIO_WRITE)) {
        biofinish(bio, 0, BSD_CAM_EINVAL);
        return;
    }
    bsd_memset(command, 0, sizeof(command));
    direction = bio->bio_cmd == BIO_READ ? CAM_DIR_IN : CAM_DIR_OUT;
    if (entry->protocol == PROTO_ATA) {
        if (entry->ata_lba48) {
            if (count > 65536u || lba > 0xffffffffffffULL ||
                lba + count - 1u > 0xffffffffffffULL) {
                biofinish(bio, 0, BSD_CAM_EINVAL);
                return;
            }
            cam_ata_48bit_command(&ata_command,
                bio->bio_cmd == BIO_READ ? ATA_READ_DMA48 :
                ATA_WRITE_DMA48, lba, count);
        } else {
            if (count > 256u || lba > ATA_MAX_28BIT_LBA ||
                lba + count - 1u > ATA_MAX_28BIT_LBA) {
                biofinish(bio, 0, BSD_CAM_EINVAL);
                return;
            }
            cam_ata_28bit_command(&ata_command,
                bio->bio_cmd == BIO_READ ? ATA_READ_DMA :
                ATA_WRITE_DMA, lba, count);
        }
        error = cam_ata_execute(entry->path, &ata_command, direction,
            bio->bio_data, (uint32_t)bio->bio_bcount, &residual);
    } else if (lba <= UINT32_MAX && count <= UINT16_MAX &&
        lba + count - 1u <= UINT32_MAX) {
        command[0] = bio->bio_cmd == BIO_READ ? READ_10 : WRITE_10;
        cam_store_be32(&command[2], (uint32_t)lba);
        cam_store_be16(&command[7], (uint16_t)count);
        error = cam_scsi_execute(entry->path, command, 10, direction,
            bio->bio_data, (uint32_t)bio->bio_bcount, &residual);
    } else {
        command[0] = bio->bio_cmd == BIO_READ ? READ_16 : WRITE_16;
        cam_store_be64(&command[2], lba);
        cam_store_be32(&command[10], count);
        error = cam_scsi_execute(entry->path, command, 16, direction,
            bio->bio_data, (uint32_t)bio->bio_bcount, &residual);
    }
    if (error || residual != 0) {
        bio->bio_resid = bio->bio_bcount;
        biofinish(bio, 0, error ? error : BSD_CAM_EIO);
    } else {
        bio->bio_resid = 0;
        biodone(bio);
    }
}

static bsd_cam_disk_t *
cam_find_disk(struct cam_sim *sim, target_id_t target, lun_id_t lun)
{
    bsd_cam_disk_t *entry;

    for (entry = g_cam_disks; entry; entry = entry->next) {
        if (entry->sim == sim && entry->target == target &&
            entry->lun == lun)
            return entry;
    }
    return 0;
}

static int
cam_read_capacity(struct cam_path *path, uint64_t *sectors,
    uint32_t *sector_size)
{
    uint8_t command[16];
    uint8_t response[32];
    uint64_t last_lba;
    uint32_t residual = 0;

    bsd_memset(command, 0, sizeof(command));
    bsd_memset(response, 0, sizeof(response));
    command[0] = READ_CAPACITY;
    if (cam_scsi_execute(path, command, 10, CAM_DIR_IN, response, 8,
        &residual) != 0 || residual != 0)
        return BSD_CAM_EIO;
    last_lba = cam_be32(response);
    *sector_size = cam_be32(response + 4);
    if (last_lba == UINT32_MAX) {
        bsd_memset(command, 0, sizeof(command));
        bsd_memset(response, 0, sizeof(response));
        command[0] = SERVICE_ACTION_IN;
        command[1] = SAI_READ_CAPACITY_16;
        cam_store_be32(command + 10, sizeof(response));
        if (cam_scsi_execute(path, command, 16, CAM_DIR_IN, response,
            sizeof(response), &residual) != 0 || residual != 0)
            return BSD_CAM_EIO;
        last_lba = cam_be64(response);
        *sector_size = cam_be32(response + 8);
    }
    if (!*sector_size || last_lba == UINT64_MAX)
        return BSD_CAM_EOVERFLOW;
    *sectors = last_lba + 1u;
    return 0;
}

static int
cam_publish_disk(struct cam_sim *sim, const struct ccb_pathinq *inquiry,
    struct cam_path *path, target_id_t target, lun_id_t lun,
    uint32_t generation, cam_proto protocol, uint8_t ata_lba48,
    uint64_t sectors, uint32_t sector_size,
    const struct scsi_inquiry_data *scsi_identity,
    const struct ata_params *ata_identity)
{
    bsd_cam_disk_t *entry;
    struct ccb_getdev device;
    struct disk *disk;
    uint64_t media_size;
    uint32_t max_io;
    int error;

    if (path && path->device)
        path->device->protocol = protocol;

    media_size = sectors * sector_size;
    cam_guard_lock();
    entry = cam_find_disk(sim, target, lun);
    if (entry) {
        entry->generation = generation;
        entry->protocol = protocol;
        entry->ata_lba48 = ata_lba48;
        if (entry->sectors != sectors || entry->sector_size != sector_size) {
            entry->sectors = sectors;
            entry->sector_size = sector_size;
            entry->disk->d_sectorsize = sector_size;
            entry->disk->d_mediasize = (int64_t)media_size;
            (void)disk_resize(entry->disk, 0);
        }
        cam_guard_unlock();
        xpt_free_path(path);
        return 0;
    }
    cam_guard_unlock();

    entry = bsd_malloc(sizeof(*entry), M_DEVBUF, M_NOWAIT | M_ZERO);
    disk = disk_alloc();
    if (!entry || !disk) {
        if (entry)
            bsd_free(entry, M_DEVBUF);
        if (disk)
            bsd_free(disk, M_DEVBUF);
        xpt_free_path(path);
        return BSD_CAM_ENOMEM;
    }
    entry->sim = sim;
    entry->path = path;
    entry->disk = disk;
    entry->target = target;
    entry->lun = lun;
    entry->sectors = sectors;
    entry->sector_size = sector_size;
    entry->generation = generation;
    entry->protocol = protocol;
    entry->ata_lba48 = ata_lba48;

    max_io = inquiry->maxio ? inquiry->maxio : BSD_CAM_DEFAULT_MAX_IO;
    if (max_io < sector_size)
        max_io = sector_size;
    if (protocol == PROTO_ATA && !ata_lba48 &&
        max_io > sector_size * 256u)
        max_io = sector_size * 256u;
    disk->d_name = protocol == PROTO_ATA ? "ada" : "da";
    disk->d_unit = protocol == PROTO_ATA ?
        g_next_ata_disk_unit++ : g_next_scsi_disk_unit++;
    entry->periph.periph_name = (char *)(uintptr_t)disk->d_name;
    entry->periph.path = path;
    entry->periph.softc = entry;
    entry->periph.sim = sim;
    entry->periph.unit_number = disk->d_unit;
    entry->periph.type = CAM_PERIPH_BIO;
    entry->periph.scheduled_priority = CAM_PRIORITY_NONE;
    entry->periph.immediate_priority = CAM_PRIORITY_NONE;
    entry->periph.refcount = 1;
    disk->d_strategy = cam_disk_strategy;
    disk->d_sectorsize = sector_size;
    disk->d_mediasize = (int64_t)media_size;
    disk->d_maxsize = max_io;
    disk->d_drv1 = entry;
    disk_create(disk, DISK_VERSION);
    if (!disk->d_bridge_published) {
        error = disk->d_bridge_error ? disk->d_bridge_error : BSD_CAM_EIO;
        disk_destroy(disk);
        xpt_free_path(path);
        bsd_free(entry, M_DEVBUF);
        return error;
    }
    cam_guard_lock();
    entry->next = g_cam_disks;
    g_cam_disks = entry;
    cam_guard_unlock();
    printf("[bsd-cam] %s%u ready: %llu sectors, %u-byte sectors\n",
        disk->d_name, disk->d_unit, (unsigned long long)sectors,
        sector_size);
    bsd_memset(&device, 0, sizeof(device));
    xpt_setup_ccb(&device.ccb_h, path, 5);
    device.ccb_h.func_code = XPT_GDEV_TYPE;
    device.ccb_h.status = CAM_REQ_CMP;
    device.protocol = protocol;
    if (scsi_identity)
        device.inq_data = *scsi_identity;
    if (ata_identity)
        device.ident_data = *ata_identity;
    xpt_async(AC_FOUND_DEVICE, path, &device);
    xpt_async(AC_ADVINFO_CHANGED, path,
        (void *)(uintptr_t)CDAI_TYPE_RCAPLONG);
    return 0;
}

static int
cam_publish_scsi_lun(struct cam_sim *sim,
    const struct ccb_pathinq *inquiry, target_id_t target, lun_id_t lun,
    uint32_t generation)
{
    struct scsi_inquiry_data identity;
    struct cam_path *path = 0;
    uint8_t command[6] = {INQUIRY, 0, 0, 0,
        sizeof(struct scsi_inquiry_data), 0};
    uint64_t sectors;
    uint32_t sector_size;
    uint32_t residual = 0;
    int error;

    error = xpt_create_path(&path, 0, sim->path_id, target, lun);
    if (error != CAM_REQ_CMP)
        return BSD_CAM_ENOMEM;
    bsd_memset(&identity, 0, sizeof(identity));
    error = cam_scsi_execute(path, command, sizeof(command), CAM_DIR_IN,
        &identity, sizeof(identity), &residual);
    if (error || residual > sizeof(identity) - 5u ||
        SID_TYPE(&identity) != T_DIRECT) {
        if (target == 0 && lun == 0)
            printf("[bsd-cam] initial disk inquiry failed: error=%d "
                "residual=%u type=%u\n", error, residual,
                SID_TYPE(&identity));
        xpt_free_path(path);
        return BSD_CAM_ENOENT;
    }
    error = cam_read_capacity(path, &sectors, &sector_size);
    if (error) {
        if (target == 0 && lun == 0)
            printf("[bsd-cam] initial disk capacity failed: error=%d\n",
                error);
        xpt_free_path(path);
        return error;
    }
    return cam_publish_disk(sim, inquiry, path, target, lun, generation,
        PROTO_SCSI, 0, sectors, sector_size, &identity, 0);
}

static int
cam_publish_ata_device(struct cam_sim *sim,
    const struct ccb_pathinq *inquiry, target_id_t target,
    uint32_t generation)
{
    struct ata_params identity;
    struct ata_cmd command;
    struct cam_path *path = 0;
    uint64_t sectors;
    uint32_t sector_size;
    uint32_t residual = 0;
    uint8_t lba48;
    int error;

    error = xpt_create_path(&path, 0, sim->path_id, target, 0);
    if (error != CAM_REQ_CMP)
        return BSD_CAM_ENOMEM;
    bsd_memset(&identity, 0, sizeof(identity));
    bsd_memset(&command, 0, sizeof(command));
    command.command = ATA_ATA_IDENTIFY;
    error = cam_ata_execute(path, &command, CAM_DIR_IN, &identity,
        sizeof(identity), &residual);
    if (error || residual != 0) {
        if (target == 0 && error != BSD_CAM_ENOENT)
            printf("[bsd-cam] initial ATA identify failed: error=%d "
                "residual=%u\n", error, residual);
        xpt_free_path(path);
        return error ? error : BSD_CAM_EIO;
    }
    error = cam_ata_ident_geometry(&identity, &sectors, &sector_size,
        &lba48);
    if (error) {
        if (target == 0)
            printf("[bsd-cam] initial ATA geometry failed: error=%d\n",
                error);
        xpt_free_path(path);
        return error;
    }
    return cam_publish_disk(sim, inquiry, path, target, 0, generation,
        PROTO_ATA, lba48, sectors, sector_size, 0, &identity);
}

static lun_id_t
cam_reported_lun(const uint8_t *entry)
{
    if ((entry[0] & 0xc0u) == 0)
        return entry[1];
    if ((entry[0] & 0xc0u) == 0x40u)
        return ((lun_id_t)(entry[0] & 0x3fu) << 8) | entry[1];
    return CAM_LUN_WILDCARD;
}

static int
cam_scan_target(struct cam_sim *sim, const struct ccb_pathinq *inquiry,
    target_id_t target, uint32_t generation)
{
    struct cam_path *path = 0;
    uint8_t command[12];
    uint8_t *response;
    uint32_t list_bytes;
    uint32_t entries;
    uint32_t residual = 0;
    uint32_t available;
    int error;

    if (xpt_create_path(&path, 0, sim->path_id, target, 0) != CAM_REQ_CMP)
        return BSD_CAM_ENOMEM;
    response = bsd_malloc(BSD_CAM_REPORT_LUNS_BYTES, M_DEVBUF,
        M_NOWAIT | M_ZERO);
    if (!response) {
        xpt_free_path(path);
        return BSD_CAM_ENOMEM;
    }
    bsd_memset(command, 0, sizeof(command));
    command[0] = REPORT_LUNS;
    cam_store_be32(command + 6, BSD_CAM_REPORT_LUNS_BYTES);
    error = cam_scsi_execute(path, command, sizeof(command), CAM_DIR_IN,
        response, BSD_CAM_REPORT_LUNS_BYTES, &residual);
    if (error != 0) {
        if (target == 0)
            printf("[bsd-cam] LUN report unavailable; probing LUN 0\n");
        bsd_free(response, M_DEVBUF);
        xpt_free_path(path);
        if (error == BSD_CAM_ETIMEDOUT)
            return error;
        return cam_publish_scsi_lun(
            sim, inquiry, target, 0, generation);
    }
    available = BSD_CAM_REPORT_LUNS_BYTES - residual;
    if (available < 8u) {
        bsd_free(response, M_DEVBUF);
        xpt_free_path(path);
        return BSD_CAM_EIO;
    }
    list_bytes = cam_be32(response);
    if (list_bytes > available - 8u)
        list_bytes = available - 8u;
    entries = list_bytes / 8u;
    for (uint32_t index = 0; index < entries; ++index) {
        lun_id_t lun = cam_reported_lun(response + 8u + index * 8u);

        if (lun != CAM_LUN_WILDCARD && lun <= inquiry->max_lun)
            (void)cam_publish_scsi_lun(sim, inquiry, target, lun,
                generation);
    }
    bsd_free(response, M_DEVBUF);
    xpt_free_path(path);
    return 0;
}

static int
cam_scan_sim(struct cam_sim *sim, uint32_t generation)
{
    struct cam_path *path = 0;
    union ccb request;
    uint32_t targets;

    if (xpt_create_path(&path, 0, sim->path_id, CAM_TARGET_WILDCARD,
        CAM_LUN_WILDCARD) != CAM_REQ_CMP)
        return BSD_CAM_ENOMEM;
    bsd_memset(&request, 0, sizeof(request));
    xpt_setup_ccb(&request.ccb_h, path, 5);
    request.ccb_h.func_code = XPT_PATH_INQ;
    xpt_action(&request);
    if (cam_poll_request(&request) != 0 ||
        (request.ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
        xpt_free_path(path);
        return BSD_CAM_EIO;
    }
    if (request.cpi.protocol == PROTO_ATA && !sim->transport_ready) {
        union ccb reset;

        bsd_memset(&reset, 0, sizeof(reset));
        xpt_setup_ccb(&reset.ccb_h, path, 5);
        reset.ccb_h.func_code = XPT_RESET_BUS;
        xpt_action(&reset);
        if (cam_poll_request(&reset) != 0 ||
            (reset.ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
            xpt_free_path(path);
            return BSD_CAM_EIO;
        }
        sim->transport_ready = 1;
    }
    targets = request.cpi.max_target + 1u;
    if (!targets || targets > BSD_CAM_MAX_TARGETS)
        targets = BSD_CAM_MAX_TARGETS;
    printf("[bsd-cam] scanning %u targets, max LUN %u\n", targets,
        request.cpi.max_lun);
    for (uint32_t target = 0; target < targets; ++target) {
        if (request.cpi.protocol != PROTO_ATA &&
            target == request.cpi.initiator_id)
            continue;
        if (request.cpi.protocol == PROTO_ATA)
            (void)cam_publish_ata_device(sim, &request.cpi, target,
                generation);
        else if (cam_scan_target(sim, &request.cpi, target,
            generation) == BSD_CAM_ETIMEDOUT) {
            printf("[bsd-cam] transport timed out; scan deferred\n");
            break;
        }
    }
    xpt_free_path(path);
    return 0;
}

static void
cam_remove_stale_disks(struct cam_sim *sim, uint32_t generation)
{
    for (;;) {
        bsd_cam_disk_t **cursor;
        bsd_cam_disk_t *entry = 0;

        cam_guard_lock();
        for (cursor = &g_cam_disks; *cursor;
             cursor = &(*cursor)->next) {
            if ((*cursor)->sim == sim &&
                (*cursor)->generation != generation) {
                entry = *cursor;
                *cursor = entry->next;
                break;
            }
        }
        cam_guard_unlock();
        if (!entry)
            break;
        if (entry->disk)
            disk_destroy(entry->disk);
        xpt_free_path(entry->path);
        bsd_free(entry, M_DEVBUF);
    }
}

int
bsd_cam_scan_pending(void)
{
    static uint32_t generation;
    struct cam_sim **sims;
    size_t capacity = 0;
    size_t count = 0;
    int first_error = 0;
    uint32_t current_generation = ++generation;

    cam_guard_lock();
    for (struct cam_sim *sim = g_cam_sims; sim; sim = sim->bridge_next) {
        if (sim->registered && sim->scan_pending)
            capacity++;
    }
    cam_guard_unlock();
    if (!capacity)
        return 0;
    if (capacity > SIZE_MAX / sizeof(*sims))
        return BSD_CAM_EOVERFLOW;
    sims = bsd_malloc(capacity * sizeof(*sims), M_DEVBUF, M_NOWAIT);
    if (!sims)
        return BSD_CAM_ENOMEM;

    cam_guard_lock();
    for (struct cam_sim *sim = g_cam_sims; sim && count < capacity;
         sim = sim->bridge_next) {
        if (!sim->registered || !sim->scan_pending)
            continue;
        sim->scan_pending = 0;
        sim->refcount++;
        sims[count++] = sim;
    }
    cam_guard_unlock();

    for (size_t index = 0; index < count; ++index) {
        int error = cam_scan_sim(sims[index], current_generation);

        if (!error)
            cam_remove_stale_disks(sims[index], current_generation);
        else {
            cam_guard_lock();
            sims[index]->scan_pending = 1;
            cam_guard_unlock();
        }
        if (error && !first_error)
            first_error = error;
        cam_put_sim(sims[index]);
    }
    bsd_free(sims, M_DEVBUF);
    return first_error;
}

#ifndef BSD_BRIDGE_HOST_TEST
static void
cam_scan_task(void *argument, int pending)
{
    (void)argument;
    (void)pending;
    (void)bsd_cam_scan_pending();
}
#endif

size_t
bsd_cam_sim_count(void)
{
    size_t count = 0;

    cam_guard_lock();
    for (struct cam_sim *sim = g_cam_sims; sim; sim = sim->bridge_next)
        count++;
    cam_guard_unlock();
    return count;
}

size_t
bsd_cam_disk_count(void)
{
    size_t count = 0;

    cam_guard_lock();
    for (bsd_cam_disk_t *entry = g_cam_disks; entry; entry = entry->next)
        count++;
    cam_guard_unlock();
    return count;
}
