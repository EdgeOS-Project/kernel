/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS multi-device virtio-input and Linux evdev backend. */

#include <stdint.h>
#include "arch/arm64/interrupt.h"
#include "drivers/virtio_input_mmio.h"
#include "kernel/deferred_work.h"
#include "drivers/virtio_net_mmio.h"
#include "kernel/drm_runtime.h"
#include "kernel/linux_time.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"
#include "stdio.h"
#include "string.h"

#define VIRTIO_DEVICE_INPUT 18u
#define VIRTIO_F_VERSION_1 32u
#define STATUS_ACK 1u
#define STATUS_DRIVER 2u
#define STATUS_DRIVER_OK 4u
#define STATUS_FEATURES_OK 8u
#define STATUS_FAILED 128u
#define REG_DEVICE_FEATURES 0x010u
#define REG_DEVICE_FEATURES_SEL 0x014u
#define REG_DRIVER_FEATURES 0x020u
#define REG_DRIVER_FEATURES_SEL 0x024u
#define REG_QUEUE_SEL 0x030u
#define REG_QUEUE_NUM_MAX 0x034u
#define REG_QUEUE_NUM 0x038u
#define REG_QUEUE_READY 0x044u
#define REG_QUEUE_NOTIFY 0x050u
#define REG_INTERRUPT_STATUS 0x060u
#define REG_INTERRUPT_ACK 0x064u
#define REG_STATUS 0x070u
#define REG_QUEUE_DESC_LOW 0x080u
#define REG_QUEUE_AVAIL_LOW 0x090u
#define REG_QUEUE_USED_LOW 0x0a0u
#define REG_CONFIG 0x100u
#define VIRTIO_INPUT_CFG_ID_NAME 0x01u
#define VIRTIO_INPUT_CFG_ID_DEVIDS 0x03u
#define VIRTIO_INPUT_CFG_PROP_BITS 0x10u
#define VIRTIO_INPUT_CFG_EV_BITS 0x11u
#define VIRTIO_INPUT_CFG_ABS_INFO 0x12u
#define VQ_SIZE 64u
#define DEVICE_MAX 4u
/*
 * Keep enough history for every open evdev description to advance its own
 * cursor while a compositor is briefly busy rendering or launching a client.
 * The x86 input path retains 8192 complete records for the same reason.
 */
#define EVENT_QUEUE_SIZE 8192u
#define DESC_WRITE 2u
#define EV_SYN 0u
#define EV_KEY 1u
#define EV_REL 2u
#define EV_ABS 3u
#define EV_LED 17u

typedef struct { uint64_t address; uint32_t length; uint16_t flags, next; } __attribute__((packed)) desc_t;
typedef struct { uint32_t id, length; } __attribute__((packed)) used_elem_t;
typedef struct { uint16_t flags, index, ring[VQ_SIZE], used_event; } __attribute__((packed, aligned(4096))) avail_t;
typedef struct { uint16_t flags, index; used_elem_t ring[VQ_SIZE]; uint16_t avail_event; } __attribute__((packed, aligned(4096))) used_t;
typedef struct { uint16_t type, code; int32_t value; } __attribute__((packed)) virtio_event_t;

typedef struct {
    uint64_t seconds;
    uint64_t microseconds;
    uint16_t type;
    uint16_t code;
    int32_t value;
} linux_input_event_t;

typedef struct {
    uint64_t sequence;
    uint64_t realtime_usec;
    uint64_t monotonic_usec;
    uint16_t type;
    uint16_t code;
    int32_t value;
} queued_event_t;

typedef struct {
    volatile uint8_t *mmio;
    desc_t desc[VQ_SIZE] __attribute__((aligned(4096)));
    avail_t avail;
    used_t used;
    virtio_event_t buffers[VQ_SIZE] __attribute__((aligned(16)));
    uint16_t used_index;
    desc_t status_desc[VQ_SIZE] __attribute__((aligned(4096)));
    avail_t status_avail;
    used_t status_used;
    virtio_event_t status_buffers[VQ_SIZE] __attribute__((aligned(16)));
    uint16_t status_used_index;
    queued_event_t queue[EVENT_QUEUE_SIZE];
    uint16_t event_head;
    uint16_t event_tail;
    uint64_t event_sequence;
    spinlock_t event_lock;
    char name[128];
    uint16_t bustype, vendor, product, version;
    uint8_t prop_bits[128];
    uint8_t key_bits[128];
    uint8_t rel_bits[128];
    uint8_t abs_bits[128];
    input_absinfo_t abs[64];
    uint32_t repeat_delay_ms;
    uint32_t repeat_period_ms;
    uint32_t interrupt;
    uint32_t interrupt_flags;
    input_device_description_t input_description;
    uint8_t ready;
} input_device_t;

static input_device_t g_devices[DEVICE_MAX];
static uint32_t g_device_count;
static uint32_t g_poll_active;
static uint32_t g_poll_pending;
static uint8_t g_chars[256];
static uint16_t g_char_head, g_char_tail;
static uint8_t g_shift, g_caps;
static uint8_t g_console_extended;

static int input_bitmap_has_any(const uint8_t *bitmap, uint32_t length) {
    if (!bitmap) return 0;
    for (uint32_t index = 0; index < length; ++index)
        if (bitmap[index]) return 1;
    return 0;
}

static void input_bitmap_set(uint8_t *bitmap, uint32_t bit) {
    if (!bitmap || bit >= EDGE_INPUT_BITMAP_BYTES * 8u) return;
    bitmap[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
}

static int publish_device(input_device_t *device, uint32_t event_index) {
    static const char *const physical_paths[EDGE_INPUT_DEVICE_MAX] = {
        "virtio-mmio/input0", "virtio-mmio/input1"
    };
    input_device_description_t *description;
    int has_key;
    int has_relative;
    int has_absolute;
    if (!device || event_index >= EDGE_INPUT_DEVICE_MAX) return -22;
    description = &device->input_description;
    has_key = input_bitmap_has_any(device->key_bits,
                                   sizeof(device->key_bits));
    has_relative = input_bitmap_has_any(device->rel_bits,
                                        sizeof(device->rel_bits));
    has_absolute = input_bitmap_has_any(device->abs_bits,
                                        sizeof(device->abs_bits));
    if (!has_key && !has_relative && !has_absolute) return -19;
    memset(description, 0, sizeof(*description));
    description->name = device->name;
    description->physical_path = physical_paths[event_index];
    description->driver = "virtio_input";
    description->role = (has_relative || has_absolute) ?
                        EDGE_INPUT_ROLE_POINTER : EDGE_INPUT_ROLE_KEYBOARD;
    description->bustype = device->bustype;
    description->vendor = device->vendor;
    description->product = device->product;
    description->version = device->version;
    description->repeat_delay_ms = device->repeat_delay_ms;
    description->repeat_period_ms = device->repeat_period_ms;
    memcpy(description->properties, device->prop_bits,
           sizeof(description->properties));
    memcpy(description->key_bits, device->key_bits,
           sizeof(description->key_bits));
    memcpy(description->relative_bits, device->rel_bits,
           sizeof(description->relative_bits));
    memcpy(description->absolute_bits, device->abs_bits,
           sizeof(description->absolute_bits));
    memcpy(description->absolute, device->abs, sizeof(description->absolute));
    input_bitmap_set(description->event_bits, EV_SYN);
    if (has_key) input_bitmap_set(description->event_bits, EV_KEY);
    if (has_relative) input_bitmap_set(description->event_bits, EV_REL);
    if (has_absolute) input_bitmap_set(description->event_bits, EV_ABS);
    return input_device_register(event_index, description, device);
}

static uint32_t rd(input_device_t *d, uint32_t off) { return *(volatile uint32_t *)(d->mmio + off); }
static void wr(input_device_t *d, uint32_t off, uint32_t v) { *(volatile uint32_t *)(d->mmio + off) = v; }
static void wraddr(input_device_t *d, uint32_t off, uint64_t v) { wr(d, off, (uint32_t)v); wr(d, off + 4u, (uint32_t)(v >> 32)); }
static void zero(void *p, uint32_t n) { uint8_t *b = p; while (n--) *b++ = 0; }

static uint8_t config_read(input_device_t *d, uint8_t select, uint8_t subsel,
                           void *out, uint8_t maximum) {
    uint8_t size;
    uint32_t selector = (uint32_t)select | ((uint32_t)subsel << 8);
    wr(d, REG_CONFIG, selector);
    __asm__ __volatile__("dmb osh" ::: "memory");
    size = (uint8_t)(rd(d, REG_CONFIG) >> 16);
    if (size > maximum) size = maximum;
    for (uint8_t i = 0; i < size; i += 4u) {
        uint32_t value = rd(d, REG_CONFIG + 8u + i);
        uint8_t count = size - i < 4u ? (uint8_t)(size - i) : 4u;
        /*
         * Some virtio-mmio hosts expose a config region whose byte length is
         * not word aligned while only permitting word-sized guest MMIO.  An
         * aligned final read then crosses the region boundary and returns all
         * ones.  Never publish those nonexistent capability bits to evdev;
         * launchers can avoid the transport limitation entirely by providing
         * a sufficiently long standard virtio-input serial configuration.
         */
        if (count < 4u && value == UINT32_MAX &&
            (select == VIRTIO_INPUT_CFG_PROP_BITS ||
             select == VIRTIO_INPUT_CFG_EV_BITS)) {
            for (uint8_t byte = 0; byte < count; ++byte)
                ((uint8_t *)out)[i + byte] = 0;
            break;
        }
        for (uint8_t byte = 0; byte < count; ++byte)
            ((uint8_t *)out)[i + byte] =
                (uint8_t)(value >> (byte * 8u));
    }
    return size;
}

static void enqueue_char(uint8_t ch) {
    uint16_t next = (uint16_t)((g_char_tail + 1u) & 255u);
    if (next == g_char_head) return;
    g_chars[g_char_tail] = ch;
    g_char_tail = next;
}

static uint8_t key_ascii(uint16_t code) {
    static const char normal[] = "\0\0331234567890-=\b\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 \0";
    static const char shifted[] = "\0\033!@#$%^&*()_+\b\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 \0";
    uint8_t ch;
    if (code >= sizeof(normal) - 1u) return 0;
    ch = (uint8_t)(g_shift ? shifted[code] : normal[code]);
    if (g_caps && ch >= 'a' && ch <= 'z') ch = (uint8_t)(ch - 'a' + 'A');
    else if (g_caps && ch >= 'A' && ch <= 'Z') ch = (uint8_t)(ch - 'A' + 'a');
    return ch;
}

static void console_key_event(uint16_t type, uint16_t code, int32_t value) {
    uint8_t ch;

    if (type != EV_KEY) return;
    if (code == 42u || code == 54u) {
        g_shift = value != 0;
        return;
    }
    if (code == 58u && value == 1) {
        g_caps ^= 1u;
        return;
    }
    if (value != 1 && value != 2) return;
    ch = key_ascii(code);
    if (ch) enqueue_char(ch);
}

static void queue_event(input_device_t *d, const virtio_event_t *event) {
    uint64_t realtime_usec = boottime_realtime_us();
    uint64_t monotonic_usec = boottime_monotonic_us();
    uint64_t irq_flags;
    uint64_t sequence;
    uint16_t next;

    irq_flags = spin_lock_irqsave(&d->event_lock);
    next = (uint16_t)((d->event_tail + 1u) % EVENT_QUEUE_SIZE);
    if (next == d->event_head) d->event_head = (uint16_t)((d->event_head + 1u) % EVENT_QUEUE_SIZE);
    sequence = d->event_sequence + 1u;
    if (!sequence) ++sequence;
    d->queue[d->event_tail].sequence = sequence;
    d->queue[d->event_tail].realtime_usec = realtime_usec;
    d->queue[d->event_tail].monotonic_usec = monotonic_usec;
    d->queue[d->event_tail].type = event->type;
    d->queue[d->event_tail].code = event->code;
    d->queue[d->event_tail].value = event->value;
    d->event_tail = next;
    __atomic_store_n(&d->event_sequence, sequence, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&d->event_lock, irq_flags);
    if (event->type != EV_SYN)
        edge_drm_scanout_activity();
    kernel_input_work_request();
}

static void read_capabilities(input_device_t *d) {
    struct { uint16_t bustype, vendor, product, version; } __attribute__((packed)) ids;
    zero(&ids, sizeof(ids));
    zero(d->name, sizeof(d->name));
    config_read(d, VIRTIO_INPUT_CFG_ID_NAME, 0, d->name, sizeof(d->name) - 1u);
    config_read(d, VIRTIO_INPUT_CFG_ID_DEVIDS, 0, &ids, sizeof(ids));
    d->bustype = ids.bustype; d->vendor = ids.vendor;
    d->product = ids.product; d->version = ids.version;
    config_read(d, VIRTIO_INPUT_CFG_PROP_BITS, 0, d->prop_bits, sizeof(d->prop_bits));
    config_read(d, VIRTIO_INPUT_CFG_EV_BITS, EV_KEY, d->key_bits, sizeof(d->key_bits));
    config_read(d, VIRTIO_INPUT_CFG_EV_BITS, EV_REL, d->rel_bits, sizeof(d->rel_bits));
    config_read(d, VIRTIO_INPUT_CFG_EV_BITS, EV_ABS, d->abs_bits, sizeof(d->abs_bits));
    for (uint8_t axis = 0; axis < 64u; ++axis) {
        struct { int32_t minimum, maximum, fuzz, flat, resolution; } info;
        if (!(d->abs_bits[axis >> 3] & (1u << (axis & 7u)))) continue;
        zero(&info, sizeof(info));
        config_read(d, VIRTIO_INPUT_CFG_ABS_INFO, axis, &info, sizeof(info));
        d->abs[axis].minimum = info.minimum;
        d->abs[axis].maximum = info.maximum;
        d->abs[axis].fuzz = info.fuzz;
        d->abs[axis].flat = info.flat;
        d->abs[axis].resolution = info.resolution;
    }
}

static int initialize_device(input_device_t *d, uint64_t base,
                             uint32_t interrupt,
                             uint32_t interrupt_flags) {
    uint32_t high, status;
    zero(d, sizeof(*d));
    d->repeat_delay_ms = 250u;
    d->repeat_period_ms = 33u;
    d->mmio = (volatile uint8_t *)(uintptr_t)base;
    d->interrupt = interrupt;
    d->interrupt_flags = interrupt_flags;
    wr(d, REG_STATUS, 0); wr(d, REG_STATUS, STATUS_ACK | STATUS_DRIVER);
    wr(d, REG_DEVICE_FEATURES_SEL, 1); high = rd(d, REG_DEVICE_FEATURES);
    if (!(high & 1u)) goto fail;
    wr(d, REG_DRIVER_FEATURES_SEL, 0); wr(d, REG_DRIVER_FEATURES, 0);
    wr(d, REG_DRIVER_FEATURES_SEL, 1); wr(d, REG_DRIVER_FEATURES, 1u << (VIRTIO_F_VERSION_1 - 32u));
    status = rd(d, REG_STATUS) | STATUS_FEATURES_OK; wr(d, REG_STATUS, status);
    if (!(rd(d, REG_STATUS) & STATUS_FEATURES_OK)) goto fail;
    read_capabilities(d);
    wr(d, REG_QUEUE_SEL, 0);
    if (rd(d, REG_QUEUE_READY) || rd(d, REG_QUEUE_NUM_MAX) < VQ_SIZE) goto fail;
    wr(d, REG_QUEUE_NUM, VQ_SIZE);
    wraddr(d, REG_QUEUE_DESC_LOW, (uint64_t)(uintptr_t)d->desc);
    wraddr(d, REG_QUEUE_AVAIL_LOW, (uint64_t)(uintptr_t)&d->avail);
    wraddr(d, REG_QUEUE_USED_LOW, (uint64_t)(uintptr_t)&d->used);
    wr(d, REG_QUEUE_READY, 1);
    for (uint16_t i = 0; i < VQ_SIZE; ++i) {
        d->desc[i].address = (uint64_t)(uintptr_t)&d->buffers[i];
        d->desc[i].length = sizeof(virtio_event_t); d->desc[i].flags = DESC_WRITE;
        d->avail.ring[i] = i;
    }
    d->avail.index = VQ_SIZE;
    __asm__ __volatile__("dmb oshst" ::: "memory");

    /* Queue 1 carries host-directed events such as keyboard LED state. */
    wr(d, REG_QUEUE_SEL, 1);
    if (rd(d, REG_QUEUE_READY) || rd(d, REG_QUEUE_NUM_MAX) < VQ_SIZE) goto fail;
    wr(d, REG_QUEUE_NUM, VQ_SIZE);
    wraddr(d, REG_QUEUE_DESC_LOW, (uint64_t)(uintptr_t)d->status_desc);
    wraddr(d, REG_QUEUE_AVAIL_LOW, (uint64_t)(uintptr_t)&d->status_avail);
    wraddr(d, REG_QUEUE_USED_LOW, (uint64_t)(uintptr_t)&d->status_used);
    wr(d, REG_QUEUE_READY, 1);
    for (uint16_t i = 0; i < VQ_SIZE; ++i) {
        d->status_desc[i].address = (uint64_t)(uintptr_t)&d->status_buffers[i];
        d->status_desc[i].length = sizeof(virtio_event_t);
    }
    wr(d, REG_STATUS, rd(d, REG_STATUS) | STATUS_DRIVER_OK);
    /*
     * A device may ignore queue notifications until DRIVER_OK is visible.
     * Publish the receive buffers first, finish device activation, and only
     * then notify the event queue.  Without this final notification, an MMIO
     * input device can remain idle indefinitely even though all descriptors
     * are available.
     */
    __asm__ __volatile__("dmb oshst" ::: "memory");
    wr(d, REG_QUEUE_NOTIFY, 0);
    d->ready = 1;
    return 0;
fail:
    wr(d, REG_STATUS, rd(d, REG_STATUS) | STATUS_FAILED);
    return -1;
}

int edgeos_arm64_virtio_input_init(const edgeos_arm64_bootinfo_t *bootinfo) {
    uint64_t base;
    uint32_t interrupt;
    uint32_t interrupt_flags;
    for (uint32_t index = 0; index < DEVICE_MAX; ++index) {
        if (edgeos_arm64_virtio_mmio_find_nth_irq(
                bootinfo, VIRTIO_DEVICE_INPUT, index, &base, &interrupt,
                &interrupt_flags) < 0)
            break;
        if (initialize_device(&g_devices[g_device_count], base, interrupt,
                              interrupt_flags) == 0) {
            if (publish_device(&g_devices[g_device_count],
                               g_device_count) < 0) {
                printf("[virtio-input] failed to publish event%u\n",
                       g_device_count);
                g_devices[g_device_count].ready = 0;
                continue;
            }
            printf("[virtio-input] event%u ready name=%s base=0x%x\n",
                   g_device_count, g_devices[g_device_count].name,
                   (uint32_t)base);
            ++g_device_count;
        }
    }
    return g_device_count ? 0 : -1;
}

static void virtio_input_interrupt(uint32_t interrupt, void *context) {
    input_device_t *device = (input_device_t *)context;

    (void)interrupt;
    if (!device || !device->ready) return;
    /*
     * Drain the completed descriptors before publishing deferred work.  An
     * idle CPU may have stopped its scheduler tick, so merely setting a flag
     * here can leave every evdev reader asleep indefinitely.  The poller is
     * non-blocking under contention and queue_event() broadcasts the first
     * idle-to-pending transition after the records are visible.
     */
    virtio_input_poll();
    kernel_input_work_request();
}

int edgeos_arm64_virtio_input_enable_interrupts(void) {
    uint32_t enabled = 0;

    for (uint32_t index = 0; index < g_device_count; ++index) {
        input_device_t *device = &g_devices[index];

        if (!device->ready || device->interrupt == UINT32_MAX) continue;
        {
            uint32_t status = rd(device, REG_INTERRUPT_STATUS);

            if (status) wr(device, REG_INTERRUPT_ACK, status);
        }
        if (edgeos_arm64_irq_register(
                device->interrupt, device->interrupt_flags,
                virtio_input_interrupt, device) < 0)
            continue;
        ++enabled;
        printf("[virtio-input] interrupt enabled irq=%u base=0x%x\n",
               device->interrupt,
               (uint32_t)(uintptr_t)device->mmio);
    }
    return enabled ? 0 : -1;
}

int virtio_input_pending(void) {
    if (__atomic_load_n(&g_poll_pending, __ATOMIC_ACQUIRE)) return 1;
    for (uint32_t index = 0; index < g_device_count; ++index) {
        input_device_t *device = &g_devices[index];
        uint16_t used_index;

        if (!device->ready) continue;
        used_index = *(volatile uint16_t *)&device->used.index;
        __asm__ __volatile__("dmb oshld" ::: "memory");
        if (used_index != device->used_index) return 1;
    }
    return 0;
}

void virtio_input_poll(void) {
    uint32_t passes = 0u;

    /*
     * Timer ticks, device interrupts, and evdev readers can enter from
     * different CPUs.  EdgeOS serializes kernel execution separately, so an
     * interrupt must never spin while another CPU owns this poller.  Publish
     * a pending pass instead.  The owner coalesces a bounded number of passes
     * before releasing ownership; the periodic tick drains anything that
     * arrives across the final handoff without allowing cross-CPU livelock.
     */
    if (__atomic_exchange_n(&g_poll_active, 1u, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&g_poll_pending, 1u, __ATOMIC_RELEASE);
        return;
    }
drain_again:
    __atomic_store_n(&g_poll_pending, 0u, __ATOMIC_RELEASE);
    for (uint32_t index = 0; index < g_device_count; ++index) {
        input_device_t *d = &g_devices[index];
        uint16_t device_index;
        int replenished = 0;
        if (rd(d, REG_INTERRUPT_STATUS)) wr(d, REG_INTERRUPT_ACK, rd(d, REG_INTERRUPT_STATUS));
        device_index = *(volatile uint16_t *)&d->used.index;
        __asm__ __volatile__("dmb oshld" ::: "memory");
        while (d->used_index != device_index) {
            used_elem_t elem = d->used.ring[d->used_index % VQ_SIZE];
            if (elem.id < VQ_SIZE && elem.length >= sizeof(virtio_event_t)) {
                queue_event(d, &d->buffers[elem.id]);
                console_key_event(d->buffers[elem.id].type,
                                  d->buffers[elem.id].code,
                                  d->buffers[elem.id].value);
            }
            if (elem.id < VQ_SIZE) {
                d->avail.ring[d->avail.index % VQ_SIZE] = (uint16_t)elem.id;
                ++d->avail.index;
                replenished = 1;
            }
            ++d->used_index;
        }
        d->status_used_index = *(volatile uint16_t *)&d->status_used.index;
        /*
         * A virtqueue notification announces newly available descriptors; it
         * is not a polling operation.  Unconditionally ringing the MMIO
         * doorbell made every timer/input readiness pass exit through the
         * hypervisor even while the queues were idle.  Notify exactly once
         * after returning consumed event buffers to the device.
         */
        if (replenished) {
            /* Publish ring entries and avail->idx before the MMIO kick. */
            __asm__ __volatile__("dmb oshst" ::: "memory");
            wr(d, REG_QUEUE_NOTIFY, 0);
        }
    }
    ++passes;
    if (__atomic_exchange_n(&g_poll_pending, 0u, __ATOMIC_ACQ_REL) &&
        passes < 4u)
        goto drain_again;
    __atomic_store_n(&g_poll_active, 0u, __ATOMIC_RELEASE);

    /*
     * Close the ownership handoff window. An interrupt can observe the old
     * owner immediately before it clears g_poll_active and publish a pending
     * pass that no owner would otherwise consume until a later timer tick.
     * Reacquire once after releasing ownership; if another caller won, leave
     * the pending bit set for that owner.
     */
    if (__atomic_exchange_n(&g_poll_pending, 0u, __ATOMIC_ACQ_REL)) {
        if (!__atomic_exchange_n(&g_poll_active, 1u, __ATOMIC_ACQUIRE)) {
            passes = 0u;
            goto drain_again;
        }
        __atomic_store_n(&g_poll_pending, 1u, __ATOMIC_RELEASE);
    }
}

int input_write_events(uint32_t device, const void *events,
                                    uint32_t length) {
    input_device_t *d;
    const linux_input_event_t *input = events;
    uint32_t count;
    if (device >= g_device_count || !events ||
        length % sizeof(linux_input_event_t)) return -1;
    d = &g_devices[device];
    count = length / sizeof(linux_input_event_t);
    for (uint32_t event = 0; event < count; ++event) {
        uint16_t used = *(volatile uint16_t *)&d->status_used.index;
        uint16_t outstanding = (uint16_t)(d->status_avail.index - used);
        uint16_t descriptor;

        /*
         * Virtio-input's status queue carries host-directed status changes;
         * the standardized device status currently exposed by QEMU is LED
         * state.  The evdev write path also supplies EV_SYN records, but those
         * delimit input-core batches and are not device status.  Linux treats
         * such records as consumed without forwarding them to this queue.
         */
        if (input[event].type != EV_LED) continue;
        if (outstanding >= VQ_SIZE) return event ? (int)(event * sizeof(*input)) : -2;
        descriptor = (uint16_t)(d->status_avail.index % VQ_SIZE);
        d->status_buffers[descriptor].type = input[event].type;
        d->status_buffers[descriptor].code = input[event].code;
        d->status_buffers[descriptor].value = input[event].value;
        d->status_avail.ring[d->status_avail.index % VQ_SIZE] = descriptor;
        ++d->status_avail.index;
    }
    __asm__ __volatile__("dmb oshst" ::: "memory");
    wr(d, REG_QUEUE_NOTIFY, 1);
    return (int)length;
}
int input_has_event(uint32_t device) {
    input_device_t *d;
    uint64_t irq_flags;
    int ready;

    if (device >= EDGE_INPUT_DEVICE_MAX) return 0;
    d = &g_devices[device];
    irq_flags = spin_lock_irqsave(&d->event_lock);
    ready = d->event_head != d->event_tail;
    spin_unlock_irqrestore(&d->event_lock, irq_flags);
    return ready;
}
uint64_t input_event_sequence(uint32_t device) {
    return device < EDGE_INPUT_DEVICE_MAX ?
           __atomic_load_n(&g_devices[device].event_sequence,
                           __ATOMIC_ACQUIRE) : 0;
}

uint64_t input_event_cursor_init(uint32_t device) {
    if (device >= EDGE_INPUT_DEVICE_MAX) return 0;
    virtio_input_poll();
    return input_event_sequence(device) + 1u;
}

int input_has_event_from(uint32_t device, uint64_t cursor) {
    input_device_t *d;
    uint64_t irq_flags;
    uint64_t oldest;
    uint64_t latest;
    int ready;
    if (device >= EDGE_INPUT_DEVICE_MAX) return 0;
    virtio_input_poll();
    d = &g_devices[device];
    irq_flags = spin_lock_irqsave(&d->event_lock);
    if (d->event_head == d->event_tail) {
        spin_unlock_irqrestore(&d->event_lock, irq_flags);
        return 0;
    }
    oldest = d->queue[d->event_head].sequence;
    if (!cursor || cursor < oldest) cursor = oldest;
    latest = d->event_sequence;
    ready = cursor <= latest;
    spin_unlock_irqrestore(&d->event_lock, irq_flags);
    return ready;
}

int input_read_event_from(uint32_t device, uint64_t *cursor, int clock_id,
                          void *out, uint32_t length) {
    input_device_t *d;
    linux_input_event_t event;
    queued_event_t queued;
    uint64_t irq_flags;
    uint64_t oldest;
    uint64_t sequence;
    uint64_t offset;
    uint64_t usec;
    uint16_t index;
    if (!cursor || !out || length < sizeof(event) ||
        device >= EDGE_INPUT_DEVICE_MAX ||
        !linux_evdev_clock_supported(clock_id))
        return -1;
    virtio_input_poll();
    d = &g_devices[device];
    irq_flags = spin_lock_irqsave(&d->event_lock);
    if (d->event_head == d->event_tail) {
        spin_unlock_irqrestore(&d->event_lock, irq_flags);
        return 0;
    }
    oldest = d->queue[d->event_head].sequence;
    sequence = *cursor;
    if (!sequence || sequence < oldest) sequence = oldest;
    if (sequence > d->event_sequence) {
        spin_unlock_irqrestore(&d->event_lock, irq_flags);
        return 0;
    }
    offset = sequence - oldest;
    if (offset >= EVENT_QUEUE_SIZE - 1u) {
        spin_unlock_irqrestore(&d->event_lock, irq_flags);
        return 0;
    }
    index = (uint16_t)((d->event_head + offset) % EVENT_QUEUE_SIZE);
    queued = d->queue[index];
    spin_unlock_irqrestore(&d->event_lock, irq_flags);
    if (queued.sequence != sequence) return 0;
    usec = linux_evdev_timestamp_us(clock_id, queued.realtime_usec,
                                    queued.monotonic_usec);
    event.seconds = usec / 1000000u;
    event.microseconds = usec % 1000000u;
    event.type = queued.type; event.code = queued.code; event.value = queued.value;
    *(linux_input_event_t *)out = event;
    *cursor = sequence + 1u;
    return sizeof(event);
}

void keyboard_emit_linux_input_event(int event_id, uint16_t type,
                                     uint16_t code, int32_t value) {
    virtio_event_t event;

    if (event_id < 0 || event_id >= (int)EDGE_INPUT_DEVICE_MAX) return;
    event.type = type;
    event.code = code;
    event.value = value;
    queue_event(&g_devices[event_id], &event);
}

void keyboard_emit_scancode_console_only(uint8_t scancode) {
    uint16_t code;
    int32_t value;

    if (scancode == 0xe0u) {
        g_console_extended = 1;
        return;
    }
    value = (scancode & 0x80u) != 0 ? 0 : 1;
    code = (uint16_t)(scancode & 0x7fu);
    if (g_console_extended) {
        switch (code) {
        case 0x1cu: code = 96u; break;
        case 0x1du: code = 97u; break;
        case 0x35u: code = 98u; break;
        case 0x38u: code = 100u; break;
        case 0x47u: code = 102u; break;
        case 0x48u: code = 103u; break;
        case 0x49u: code = 104u; break;
        case 0x4bu: code = 105u; break;
        case 0x4du: code = 106u; break;
        case 0x4fu: code = 107u; break;
        case 0x50u: code = 108u; break;
        case 0x51u: code = 109u; break;
        case 0x52u: code = 110u; break;
        case 0x53u: code = 111u; break;
        case 0x5bu: code = 125u; break;
        case 0x5cu: code = 126u; break;
        case 0x5du: code = 127u; break;
        default: break;
        }
        g_console_extended = 0;
    }
    console_key_event(EV_KEY, code, value);
}

int virtio_input_getchar(void) {
    uint8_t ch;
    virtio_input_poll();
    if (g_char_head == g_char_tail) return -1;
    ch = g_chars[g_char_head]; g_char_head = (uint16_t)((g_char_head + 1u) & 255u);
    return ch;
}
int virtio_input_haschar(void) { virtio_input_poll(); return g_char_head != g_char_tail; }
