/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 virtio-mmio block driver.
 * Copyright (c) EdgeOS Contributors.
 *
 * The transport follows the modern virtio 1.x MMIO register ABI and uses a
 * split virtqueue. Requests complete by polling, which keeps the root device
 * usable before the GIC and scheduler are initialized and remains correct on
 * Generic UEFI systems that do not expose a usable virtio interrupt route.
 */

#include <stdint.h>
#include "arch/arm64/interrupt.h"
#include "block/block.h"
#include "drivers/virtio_blk_mmio.h"
#include "drivers/virtio_net_mmio.h"
#include "kernel/smp.h"
#include "stdio.h"

#define VIRTIO_DEVICE_BLOCK 2u
#define VIRTIO_F_VERSION_1 32u
#define VIRTIO_BLK_F_RO 5u
#define VIRTIO_BLK_F_BLK_SIZE 6u

#define VIRTIO_STATUS_ACKNOWLEDGE 1u
#define VIRTIO_STATUS_DRIVER 2u
#define VIRTIO_STATUS_DRIVER_OK 4u
#define VIRTIO_STATUS_FEATURES_OK 8u
#define VIRTIO_STATUS_FAILED 128u

#define MMIO_DEVICE_FEATURES 0x010u
#define MMIO_DEVICE_FEATURES_SEL 0x014u
#define MMIO_DRIVER_FEATURES 0x020u
#define MMIO_DRIVER_FEATURES_SEL 0x024u
#define MMIO_QUEUE_SEL 0x030u
#define MMIO_QUEUE_NUM_MAX 0x034u
#define MMIO_QUEUE_NUM 0x038u
#define MMIO_QUEUE_READY 0x044u
#define MMIO_QUEUE_NOTIFY 0x050u
#define MMIO_INTERRUPT_STATUS 0x060u
#define MMIO_INTERRUPT_ACK 0x064u
#define MMIO_STATUS 0x070u
#define MMIO_QUEUE_DESC_LOW 0x080u
#define MMIO_QUEUE_AVAIL_LOW 0x090u
#define MMIO_QUEUE_USED_LOW 0x0a0u
#define MMIO_CONFIG_GENERATION 0x0fcu
#define MMIO_CONFIG 0x100u

#define VIRTIO_BLK_T_IN 0u
#define VIRTIO_BLK_T_OUT 1u
#define VIRTIO_BLK_S_OK 0u
#define VIRTIO_BLK_S_IOERR 1u
#define VIRTIO_BLK_S_UNSUPP 2u

#define VRING_DESC_F_NEXT 1u
#define VRING_DESC_F_WRITE 2u
#define VIRTIO_BLK_QUEUE_SIZE 8u
#define VIRTIO_BLK_MAX_DEVICES 8u
#define VIRTIO_SECTOR_SIZE 512u

typedef struct {
    uint64_t address;
    uint32_t length;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed)) virtio_desc_t;

typedef struct {
    uint32_t id;
    uint32_t length;
} __attribute__((packed)) virtio_used_element_t;

typedef struct {
    uint16_t flags;
    uint16_t index;
    uint16_t ring[VIRTIO_BLK_QUEUE_SIZE];
    uint16_t used_event;
} __attribute__((packed, aligned(4096))) virtio_available_t;

typedef struct {
    uint16_t flags;
    uint16_t index;
    virtio_used_element_t ring[VIRTIO_BLK_QUEUE_SIZE];
    uint16_t available_event;
} __attribute__((packed, aligned(4096))) virtio_used_t;

typedef struct {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} __attribute__((packed)) virtio_blk_header_t;

typedef struct {
    volatile uint8_t *mmio;
    virtio_desc_t descriptors[VIRTIO_BLK_QUEUE_SIZE] __attribute__((aligned(4096)));
    virtio_available_t available;
    virtio_used_t used;
    virtio_blk_header_t header __attribute__((aligned(16)));
    uint8_t request_status __attribute__((aligned(16)));
    uint64_t capacity_512;
    uint32_t logical_sector_size;
    uint16_t used_index;
    uint8_t read_only;
    uint8_t ready;
    uint8_t interrupt_enabled;
    uint8_t interrupt_flags;
    uint32_t interrupt;
    volatile uint32_t interrupt_sequence;
    volatile uint16_t request_waiter_cpu_plus_one;
    volatile uint32_t lock;
} __attribute__((aligned(4096))) virtio_blk_mmio_device_t;

static virtio_blk_mmio_device_t g_devices[VIRTIO_BLK_MAX_DEVICES];
static uint32_t g_device_count;

static uint32_t mmio_read(virtio_blk_mmio_device_t *device, uint32_t offset) {
    return *(volatile uint32_t *)(void *)(device->mmio + offset);
}

static void mmio_write(virtio_blk_mmio_device_t *device, uint32_t offset,
                       uint32_t value) {
    *(volatile uint32_t *)(void *)(device->mmio + offset) = value;
}

static void mmio_write_address(virtio_blk_mmio_device_t *device,
                               uint32_t low_register, uint64_t address) {
    mmio_write(device, low_register, (uint32_t)address);
    mmio_write(device, low_register + 4u, (uint32_t)(address >> 32));
}

static void zero_bytes(void *pointer, uint32_t length) {
    uint8_t *bytes = (uint8_t *)pointer;
    while (length--) *bytes++ = 0;
}

static uint64_t read_config_u64(virtio_blk_mmio_device_t *device,
                                uint32_t offset) {
    uint32_t before;
    uint32_t after;
    uint32_t low;
    uint32_t high;
    do {
        before = mmio_read(device, MMIO_CONFIG_GENERATION);
        __asm__ __volatile__("dmb oshld" ::: "memory");
        low = mmio_read(device, MMIO_CONFIG + offset);
        high = mmio_read(device, MMIO_CONFIG + offset + 4u);
        __asm__ __volatile__("dmb oshld" ::: "memory");
        after = mmio_read(device, MMIO_CONFIG_GENERATION);
    } while (before != after);
    return (uint64_t)low | ((uint64_t)high << 32);
}

static uint32_t read_config_u32(virtio_blk_mmio_device_t *device,
                                uint32_t offset) {
    uint32_t before;
    uint32_t after;
    uint32_t value;
    do {
        before = mmio_read(device, MMIO_CONFIG_GENERATION);
        __asm__ __volatile__("dmb oshld" ::: "memory");
        value = mmio_read(device, MMIO_CONFIG + offset);
        __asm__ __volatile__("dmb oshld" ::: "memory");
        after = mmio_read(device, MMIO_CONFIG_GENERATION);
    } while (before != after);
    return value;
}

static uint64_t counter_ticks(void) {
    uint64_t value;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

static uint64_t counter_frequency(void) {
    uint64_t value;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(value));
    return value;
}

static void device_lock(virtio_blk_mmio_device_t *device) {
    while (__atomic_exchange_n(&device->lock, 1u, __ATOMIC_ACQUIRE))
        __asm__ __volatile__("yield");
}

static void device_unlock(virtio_blk_mmio_device_t *device) {
    __atomic_store_n(&device->lock, 0u, __ATOMIC_RELEASE);
}

static int submit_request(virtio_blk_mmio_device_t *device, uint32_t type,
                          uint32_t lba, uint32_t count, void *buffer) {
    uint64_t bytes;
    uint64_t saved_daif = 0;
    uint64_t request_sector;
    uint64_t deadline;
    uint64_t frequency;
    uint16_t expected_used;
    uint32_t interrupt_status;
    uint32_t observed_interrupt;

    if (!device || !device->ready || !buffer || !count) return -1;
    if (type == VIRTIO_BLK_T_OUT && device->read_only) return -1;
    if ((uint64_t)lba + count >
        device->capacity_512 * VIRTIO_SECTOR_SIZE / device->logical_sector_size)
        return -1;
    bytes = (uint64_t)count * device->logical_sector_size;
    if (!bytes || bytes > UINT32_MAX) return -1;
    request_sector = (uint64_t)lba * device->logical_sector_size /
                     VIRTIO_SECTOR_SIZE;

    device_lock(device);
    device->header.type = type;
    device->header.reserved = 0;
    device->header.sector = request_sector;
    device->request_status = 0xffu;

    device->descriptors[0].address = (uint64_t)(uintptr_t)&device->header;
    device->descriptors[0].length = sizeof(device->header);
    device->descriptors[0].flags = VRING_DESC_F_NEXT;
    device->descriptors[0].next = 1;
    device->descriptors[1].address = (uint64_t)(uintptr_t)buffer;
    device->descriptors[1].length = (uint32_t)bytes;
    device->descriptors[1].flags = VRING_DESC_F_NEXT |
        (type == VIRTIO_BLK_T_IN ? VRING_DESC_F_WRITE : 0u);
    device->descriptors[1].next = 2;
    device->descriptors[2].address =
        (uint64_t)(uintptr_t)&device->request_status;
    device->descriptors[2].length = 1;
    device->descriptors[2].flags = VRING_DESC_F_WRITE;
    device->descriptors[2].next = 0;

    device->available.ring[device->available.index %
                           VIRTIO_BLK_QUEUE_SIZE] = 0;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    ++device->available.index;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    expected_used = (uint16_t)(device->used_index + 1u);
    observed_interrupt = device->interrupt_sequence;
    if (device->interrupt_enabled)
        __atomic_store_n(&device->request_waiter_cpu_plus_one,
                         (uint16_t)(edge_smp_current_cpu() + 1u),
                         __ATOMIC_RELEASE);
    mmio_write(device, MMIO_QUEUE_NOTIFY, 0);

    if (device->interrupt_enabled) {
        __asm__ __volatile__("mrs %0, daif\n\t"
                             "msr daifclr, #2\n\t"
                             "isb"
                             : "=r"(saved_daif) :: "memory");
    }

    frequency = counter_frequency();
    deadline = counter_ticks() + (frequency ? frequency * 10u : 1000000000u);
    for (;;) {
        uint16_t device_used = *(volatile uint16_t *)&device->used.index;
        __asm__ __volatile__("dmb oshld" ::: "memory");
        if (device_used == expected_used) break;
        if ((int64_t)(counter_ticks() - deadline) >= 0) {
            printf("[virtio-blk-mmio] request timeout type=%u lba=%u count=%u\n",
                   type, lba, count);
            if (device->interrupt_enabled)
                __asm__ __volatile__("msr daif, %0\n\tisb" ::
                                     "r"(saved_daif) : "memory");
            __atomic_store_n(&device->request_waiter_cpu_plus_one, 0u,
                             __ATOMIC_RELEASE);
            device_unlock(device);
            return -1;
        }
        if (device->interrupt_enabled) {
            uint32_t current_interrupt =
                __atomic_load_n(&device->interrupt_sequence,
                                __ATOMIC_ACQUIRE);
            if (current_interrupt == observed_interrupt)
                __asm__ __volatile__("wfe" ::: "memory");
            observed_interrupt = current_interrupt;
        } else {
            __asm__ __volatile__("yield");
        }
    }
    if (device->interrupt_enabled)
        __asm__ __volatile__("msr daif, %0\n\tisb" ::
                             "r"(saved_daif) : "memory");
    __atomic_store_n(&device->request_waiter_cpu_plus_one, 0u,
                     __ATOMIC_RELEASE);
    if (device->used.ring[device->used_index % VIRTIO_BLK_QUEUE_SIZE].id != 0) {
        device_unlock(device);
        return -1;
    }
    device->used_index = expected_used;
    __asm__ __volatile__("dmb oshld" ::: "memory");
    interrupt_status = mmio_read(device, MMIO_INTERRUPT_STATUS);
    if (interrupt_status) mmio_write(device, MMIO_INTERRUPT_ACK, interrupt_status);
    type = device->request_status;
    device_unlock(device);
    if (type == VIRTIO_BLK_S_OK) return 0;
    if (type != VIRTIO_BLK_S_IOERR && type != VIRTIO_BLK_S_UNSUPP)
        printf("[virtio-blk-mmio] invalid completion status=%u\n", type);
    return -1;
}

static int block_read(block_device_t *block, uint32_t lba, uint32_t count,
                      void *output) {
    return submit_request((virtio_blk_mmio_device_t *)block->ctx,
                          VIRTIO_BLK_T_IN, lba, count, output);
}

static int block_write(block_device_t *block, uint32_t lba, uint32_t count,
                       const void *input) {
    return submit_request((virtio_blk_mmio_device_t *)block->ctx,
                          VIRTIO_BLK_T_OUT, lba, count, (void *)input);
}

static int initialize_device(virtio_blk_mmio_device_t *device, uint64_t base,
                             uint32_t interrupt, uint32_t interrupt_flags,
                             uint32_t index) {
    uint32_t features_low;
    uint32_t features_high;
    uint32_t accepted_low = 0;
    uint32_t status;
    uint32_t sector_size = VIRTIO_SECTOR_SIZE;
    uint64_t sector_count;
    block_ops_t operations = {0};
    char name[4] = {'v', 'd', (char)('a' + index), 0};

    zero_bytes(device, sizeof(*device));
    device->mmio = (volatile uint8_t *)(uintptr_t)base;
    device->interrupt = interrupt;
    device->interrupt_flags = (uint8_t)interrupt_flags;
    mmio_write(device, MMIO_STATUS, 0);
    mmio_write(device, MMIO_STATUS,
               VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
    mmio_write(device, MMIO_DEVICE_FEATURES_SEL, 0);
    features_low = mmio_read(device, MMIO_DEVICE_FEATURES);
    mmio_write(device, MMIO_DEVICE_FEATURES_SEL, 1);
    features_high = mmio_read(device, MMIO_DEVICE_FEATURES);
    if (!(features_high & 1u)) goto fail;
    if (features_low & (1u << VIRTIO_BLK_F_BLK_SIZE))
        accepted_low |= 1u << VIRTIO_BLK_F_BLK_SIZE;

    mmio_write(device, MMIO_DRIVER_FEATURES_SEL, 0);
    mmio_write(device, MMIO_DRIVER_FEATURES, accepted_low);
    mmio_write(device, MMIO_DRIVER_FEATURES_SEL, 1);
    mmio_write(device, MMIO_DRIVER_FEATURES,
               1u << (VIRTIO_F_VERSION_1 - 32u));
    status = mmio_read(device, MMIO_STATUS) | VIRTIO_STATUS_FEATURES_OK;
    mmio_write(device, MMIO_STATUS, status);
    if (!(mmio_read(device, MMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK)) goto fail;

    device->capacity_512 = read_config_u64(device, 0);
    if (!device->capacity_512) goto fail;
    if (accepted_low & (1u << VIRTIO_BLK_F_BLK_SIZE))
        sector_size = read_config_u32(device, 20u);
    if (sector_size < VIRTIO_SECTOR_SIZE || sector_size > BLOCK_MAX_SECTOR_SIZE ||
        (sector_size & (sector_size - 1u)) != 0 ||
        sector_size % VIRTIO_SECTOR_SIZE != 0)
        goto fail;
    sector_count = device->capacity_512 * VIRTIO_SECTOR_SIZE / sector_size;
    if (!sector_count || sector_count > UINT32_MAX) goto fail;
    device->logical_sector_size = sector_size;
    device->read_only =
        (features_low & (1u << VIRTIO_BLK_F_RO)) != 0;

    mmio_write(device, MMIO_QUEUE_SEL, 0);
    if (mmio_read(device, MMIO_QUEUE_READY) ||
        mmio_read(device, MMIO_QUEUE_NUM_MAX) < VIRTIO_BLK_QUEUE_SIZE)
        goto fail;
    mmio_write(device, MMIO_QUEUE_NUM, VIRTIO_BLK_QUEUE_SIZE);
    mmio_write_address(device, MMIO_QUEUE_DESC_LOW,
                       (uint64_t)(uintptr_t)device->descriptors);
    mmio_write_address(device, MMIO_QUEUE_AVAIL_LOW,
                       (uint64_t)(uintptr_t)&device->available);
    mmio_write_address(device, MMIO_QUEUE_USED_LOW,
                       (uint64_t)(uintptr_t)&device->used);
    mmio_write(device, MMIO_QUEUE_READY, 1);
    mmio_write(device, MMIO_STATUS,
               mmio_read(device, MMIO_STATUS) | VIRTIO_STATUS_DRIVER_OK);
    device->ready = 1;

    operations.read_sectors = block_read;
    operations.write_sectors = device->read_only ? 0 : block_write;
    if (block_register(name, sector_size, (uint32_t)sector_count, 0,
                       device, operations) < 0)
        goto fail;
    printf("[virtio-blk-mmio] %s ready base=0x%x irq=%u sectors=%u sector_size=%u%s\n",
           name, (uint32_t)base, interrupt, (uint32_t)sector_count,
           sector_size,
           device->read_only ? " read-only" : "");
    return 0;

fail:
    if (device->mmio)
        mmio_write(device, MMIO_STATUS,
                   mmio_read(device, MMIO_STATUS) | VIRTIO_STATUS_FAILED);
    device->ready = 0;
    return -1;
}

int edgeos_arm64_virtio_blk_init(const edgeos_arm64_bootinfo_t *bootinfo) {
    uint64_t base;
    uint32_t interrupt;
    uint32_t interrupt_flags;
    g_device_count = 0;
    for (uint32_t index = 0; index < VIRTIO_BLK_MAX_DEVICES; ++index) {
        if (edgeos_arm64_virtio_mmio_find_nth_irq(
                bootinfo, VIRTIO_DEVICE_BLOCK, index, &base, &interrupt,
                &interrupt_flags) < 0)
            break;
        if (initialize_device(&g_devices[g_device_count], base, interrupt,
                              interrupt_flags,
                              g_device_count) == 0)
            ++g_device_count;
    }
    return g_device_count ? 0 : -1;
}

static void virtio_blk_interrupt(uint32_t interrupt, void *context) {
    virtio_blk_mmio_device_t *device =
        (virtio_blk_mmio_device_t *)context;
    uint32_t status;
    uint16_t waiter_plus_one;
    (void)interrupt;
    if (!device || !device->ready) return;
    status = mmio_read(device, MMIO_INTERRUPT_STATUS);
    if (status) mmio_write(device, MMIO_INTERRUPT_ACK, status);
    __atomic_add_fetch(&device->interrupt_sequence, 1u, __ATOMIC_RELEASE);
    waiter_plus_one = __atomic_load_n(
        &device->request_waiter_cpu_plus_one, __ATOMIC_ACQUIRE);
    if (waiter_plus_one &&
        waiter_plus_one != (uint16_t)(edge_smp_current_cpu() + 1u))
        (void)edge_smp_reschedule((uint32_t)waiter_plus_one - 1u);
}

int edgeos_arm64_virtio_blk_enable_interrupts(void) {
    uint32_t enabled = 0;
    for (uint32_t index = 0; index < g_device_count; ++index) {
        virtio_blk_mmio_device_t *device = &g_devices[index];
        if (!device->ready || device->interrupt == UINT32_MAX) continue;
        if (edgeos_arm64_irq_register(
                device->interrupt, device->interrupt_flags,
                virtio_blk_interrupt, device) < 0)
            continue;
        device->interrupt_enabled = 1;
        ++enabled;
        printf("[virtio-blk-mmio] interrupt enabled irq=%u base=0x%x\n",
               device->interrupt, (uint32_t)(uintptr_t)device->mmio);
    }
    return enabled ? 0 : -1;
}
