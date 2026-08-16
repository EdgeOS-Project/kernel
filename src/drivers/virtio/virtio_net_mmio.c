/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 virtio-mmio network driver.
 * Copyright (c) EdgeOS Contributors.
 *
 * The transport is discovered from Generic UEFI's device tree handoff.  It
 * uses the modern virtio 1.x MMIO register layout and split virtqueues.
 */

#include <stdint.h>
#include "arch/arm64/interrupt.h"
#include "drivers/virtio_net_mmio.h"
#include "drivers/virtio_net.h"
#include "stdio.h"
#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
#define EDGEOS_ARM64_SHARED_OFW 1
#include "compat/freebsd/edgeos/ofw.h"
#endif

#ifndef EDGEOS_ARM64_SHARED_OFW
#define FDT_MAGIC 0xd00dfeedu
#define FDT_BEGIN_NODE 1u
#define FDT_END_NODE 2u
#define FDT_PROP 3u
#define FDT_NOP 4u
#define FDT_END 9u
#endif

#define VIRTIO_MAGIC 0x74726976u
#define VIRTIO_DEVICE_NET 1u
#define VIRTIO_VERSION_MODERN 2u
#define VIRTIO_F_VERSION_1 32u
#define VIRTIO_NET_F_MAC 5u
#define VIRTIO_STATUS_ACKNOWLEDGE 1u
#define VIRTIO_STATUS_DRIVER 2u
#define VIRTIO_STATUS_DRIVER_OK 4u
#define VIRTIO_STATUS_FEATURES_OK 8u
#define VIRTIO_STATUS_FAILED 128u

#define MMIO_MAGIC 0x000u
#define MMIO_VERSION 0x004u
#define MMIO_DEVICE_ID 0x008u
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
#define MMIO_QUEUE_DESC_HIGH 0x084u
#define MMIO_QUEUE_AVAIL_LOW 0x090u
#define MMIO_QUEUE_AVAIL_HIGH 0x094u
#define MMIO_QUEUE_USED_LOW 0x0a0u
#define MMIO_QUEUE_USED_HIGH 0x0a4u
#define MMIO_CONFIG 0x100u

#define VQ_RX 0u
#define VQ_TX 1u
#define VQ_SIZE 64u
#define RX_FRAME_BYTES 2048u
#define TX_FRAME_BYTES 2048u
#define VRING_DESC_F_WRITE 2u

#ifndef EDGEOS_ARM64_SHARED_OFW
typedef struct {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
} fdt_header_t;
#endif

typedef struct {
    uint64_t address;
    uint32_t length;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed)) vring_desc_t;

typedef struct {
    uint32_t id;
    uint32_t length;
} __attribute__((packed)) vring_used_elem_t;

typedef struct {
    uint16_t flags;
    uint16_t index;
    uint16_t ring[VQ_SIZE];
    uint16_t used_event;
} __attribute__((packed, aligned(4096))) vring_avail_t;

typedef struct {
    uint16_t flags;
    uint16_t index;
    vring_used_elem_t ring[VQ_SIZE];
    uint16_t avail_event;
} __attribute__((packed, aligned(4096))) vring_used_t;

typedef struct {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t header_length;
    uint16_t gso_size;
    uint16_t checksum_start;
    uint16_t checksum_offset;
    uint16_t buffers;
} __attribute__((packed)) virtio_net_header_t;

typedef struct {
    virtio_net_header_t header;
    uint8_t frame[RX_FRAME_BYTES];
} __attribute__((packed, aligned(16))) rx_buffer_t;

typedef struct {
    virtio_net_header_t header;
    uint8_t frame[TX_FRAME_BYTES];
} __attribute__((packed, aligned(16))) tx_buffer_t;

static volatile uint8_t *g_mmio;
static vring_desc_t g_rx_desc[VQ_SIZE] __attribute__((aligned(4096)));
static vring_avail_t g_rx_avail;
static vring_used_t g_rx_used;
static rx_buffer_t g_rx_buffers[VQ_SIZE];
static vring_desc_t g_tx_desc[VQ_SIZE] __attribute__((aligned(4096)));
static vring_avail_t g_tx_avail;
static vring_used_t g_tx_used;
static tx_buffer_t g_tx_buffers[VQ_SIZE];
static uint16_t g_rx_used_index;
static uint16_t g_tx_used_index;
static uint16_t g_tx_next;
static uint16_t g_tx_free_count;
static uint8_t g_tx_in_flight[VQ_SIZE];
static uint8_t g_mac[6];
static int g_ready;
static uint32_t g_interrupt = UINT32_MAX;
static uint32_t g_interrupt_flags;
static virtio_net_rx_frame_cb_t g_rx_callback;
static const edgeos_arm64_bootinfo_t *g_bootinfo;
static int g_interrupt_registered;
static int g_interrupt_requested;

static void zero_bytes(void *pointer, uint32_t length);

static uint16_t device_load_index(const uint16_t *index) {
    uint16_t value = *(const volatile uint16_t *)index;
    __asm__ __volatile__("dmb oshld" ::: "memory");
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

#ifndef EDGEOS_ARM64_SHARED_OFW
static uint32_t be32(const void *pointer) {
    const uint8_t *p = (const uint8_t *)pointer;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t fdt_cells(const uint8_t *data, uint32_t cells) {
    uint64_t value = 0;
    if (!cells || cells > 2u) return 0;
    for (uint32_t i = 0; i < cells; ++i) value = (value << 32) | be32(data + i * 4u);
    return value;
}

static int text_equal(const char *left, const char *right) {
    while (*left && *right && *left == *right) { ++left; ++right; }
    return *left == 0 && *right == 0;
}

static int compatible_virtio_mmio(const uint8_t *data, uint32_t length) {
    uint32_t offset = 0;
    while (offset < length) {
        const char *text = (const char *)(data + offset);
        uint32_t count = 0;
        while (offset + count < length && text[count]) ++count;
        if (offset + count >= length) return 0;
        if (text_equal(text, "virtio,mmio")) return 1;
        offset += count + 1u;
    }
    return 0;
}
#endif

static uint32_t mmio_read(uint32_t offset) {
    return *(volatile uint32_t *)(void *)(g_mmio + offset);
}

static void mmio_write(uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(void *)(g_mmio + offset) = value;
}

static int test_transport(uint64_t address, uint32_t device_id, int activate) {
    volatile uint32_t *registers = (volatile uint32_t *)(uintptr_t)address;
    if (!address) return 0;
    if (registers[MMIO_MAGIC / 4u] != VIRTIO_MAGIC ||
        registers[MMIO_VERSION / 4u] != VIRTIO_VERSION_MODERN ||
        registers[MMIO_DEVICE_ID / 4u] != device_id) return 0;
    if (activate) g_mmio = (volatile uint8_t *)(uintptr_t)address;
    return 1;
}

#ifdef EDGEOS_ARM64_SHARED_OFW
static int discover_transport(const edgeos_arm64_bootinfo_t *bootinfo, int probe,
                              uint32_t device_id, uint32_t match_index,
                              int activate, uint64_t *base_out) {
    unsigned int ordinal = 0;
    phandle_t node;

    if (!bootinfo ||
        !(bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_FDT) ||
        !bsd_ofw_fdt_available())
        return -1;
    while ((node = bsd_ofw_fdt_find_compatible(
        "virtio,mmio", ordinal++)) != 0) {
        uint64_t address;
        uint64_t size;

        if (bsd_ofw_fdt_get_reg(node, 0, &address, &size) != 0 ||
            address == 0 || size == 0)
            continue;
        if (!probe) {
            if (base_out)
                *base_out = address;
            return 0;
        }
        if (!test_transport(address, device_id,
            activate && match_index == 0))
            continue;
        if (match_index != 0) {
            --match_index;
            continue;
        }
        if (base_out)
            *base_out = address;
        return 0;
    }
    return -1;
}
#else
static int discover_transport(const edgeos_arm64_bootinfo_t *bootinfo, int probe,
                              uint32_t device_id, uint32_t match_index,
                              int activate, uint64_t *base_out) {
    const uint8_t *base;
    const fdt_header_t *header;
    const uint8_t *cursor;
    const uint8_t *end;
    const char *strings;
    uint32_t address_cells = 2u;
    uint32_t size_cells = 2u;
    int depth = -1;
    int candidate_depth = -1;
    int register_depth = -1;
    uint64_t register_address = 0;

    if (!bootinfo || !(bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_FDT) ||
        bootinfo->fdt_size < sizeof(*header)) return -1;
    base = (const uint8_t *)(uintptr_t)bootinfo->fdt_base;
    header = (const fdt_header_t *)base;
    if (be32(&header->magic) != FDT_MAGIC || be32(&header->totalsize) > bootinfo->fdt_size)
        return -1;
    cursor = base + be32(&header->off_dt_struct);
    end = cursor + be32(&header->size_dt_struct);
    strings = (const char *)(base + be32(&header->off_dt_strings));
    while (cursor + 4u <= end) {
        uint32_t token = be32(cursor);
        cursor += 4u;
        if (token == FDT_BEGIN_NODE) {
            while (cursor < end && *cursor) ++cursor;
            if (cursor >= end) return -1;
            cursor = (const uint8_t *)(((uintptr_t)(cursor + 1u) + 3u) & ~(uintptr_t)3u);
            ++depth;
            register_depth = -1;
            register_address = 0;
            continue;
        }
        if (token == FDT_END_NODE) {
            if (candidate_depth == depth) candidate_depth = -1;
            if (register_depth == depth) {
                register_depth = -1;
                register_address = 0;
            }
            --depth;
            continue;
        }
        if (token == FDT_NOP) continue;
        if (token == FDT_END) break;
        if (token != FDT_PROP || cursor + 8u > end) return -1;
        {
            uint32_t length = be32(cursor);
            uint32_t name_offset = be32(cursor + 4u);
            const char *name = strings + name_offset;
            const uint8_t *data;
            cursor += 8u;
            if (cursor + length > end) return -1;
            data = cursor;
            cursor = (const uint8_t *)(((uintptr_t)(cursor + length) + 3u) & ~(uintptr_t)3u);
            if (depth == 0 && text_equal(name, "#address-cells") && length == 4u)
                address_cells = be32(data);
            else if (depth == 0 && text_equal(name, "#size-cells") && length == 4u)
                size_cells = be32(data);
            else if (text_equal(name, "compatible") && compatible_virtio_mmio(data, length)) {
                candidate_depth = depth;
                if (register_depth == depth) {
                    if (!probe) {
                        if (base_out) *base_out = register_address;
                        return 0;
                    }
                    if (test_transport(register_address, device_id,
                                       activate && match_index == 0u)) {
                        if (match_index) { --match_index; continue; }
                        if (base_out) *base_out = register_address;
                        return 0;
                    }
                }
            } else if (text_equal(name, "reg") &&
                       length >= (address_cells + size_cells) * 4u) {
                register_depth = depth;
                register_address = fdt_cells(data, address_cells);
                if (candidate_depth == depth) {
                    if (!probe) {
                        if (base_out) *base_out = register_address;
                        return 0;
                    }
                    if (test_transport(register_address, device_id,
                                       activate && match_index == 0u)) {
                        if (match_index) { --match_index; continue; }
                        if (base_out) *base_out = register_address;
                        return 0;
                    }
                }
            }
        }
    }
    return -1;
}
#endif

int edgeos_arm64_virtio_mmio_aperture(const edgeos_arm64_bootinfo_t *bootinfo,
                                      uint64_t *base_out) {
    return discover_transport(bootinfo, 0, 0, 0, 0, base_out);
}

int edgeos_arm64_virtio_mmio_find(const edgeos_arm64_bootinfo_t *bootinfo,
                                  uint32_t device_id, uint64_t *base_out) {
    return discover_transport(bootinfo, 1, device_id, 0, 0, base_out);
}

int edgeos_arm64_virtio_mmio_find_nth(const edgeos_arm64_bootinfo_t *bootinfo,
                                      uint32_t device_id, uint32_t match_index,
                                      uint64_t *base_out) {
    return discover_transport(bootinfo, 1, device_id, match_index, 0, base_out);
}

#ifdef EDGEOS_ARM64_SHARED_OFW
int edgeos_arm64_virtio_mmio_describe_nth(
    const edgeos_arm64_bootinfo_t *bootinfo, uint32_t device_id,
    uint32_t match_index, uint64_t *base_out, uint64_t *size_out,
    uint32_t *interrupt_out, uint32_t *interrupt_flags_out) {
    unsigned int ordinal = 0;
    phandle_t node;

    if (base_out)
        *base_out = 0;
    if (size_out)
        *size_out = 0;
    if (interrupt_out)
        *interrupt_out = UINT32_MAX;
    if (interrupt_flags_out)
        *interrupt_flags_out = 0;
    if (!bootinfo ||
        !(bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_FDT) ||
        !bsd_ofw_fdt_available())
        return -1;
    while ((node = bsd_ofw_fdt_find_compatible(
        "virtio,mmio", ordinal++)) != 0) {
        uint64_t address;
        uint64_t size;
        uint32_t interrupt;
        uint32_t interrupt_flags;

        if (bsd_ofw_fdt_get_reg(node, 0, &address, &size) != 0 ||
            !test_transport(address, device_id, 0))
            continue;
        if (match_index != 0) {
            --match_index;
            continue;
        }
        if (base_out)
            *base_out = address;
        if (size_out)
            *size_out = size;
        if (bsd_ofw_fdt_get_interrupt(node, 0, &interrupt,
            &interrupt_flags) == 0) {
            if (interrupt_out)
                *interrupt_out = interrupt;
            if (interrupt_flags_out)
                *interrupt_flags_out = interrupt_flags;
        }
        return 0;
    }
    return -1;
}
#else
int edgeos_arm64_virtio_mmio_describe_nth(
    const edgeos_arm64_bootinfo_t *bootinfo, uint32_t device_id,
    uint32_t match_index, uint64_t *base_out, uint64_t *size_out,
    uint32_t *interrupt_out, uint32_t *interrupt_flags_out) {
    typedef struct {
        uint64_t address;
        uint64_t size;
        uint32_t interrupt;
        uint32_t interrupt_flags;
        uint32_t address_cells;
        uint32_t size_cells;
        uint8_t compatible;
        uint8_t have_interrupt;
    } node_state_t;
    node_state_t nodes[32];
    const uint8_t *base;
    const fdt_header_t *header;
    const uint8_t *cursor;
    const uint8_t *end;
    const char *strings;
    uint32_t strings_size;
    int depth = -1;

    if (base_out) *base_out = 0;
    if (size_out) *size_out = 0;
    if (interrupt_out) *interrupt_out = UINT32_MAX;
    if (interrupt_flags_out) *interrupt_flags_out = 0;
    if (!bootinfo || !(bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_FDT) ||
        bootinfo->fdt_size < sizeof(*header))
        return -1;
    base = (const uint8_t *)(uintptr_t)bootinfo->fdt_base;
    header = (const fdt_header_t *)base;
    if (be32(&header->magic) != FDT_MAGIC ||
        be32(&header->totalsize) > bootinfo->fdt_size)
        return -1;
    cursor = base + be32(&header->off_dt_struct);
    end = cursor + be32(&header->size_dt_struct);
    strings = (const char *)(base + be32(&header->off_dt_strings));
    strings_size = be32(&header->size_dt_strings);
    if (cursor < base || end > base + bootinfo->fdt_size ||
        (const uint8_t *)strings < base ||
        (const uint8_t *)strings + strings_size >
            base + bootinfo->fdt_size)
        return -1;
    zero_bytes(nodes, sizeof(nodes));

    while (cursor + 4u <= end) {
        uint32_t token = be32(cursor);
        cursor += 4u;
        if (token == FDT_BEGIN_NODE) {
            while (cursor < end && *cursor) ++cursor;
            if (cursor >= end || depth + 1 >= (int)(sizeof(nodes) /
                                                     sizeof(nodes[0])))
                return -1;
            cursor = (const uint8_t *)
                (((uintptr_t)(cursor + 1u) + 3u) & ~(uintptr_t)3u);
            ++depth;
            zero_bytes(&nodes[depth], sizeof(nodes[depth]));
            nodes[depth].address_cells =
                depth ? nodes[depth - 1].address_cells : 2u;
            nodes[depth].size_cells =
                depth ? nodes[depth - 1].size_cells : 2u;
            continue;
        }
        if (token == FDT_END_NODE) {
            node_state_t *node;
            if (depth < 0) return -1;
            node = &nodes[depth];
            if (node->compatible && node->address &&
                test_transport(node->address, device_id, 0)) {
                if (match_index) {
                    --match_index;
                } else {
                    if (base_out) *base_out = node->address;
                    if (size_out) *size_out = node->size;
                    if (interrupt_out && node->have_interrupt)
                        *interrupt_out = node->interrupt;
                    if (interrupt_flags_out && node->have_interrupt)
                        *interrupt_flags_out = node->interrupt_flags;
                    return 0;
                }
            }
            --depth;
            continue;
        }
        if (token == FDT_NOP) continue;
        if (token == FDT_END) break;
        if (token != FDT_PROP || depth < 0 || cursor + 8u > end)
            return -1;
        {
            node_state_t *node = &nodes[depth];
            uint32_t length = be32(cursor);
            uint32_t name_offset = be32(cursor + 4u);
            const uint8_t *data;
            const char *name;
            uint32_t parent_address_cells =
                depth ? nodes[depth - 1].address_cells : 2u;
            uint32_t parent_size_cells =
                depth ? nodes[depth - 1].size_cells : 2u;
            cursor += 8u;
            if (cursor + length > end || name_offset >= strings_size)
                return -1;
            data = cursor;
            name = strings + name_offset;
            {
                uint32_t name_length = 0;
                while (name_offset + name_length < strings_size &&
                       name[name_length])
                    ++name_length;
                if (name_offset + name_length >= strings_size) return -1;
            }
            cursor = (const uint8_t *)
                (((uintptr_t)(cursor + length) + 3u) & ~(uintptr_t)3u);
            if (text_equal(name, "#address-cells") && length == 4u) {
                node->address_cells = be32(data);
            } else if (text_equal(name, "#size-cells") && length == 4u) {
                node->size_cells = be32(data);
            } else if (text_equal(name, "compatible")) {
                node->compatible = compatible_virtio_mmio(data, length) != 0;
            } else if (text_equal(name, "reg") &&
                       parent_address_cells > 0u &&
                       parent_address_cells <= 2u &&
                       parent_size_cells <= 2u &&
                       length >=
                           (parent_address_cells + parent_size_cells) * 4u) {
                node->address = fdt_cells(data, parent_address_cells);
                node->size = fdt_cells(
                    data + parent_address_cells * 4u,
                    parent_size_cells);
            } else if (text_equal(name, "interrupts") && length >= 12u) {
                uint32_t kind = be32(data);
                uint32_t number = be32(data + 4u);
                if ((kind == 0u && number <= 987u) ||
                    (kind == 1u && number <= 15u)) {
                    node->interrupt = (kind == 0u ? 32u : 16u) + number;
                    node->interrupt_flags = be32(data + 8u);
                    node->have_interrupt = 1;
                }
            }
        }
    }
    return -1;
}
#endif

int edgeos_arm64_virtio_mmio_find_nth_irq(
    const edgeos_arm64_bootinfo_t *bootinfo, uint32_t device_id,
    uint32_t match_index, uint64_t *base_out, uint32_t *interrupt_out,
    uint32_t *interrupt_flags_out) {
    return edgeos_arm64_virtio_mmio_describe_nth(bootinfo, device_id,
        match_index, base_out, 0, interrupt_out, interrupt_flags_out);
}

static void zero_bytes(void *pointer, uint32_t length) {
    uint8_t *p = (uint8_t *)pointer;
    while (length--) *p++ = 0;
}

static void write_address(uint32_t low_register, uint64_t address) {
    mmio_write(low_register, (uint32_t)address);
    mmio_write(low_register + 4u, (uint32_t)(address >> 32));
}

static int configure_queue(uint16_t number, vring_desc_t *descriptors,
                           vring_avail_t *available, vring_used_t *used) {
    mmio_write(MMIO_QUEUE_SEL, number);
    if (mmio_read(MMIO_QUEUE_READY) || mmio_read(MMIO_QUEUE_NUM_MAX) < VQ_SIZE) return -1;
    mmio_write(MMIO_QUEUE_NUM, VQ_SIZE);
    write_address(MMIO_QUEUE_DESC_LOW, (uint64_t)(uintptr_t)descriptors);
    write_address(MMIO_QUEUE_AVAIL_LOW, (uint64_t)(uintptr_t)available);
    write_address(MMIO_QUEUE_USED_LOW, (uint64_t)(uintptr_t)used);
    mmio_write(MMIO_QUEUE_READY, 1u);
    return 0;
}

int edgeos_arm64_virtio_net_init(const edgeos_arm64_bootinfo_t *bootinfo) {
    uint64_t base;
    uint32_t features_low;
    uint32_t features_high;
    uint32_t status;
    if (g_ready) return 0;
    if (edgeos_arm64_virtio_mmio_find_nth_irq(
            bootinfo, VIRTIO_DEVICE_NET, 0, &base, &g_interrupt,
            &g_interrupt_flags) < 0)
        return -1;
    g_mmio = (volatile uint8_t *)(uintptr_t)base;
    mmio_write(MMIO_STATUS, 0u);
    mmio_write(MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
    mmio_write(MMIO_DEVICE_FEATURES_SEL, 0u);
    features_low = mmio_read(MMIO_DEVICE_FEATURES);
    mmio_write(MMIO_DEVICE_FEATURES_SEL, 1u);
    features_high = mmio_read(MMIO_DEVICE_FEATURES);
    if (!(features_high & 1u)) goto fail;
    mmio_write(MMIO_DRIVER_FEATURES_SEL, 0u);
    mmio_write(MMIO_DRIVER_FEATURES, features_low & (1u << VIRTIO_NET_F_MAC));
    mmio_write(MMIO_DRIVER_FEATURES_SEL, 1u);
    mmio_write(MMIO_DRIVER_FEATURES, 1u << (VIRTIO_F_VERSION_1 - 32u));
    status = mmio_read(MMIO_STATUS) | VIRTIO_STATUS_FEATURES_OK;
    mmio_write(MMIO_STATUS, status);
    if (!(mmio_read(MMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK)) goto fail;

    zero_bytes(g_rx_desc, sizeof(g_rx_desc));
    zero_bytes(&g_rx_avail, sizeof(g_rx_avail));
    zero_bytes(&g_rx_used, sizeof(g_rx_used));
    zero_bytes(g_rx_buffers, sizeof(g_rx_buffers));
    zero_bytes(g_tx_desc, sizeof(g_tx_desc));
    zero_bytes(&g_tx_avail, sizeof(g_tx_avail));
    zero_bytes(&g_tx_used, sizeof(g_tx_used));
    zero_bytes(g_tx_buffers, sizeof(g_tx_buffers));
    zero_bytes(g_tx_in_flight, sizeof(g_tx_in_flight));
    if (configure_queue(VQ_RX, g_rx_desc, &g_rx_avail, &g_rx_used) < 0 ||
        configure_queue(VQ_TX, g_tx_desc, &g_tx_avail, &g_tx_used) < 0) goto fail;
    for (uint16_t i = 0; i < VQ_SIZE; ++i) {
        g_rx_desc[i].address = (uint64_t)(uintptr_t)&g_rx_buffers[i];
        g_rx_desc[i].length = sizeof(g_rx_buffers[i]);
        g_rx_desc[i].flags = VRING_DESC_F_WRITE;
        g_rx_avail.ring[i] = i;
    }
    __asm__ __volatile__("dmb oshst" ::: "memory");
    g_rx_avail.index = VQ_SIZE;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    mmio_write(MMIO_QUEUE_NOTIFY, VQ_RX);
    for (uint32_t i = 0; i < 6u; ++i) g_mac[i] = g_mmio[MMIO_CONFIG + i];
    g_rx_used_index = 0;
    g_tx_used_index = 0;
    g_tx_next = 0;
    g_tx_free_count = VQ_SIZE;
    mmio_write(MMIO_STATUS, mmio_read(MMIO_STATUS) | VIRTIO_STATUS_DRIVER_OK);
    g_bootinfo = bootinfo;
    g_ready = 1;
    printf("[virtio-net] arm64 mmio ready base=0x%x mac=%x:%x:%x:%x:%x:%x\n",
           (uint32_t)(uintptr_t)g_mmio, g_mac[0], g_mac[1], g_mac[2],
           g_mac[3], g_mac[4], g_mac[5]);
    return 0;
fail:
    if (g_mmio) mmio_write(MMIO_STATUS, mmio_read(MMIO_STATUS) | VIRTIO_STATUS_FAILED);
    return -1;
}

int virtio_net_init(void) { return g_ready ? 0 : -1; }
int virtio_net_is_ready(void) { return g_ready; }

static void virtio_net_interrupt(uint32_t interrupt, void *context) {
    uint32_t status;
    (void)interrupt;
    (void)context;
    if (!g_ready) return;
    status = mmio_read(MMIO_INTERRUPT_STATUS);
    if (status) mmio_write(MMIO_INTERRUPT_ACK, status);
}

int edgeos_arm64_virtio_net_enable_interrupts(void) {
    uint32_t status;

    if (!g_ready || g_interrupt == UINT32_MAX) return -1;
    status = mmio_read(MMIO_INTERRUPT_STATUS);
    if (status) mmio_write(MMIO_INTERRUPT_ACK, status);
    if (edgeos_arm64_irq_register(
            g_interrupt, g_interrupt_flags, virtio_net_interrupt, 0) < 0)
        return -1;
    g_interrupt_requested = 1;
    g_interrupt_registered = 1;
    printf("[virtio-net] arm64 interrupt enabled irq=%u base=0x%x\n",
           g_interrupt, (uint32_t)(uintptr_t)g_mmio);
    return 0;
}

int
edgeos_arm64_virtio_net_stop(void)
{
    if (!g_ready)
        return 0;
    if (g_interrupt_registered &&
        edgeos_arm64_irq_unregister(g_interrupt,
            virtio_net_interrupt, 0) != 0)
        return -1;
    g_interrupt_registered = 0;
    g_rx_callback = 0;
    g_ready = 0;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    mmio_write(MMIO_STATUS, 0);
    __asm__ __volatile__("dsb oshst" ::: "memory");
    printf("[virtio-net] arm64 native transport stopped\n");
    return 0;
}

int
edgeos_arm64_virtio_net_resume(void)
{
    if (g_ready)
        return 0;
    if (!g_bootinfo || edgeos_arm64_virtio_net_init(g_bootinfo) != 0)
        return -1;
    if (g_interrupt_requested &&
        edgeos_arm64_virtio_net_enable_interrupts() != 0) {
        (void)edgeos_arm64_virtio_net_stop();
        return -1;
    }
    return 0;
}

int
virtio_net_get_pci_location(uint8_t *bus, uint8_t *slot,
                            uint8_t *function)
{
    (void)bus;
    (void)slot;
    (void)function;
    return -1;
}

int
virtio_net_stop(void)
{
    return edgeos_arm64_virtio_net_stop();
}

int
virtio_net_resume(void)
{
    return edgeos_arm64_virtio_net_resume();
}

void virtio_net_set_rx_frame_callback(virtio_net_rx_frame_cb_t callback) {
    g_rx_callback = callback;
}

int virtio_net_get_mac(uint8_t mac_out[6]) {
    if (!g_ready || !mac_out) return -1;
    for (uint32_t i = 0; i < 6u; ++i) mac_out[i] = g_mac[i];
    return 0;
}

static uint16_t virtio_net_reap_tx(void) {
    uint16_t device_index;
    uint16_t pending;
    uint16_t reaped = 0;

    device_index = device_load_index(&g_tx_used.index);
    pending = (uint16_t)(device_index - g_tx_used_index);
    if (pending > VQ_SIZE) {
        printf("[virtio-net] TX used-ring overrun driver=%u device=%u pending=%u\n",
               g_tx_used_index, device_index, pending);
        pending = VQ_SIZE;
        g_tx_used_index = (uint16_t)(device_index - VQ_SIZE);
    }
    while (pending--) {
        uint16_t used_index = g_tx_used_index % VQ_SIZE;
        uint32_t descriptor;
        __asm__ __volatile__("dmb oshld" ::: "memory");
        descriptor = g_tx_used.ring[used_index].id;
        if (descriptor < VQ_SIZE && g_tx_in_flight[descriptor]) {
            g_tx_in_flight[descriptor] = 0;
            if (g_tx_free_count < VQ_SIZE) ++g_tx_free_count;
        } else {
            printf("[virtio-net] invalid TX completion id=%u in-flight=%u\n",
                   descriptor,
                   descriptor < VQ_SIZE ?
                       (uint32_t)g_tx_in_flight[descriptor] : 0u);
        }
        ++g_tx_used_index;
        ++reaped;
    }
    return reaped;
}

static int virtio_net_reserve_tx_descriptor(uint16_t *descriptor_out) {
    uint64_t deadline;

    if (!descriptor_out) return -1;
    (void)virtio_net_reap_tx();
    deadline = counter_ticks() + counter_frequency();
    while (!g_tx_free_count && counter_ticks() < deadline) {
        if (virtio_net_reap_tx()) break;
        __asm__ __volatile__("yield" ::: "memory");
    }
    if (!g_tx_free_count) return -1;
    for (uint16_t scanned = 0; scanned < VQ_SIZE; ++scanned) {
        uint16_t descriptor = g_tx_next++ % VQ_SIZE;
        if (g_tx_in_flight[descriptor]) continue;
        g_tx_in_flight[descriptor] = 1;
        --g_tx_free_count;
        *descriptor_out = descriptor;
        return 0;
    }
    return -1;
}

void virtio_net_poll(void) {
    uint16_t device_index;
    uint16_t pending;
    if (!g_ready) return;
    (void)virtio_net_reap_tx();
    if (mmio_read(MMIO_INTERRUPT_STATUS))
        mmio_write(MMIO_INTERRUPT_ACK, mmio_read(MMIO_INTERRUPT_STATUS));
    device_index = device_load_index(&g_rx_used.index);
    pending = (uint16_t)(device_index - g_rx_used_index);
    if (pending > VQ_SIZE) {
        printf("[virtio-net] RX used-ring overrun driver=%u device=%u pending=%u\n",
               g_rx_used_index, device_index, pending);
        g_rx_used_index = (uint16_t)(device_index - VQ_SIZE);
        pending = VQ_SIZE;
    }
    while (pending--) {
        vring_used_elem_t used = g_rx_used.ring[g_rx_used_index % VQ_SIZE];
        if (used.id < VQ_SIZE && used.length > sizeof(virtio_net_header_t) &&
            used.length <= sizeof(g_rx_buffers[used.id]) && g_rx_callback) {
            g_rx_callback(g_rx_buffers[used.id].frame,
                          used.length - (uint32_t)sizeof(virtio_net_header_t));
        }
        if (used.id < VQ_SIZE) {
            g_rx_avail.ring[g_rx_avail.index % VQ_SIZE] = (uint16_t)used.id;
            __asm__ __volatile__("dmb oshst" ::: "memory");
            ++g_rx_avail.index;
        }
        ++g_rx_used_index;
    }
    __asm__ __volatile__("dmb oshst" ::: "memory");
    mmio_write(MMIO_QUEUE_NOTIFY, VQ_RX);
}

int virtio_net_send_frame_raw(const void *frame, uint16_t length) {
    uint16_t descriptor;
    uint16_t wire_length;
    const uint8_t *source = (const uint8_t *)frame;
    tx_buffer_t *buffer;
    if (!g_ready || !frame || !length || length > TX_FRAME_BYTES) return -1;
    if (virtio_net_reserve_tx_descriptor(&descriptor) < 0) return -1;
    wire_length = length < EDGE_VIRTIO_NET_ETHERNET_MIN_FRAME_SIZE ?
        EDGE_VIRTIO_NET_ETHERNET_MIN_FRAME_SIZE : length;
    buffer = &g_tx_buffers[descriptor];
    zero_bytes(&buffer->header, sizeof(buffer->header));
    for (uint32_t i = 0; i < length; ++i)
        buffer->frame[i] = source[i];
    for (uint32_t i = length; i < wire_length; ++i)
        buffer->frame[i] = 0;
    g_tx_desc[descriptor].address = (uint64_t)(uintptr_t)buffer;
    g_tx_desc[descriptor].length = sizeof(virtio_net_header_t) + wire_length;
    g_tx_desc[descriptor].flags = 0;
    g_tx_avail.ring[g_tx_avail.index % VQ_SIZE] = descriptor;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    ++g_tx_avail.index;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    mmio_write(MMIO_QUEUE_NOTIFY, VQ_TX);
    return length;
}
