/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original generic ECAM PCI host adapter for the EdgeOS BSD Driver Bridge.
 *
 * Firmware describes configuration space, host windows, and legacy interrupt
 * routing.  The adapter keeps PCI bus addresses separate from CPU physical
 * addresses so imported BSD drivers can use ordinary newbus resources.
 */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/pci.h"
#include "compat/freebsd/machine/resource.h"

#define BSD_ARM64_PCI_ENOENT 2
#define BSD_ARM64_PCI_ENXIO 6
#define BSD_ARM64_PCI_ENOMEM 12
#define BSD_ARM64_PCI_EINVAL 22
#define BSD_ARM64_PCI_ENOSPC 28

#define BSD_ARM64_PCI_VENDOR_INVALID UINT16_C(0xffff)
#define BSD_ARM64_PCI_COMMAND 0x04
#define BSD_ARM64_PCI_COMMAND_IO_ENABLE UINT16_C(0x0001)
#define BSD_ARM64_PCI_COMMAND_MEMORY_ENABLE UINT16_C(0x0002)
#define BSD_ARM64_PCI_HEADER_TYPE 0x0e
#define BSD_ARM64_PCI_HEADER_MULTIFUNCTION UINT8_C(0x80)
#define BSD_ARM64_PCI_BAR_FIRST 0x10
#define BSD_ARM64_PCI_INTERRUPT_PIN 0x3d

#define BSD_ARM64_PCI_BAR_IO UINT32_C(0x01)
#define BSD_ARM64_PCI_BAR_MEMORY_TYPE_MASK UINT32_C(0x06)
#define BSD_ARM64_PCI_BAR_MEMORY_64 UINT32_C(0x04)

#define BSD_ARM64_PCI_RANGE_SPACE_MASK UINT32_C(0x03000000)
#define BSD_ARM64_PCI_RANGE_IO UINT32_C(0x01000000)
#define BSD_ARM64_PCI_RANGE_MEMORY32 UINT32_C(0x02000000)
#define BSD_ARM64_PCI_RANGE_MEMORY64 UINT32_C(0x03000000)

#define BSD_ARM64_PCI_MAX_RANGES 16
#define BSD_ARM64_PCI_MAX_CHILD_CELLS 8

typedef struct {
    uint32_t space;
    uint64_t bus_base;
    uint64_t host_base;
    uint64_t size;
    uint64_t cursor;
} bsd_arm64_pci_range_t;

typedef struct {
    unsigned int range_index;
    uint64_t start;
    uint64_t size;
} bsd_arm64_pci_reservation_t;

typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t low_flags;
    int resource_type;
    uint8_t is_64;
    uint8_t present;
} bsd_arm64_pci_bar_t;

typedef struct {
    phandle_t node;
    uint64_t ecam_base;
    uint64_t ecam_size;
    uint32_t domain;
    uint8_t bus_start;
    uint8_t bus_end;
    bsd_pci_location_t *functions;
    size_t function_count;
    bsd_arm64_pci_range_t ranges[BSD_ARM64_PCI_MAX_RANGES];
    size_t range_count;
    bsd_arm64_pci_reservation_t *reservations;
    size_t reservation_count;
    size_t reservation_capacity;
    pcell_t *interrupt_map;
    size_t interrupt_map_cells;
    pcell_t interrupt_map_mask[BSD_ARM64_PCI_MAX_CHILD_CELLS];
    unsigned int child_address_cells;
    unsigned int child_interrupt_cells;
} bsd_arm64_pci_context_t;

static bsd_arm64_pci_context_t g_arm64_pci;

static void
bsd_arm64_pci_barrier(void)
{
#if defined(__aarch64__)
    __asm__ __volatile__("dmb osh" ::: "memory");
#else
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
#endif
}

static int
bsd_arm64_pci_read_cell(phandle_t node, const char *property,
    uint32_t fallback, uint32_t *value)
{
    pcell_t cell;
    ssize_t length;

    if (!value)
        return BSD_ARM64_PCI_EINVAL;
    length = OF_getencprop(node, property, &cell, sizeof(cell));
    if (length < 0) {
        *value = fallback;
        return 0;
    }
    if (length != (ssize_t)sizeof(cell))
        return BSD_ARM64_PCI_EINVAL;
    *value = cell;
    return 0;
}

static int
bsd_arm64_pci_decode_cells(const pcell_t *cells, unsigned int count,
    uint64_t *value)
{
    uint64_t decoded = 0;

    if (!cells || !value || count == 0 || count > 2)
        return BSD_ARM64_PCI_EINVAL;
    for (unsigned int index = 0; index < count; ++index)
        decoded = (decoded << 32) | cells[index];
    *value = decoded;
    return 0;
}

static int
bsd_arm64_pci_location_valid(
    const bsd_arm64_pci_context_t *context,
    const bsd_pci_location_t *location)
{
    return context && location &&
        location->domain == context->domain &&
        location->bus >= context->bus_start &&
        location->bus <= context->bus_end &&
        location->slot < 32 && location->function < 8;
}

static volatile uint8_t *
bsd_arm64_pci_config_address(
    const bsd_arm64_pci_context_t *context,
    const bsd_pci_location_t *location, uint16_t register_offset,
    unsigned int width)
{
    uint64_t offset;

    if (!bsd_arm64_pci_location_valid(context, location) ||
        (width != 1 && width != 2 && width != 4) ||
        register_offset > 4096u - width ||
        (register_offset & (width - 1u)) != 0)
        return 0;
    offset = ((uint64_t)(location->bus - context->bus_start) << 20) |
        ((uint64_t)location->slot << 15) |
        ((uint64_t)location->function << 12) |
        register_offset;
    if (offset > context->ecam_size ||
        width > context->ecam_size - offset ||
        context->ecam_base > UINT64_MAX - offset)
        return 0;
    return (volatile uint8_t *)(uintptr_t)(context->ecam_base + offset);
}

static uint32_t
bsd_arm64_pci_read_config(void *opaque_context,
    const bsd_pci_location_t *location, uint16_t register_offset,
    unsigned int width)
{
    bsd_arm64_pci_context_t *context = opaque_context;
    volatile uint8_t *address = bsd_arm64_pci_config_address(
        context, location, register_offset, width);
    uint32_t value;

    if (!address)
        return UINT32_MAX;
    bsd_arm64_pci_barrier();
    if (width == 1)
        value = *(volatile uint8_t *)address;
    else if (width == 2)
        value = *(volatile uint16_t *)address;
    else
        value = *(volatile uint32_t *)address;
    bsd_arm64_pci_barrier();
    return value;
}

static void
bsd_arm64_pci_write_config(void *opaque_context,
    const bsd_pci_location_t *location, uint16_t register_offset,
    uint32_t value, unsigned int width)
{
    bsd_arm64_pci_context_t *context = opaque_context;
    volatile uint8_t *address = bsd_arm64_pci_config_address(
        context, location, register_offset, width);

    if (!address)
        return;
    bsd_arm64_pci_barrier();
    if (width == 1)
        *(volatile uint8_t *)address = (uint8_t)value;
    else if (width == 2)
        *(volatile uint16_t *)address = (uint16_t)value;
    else
        *(volatile uint32_t *)address = value;
    bsd_arm64_pci_barrier();
}

static size_t
bsd_arm64_pci_function_count(void *opaque_context)
{
    bsd_arm64_pci_context_t *context = opaque_context;

    return context ? context->function_count : 0;
}

static int
bsd_arm64_pci_function_at(void *opaque_context, size_t index,
    bsd_pci_location_t *location)
{
    bsd_arm64_pci_context_t *context = opaque_context;

    if (!context || !location || index >= context->function_count)
        return BSD_ARM64_PCI_ENOENT;
    *location = context->functions[index];
    return 0;
}

static int
bsd_arm64_pci_probe_bar(bsd_arm64_pci_context_t *context,
    const bsd_pci_location_t *location, unsigned int bar,
    unsigned int bar_count, bsd_arm64_pci_bar_t *description)
{
    uint16_t register_offset;
    uint32_t original_low;
    uint32_t original_high = 0;
    uint32_t mask_low;
    uint32_t mask_high = UINT32_MAX;
    uint64_t mask;

    if (!context || !description || bar >= bar_count)
        return BSD_ARM64_PCI_EINVAL;
    *description = (bsd_arm64_pci_bar_t){0};
    register_offset = (uint16_t)(BSD_ARM64_PCI_BAR_FIRST + bar * 4u);
    original_low = bsd_arm64_pci_read_config(
        context, location, register_offset, 4);
    if (original_low == UINT32_MAX)
        return 0;
    description->low_flags = original_low &
        ((original_low & BSD_ARM64_PCI_BAR_IO) ? UINT32_C(3) :
        UINT32_C(15));
    description->resource_type =
        (original_low & BSD_ARM64_PCI_BAR_IO) ?
        SYS_RES_IOPORT : SYS_RES_MEMORY;
    description->is_64 =
        description->resource_type == SYS_RES_MEMORY &&
        (original_low & BSD_ARM64_PCI_BAR_MEMORY_TYPE_MASK) ==
        BSD_ARM64_PCI_BAR_MEMORY_64 && bar + 1u < bar_count;
    if (description->is_64)
        original_high = bsd_arm64_pci_read_config(
            context, location, register_offset + 4u, 4);

    bsd_arm64_pci_write_config(
        context, location, register_offset, UINT32_MAX, 4);
    if (description->is_64)
        bsd_arm64_pci_write_config(
            context, location, register_offset + 4u, UINT32_MAX, 4);
    mask_low = bsd_arm64_pci_read_config(
        context, location, register_offset, 4);
    if (description->is_64)
        mask_high = bsd_arm64_pci_read_config(
            context, location, register_offset + 4u, 4);
    bsd_arm64_pci_write_config(
        context, location, register_offset, original_low, 4);
    if (description->is_64)
        bsd_arm64_pci_write_config(
            context, location, register_offset + 4u, original_high, 4);

    if (description->resource_type == SYS_RES_IOPORT) {
        mask = mask_low & ~UINT64_C(3);
        description->base = original_low & ~UINT64_C(3);
        description->size =
            mask == 0 ? 0 : ((~mask) & UINT32_MAX) + 1u;
    } else if (description->is_64) {
        mask = ((uint64_t)mask_high << 32) |
            (mask_low & ~UINT64_C(15));
        description->base = ((uint64_t)original_high << 32) |
            (original_low & ~UINT64_C(15));
        description->size = mask == 0 ? 0 : ~mask + 1u;
    } else {
        mask = mask_low & ~UINT64_C(15);
        description->base = original_low & ~UINT64_C(15);
        description->size =
            mask == 0 ? 0 : ((~mask) & UINT32_MAX) + 1u;
    }
    description->present = description->size != 0;
    return 0;
}

static int
bsd_arm64_pci_range_contains(
    const bsd_arm64_pci_range_t *range, int resource_type,
    uint64_t address, uint64_t size)
{
    uint64_t offset;

    if (!range || size == 0 ||
        ((resource_type == SYS_RES_IOPORT) !=
         (range->space == BSD_ARM64_PCI_RANGE_IO)) ||
        address < range->bus_base)
        return 0;
    offset = address - range->bus_base;
    return offset < range->size && size <= range->size - offset;
}

static int
bsd_arm64_pci_find_range(bsd_arm64_pci_context_t *context,
    int resource_type, uint64_t address, uint64_t size,
    unsigned int *range_index)
{
    for (unsigned int index = 0; index < context->range_count; ++index) {
        if (bsd_arm64_pci_range_contains(&context->ranges[index],
            resource_type, address, size)) {
            if (range_index)
                *range_index = index;
            return 0;
        }
    }
    return BSD_ARM64_PCI_ENOENT;
}

static int
bsd_arm64_pci_reserve(bsd_arm64_pci_context_t *context,
    unsigned int range_index, uint64_t start, uint64_t size)
{
    bsd_arm64_pci_reservation_t *reservation;

    if (!context || range_index >= context->range_count || size == 0 ||
        context->reservation_count >= context->reservation_capacity)
        return BSD_ARM64_PCI_ENOSPC;
    reservation =
        &context->reservations[context->reservation_count++];
    reservation->range_index = range_index;
    reservation->start = start;
    reservation->size = size;
    return 0;
}

static uint64_t
bsd_arm64_pci_align_up(uint64_t value, uint64_t alignment)
{
    uint64_t mask;

    if (alignment == 0 || (alignment & (alignment - 1u)) != 0)
        return 0;
    mask = alignment - 1u;
    if (value > UINT64_MAX - mask)
        return 0;
    return (value + mask) & ~mask;
}

static int
bsd_arm64_pci_allocate_bar(bsd_arm64_pci_context_t *context,
    const bsd_arm64_pci_bar_t *bar, uint64_t *address,
    unsigned int *range_index)
{
    for (unsigned int index = 0; index < context->range_count; ++index) {
        bsd_arm64_pci_range_t *range = &context->ranges[index];
        uint64_t candidate;

        if ((bar->resource_type == SYS_RES_IOPORT) !=
            (range->space == BSD_ARM64_PCI_RANGE_IO))
            continue;
        if (!bar->is_64 &&
            range->bus_base > UINT32_MAX)
            continue;
        candidate = range->cursor;
        if (bar->resource_type == SYS_RES_IOPORT &&
            candidate < UINT64_C(0x1000) &&
            range->bus_base <= UINT64_C(0x1000))
            candidate = UINT64_C(0x1000);
        for (;;) {
            uint64_t next;
            int overlap = 0;

            candidate = bsd_arm64_pci_align_up(candidate, bar->size);
            if (candidate < range->bus_base ||
                candidate - range->bus_base >= range->size ||
                bar->size > range->size -
                    (candidate - range->bus_base))
                break;
            if (!bar->is_64 &&
                (candidate > UINT32_MAX ||
                 bar->size - 1u > UINT32_MAX - candidate))
                break;
            next = candidate + bar->size;
            for (size_t reservation_index = 0;
                reservation_index < context->reservation_count;
                ++reservation_index) {
                const bsd_arm64_pci_reservation_t *reservation =
                    &context->reservations[reservation_index];
                uint64_t reservation_end;

                if (reservation->range_index != index)
                    continue;
                reservation_end =
                    reservation->start + reservation->size;
                if (candidate < reservation_end &&
                    reservation->start < next) {
                    candidate = reservation_end;
                    overlap = 1;
                    break;
                }
            }
            if (overlap)
                continue;
            if (bsd_arm64_pci_reserve(
                context, index, candidate, bar->size) != 0)
                return BSD_ARM64_PCI_ENOSPC;
            range->cursor = next;
            *address = candidate;
            *range_index = index;
            return 0;
        }
    }
    return BSD_ARM64_PCI_ENOSPC;
}

static int
bsd_arm64_pci_prepare_device(void *opaque_context,
    const bsd_pci_location_t *location)
{
    bsd_arm64_pci_context_t *context = opaque_context;
    uint8_t header_type;
    unsigned int bar_count;
    uint16_t command;
    int result = 0;

    if (!bsd_arm64_pci_location_valid(context, location))
        return BSD_ARM64_PCI_EINVAL;
    header_type = (uint8_t)bsd_arm64_pci_read_config(
        context, location, BSD_ARM64_PCI_HEADER_TYPE, 1);
    bar_count = (header_type & UINT8_C(0x7f)) == 0 ? 6u : 2u;
    command = (uint16_t)bsd_arm64_pci_read_config(
        context, location, BSD_ARM64_PCI_COMMAND, 2);
    bsd_arm64_pci_write_config(context, location,
        BSD_ARM64_PCI_COMMAND,
        command & ~(BSD_ARM64_PCI_COMMAND_IO_ENABLE |
                    BSD_ARM64_PCI_COMMAND_MEMORY_ENABLE), 2);
    for (unsigned int bar_index = 0;
        bar_index < bar_count; ++bar_index) {
        bsd_arm64_pci_bar_t bar;
        uint16_t register_offset;
        uint64_t address;
        unsigned int range_index;

        result = bsd_arm64_pci_probe_bar(
            context, location, bar_index, bar_count, &bar);
        if (result != 0 || !bar.present)
            continue;
        if (bar.base != 0) {
            if (bar.is_64)
                ++bar_index;
            continue;
        }
        result = bsd_arm64_pci_allocate_bar(
            context, &bar, &address, &range_index);
        if (result != 0)
            break;
        (void)range_index;
        register_offset = (uint16_t)(
            BSD_ARM64_PCI_BAR_FIRST + bar_index * 4u);
        bsd_arm64_pci_write_config(context, location,
            register_offset,
            (uint32_t)address | bar.low_flags, 4);
        if (bar.is_64) {
            bsd_arm64_pci_write_config(context, location,
                register_offset + 4u, (uint32_t)(address >> 32), 4);
            ++bar_index;
        }
    }
    bsd_arm64_pci_write_config(
        context, location, BSD_ARM64_PCI_COMMAND, command, 2);
    return result;
}

static int
bsd_arm64_pci_translate_resource(void *opaque_context,
    const bsd_pci_location_t *location, int resource_type,
    uint64_t bus_address, uint64_t size, uint64_t *host_address)
{
    bsd_arm64_pci_context_t *context = opaque_context;
    unsigned int range_index;
    const bsd_arm64_pci_range_t *range;
    uint64_t offset;

    if (!bsd_arm64_pci_location_valid(context, location) ||
        !host_address ||
        bsd_arm64_pci_find_range(context, resource_type,
            bus_address, size, &range_index) != 0)
        return BSD_ARM64_PCI_ENOENT;
    range = &context->ranges[range_index];
    offset = bus_address - range->bus_base;
    if (range->host_base > UINT64_MAX - offset)
        return BSD_ARM64_PCI_EINVAL;
    *host_address = range->host_base + offset;
    return 0;
}

static int
bsd_arm64_pci_decode_interrupt(const pcell_t *specifier,
    unsigned int cells, uint32_t *interrupt, uint32_t *flags)
{
    if (!specifier || cells < 3 || !interrupt || !flags)
        return BSD_ARM64_PCI_EINVAL;
    if (specifier[0] == 0)
        *interrupt = specifier[1] + 32u;
    else if (specifier[0] == 1)
        *interrupt = specifier[1] + 16u;
    else
        return BSD_ARM64_PCI_ENXIO;
    *flags = specifier[2];
    return 0;
}

static int
bsd_arm64_pci_legacy_interrupt(void *opaque_context,
    const bsd_pci_location_t *location, uint8_t interrupt_line,
    uint32_t *interrupt, uint32_t *interrupt_flags)
{
    bsd_arm64_pci_context_t *context = opaque_context;
    pcell_t child[BSD_ARM64_PCI_MAX_CHILD_CELLS] = {0};
    unsigned int child_cells;
    uint8_t pin;
    size_t offset = 0;

    (void)interrupt_line;
    if (!bsd_arm64_pci_location_valid(context, location) ||
        !interrupt || !interrupt_flags)
        return BSD_ARM64_PCI_EINVAL;
    child_cells = context->child_address_cells +
        context->child_interrupt_cells;
    if (child_cells == 0 ||
        child_cells > BSD_ARM64_PCI_MAX_CHILD_CELLS ||
        context->child_address_cells < 1 ||
        context->child_interrupt_cells != 1)
        return BSD_ARM64_PCI_ENXIO;
    pin = (uint8_t)bsd_arm64_pci_read_config(
        context, location, BSD_ARM64_PCI_INTERRUPT_PIN, 1);
    if (pin == 0 || pin > 4)
        return BSD_ARM64_PCI_ENOENT;
    child[0] = ((pcell_t)location->bus << 16) |
        ((pcell_t)location->slot << 11) |
        ((pcell_t)location->function << 8);
    child[context->child_address_cells] = pin;

    while (offset < context->interrupt_map_cells) {
        phandle_t parent;
        uint32_t parent_address_cells;
        uint32_t parent_interrupt_cells;
        size_t parent_xref_offset;
        size_t specifier_offset;
        size_t entry_cells;
        int matched = 1;

        if (context->interrupt_map_cells - offset <
            child_cells + 1u)
            return BSD_ARM64_PCI_EINVAL;
        for (unsigned int index = 0; index < child_cells; ++index) {
            if ((context->interrupt_map[offset + index] &
                 context->interrupt_map_mask[index]) !=
                (child[index] &
                 context->interrupt_map_mask[index])) {
                matched = 0;
                break;
            }
        }
        parent_xref_offset = offset + child_cells;
        parent = OF_node_from_xref(
            context->interrupt_map[parent_xref_offset]);
        if (parent == 0 ||
            bsd_arm64_pci_read_cell(parent, "#address-cells",
                0, &parent_address_cells) != 0 ||
            bsd_arm64_pci_read_cell(parent, "#interrupt-cells",
                0, &parent_interrupt_cells) != 0)
            return BSD_ARM64_PCI_EINVAL;
        entry_cells = child_cells + 1u +
            parent_address_cells + parent_interrupt_cells;
        if (entry_cells == 0 ||
            entry_cells > context->interrupt_map_cells - offset)
            return BSD_ARM64_PCI_EINVAL;
        specifier_offset = parent_xref_offset + 1u +
            parent_address_cells;
        if (matched)
            return bsd_arm64_pci_decode_interrupt(
                &context->interrupt_map[specifier_offset],
                parent_interrupt_cells, interrupt, interrupt_flags);
        offset += entry_cells;
    }
    return BSD_ARM64_PCI_ENOENT;
}

static int
bsd_arm64_pci_parse_ranges(bsd_arm64_pci_context_t *context)
{
    phandle_t parent = OF_parent(context->node);
    uint32_t parent_address_cells;
    uint32_t size_cells;
    pcell_t *cells = 0;
    ssize_t length;
    size_t cell_count;
    size_t stride;
    int result = BSD_ARM64_PCI_EINVAL;

    if (parent == 0 ||
        bsd_arm64_pci_read_cell(parent, "#address-cells",
            2, &parent_address_cells) != 0 ||
        bsd_arm64_pci_read_cell(context->node, "#size-cells",
            2, &size_cells) != 0 ||
        context->child_address_cells != 3 ||
        parent_address_cells == 0 || parent_address_cells > 2 ||
        size_cells == 0 || size_cells > 2)
        return BSD_ARM64_PCI_EINVAL;
    length = OF_getencprop_alloc(context->node, "ranges",
        (void **)&cells);
    if (length <= 0 ||
        length % (ssize_t)sizeof(*cells) != 0)
        goto out;
    cell_count = (size_t)length / sizeof(*cells);
    stride = context->child_address_cells +
        parent_address_cells + size_cells;
    if (stride == 0 || cell_count % stride != 0 ||
        cell_count / stride > BSD_ARM64_PCI_MAX_RANGES)
        goto out;
    for (size_t offset = 0; offset < cell_count; offset += stride) {
        bsd_arm64_pci_range_t *range =
            &context->ranges[context->range_count];
        uint64_t bus_base;
        uint64_t host_base;
        uint64_t size;
        uint32_t space =
            cells[offset] & BSD_ARM64_PCI_RANGE_SPACE_MASK;

        if (space != BSD_ARM64_PCI_RANGE_IO &&
            space != BSD_ARM64_PCI_RANGE_MEMORY32 &&
            space != BSD_ARM64_PCI_RANGE_MEMORY64)
            continue;
        if (bsd_arm64_pci_decode_cells(
                &cells[offset + 1], 2, &bus_base) != 0 ||
            bsd_arm64_pci_decode_cells(
                &cells[offset + context->child_address_cells],
                parent_address_cells, &host_base) != 0 ||
            bsd_arm64_pci_decode_cells(
                &cells[offset + context->child_address_cells +
                    parent_address_cells],
                size_cells, &size) != 0 ||
            size == 0)
            goto out;
        range->space = space;
        range->bus_base = bus_base;
        range->host_base = host_base;
        range->size = size;
        range->cursor = bus_base;
        context->range_count++;
    }
    result = context->range_count != 0 ? 0 : BSD_ARM64_PCI_ENXIO;
out:
    OF_prop_free(cells);
    return result;
}

static int
bsd_arm64_pci_parse_interrupt_map(
    bsd_arm64_pci_context_t *context)
{
    pcell_t *mask = 0;
    ssize_t mask_length;
    ssize_t map_length;
    unsigned int child_cells =
        context->child_address_cells +
        context->child_interrupt_cells;

    if (child_cells == 0 ||
        child_cells > BSD_ARM64_PCI_MAX_CHILD_CELLS)
        return BSD_ARM64_PCI_EINVAL;
    mask_length = OF_getencprop_alloc(context->node,
        "interrupt-map-mask", (void **)&mask);
    if (mask_length !=
        (ssize_t)(child_cells * sizeof(*mask))) {
        OF_prop_free(mask);
        return BSD_ARM64_PCI_EINVAL;
    }
    for (unsigned int index = 0; index < child_cells; ++index)
        context->interrupt_map_mask[index] = mask[index];
    OF_prop_free(mask);
    map_length = OF_getencprop_alloc(context->node,
        "interrupt-map", (void **)&context->interrupt_map);
    if (map_length <= 0 ||
        map_length % (ssize_t)sizeof(*context->interrupt_map) != 0) {
        OF_prop_free(context->interrupt_map);
        context->interrupt_map = 0;
        return BSD_ARM64_PCI_EINVAL;
    }
    context->interrupt_map_cells =
        (size_t)map_length / sizeof(*context->interrupt_map);
    return 0;
}

static size_t
bsd_arm64_pci_count_functions(bsd_arm64_pci_context_t *context)
{
    size_t count = 0;

    for (unsigned int bus = context->bus_start;
        bus <= context->bus_end; ++bus) {
        for (unsigned int slot = 0; slot < 32; ++slot) {
            bsd_pci_location_t location = {
                .domain = context->domain,
                .bus = (uint8_t)bus,
                .slot = (uint8_t)slot,
            };
            uint16_t vendor = (uint16_t)bsd_arm64_pci_read_config(
                context, &location, 0, 2);
            unsigned int functions = 1;

            if (vendor == BSD_ARM64_PCI_VENDOR_INVALID)
                continue;
            if (bsd_arm64_pci_read_config(context, &location,
                BSD_ARM64_PCI_HEADER_TYPE, 1) &
                BSD_ARM64_PCI_HEADER_MULTIFUNCTION)
                functions = 8;
            ++count;
            for (unsigned int function = 1;
                function < functions; ++function) {
                location.function = (uint8_t)function;
                vendor = (uint16_t)bsd_arm64_pci_read_config(
                    context, &location, 0, 2);
                if (vendor != BSD_ARM64_PCI_VENDOR_INVALID)
                    ++count;
            }
        }
        if (bus == UINT8_MAX)
            break;
    }
    return count;
}

static int
bsd_arm64_pci_inventory_functions(
    bsd_arm64_pci_context_t *context)
{
    size_t expected = bsd_arm64_pci_count_functions(context);
    size_t populated = 0;

    if (expected == 0)
        return BSD_ARM64_PCI_ENXIO;
    context->functions = bsd_mallocarray(expected,
        sizeof(*context->functions), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!context->functions)
        return BSD_ARM64_PCI_ENOMEM;
    for (unsigned int bus = context->bus_start;
        bus <= context->bus_end; ++bus) {
        for (unsigned int slot = 0; slot < 32; ++slot) {
            bsd_pci_location_t location = {
                .domain = context->domain,
                .bus = (uint8_t)bus,
                .slot = (uint8_t)slot,
            };
            uint16_t vendor = (uint16_t)bsd_arm64_pci_read_config(
                context, &location, 0, 2);
            unsigned int functions = 1;

            if (vendor == BSD_ARM64_PCI_VENDOR_INVALID)
                continue;
            if (bsd_arm64_pci_read_config(context, &location,
                BSD_ARM64_PCI_HEADER_TYPE, 1) &
                BSD_ARM64_PCI_HEADER_MULTIFUNCTION)
                functions = 8;
            context->functions[populated++] = location;
            for (unsigned int function = 1;
                function < functions; ++function) {
                location.function = (uint8_t)function;
                vendor = (uint16_t)bsd_arm64_pci_read_config(
                    context, &location, 0, 2);
                if (vendor != BSD_ARM64_PCI_VENDOR_INVALID)
                    context->functions[populated++] = location;
            }
        }
        if (bus == UINT8_MAX)
            break;
    }
    if (populated != expected)
        return BSD_ARM64_PCI_EINVAL;
    context->function_count = populated;
    if (populated > SIZE_MAX / 6u)
        return BSD_ARM64_PCI_ENOMEM;
    context->reservation_capacity = populated * 6u;
    context->reservations = bsd_mallocarray(
        context->reservation_capacity, sizeof(*context->reservations),
        M_DEVBUF, M_WAITOK | M_ZERO);
    return context->reservations ? 0 : BSD_ARM64_PCI_ENOMEM;
}

static int
bsd_arm64_pci_reserve_firmware_bars(
    bsd_arm64_pci_context_t *context)
{
    for (size_t function_index = 0;
        function_index < context->function_count; ++function_index) {
        const bsd_pci_location_t *location =
            &context->functions[function_index];
        uint8_t header_type = (uint8_t)bsd_arm64_pci_read_config(
            context, location, BSD_ARM64_PCI_HEADER_TYPE, 1);
        unsigned int bar_count =
            (header_type & UINT8_C(0x7f)) == 0 ? 6u : 2u;
        uint16_t command = (uint16_t)bsd_arm64_pci_read_config(
            context, location, BSD_ARM64_PCI_COMMAND, 2);

        bsd_arm64_pci_write_config(context, location,
            BSD_ARM64_PCI_COMMAND,
            command & ~(BSD_ARM64_PCI_COMMAND_IO_ENABLE |
                        BSD_ARM64_PCI_COMMAND_MEMORY_ENABLE), 2);
        for (unsigned int bar_index = 0;
            bar_index < bar_count; ++bar_index) {
            bsd_arm64_pci_bar_t bar;
            unsigned int range_index;
            int result = bsd_arm64_pci_probe_bar(
                context, location, bar_index, bar_count, &bar);

            if (result != 0) {
                bsd_arm64_pci_write_config(context, location,
                    BSD_ARM64_PCI_COMMAND, command, 2);
                return result;
            }
            if (bar.present && bar.base != 0 &&
                bsd_arm64_pci_find_range(context,
                    bar.resource_type, bar.base, bar.size,
                    &range_index) == 0) {
                result = bsd_arm64_pci_reserve(
                    context, range_index, bar.base, bar.size);
                if (result != 0) {
                    bsd_arm64_pci_write_config(context, location,
                        BSD_ARM64_PCI_COMMAND, command, 2);
                    return result;
                }
            }
            if (bar.is_64)
                ++bar_index;
        }
        bsd_arm64_pci_write_config(
            context, location, BSD_ARM64_PCI_COMMAND, command, 2);
    }
    return 0;
}

int
bsd_pci_arch_initialize(void)
{
    bsd_arm64_pci_context_t *context = &g_arm64_pci;
    pcell_t bus_range[2] = {0, UINT8_MAX};
    pcell_t domain = 0;
    uint32_t child_address_cells;
    uint32_t child_interrupt_cells;
    int result;
    bsd_pci_backend_ops_t operations;

    if (context->node != 0)
        return BSD_ARM64_PCI_ENXIO;
    context->node = bsd_ofw_fdt_find_compatible(
        "pci-host-ecam-generic", 0);
    if (context->node == 0 ||
        bsd_ofw_fdt_get_reg(context->node, 0,
            &context->ecam_base, &context->ecam_size) != 0 ||
        context->ecam_size < UINT64_C(0x100000))
        return BSD_ARM64_PCI_ENXIO;
    if (OF_getencprop(context->node, "bus-range",
        bus_range, sizeof(bus_range)) < 0) {
        bus_range[0] = 0;
        bus_range[1] = UINT8_MAX;
    }
    if (bus_range[0] > bus_range[1] ||
        bus_range[1] > UINT8_MAX)
        return BSD_ARM64_PCI_EINVAL;
    if (OF_getencprop(context->node, "linux,pci-domain",
        &domain, sizeof(domain)) < 0)
        domain = 0;
    if (bsd_arm64_pci_read_cell(context->node, "#address-cells",
            3, &child_address_cells) != 0 ||
        bsd_arm64_pci_read_cell(context->node, "#interrupt-cells",
            1, &child_interrupt_cells) != 0)
        return BSD_ARM64_PCI_EINVAL;
    context->domain = domain;
    context->bus_start = (uint8_t)bus_range[0];
    context->bus_end = (uint8_t)bus_range[1];
    context->child_address_cells = child_address_cells;
    context->child_interrupt_cells = child_interrupt_cells;
    result = bsd_arm64_pci_parse_ranges(context);
    if (result == 0)
        result = bsd_arm64_pci_parse_interrupt_map(context);
    if (result == 0)
        result = bsd_arm64_pci_inventory_functions(context);
    if (result == 0)
        result = bsd_arm64_pci_reserve_firmware_bars(context);
    if (result != 0)
        return result;

    operations = (bsd_pci_backend_ops_t) {
        .read_config = bsd_arm64_pci_read_config,
        .write_config = bsd_arm64_pci_write_config,
        .function_count = bsd_arm64_pci_function_count,
        .function_at = bsd_arm64_pci_function_at,
        .prepare_device = bsd_arm64_pci_prepare_device,
        .translate_resource = bsd_arm64_pci_translate_resource,
        .legacy_interrupt = bsd_arm64_pci_legacy_interrupt,
        .context = context,
    };
    return bsd_pci_initialize(&operations);
}
