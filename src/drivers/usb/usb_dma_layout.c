/* SPDX-License-Identifier: MPL-2.0 */
/* Boundary-aware USB DMA placement shared by the allocator and tests. */

#include "drivers/usb_dma_layout.h"

static int
is_power_of_two(uint32_t value)
{
    return value != 0 && (value & (value - 1u)) == 0;
}

static int
align_up(uintptr_t value, uint32_t alignment, uintptr_t *result)
{
    uintptr_t mask;

    if (!result || !is_power_of_two(alignment))
        return -1;
    mask = (uintptr_t)alignment - 1u;
    if (value > UINTPTR_MAX - mask)
        return -1;
    *result = (value + mask) & ~mask;
    return 0;
}

int
usb_dma_layout_start(uintptr_t current,
                     uint32_t size,
                     uint32_t alignment,
                     uint32_t boundary,
                     uintptr_t *start_out)
{
    uintptr_t start;
    uintptr_t offset;

    if (!start_out || size == 0 || !is_power_of_two(alignment))
        return -1;
    if (boundary != 0 &&
        (!is_power_of_two(boundary) || size > boundary))
        return -1;
    if (align_up(current, alignment, &start) < 0)
        return -1;
    if (boundary != 0) {
        offset = start & ((uintptr_t)boundary - 1u);
        if (offset > (uintptr_t)boundary - size &&
            align_up(start, boundary, &start) < 0)
            return -1;
    }
    if (start > UINTPTR_MAX - size)
        return -1;
    *start_out = start;
    return 0;
}
