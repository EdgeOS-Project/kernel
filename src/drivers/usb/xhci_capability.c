/* SPDX-License-Identifier: MPL-2.0 */
/* xHCI capability decoding shared by the driver and host-side tests. */

#include "drivers/xhci_capability.h"

uint16_t
xhci_hcs2_scratchpad_count(uint32_t hcs2)
{
    return (uint16_t)(((hcs2 >> 16) & 0x3e0u) |
        ((hcs2 >> 27) & 0x1fu));
}

uint32_t
xhci_extended_capability_offset(uint32_t hcc1)
{
    return ((hcc1 >> 16) & 0xffffu) << 2;
}

int
xhci_select_page_size(uint32_t page_size_mask, uint32_t *page_size_out)
{
    uint32_t bit;

    if (page_size_out == 0 || page_size_mask == 0)
        return -1;
    for (bit = 0; bit < 16u; ++bit) {
        if ((page_size_mask & (1u << bit)) == 0)
            continue;
        *page_size_out = 4096u << bit;
        return 0;
    }
    return -1;
}
