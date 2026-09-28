/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for xHCI structural capability decoding. */

#include "drivers/xhci_capability.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int
main(void)
{
    uint32_t page_size = 0;

    assert(xhci_hcs2_scratchpad_count(0) == 0);
    assert(xhci_hcs2_scratchpad_count(0x08000000u) == 1);
    assert(xhci_hcs2_scratchpad_count(0xf8000000u) == 31);
    assert(xhci_hcs2_scratchpad_count(0x03e00000u) == 992);
    assert(xhci_hcs2_scratchpad_count(0xfbe00000u) == 1023);

    assert(xhci_extended_capability_offset(0) == 0);
    assert(xhci_extended_capability_offset(0x00100000u) == 0x40u);
    assert(xhci_extended_capability_offset(0x01230000u) == 0x48cu);

    assert(xhci_select_page_size(0, &page_size) == -1);
    assert(xhci_select_page_size(1u, &page_size) == 0);
    assert(page_size == 4096u);
    assert(xhci_select_page_size(0x14u, &page_size) == 0);
    assert(page_size == 16384u);
    assert(xhci_select_page_size(1u << 15, &page_size) == 0);
    assert(page_size == 0x08000000u);
    assert(xhci_select_page_size(1u << 16, &page_size) == -1);
    assert(xhci_select_page_size(1u, 0) == -1);

    puts("xhci_capability_unit: PASS");
    return 0;
}
