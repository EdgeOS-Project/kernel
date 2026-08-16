/* SPDX-License-Identifier: MPL-2.0 */
/* xHCI capability decoding shared by the driver and host-side tests. */

#ifndef EDGEOS_DRIVERS_XHCI_CAPABILITY_H
#define EDGEOS_DRIVERS_XHCI_CAPABILITY_H

#include <stdint.h>

uint16_t xhci_hcs2_scratchpad_count(uint32_t hcs2);
uint32_t xhci_extended_capability_offset(uint32_t hcc1);
int xhci_select_page_size(uint32_t page_size_mask, uint32_t *page_size_out);

#endif
