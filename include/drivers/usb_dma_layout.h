/* SPDX-License-Identifier: MPL-2.0 */
/* Boundary-aware USB DMA placement shared by the allocator and tests. */

#ifndef EDGEOS_DRIVERS_USB_DMA_LAYOUT_H
#define EDGEOS_DRIVERS_USB_DMA_LAYOUT_H

#include <stdint.h>

int usb_dma_layout_start(uintptr_t current,
                         uint32_t size,
                         uint32_t alignment,
                         uint32_t boundary,
                         uintptr_t *start_out);

#endif
