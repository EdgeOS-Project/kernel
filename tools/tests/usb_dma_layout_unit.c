/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "drivers/usb_dma_layout.h"

int
main(void)
{
    uintptr_t start = 0;

    assert(usb_dma_layout_start(0x1003u, 64u, 64u, 4096u, &start) == 0);
    assert(start == 0x1040u);

    assert(usb_dma_layout_start(0x1fc0u, 128u, 64u, 4096u, &start) == 0);
    assert(start == 0x2000u);

    assert(usb_dma_layout_start(0xff80u, 1024u, 64u, 65536u, &start) == 0);
    assert(start == 0x10000u);

    assert(usb_dma_layout_start(0x1234u, 65536u, 64u, 65536u,
                                &start) == 0);
    assert(start == 0x10000u);

    assert(usb_dma_layout_start(0x1000u, 4097u, 64u, 4096u,
                                &start) < 0);
    assert(usb_dma_layout_start(0x1000u, 64u, 24u, 4096u,
                                &start) < 0);

    puts("usb_dma_layout_unit: PASS");
    return 0;
}
