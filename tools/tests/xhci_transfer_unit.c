/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "drivers/xhci_transfer.h"

#define TRB_TYPE(value) (((value) >> 10) & 0x3fu)
#define TRB_CHAIN       (1u << 4)
#define TRB_IOC         (1u << 5)
#define TRB_IDT         (1u << 6)
#define TRB_DIR         (1u << 16)
#define TRB_TRT(value)  (((value) >> 16) & 0x3u)

int
main(void)
{
    uint32_t flags;

    flags = xhci_control_setup_flags(0, 0);
    assert(TRB_TYPE(flags) == 2u);
    assert((flags & TRB_IDT) != 0);
    assert((flags & (TRB_CHAIN | TRB_IOC)) == 0);
    assert(TRB_TRT(flags) == 0u);

    flags = xhci_control_setup_flags(0, 18);
    assert(TRB_TRT(flags) == 2u);
    assert((flags & TRB_CHAIN) == 0);

    flags = xhci_control_setup_flags(1, 18);
    assert(TRB_TRT(flags) == 3u);
    assert((flags & TRB_CHAIN) == 0);

    flags = xhci_control_data_flags(1);
    assert(TRB_TYPE(flags) == 3u);
    assert((flags & TRB_DIR) != 0);
    assert((flags & TRB_CHAIN) == 0);

    flags = xhci_control_status_flags(1);
    assert(TRB_TYPE(flags) == 4u);
    assert((flags & TRB_DIR) == 0);
    assert((flags & TRB_IOC) != 0);

    flags = xhci_control_status_flags(0);
    assert((flags & TRB_DIR) != 0);

    assert(xhci_control_event_is_terminal(0x30, 0x30, 0x10, 0x20, 1));
    assert(!xhci_control_event_is_terminal(0x10, 0x30, 0x10, 0x20, 1));
    assert(!xhci_control_event_is_terminal(0x20, 0x30, 0x10, 0x20, 13));
    assert(xhci_control_event_is_terminal(0x20, 0x30, 0x10, 0x20, 4));
    assert(!xhci_control_event_is_terminal(0x40, 0x30, 0x10, 0x20, 4));

    puts("xhci_transfer_unit: PASS");
    return 0;
}
