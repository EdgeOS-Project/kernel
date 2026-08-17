/* SPDX-License-Identifier: MPL-2.0 */
/* xHCI control-transfer policy shared by the driver and host-side tests. */

#include "drivers/xhci_transfer.h"

#define XHCI_TRB_TYPE_SETUP_STAGE  2u
#define XHCI_TRB_TYPE_DATA_STAGE   3u
#define XHCI_TRB_TYPE_STATUS_STAGE 4u

#define XHCI_TRB_ISP (1u << 2)
#define XHCI_TRB_IOC (1u << 5)
#define XHCI_TRB_IDT (1u << 6)
#define XHCI_TRB_DIR (1u << 16)

#define XHCI_COMP_SUCCESS      1u
#define XHCI_COMP_SHORT_PACKET 13u

uint32_t
xhci_control_setup_flags(int direction_in, uint16_t length)
{
    uint32_t transfer_type;

    if (length == 0)
        transfer_type = 0;
    else
        transfer_type = direction_in ? 3u : 2u;
    /*
     * A Setup Stage TD contains exactly one Setup Stage TRB. Bits 1:4 are
     * reserved in this TRB type, so it must never carry the Chain flag.
     */
    return ((uint32_t)XHCI_TRB_TYPE_SETUP_STAGE << 10) |
        XHCI_TRB_IDT | (transfer_type << 16);
}

uint32_t
xhci_control_data_flags(int direction_in)
{
    /*
     * The current control buffer is physically contiguous and uses one Data
     * Stage TRB. The Chain flag is therefore clear because this TRB is also
     * the last TRB of its Data Stage TD.
     */
    return ((uint32_t)XHCI_TRB_TYPE_DATA_STAGE << 10) |
        (direction_in ? (XHCI_TRB_DIR | XHCI_TRB_ISP) : 0u);
}

uint32_t
xhci_control_status_flags(int direction_in)
{
    return ((uint32_t)XHCI_TRB_TYPE_STATUS_STAGE << 10) |
        XHCI_TRB_IOC | (direction_in ? 0u : XHCI_TRB_DIR);
}

int
xhci_control_event_is_terminal(uint64_t event_trb,
                               uint64_t status_trb,
                               uint64_t setup_trb,
                               uint64_t data_trb,
                               uint8_t completion_code)
{
    if (event_trb == status_trb)
        return 1;
    if (event_trb != setup_trb &&
        (data_trb == 0 || event_trb != data_trb))
        return 0;
    /*
     * Successful intermediate events do not complete the control transfer.
     * The status stage is still required. An intermediate error is terminal
     * so callers do not wait for a status stage that cannot execute.
     */
    return completion_code != XHCI_COMP_SUCCESS &&
        completion_code != XHCI_COMP_SHORT_PACKET;
}
