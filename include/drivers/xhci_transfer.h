/* SPDX-License-Identifier: MPL-2.0 */
/* xHCI control-transfer policy shared by the driver and host-side tests. */

#ifndef EDGEOS_DRIVERS_XHCI_TRANSFER_H
#define EDGEOS_DRIVERS_XHCI_TRANSFER_H

#include <stdint.h>

uint32_t xhci_control_setup_flags(int direction_in, uint16_t length);
uint32_t xhci_control_data_flags(int direction_in);
uint32_t xhci_control_status_flags(int direction_in);
int xhci_control_event_is_terminal(uint64_t event_trb,
                                   uint64_t status_trb,
                                   uint64_t setup_trb,
                                   uint64_t data_trb,
                                   uint8_t completion_code);

#endif
