/* SPDX-License-Identifier: MPL-2.0 */
/* Transactional ownership state for native PCI USB controllers. */

#ifndef EDGEOS_DRIVERS_USB_HANDOFF_H
#define EDGEOS_DRIVERS_USB_HANDOFF_H

#include <stdint.h>

#define USB_HANDOFF_MAX_LOCATIONS 32u
#define USB_HANDOFF_MAX_CONTROLLERS 8u

typedef struct usb_handoff_location {
    uint32_t domain;
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
} usb_handoff_location_t;

typedef struct usb_handoff_state {
    uint32_t controller_mask;
} usb_handoff_state_t;

typedef int (*usb_handoff_controller_prepare_fn)(void *context);
typedef int (*usb_handoff_controller_restore_fn)(void *context);

int usb_handoff_reserve_locations(
    const usb_handoff_location_t *locations, uint32_t count);
int usb_handoff_location_reserved(
    const usb_handoff_location_t *location);
int usb_handoff_controller_register(
    const usb_handoff_location_t *location,
    usb_handoff_controller_prepare_fn prepare,
    usb_handoff_controller_restore_fn restore, void *context);
int usb_handoff_prepare_locations(
    const usb_handoff_location_t *locations, uint32_t count,
    usb_handoff_state_t *state);
int usb_handoff_restore(usb_handoff_state_t *state);
int usb_handoff_release_reservations(void);

#endif
