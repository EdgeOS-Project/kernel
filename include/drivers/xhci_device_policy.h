/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS xHCI device selection and recovery policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_XHCI_DEVICE_POLICY_H
#define EDGEOS_DRIVERS_XHCI_DEVICE_POLICY_H

#include <stdint.h>

#define XHCI_DEVICE_DRIVER_HID_BOOT (1u << 0)
#define XHCI_DEVICE_DRIVER_STORAGE  (1u << 1)
#define XHCI_DEVICE_DRIVER_AUDIO    (1u << 2)
#define XHCI_DEVICE_DRIVER_VIDEO    (1u << 3)
#define XHCI_DEVICE_DRIVER_NETWORK  (1u << 4)
#define XHCI_DEVICE_DRIVER_HID_REPORT (1u << 5)
#define XHCI_DEVICE_MAX_FAILURES 3u
#define XHCI_DEVICE_DISCONNECT_CONFIRMATIONS 3u

typedef struct {
    uint8_t valid;
    uint8_t report_id;
    uint8_t button_count;
    uint8_t x_size;
    uint8_t y_size;
    uint8_t wheel_size;
    uint8_t x_signed;
    uint8_t y_signed;
    uint8_t wheel_signed;
    uint8_t buttons_report_id;
    uint16_t buttons_offset;
    uint16_t x_offset;
    uint16_t y_offset;
    uint16_t wheel_offset;
} xhci_hid_pointer_layout_t;

uint32_t xhci_device_driver_candidates(
    uint8_t device_class, uint8_t device_subclass, uint8_t device_protocol,
    const uint8_t *configuration, uint16_t length);
uint16_t xhci_device_ep0_packet_size(uint8_t speed_id,
                                     uint8_t descriptor_value);
int xhci_hid_pointer_layout_parse(
    const uint8_t *descriptor, uint16_t length,
    xhci_hid_pointer_layout_t *layout);
int xhci_hid_pointer_report_decode(
    const xhci_hid_pointer_layout_t *layout,
    const uint8_t *report, uint16_t length,
    int *dx_out, int *dy_out, int *wheel_out,
    uint8_t *buttons_out, int *wheel_present_out);
uint64_t xhci_device_retry_delay_us(uint8_t failure_count);
int xhci_device_retry_permitted(uint8_t failure_count);
int xhci_device_disconnect_update(uint8_t *observations, int connected);

#endif /* EDGEOS_DRIVERS_XHCI_DEVICE_POLICY_H */
