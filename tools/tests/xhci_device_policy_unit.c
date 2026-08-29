/* SPDX-License-Identifier: MPL-2.0 */
/* xHCI device selection and recovery policy tests. */

#include <assert.h>
#include <stdint.h>

#include "drivers/xhci_device_policy.h"

static void set_interface(uint8_t *configuration, uint8_t offset,
                          uint8_t interface_class,
                          uint8_t interface_subclass,
                          uint8_t interface_protocol) {
    configuration[offset] = 9;
    configuration[offset + 1u] = 4;
    configuration[offset + 5u] = interface_class;
    configuration[offset + 6u] = interface_subclass;
    configuration[offset + 7u] = interface_protocol;
}

int main(void) {
    uint8_t configuration[27] = {
        9, 2, 27, 0, 2, 1, 0, 0x80, 50
    };
    uint32_t candidates;
    static const uint8_t report_descriptor[] = {
        0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x03,
        0x09, 0x01, 0xa1, 0x00, 0x05, 0x09, 0x19, 0x01,
        0x29, 0x08, 0x15, 0x00, 0x25, 0x01, 0x95, 0x08,
        0x75, 0x01, 0x81, 0x02, 0x05, 0x01, 0x09, 0x30,
        0x09, 0x31, 0x16, 0x01, 0xf8, 0x26, 0xff, 0x07,
        0x75, 0x0c, 0x95, 0x02, 0x81, 0x06, 0x05, 0x01,
        0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x08,
        0x95, 0x01, 0x81, 0x06, 0xc0, 0xc0
    };
    const uint8_t pointer_report[] = {
        0x03, 0x01, 0x0a, 0xb0, 0xff, 0xff
    };
    const uint8_t unrelated_report[] = {0x02, 0x00};
    xhci_hid_pointer_layout_t layout;
    int dx;
    int dy;
    int wheel;
    int wheel_present;
    uint8_t buttons;
    uint8_t disconnect_observations = 0;

    set_interface(configuration, 9, 8, 6, 0x50);
    set_interface(configuration, 18, 3, 1, 2);
    candidates = xhci_device_driver_candidates(
        0, 0, 0, configuration, sizeof(configuration));
    assert(candidates & XHCI_DEVICE_DRIVER_STORAGE);
    assert(candidates & XHCI_DEVICE_DRIVER_HID_BOOT);

    set_interface(configuration, 9, 3, 0, 0);
    set_interface(configuration, 18, 9, 0, 0);
    candidates = xhci_device_driver_candidates(
        0, 0, 0, configuration, sizeof(configuration));
    assert(candidates == XHCI_DEVICE_DRIVER_HID_REPORT);

    set_interface(configuration, 9, 0xff, 0, 0);
    candidates = xhci_device_driver_candidates(
        0, 0, 0, configuration, 18);
    assert(candidates == XHCI_DEVICE_DRIVER_NETWORK);

    assert(xhci_device_ep0_packet_size(1, 8) == 8);
    assert(xhci_device_ep0_packet_size(1, 64) == 64);
    assert(xhci_device_ep0_packet_size(1, 9) == 0);
    assert(xhci_device_ep0_packet_size(2, 8) == 8);
    assert(xhci_device_ep0_packet_size(2, 64) == 0);
    assert(xhci_device_ep0_packet_size(3, 64) == 64);
    assert(xhci_device_ep0_packet_size(4, 9) == 512);
    assert(xhci_device_ep0_packet_size(4, 64) == 0);

    assert(xhci_hid_pointer_layout_parse(
               report_descriptor, sizeof(report_descriptor), &layout) == 0);
    assert(layout.valid);
    assert(layout.report_id == 3);
    assert(layout.buttons_offset == 8);
    assert(layout.button_count == 8);
    assert(layout.x_offset == 16);
    assert(layout.x_size == 12);
    assert(layout.y_offset == 28);
    assert(layout.y_size == 12);
    assert(layout.wheel_offset == 40);
    assert(layout.wheel_size == 8);
    assert(xhci_hid_pointer_report_decode(
               &layout, pointer_report, sizeof(pointer_report),
               &dx, &dy, &wheel, &buttons, &wheel_present) == 1);
    assert(dx == 10);
    assert(dy == -5);
    assert(wheel == -1);
    assert(buttons == 1);
    assert(wheel_present);
    assert(xhci_hid_pointer_report_decode(
               &layout, unrelated_report, sizeof(unrelated_report),
               &dx, &dy, &wheel, &buttons, &wheel_present) == 0);

    assert(xhci_device_retry_delay_us(0) == 250000ull);
    assert(xhci_device_retry_delay_us(1) == 250000ull);
    assert(xhci_device_retry_delay_us(2) == 500000ull);
    assert(xhci_device_retry_delay_us(7) == 16000000ull);
    assert(xhci_device_retry_delay_us(8) == 30000000ull);
    assert(xhci_device_retry_delay_us(255) == 30000000ull);
    assert(xhci_device_retry_permitted(0));
    assert(xhci_device_retry_permitted(2));
    assert(!xhci_device_retry_permitted(3));
    assert(!xhci_device_retry_permitted(255));
    assert(!xhci_device_disconnect_update(
        &disconnect_observations, 0));
    assert(disconnect_observations == 1);
    assert(!xhci_device_disconnect_update(
        &disconnect_observations, 1));
    assert(disconnect_observations == 0);
    assert(!xhci_device_disconnect_update(
        &disconnect_observations, 0));
    assert(!xhci_device_disconnect_update(
        &disconnect_observations, 0));
    assert(xhci_device_disconnect_update(
        &disconnect_observations, 0));
    assert(disconnect_observations ==
           XHCI_DEVICE_DISCONNECT_CONFIRMATIONS);
    assert(xhci_device_disconnect_update(
        &disconnect_observations, 0));
    assert(!xhci_device_disconnect_update(0, 0));
    return 0;
}
