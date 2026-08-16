#ifndef DRIVERS_USB_H
#define DRIVERS_USB_H

#include <stdint.h>

void usb_init(void);
void usb_poll(void);
void usb_poll_irq(void);
int usb_present_mouse(void);
int usb_storage_register_block_if_present(const char *name);
void usb_hid_mouse_report_boot(int8_t dx, int8_t dy, int8_t wheel, uint8_t buttons, int wheel_present);
void usb_hid_mouse_report(int dx, int dy, int wheel, uint8_t buttons,
                          int wheel_present);
void usb_hid_process_boot_report(const uint8_t *report, uint16_t n);
void usb_hid_process_boot_keyboard_report(const uint8_t *report, uint16_t n);
int usb_inventory_snapshot(char *buf, uint32_t max);

#endif
