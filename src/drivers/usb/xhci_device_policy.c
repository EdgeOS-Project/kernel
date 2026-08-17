/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS xHCI device selection and recovery policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "drivers/xhci_device_policy.h"

#define USB_CLASS_AUDIO 0x01u
#define USB_CLASS_COMMUNICATIONS 0x02u
#define USB_CLASS_HID 0x03u
#define USB_CLASS_STORAGE 0x08u
#define USB_CLASS_DATA 0x0au
#define USB_CLASS_VIDEO 0x0eu
#define USB_CLASS_VENDOR 0xffu

#define USB_STORAGE_SUBCLASS_SCSI 0x06u
#define USB_STORAGE_PROTOCOL_BULK_ONLY 0x50u

#define XHCI_RETRY_BASE_US 250000ull
#define XHCI_RETRY_MAX_US 30000000ull

static uint32_t xhci_driver_for_interface(uint8_t interface_class,
                                          uint8_t interface_subclass,
                                          uint8_t interface_protocol) {
    if (interface_class == USB_CLASS_HID) {
        if (interface_subclass == 1u &&
            (interface_protocol == 1u || interface_protocol == 2u))
            return XHCI_DEVICE_DRIVER_HID_BOOT;
        return XHCI_DEVICE_DRIVER_HID_REPORT;
    }
    if (interface_class == USB_CLASS_STORAGE &&
        interface_subclass == USB_STORAGE_SUBCLASS_SCSI &&
        interface_protocol == USB_STORAGE_PROTOCOL_BULK_ONLY)
        return XHCI_DEVICE_DRIVER_STORAGE;
    if (interface_class == USB_CLASS_AUDIO)
        return XHCI_DEVICE_DRIVER_AUDIO;
    if (interface_class == USB_CLASS_VIDEO)
        return XHCI_DEVICE_DRIVER_VIDEO;
    if (interface_class == USB_CLASS_COMMUNICATIONS ||
        interface_class == USB_CLASS_DATA ||
        interface_class == USB_CLASS_VENDOR)
        return XHCI_DEVICE_DRIVER_NETWORK;
    return 0;
}

uint32_t xhci_device_driver_candidates(
    uint8_t device_class, uint8_t device_subclass, uint8_t device_protocol,
    const uint8_t *configuration, uint16_t length) {
    uint32_t candidates = xhci_driver_for_interface(
        device_class, device_subclass, device_protocol);
    uint16_t offset = 0;

    while (configuration && offset + 2u <= length) {
        uint8_t descriptor_length = configuration[offset];
        uint8_t descriptor_type = configuration[offset + 1u];

        if (descriptor_length < 2u ||
            offset + descriptor_length > length)
            break;
        if (descriptor_type == 4u && descriptor_length >= 9u) {
            candidates |= xhci_driver_for_interface(
                configuration[offset + 5u],
                configuration[offset + 6u],
                configuration[offset + 7u]);
        }
        offset = (uint16_t)(offset + descriptor_length);
    }
    return candidates;
}

uint16_t xhci_device_ep0_packet_size(uint8_t speed_id,
                                     uint8_t descriptor_value) {
    if (speed_id >= 4u) {
        if (descriptor_value > 10u) return 0;
        return (uint16_t)(1u << descriptor_value);
    }
    if (speed_id == 3u)
        return descriptor_value == 64u ? 64u : 0u;
    if (speed_id == 2u)
        return descriptor_value == 8u ? 8u : 0u;
    if (speed_id == 1u &&
        (descriptor_value == 8u || descriptor_value == 16u ||
         descriptor_value == 32u || descriptor_value == 64u))
        return descriptor_value;
    return 0;
}

typedef struct {
    uint32_t usage_page;
    int32_t logical_minimum;
    uint32_t report_size;
    uint32_t report_count;
    uint8_t report_id;
} xhci_hid_global_state_t;

typedef struct {
    uint32_t usages[16];
    uint8_t usage_count;
    uint8_t have_usage_minimum;
    uint8_t have_usage_maximum;
    uint32_t usage_minimum;
    uint32_t usage_maximum;
} xhci_hid_local_state_t;

static uint32_t xhci_hid_item_unsigned(const uint8_t *data, uint8_t size) {
    uint32_t value = 0;

    for (uint8_t index = 0; index < size; ++index)
        value |= (uint32_t)data[index] << (index * 8u);
    return value;
}

static int32_t xhci_hid_item_signed(const uint8_t *data, uint8_t size) {
    uint32_t value = xhci_hid_item_unsigned(data, size);

    if (size == 1u && (value & 0x80u)) value |= 0xffffff00u;
    if (size == 2u && (value & 0x8000u)) value |= 0xffff0000u;
    return (int32_t)value;
}

static void xhci_hid_local_reset(xhci_hid_local_state_t *local) {
    if (!local) return;
    local->usage_count = 0;
    local->have_usage_minimum = 0;
    local->have_usage_maximum = 0;
    local->usage_minimum = 0;
    local->usage_maximum = 0;
}

static uint32_t xhci_hid_local_usage(
    const xhci_hid_local_state_t *local, uint32_t index) {
    if (!local) return 0;
    if (index < local->usage_count) return local->usages[index];
    if (local->have_usage_minimum && local->have_usage_maximum &&
        local->usage_minimum + index <= local->usage_maximum)
        return local->usage_minimum + index;
    if (local->usage_count == 1u) return local->usages[0];
    return 0;
}

static int xhci_hid_field_set(
    xhci_hid_pointer_layout_t *layout, uint32_t usage_page,
    uint32_t usage, uint8_t report_id, uint16_t offset,
    uint8_t size, int is_signed) {
    if (!layout || size == 0u || size > 32u) return 0;
    if (usage_page == 0x09u && usage >= 1u && usage <= 8u) {
        if (layout->button_count == 0u) {
            layout->buttons_report_id = report_id;
            layout->buttons_offset = offset;
        }
        if (layout->buttons_report_id != report_id) return 0;
        if (layout->button_count < 8u) layout->button_count++;
        return 1;
    }
    if (usage_page != 0x01u) return 0;
    if (usage == 0x30u && layout->x_size == 0u) {
        layout->report_id = report_id;
        if (layout->button_count != 0u &&
            layout->buttons_report_id != report_id)
            layout->button_count = 0;
        layout->x_offset = offset;
        layout->x_size = size;
        layout->x_signed = is_signed ? 1u : 0u;
        return 1;
    }
    if (usage == 0x31u && layout->y_size == 0u &&
        layout->report_id == report_id) {
        layout->y_offset = offset;
        layout->y_size = size;
        layout->y_signed = is_signed ? 1u : 0u;
        return 1;
    }
    if (usage == 0x38u && layout->wheel_size == 0u &&
        layout->report_id == report_id) {
        layout->wheel_offset = offset;
        layout->wheel_size = size;
        layout->wheel_signed = is_signed ? 1u : 0u;
        return 1;
    }
    return 0;
}

int xhci_hid_pointer_layout_parse(
    const uint8_t *descriptor, uint16_t length,
    xhci_hid_pointer_layout_t *layout) {
    xhci_hid_global_state_t global = {0};
    xhci_hid_global_state_t stack[4];
    xhci_hid_local_state_t local = {0};
    uint16_t input_bits[256] = {0};
    uint8_t stack_depth = 0;
    uint8_t collection_depth = 0;
    uint8_t mouse_depth = 0;
    uint16_t offset = 0;

    if (!descriptor || !layout) return -1;
    *layout = (xhci_hid_pointer_layout_t){0};
    while (offset < length) {
        uint8_t prefix = descriptor[offset++];
        uint8_t size;
        uint8_t type;
        uint8_t tag;
        uint32_t value;

        if (prefix == 0xfeu) {
            uint8_t long_size;
            if (offset + 2u > length) return -1;
            long_size = descriptor[offset];
            offset = (uint16_t)(offset + 2u);
            if (offset + long_size > length) return -1;
            offset = (uint16_t)(offset + long_size);
            continue;
        }
        size = (uint8_t)(prefix & 0x03u);
        if (size == 3u) size = 4u;
        type = (uint8_t)((prefix >> 2) & 0x03u);
        tag = (uint8_t)((prefix >> 4) & 0x0fu);
        if (offset + size > length) return -1;
        value = xhci_hid_item_unsigned(descriptor + offset, size);

        if (type == 1u) {
            if (tag == 0u) global.usage_page = value;
            else if (tag == 1u)
                global.logical_minimum =
                    xhci_hid_item_signed(descriptor + offset, size);
            else if (tag == 7u) global.report_size = value;
            else if (tag == 8u && value > 0u && value <= 255u) {
                global.report_id = (uint8_t)value;
                if (input_bits[global.report_id] == 0u)
                    input_bits[global.report_id] = 8u;
            } else if (tag == 9u) global.report_count = value;
            else if (tag == 10u && stack_depth < 4u)
                stack[stack_depth++] = global;
            else if (tag == 11u && stack_depth > 0u)
                global = stack[--stack_depth];
        } else if (type == 2u) {
            if (tag == 0u && local.usage_count < 16u)
                local.usages[local.usage_count++] = value;
            else if (tag == 1u) {
                local.have_usage_minimum = 1;
                local.usage_minimum = value;
            } else if (tag == 2u) {
                local.have_usage_maximum = 1;
                local.usage_maximum = value;
            }
        } else if (type == 0u) {
            if (tag == 10u) {
                uint32_t usage = xhci_hid_local_usage(&local, 0);
                collection_depth++;
                if (mouse_depth == 0u && global.usage_page == 0x01u &&
                    usage == 0x02u)
                    mouse_depth = collection_depth;
            } else if (tag == 12u) {
                if (mouse_depth == collection_depth) mouse_depth = 0;
                if (collection_depth > 0u) collection_depth--;
            } else if (tag == 8u) {
                uint32_t bits = global.report_size * global.report_count;
                uint16_t bit_offset = input_bits[global.report_id];
                int variable = (value & 0x02u) != 0;
                int relative = (value & 0x04u) != 0;

                if (mouse_depth != 0u && variable && relative &&
                    global.report_size <= 32u &&
                    bits <= 0xffffu - bit_offset) {
                    for (uint32_t index = 0;
                         index < global.report_count; ++index) {
                        uint32_t usage =
                            xhci_hid_local_usage(&local, index);
                        (void)xhci_hid_field_set(
                            layout, global.usage_page, usage,
                            global.report_id,
                            (uint16_t)(bit_offset +
                                index * global.report_size),
                            (uint8_t)global.report_size,
                            global.logical_minimum < 0);
                    }
                } else if (mouse_depth != 0u && variable &&
                           global.usage_page == 0x09u &&
                           global.report_size <= 32u &&
                           bits <= 0xffffu - bit_offset) {
                    for (uint32_t index = 0;
                         index < global.report_count; ++index) {
                        uint32_t usage =
                            xhci_hid_local_usage(&local, index);
                        (void)xhci_hid_field_set(
                            layout, global.usage_page, usage,
                            global.report_id,
                            (uint16_t)(bit_offset +
                                index * global.report_size),
                            (uint8_t)global.report_size, 0);
                    }
                }
                if (bits > 0xffffu - bit_offset) return -1;
                input_bits[global.report_id] =
                    (uint16_t)(bit_offset + bits);
            }
            xhci_hid_local_reset(&local);
        }
        offset = (uint16_t)(offset + size);
    }
    if (layout->x_size == 0u || layout->y_size == 0u) return -1;
    layout->valid = 1;
    return 0;
}

static int xhci_hid_extract_bits(
    const uint8_t *report, uint16_t length,
    uint16_t bit_offset, uint8_t bit_size,
    int is_signed, int *value_out) {
    uint32_t value = 0;

    if (!report || !value_out || bit_size == 0u || bit_size > 32u ||
        (uint32_t)bit_offset + bit_size > (uint32_t)length * 8u)
        return -1;
    for (uint8_t bit = 0; bit < bit_size; ++bit) {
        uint16_t source = (uint16_t)(bit_offset + bit);
        if (report[source / 8u] & (uint8_t)(1u << (source % 8u)))
            value |= 1u << bit;
    }
    if (is_signed && bit_size < 32u &&
        (value & (1u << (bit_size - 1u))))
        value |= ~((1u << bit_size) - 1u);
    *value_out = (int32_t)value;
    return 0;
}

int xhci_hid_pointer_report_decode(
    const xhci_hid_pointer_layout_t *layout,
    const uint8_t *report, uint16_t length,
    int *dx_out, int *dy_out, int *wheel_out,
    uint8_t *buttons_out, int *wheel_present_out) {
    int buttons = 0;
    int wheel = 0;

    if (!layout || !layout->valid || !report || !dx_out || !dy_out ||
        !wheel_out || !buttons_out || !wheel_present_out)
        return -1;
    if (layout->report_id != 0u &&
        (length == 0u || report[0] != layout->report_id))
        return 0;
    if (xhci_hid_extract_bits(
            report, length, layout->x_offset, layout->x_size,
            layout->x_signed, dx_out) < 0 ||
        xhci_hid_extract_bits(
            report, length, layout->y_offset, layout->y_size,
            layout->y_signed, dy_out) < 0)
        return -1;
    if (layout->button_count != 0u &&
        xhci_hid_extract_bits(
            report, length, layout->buttons_offset,
            layout->button_count, 0, &buttons) < 0)
        return -1;
    if (layout->wheel_size != 0u) {
        if (xhci_hid_extract_bits(
                report, length, layout->wheel_offset,
                layout->wheel_size, layout->wheel_signed,
                &wheel) < 0)
            return -1;
        *wheel_present_out = 1;
    } else {
        *wheel_present_out = 0;
    }
    *wheel_out = wheel;
    *buttons_out = (uint8_t)(buttons & 0x07u);
    return 1;
}

uint64_t xhci_device_retry_delay_us(uint8_t failure_count) {
    uint64_t delay = XHCI_RETRY_BASE_US;
    uint8_t shifts;

    if (failure_count == 0) return delay;
    shifts = (uint8_t)(failure_count - 1u);
    if (shifts > 7u) shifts = 7u;
    delay <<= shifts;
    if (delay > XHCI_RETRY_MAX_US) delay = XHCI_RETRY_MAX_US;
    return delay;
}

int xhci_device_retry_permitted(uint8_t failure_count) {
    return failure_count < XHCI_DEVICE_MAX_FAILURES;
}
