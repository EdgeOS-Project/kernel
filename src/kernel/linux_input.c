/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux evdev ioctl policy. */

#include <stdint.h>

#include "kernel/input_device.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_input.h"
#include "kernel/linux_time.h"
#include "string.h"

#define LINUX_EV_KEY 1u
#define LINUX_EV_SW 5u
#define LINUX_EV_LED 17u
#define LINUX_EV_SND 18u
#define LINUX_INPUT_KEYMAP_BY_INDEX 1u

typedef struct {
    uint8_t flags;
    uint8_t len;
    uint16_t index;
    uint32_t keycode;
    uint8_t scancode[32];
} edge_linux_input_keymap_entry_t;

static uint32_t ioctl_size(uint32_t command) {
    return (command >> 16) & 0x3fffu;
}

static uint32_t bounded_text_copy(void *output, uint32_t capacity,
                                  const char *text) {
    uint32_t length = 0;
    uint8_t *bytes = output;
    if (!output || !capacity || !text) return 0;
    while (text[length] && length + 1u < capacity) {
        bytes[length] = (uint8_t)text[length];
        ++length;
    }
    bytes[length++] = 0;
    return length;
}

static uint32_t keymap_scancode(const edge_linux_input_keymap_entry_t *entry,
                                int *valid) {
    uint32_t scancode = 0;
    uint32_t length;
    if (!entry || !valid) return 0;
    if (entry->flags & LINUX_INPUT_KEYMAP_BY_INDEX) {
        *valid = entry->index < EDGE_INPUT_KEYCODE_SLOTS;
        return entry->index;
    }
    length = entry->len;
    if (!length || length > 4u) {
        *valid = 0;
        return 0;
    }
    for (uint32_t index = 0; index < length; ++index)
        scancode |= (uint32_t)entry->scancode[index] << (index * 8u);
    *valid = scancode < EDGE_INPUT_KEYCODE_SLOTS;
    return scancode;
}

uint32_t edge_linux_input_ioctl_input_size(uint32_t command) {
    if (command == 0x80084504u || command == 0x40084504u)
        return 8u;
    if (command == 0x80284504u || command == 0x40284504u)
        return sizeof(edge_linux_input_keymap_entry_t);
    if (command == 0x40084503u) return 8u;
    if (command == 0x40044590u || command == 0x40044591u ||
        command == 0x400445a0u)
        return 4u;
    if ((command & 0xffffu) == 0x450au) return 4u;
    if (((command >> 8) & 0xffu) == 'E' &&
        (command & 0xffu) >= 0xc0u)
        return sizeof(input_absinfo_t);
    return 0;
}

static int input_ioctl_keycode(
    uint32_t device, uint32_t command, const void *input,
    uint32_t input_length, void *output, uint32_t output_capacity,
    edge_linux_input_ioctl_result_t *result) {
    uint32_t scancode;
    uint32_t keycode;
    int valid;
    if (command == 0x80084504u || command == 0x40084504u) {
        uint32_t map[2];
        if (!input || input_length < sizeof(map)) return -EDGE_LINUX_EFAULT;
        memcpy(map, input, sizeof(map));
        scancode = map[0];
        if (command == 0x40084504u)
            return input_keycode_set(device, scancode, map[1]) < 0 ?
                   -EDGE_LINUX_EINVAL : 0;
        if (input_keycode_get(device, scancode, &map[1]) < 0)
            return -EDGE_LINUX_EINVAL;
        if (!output || output_capacity < sizeof(map))
            return -EDGE_LINUX_EFAULT;
        memcpy(output, map, sizeof(map));
        result->output_length = sizeof(map);
        return 0;
    }
    if (command == 0x80284504u || command == 0x40284504u) {
        edge_linux_input_keymap_entry_t entry;
        if (!input || input_length < sizeof(entry)) return -EDGE_LINUX_EFAULT;
        memcpy(&entry, input, sizeof(entry));
        scancode = keymap_scancode(&entry, &valid);
        if (!valid) return -EDGE_LINUX_EINVAL;
        if (command == 0x40284504u)
            return input_keycode_set(device, scancode, entry.keycode) < 0 ?
                   -EDGE_LINUX_EINVAL : 0;
        if (input_keycode_get(device, scancode, &keycode) < 0)
            return -EDGE_LINUX_EINVAL;
        entry.keycode = keycode;
        if (!(entry.flags & LINUX_INPUT_KEYMAP_BY_INDEX)) {
            entry.len = 1u;
            entry.scancode[0] = (uint8_t)scancode;
        }
        if (!output || output_capacity < sizeof(entry))
            return -EDGE_LINUX_EFAULT;
        memcpy(output, &entry, sizeof(entry));
        result->output_length = sizeof(entry);
        return 0;
    }
    return -EDGE_LINUX_ENOTTY;
}

int edge_linux_input_ioctl_execute(
    uint32_t device, uint32_t role, uint32_t command,
    const void *input, uint32_t input_length,
    void *output, uint32_t output_capacity,
    edge_linux_input_ioctl_result_t *result) {
    uint32_t size = ioctl_size(command);
    uint32_t number = command & 0xffu;
    int present = input_device_present(device);
    (void)role;
    if (!result) return -EDGE_LINUX_EINVAL;
    memset(result, 0, sizeof(*result));

    if (command == 0x80044501u) {
        uint32_t version = 0x00010001u;
        if (!output || output_capacity < sizeof(version))
            return -EDGE_LINUX_EFAULT;
        memcpy(output, &version, sizeof(version));
        result->output_length = sizeof(version);
        return 0;
    }
    if (command == 0x80084502u) {
        uint16_t id[4] = { 3u, 0x1af4u, 1u, 1u };
        if (present) input_id(device, id);
        if (!output || output_capacity < sizeof(id))
            return -EDGE_LINUX_EFAULT;
        memcpy(output, id, sizeof(id));
        result->output_length = sizeof(id);
        return 0;
    }
    if (command == 0x80084503u || command == 0x40084503u) {
        uint32_t repeat[2] = { 250u, 33u };
        if (command == 0x40084503u) {
            if (!input || input_length < sizeof(repeat))
                return -EDGE_LINUX_EFAULT;
            memcpy(repeat, input, sizeof(repeat));
            return input_repeat_set(device, repeat) < 0 ?
                   -EDGE_LINUX_EINVAL : 0;
        }
        if (present) (void)input_repeat_get(device, repeat);
        if (!output || output_capacity < sizeof(repeat))
            return -EDGE_LINUX_EFAULT;
        memcpy(output, repeat, sizeof(repeat));
        result->output_length = sizeof(repeat);
        return 0;
    }
    if (number == 0x04u)
        return input_ioctl_keycode(device, command, input, input_length,
                                   output, output_capacity, result);
    if (((command >> 8) & 0xffu) == 'E' &&
        (number == 0x06u || number == 0x07u || number == 0x08u)) {
        const char *text = 0;
        uint32_t length;
        if (number == 0x06u) text = present ? input_name(device) : 0;
        else if (number == 0x07u)
            text = present ? input_physical_path(device) : 0;
        if (!text || !text[0]) return -EDGE_LINUX_ENOENT;
        if (size < output_capacity) output_capacity = size;
        length = bounded_text_copy(output, output_capacity, text);
        if (!length) return -EDGE_LINUX_EFAULT;
        result->output_length = length;
        result->return_value = length;
        return 0;
    }
    if ((command & 0xffffu) == 0x450au) {
        uint32_t axis;
        uint32_t count;
        int32_t values[EDGE_INPUT_MT_SLOTS];
        if (!input || input_length < sizeof(axis) || !output || size < 4u)
            return -EDGE_LINUX_EFAULT;
        memcpy(&axis, input, sizeof(axis));
        if (input_mt_slots(device, axis, values, (size - 4u) / 4u,
                           &count) < 0)
            return -EDGE_LINUX_EINVAL;
        if (output_capacity < 4u + count * 4u)
            return -EDGE_LINUX_EFAULT;
        memcpy(output, &axis, 4u);
        memcpy((uint8_t *)output + 4u, values, count * 4u);
        result->output_length = 4u + count * 4u;
        return 0;
    }
    if (((command >> 8) & 0xffu) == 'E' &&
        (number == 0x09u || (number >= 0x18u && number <= 0x1bu))) {
        uint32_t length = size < output_capacity ? size : output_capacity;
        if (!output || !length) return -EDGE_LINUX_EFAULT;
        memset(output, 0, length);
        if (number == 0x09u)
            length = input_properties(device, output, length);
        else {
            uint32_t type = number == 0x18u ? LINUX_EV_KEY :
                            number == 0x19u ? LINUX_EV_LED :
                            number == 0x1au ? LINUX_EV_SND : LINUX_EV_SW;
            length = input_state_bits(device, type, output, length);
        }
        result->output_length = length;
        result->return_value = length;
        return 0;
    }
    if (((command >> 8) & 0xffu) == 'E' &&
        number >= 0x20u && number < 0x40u) {
        uint32_t length = size < output_capacity ? size : output_capacity;
        if (!output || !length) return -EDGE_LINUX_EFAULT;
        memset(output, 0, length);
        length = input_bits(device, number - 0x20u, output, length);
        result->output_length = length;
        result->return_value = length;
        return 0;
    }
    if (((command >> 8) & 0xffu) == 'E' &&
        number >= 0x40u && number < 0x80u) {
        input_absinfo_t info;
        if (input_absinfo(device, number - 0x40u, &info) < 0)
            return -EDGE_LINUX_EINVAL;
        if (!output || output_capacity < sizeof(info))
            return -EDGE_LINUX_EFAULT;
        memcpy(output, &info, sizeof(info));
        result->output_length = sizeof(info);
        return 0;
    }
    if (((command >> 8) & 0xffu) == 'E' && number >= 0xc0u) {
        input_absinfo_t info;
        if (!input || input_length < sizeof(info)) return -EDGE_LINUX_EFAULT;
        memcpy(&info, input, sizeof(info));
        return input_absinfo_set(device, number - 0xc0u, &info) < 0 ?
               -EDGE_LINUX_EINVAL : 0;
    }
    if (command == 0x400445a0u) {
        int32_t clock_id;
        if (!input || input_length < sizeof(clock_id))
            return -EDGE_LINUX_EFAULT;
        memcpy(&clock_id, input, sizeof(clock_id));
        if (!linux_evdev_clock_supported(clock_id))
            return -EDGE_LINUX_EINVAL;
        result->action = EDGE_LINUX_INPUT_ACTION_SET_CLOCK;
        result->action_value = clock_id;
        return 0;
    }
    if (command == 0x40044590u || command == 0x40044591u) {
        int32_t value;
        if (!input || input_length < sizeof(value))
            return -EDGE_LINUX_EFAULT;
        memcpy(&value, input, sizeof(value));
        result->action = command == 0x40044590u ?
                         EDGE_LINUX_INPUT_ACTION_GRAB :
                         EDGE_LINUX_INPUT_ACTION_REVOKE;
        result->action_value = value;
        return 0;
    }
    return -EDGE_LINUX_ENOTTY;
}
