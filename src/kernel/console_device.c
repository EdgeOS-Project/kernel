/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux-compatible console device inventory. */

#include "kernel/console_device.h"
#include "kernel/boot_command_line.h"
#include "console.h"
#include "fb_console.h"
#include "string.h"

uint32_t kernel_console_device_count(void) {
    kernel_console_device_t serial;
    uint32_t count = EDGE_FB_VT_COUNT + 3u;

    return kernel_arch_serial_console_device(&serial) == 0 ? count + 1u : count;
}

int kernel_console_device_at(uint32_t ordinal,
                             kernel_console_device_t *device) {
    uint32_t number;
    uint32_t length;
    char reversed[10];
    uint32_t digits = 0;

    if (!device) return -1;
    memset(device, 0, sizeof(*device));
    if (ordinal == 0u) {
        strcpy(device->name, "console");
        device->major = 5u;
        device->minor = 1u;
        return 0;
    }
    if (ordinal == 1u) {
        strcpy(device->name, "tty");
        device->major = 5u;
        device->minor = 0u;
        return 0;
    }
    if (ordinal <= EDGE_FB_VT_COUNT + 2u) {
        number = ordinal - 2u;
        strcpy(device->name, "tty");
        length = 3u;
        do {
            reversed[digits++] = (char)('0' + number % 10u);
            number /= 10u;
        } while (number && digits < sizeof(reversed));
        while (digits) device->name[length++] = reversed[--digits];
        device->name[length] = 0;
        device->major = 4u;
        device->minor = ordinal - 2u;
        return 0;
    }
    if (ordinal == EDGE_FB_VT_COUNT + 3u)
        return kernel_arch_serial_console_device(device);
    return -1;
}

int kernel_console_active_names(char *buffer, uint32_t capacity) {
    char reversed[10];
    uint32_t active;
    uint32_t length = 0;
    uint32_t digits = 0;

    if (!buffer) return -1;
    active = (uint32_t)console_get_active_vt();
    if (active < 1u || active > EDGE_FB_VT_COUNT) active = 1u;
    if (capacity < 5u) return -1;
    buffer[length++] = 't';
    buffer[length++] = 't';
    buffer[length++] = 'y';
    do {
        reversed[digits++] = (char)('0' + active % 10u);
        active /= 10u;
    } while (active && digits < sizeof(reversed));
    if (capacity < length + digits + 1u) return -1;
    while (digits) buffer[length++] = reversed[--digits];
    buffer[length++] = '\n';
    return (int)length;
}

static int console_name_is_virtual_terminal(const char *name) {
    uint32_t index = 3u;

    if (!name || name[0] != 't' || name[1] != 't' || name[2] != 'y')
        return 0;
    if (name[index] < '0' || name[index] > '9') return 0;
    while (name[index]) {
        if (name[index] < '0' || name[index] > '9') return 0;
        ++index;
    }
    return 1;
}

static int console_name_copy(char destination[16], const char *start,
                             uint32_t length) {
    if (!destination || !start || !length || length >= 16u) return -1;
    for (uint32_t index = 0; index < length; ++index)
        destination[index] = start[index];
    destination[length] = 0;
    return 0;
}

int kernel_console_configured_names(char *buffer, uint32_t capacity) {
    kernel_console_device_t serial;
    char configured[2][16];
    int configured_kind[2];
    char active[16];
    const char *cursor = kernel_boot_command_line_get();
    uint32_t configured_count = 0;
    uint32_t active_length;
    uint32_t output = 0;
    int active_result;

    if (!buffer || !capacity) return -1;
    active_result = kernel_console_active_names(active, sizeof(active));
    if (active_result < 0) return -1;
    active_length = (uint32_t)active_result;
    if (!active_length) return -1;
    active[active_length - 1u] = 0;

    while (cursor && *cursor) {
        const char *name;
        uint32_t length = 0;
        int kind = -1;

        while (*cursor == ' ' || *cursor == '\t' ||
               *cursor == '\n' || *cursor == '\r')
            ++cursor;
        if (!*cursor) break;
        if (strncmp(cursor, "console=", 8u) != 0) {
            while (*cursor && *cursor != ' ' && *cursor != '\t' &&
                   *cursor != '\n' && *cursor != '\r')
                ++cursor;
            continue;
        }
        name = cursor + 8u;
        while (name[length] && name[length] != ',' && name[length] != ' ' &&
               name[length] != '\t' && name[length] != '\n' &&
               name[length] != '\r')
            ++length;
        if (length && length < sizeof(configured[0])) {
            char candidate[16];
            if (console_name_copy(candidate, name, length) == 0) {
                if (console_name_is_virtual_terminal(candidate)) {
                    strcpy(candidate, active);
                    kind = 0;
                } else if (kernel_arch_serial_console_device(&serial) == 0 &&
                           strcmp(candidate, serial.name) == 0) {
                    kind = 1;
                }
                if (kind >= 0) {
                    uint32_t existing = configured_count;
                    for (uint32_t index = 0; index < configured_count;
                         ++index)
                        if (configured_kind[index] == kind) {
                            existing = index;
                            break;
                        }
                    if (existing < configured_count) {
                        for (uint32_t index = existing;
                             index + 1u < configured_count; ++index) {
                            strcpy(configured[index], configured[index + 1u]);
                            configured_kind[index] = configured_kind[index + 1u];
                        }
                        --configured_count;
                    }
                    if (configured_count < 2u) {
                        strcpy(configured[configured_count], candidate);
                        configured_kind[configured_count] = kind;
                        ++configured_count;
                    }
                }
            }
        }
        cursor = name + length;
        while (*cursor && *cursor != ' ' && *cursor != '\t' &&
               *cursor != '\n' && *cursor != '\r')
            ++cursor;
    }

    if (!configured_count) {
        configured_count = 1u;
        strcpy(configured[0], active);
    }
    for (uint32_t index = 0; index < configured_count; ++index) {
        uint32_t length = (uint32_t)strlen(configured[index]);
        if (output) {
            if (output + 1u >= capacity) return -1;
            buffer[output++] = ' ';
        }
        if (output + length + 1u >= capacity) return -1;
        memcpy(buffer + output, configured[index], length);
        output += length;
    }
    buffer[output++] = '\n';
    return (int)output;
}
