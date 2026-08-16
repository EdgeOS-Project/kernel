/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux-compatible input device registry. */

#include <stdint.h>

#include "dev/devtmpfs.h"
#include "kernel/device_uevent.h"
#include "kernel/input_device.h"
#include "string.h"

#define LINUX_EV_SYN 0u
#define LINUX_EV_KEY 1u
#define LINUX_EV_REL 2u
#define LINUX_EV_ABS 3u
#define LINUX_EV_MSC 4u
#define LINUX_REL_X 0u
#define LINUX_REL_Y 1u
#define LINUX_REL_WHEEL 8u
#define LINUX_BTN_LEFT 0x110u
#define LINUX_BTN_RIGHT 0x111u
#define LINUX_BTN_MIDDLE 0x112u

typedef struct {
    uint8_t present;
    uint8_t role;
    const void *owner;
    char name[128];
    char physical_path[128];
    char driver[32];
    uint16_t id[4];
    uint8_t properties[EDGE_INPUT_BITMAP_BYTES];
    uint8_t event_bits[EDGE_INPUT_BITMAP_BYTES];
    uint8_t key_bits[EDGE_INPUT_BITMAP_BYTES];
    uint8_t relative_bits[EDGE_INPUT_BITMAP_BYTES];
    uint8_t absolute_bits[EDGE_INPUT_BITMAP_BYTES];
    input_absinfo_t absolute[EDGE_INPUT_ABS_AXES];
    uint32_t repeat_delay_ms;
    uint32_t repeat_period_ms;
} input_registry_entry_t;

static input_registry_entry_t g_input_devices[EDGE_INPUT_DEVICE_MAX];

static void input_set_bit(uint8_t *bitmap, uint32_t bit) {
    if (!bitmap || bit >= EDGE_INPUT_BITMAP_BYTES * 8u) return;
    bitmap[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
}

static void input_copy_text(char *destination, uint32_t capacity,
                            const char *source) {
    uint32_t index = 0;
    if (!destination || !capacity) return;
    if (source) {
        while (source[index] && index + 1u < capacity) {
            destination[index] = source[index];
            ++index;
        }
    }
    destination[index] = 0;
}

static uint32_t input_append_text(char *destination, uint32_t capacity,
                                  uint32_t length, const char *source) {
    if (!destination || !capacity || !source) return length;
    while (*source && length + 1u < capacity)
        destination[length++] = *source++;
    destination[length] = 0;
    return length;
}

static uint32_t input_append_u32(char *destination, uint32_t capacity,
                                 uint32_t length, uint32_t value) {
    char digits[10];
    uint32_t count = 0;

    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(digits));
    while (count && length + 1u < capacity)
        destination[length++] = digits[--count];
    if (capacity) destination[length < capacity ? length : capacity - 1u] = 0;
    return length;
}

static void input_description_base(input_device_description_t *description,
                                   const char *name,
                                   const char *physical_path,
                                   const char *driver,
                                   uint16_t bustype, uint16_t vendor,
                                   uint16_t product, uint16_t version) {
    if (!description) return;
    memset(description, 0, sizeof(*description));
    description->name = name;
    description->physical_path = physical_path;
    description->driver = driver;
    description->role = EDGE_INPUT_ROLE_UNKNOWN;
    description->bustype = bustype;
    description->vendor = vendor;
    description->product = product;
    description->version = version;
    description->repeat_delay_ms = 250u;
    description->repeat_period_ms = 33u;
    input_set_bit(description->event_bits, LINUX_EV_SYN);
}

void input_device_describe_keyboard(input_device_description_t *description,
                                    const char *name,
                                    const char *physical_path,
                                    const char *driver,
                                    uint16_t bustype, uint16_t vendor,
                                    uint16_t product, uint16_t version) {
    static const uint16_t extended_keys[] = {
        87u, 88u, 102u, 103u, 104u, 105u, 106u,
        107u, 108u, 109u, 110u, 111u
    };
    input_description_base(description, name, physical_path, driver,
                           bustype, vendor, product, version);
    if (!description) return;
    description->role = EDGE_INPUT_ROLE_KEYBOARD;
    input_set_bit(description->event_bits, LINUX_EV_KEY);
    input_set_bit(description->event_bits, LINUX_EV_MSC);
    for (uint32_t code = 1u; code <= 83u; ++code)
        input_set_bit(description->key_bits, code);
    for (uint32_t index = 0;
         index < sizeof(extended_keys) / sizeof(extended_keys[0]); ++index)
        input_set_bit(description->key_bits, extended_keys[index]);
}

void input_device_describe_pointer(input_device_description_t *description,
                                   const char *name,
                                   const char *physical_path,
                                   const char *driver,
                                   uint16_t bustype, uint16_t vendor,
                                   uint16_t product, uint16_t version,
                                   int absolute_pointer) {
    input_description_base(description, name, physical_path, driver,
                           bustype, vendor, product, version);
    if (!description) return;
    description->role = EDGE_INPUT_ROLE_POINTER;
    input_set_bit(description->event_bits, LINUX_EV_KEY);
    input_set_bit(description->key_bits, LINUX_BTN_LEFT);
    input_set_bit(description->key_bits, LINUX_BTN_RIGHT);
    input_set_bit(description->key_bits, LINUX_BTN_MIDDLE);
    if (absolute_pointer) {
        input_set_bit(description->event_bits, LINUX_EV_ABS);
        input_set_bit(description->absolute_bits, LINUX_REL_X);
        input_set_bit(description->absolute_bits, LINUX_REL_Y);
    } else {
        input_set_bit(description->event_bits, LINUX_EV_REL);
        input_set_bit(description->relative_bits, LINUX_REL_X);
        input_set_bit(description->relative_bits, LINUX_REL_Y);
        input_set_bit(description->relative_bits, LINUX_REL_WHEEL);
    }
}

static void input_event_path(uint32_t event_index, char path[64],
                             char name[32]) {
    uint32_t length = 0;

    path[0] = 0;
    name[0] = 0;
    length = input_append_text(path, 64u, length,
                               "/devices/virtual/input/input");
    length = input_append_u32(path, 64u, length, event_index);
    length = input_append_text(path, 64u, length, "/event");
    (void)input_append_u32(path, 64u, length, event_index);
    length = input_append_text(name, 32u, 0u, "input/event");
    (void)input_append_u32(name, 32u, length, event_index);
}

static void input_parent_path(uint32_t event_index, char path[48]) {
    uint32_t length;

    path[0] = 0;
    length = input_append_text(path, 48u, 0u,
                               "/devices/virtual/input/input");
    (void)input_append_u32(path, 48u, length, event_index);
}

static void input_emit_uevent(const char *action, uint32_t event_index,
                              const input_registry_entry_t *entry) {
    char path[64];
    char parent[48];
    char name[32];
    if (!entry || event_index >= EDGE_INPUT_DEVICE_MAX) return;
    input_parent_path(event_index, parent);
    input_event_path(event_index, path, name);
    (void)kernel_device_uevent_emit(action, parent, "input", 0u, 0u, 0,
                                    entry->driver[0] ? entry->driver : 0, 0);
    (void)kernel_device_uevent_emit(action, path, "input", 13u,
                                    64u + event_index, name,
                                    entry->driver[0] ? entry->driver : 0, 0);
}

int input_device_register(uint32_t event_index,
                          const input_device_description_t *description,
                          const void *owner) {
    input_registry_entry_t *entry;
    if (event_index >= EDGE_INPUT_DEVICE_MAX || !description || !owner ||
        !description->name || !description->name[0])
        return -22;
    entry = &g_input_devices[event_index];
    if (entry->present && entry->owner != owner) return -16;

    memset(entry, 0, sizeof(*entry));
    entry->present = 1;
    entry->role = description->role;
    entry->owner = owner;
    input_copy_text(entry->name, sizeof(entry->name), description->name);
    input_copy_text(entry->physical_path, sizeof(entry->physical_path),
                    description->physical_path);
    input_copy_text(entry->driver, sizeof(entry->driver),
                    description->driver);
    entry->id[0] = description->bustype;
    entry->id[1] = description->vendor;
    entry->id[2] = description->product;
    entry->id[3] = description->version;
    memcpy(entry->properties, description->properties,
           sizeof(entry->properties));
    memcpy(entry->event_bits, description->event_bits,
           sizeof(entry->event_bits));
    memcpy(entry->key_bits, description->key_bits,
           sizeof(entry->key_bits));
    memcpy(entry->relative_bits, description->relative_bits,
           sizeof(entry->relative_bits));
    memcpy(entry->absolute_bits, description->absolute_bits,
           sizeof(entry->absolute_bits));
    memcpy(entry->absolute, description->absolute,
           sizeof(entry->absolute));
    entry->repeat_delay_ms = description->repeat_delay_ms;
    entry->repeat_period_ms = description->repeat_period_ms;
    if (!entry->repeat_delay_ms) entry->repeat_delay_ms = 250u;
    if (!entry->repeat_period_ms) entry->repeat_period_ms = 33u;

    (void)devtmpfs_refresh_input_nodes();
    input_emit_uevent("add", event_index, entry);
    return 0;
}

int input_device_register_available(
        uint32_t preferred_event_index,
        const input_device_description_t *description,
        const void *owner,
        uint32_t *event_index_out) {
    int result;

    if (!description || !owner || !event_index_out) return -22;
    if (preferred_event_index < EDGE_INPUT_DEVICE_MAX) {
        result = input_device_register(preferred_event_index, description,
                                       owner);
        if (result == 0) {
            *event_index_out = preferred_event_index;
            return 0;
        }
        if (result != -16) return result;
    }
    for (uint32_t event_index = 0;
         event_index < EDGE_INPUT_DEVICE_MAX; ++event_index) {
        if (event_index == preferred_event_index ||
            input_device_present(event_index))
            continue;
        result = input_device_register(event_index, description, owner);
        if (result == 0) {
            *event_index_out = event_index;
            return 0;
        }
        if (result != -16) return result;
    }
    return -28;
}

int input_device_unregister(uint32_t event_index, const void *owner) {
    input_registry_entry_t *entry;
    if (event_index >= EDGE_INPUT_DEVICE_MAX || !owner) return -22;
    entry = &g_input_devices[event_index];
    if (!entry->present || entry->owner != owner) return -19;
    input_emit_uevent("remove", event_index, entry);
    memset(entry, 0, sizeof(*entry));
    (void)devtmpfs_refresh_input_nodes();
    return 0;
}

int input_device_present(uint32_t device) {
    return device < EDGE_INPUT_DEVICE_MAX && g_input_devices[device].present;
}

uint32_t input_device_role(uint32_t device) {
    return input_device_present(device) ? g_input_devices[device].role :
           EDGE_INPUT_ROLE_UNKNOWN;
}

uint32_t input_device_count(void) {
    for (uint32_t count = EDGE_INPUT_DEVICE_MAX; count > 0u; --count)
        if (g_input_devices[count - 1u].present) return count;
    return 0;
}

const char *input_name(uint32_t device) {
    return input_device_present(device) ? g_input_devices[device].name : 0;
}

const char *input_physical_path(uint32_t device) {
    return input_device_present(device) ?
           g_input_devices[device].physical_path : 0;
}

const char *input_driver(uint32_t device) {
    return input_device_present(device) ? g_input_devices[device].driver : 0;
}

void input_id(uint32_t device, uint16_t out[4]) {
    if (!out) return;
    memset(out, 0, sizeof(uint16_t) * 4u);
    if (input_device_present(device))
        memcpy(out, g_input_devices[device].id, sizeof(uint16_t) * 4u);
}

uint32_t input_bits(uint32_t device, uint32_t type, uint8_t *out,
                    uint32_t length) {
    const uint8_t *source = 0;
    if (!input_device_present(device) || !out || !length) return 0;
    if (type == LINUX_EV_SYN) source = g_input_devices[device].event_bits;
    else if (type == LINUX_EV_KEY) source = g_input_devices[device].key_bits;
    else if (type == LINUX_EV_REL)
        source = g_input_devices[device].relative_bits;
    else if (type == LINUX_EV_ABS)
        source = g_input_devices[device].absolute_bits;
    if (!source) return 0;
    if (length > EDGE_INPUT_BITMAP_BYTES) length = EDGE_INPUT_BITMAP_BYTES;
    memcpy(out, source, length);
    return length;
}

uint32_t input_properties(uint32_t device, uint8_t *out,
                          uint32_t length) {
    if (!input_device_present(device) || !out || !length) return 0;
    if (length > EDGE_INPUT_BITMAP_BYTES) length = EDGE_INPUT_BITMAP_BYTES;
    memcpy(out, g_input_devices[device].properties, length);
    return length;
}

int input_absinfo(uint32_t device, uint32_t axis,
                  input_absinfo_t *out) {
    if (!input_device_present(device) || !out ||
        axis >= EDGE_INPUT_ABS_AXES ||
        !(g_input_devices[device].absolute_bits[axis >> 3] &
          (1u << (axis & 7u))))
        return -1;
    *out = g_input_devices[device].absolute[axis];
    return 0;
}

int input_repeat_get(uint32_t device, uint32_t values[2]) {
    if (!input_device_present(device) || !values) return -1;
    values[0] = g_input_devices[device].repeat_delay_ms;
    values[1] = g_input_devices[device].repeat_period_ms;
    return 0;
}

int input_repeat_set(uint32_t device, const uint32_t values[2]) {
    if (!input_device_present(device) || !values ||
        values[0] > 0x7fffffffu || values[1] > 0x7fffffffu)
        return -1;
    g_input_devices[device].repeat_delay_ms = values[0];
    g_input_devices[device].repeat_period_ms = values[1];
    return 0;
}
