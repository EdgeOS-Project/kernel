/* SPDX-License-Identifier: MPL-2.0 */
/* Host behavior tests for the BSD evdev to EdgeOS input adapter. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <dev/evdev/evdev.h>
#include <dev/evdev/input.h>

#include <edgeos/malloc.h>
#include <edgeos/sync.h>

#include "kernel/input_device.h"

#define TEST_ALLOCATION_BYTES 16384u
#define TEST_EVENT_CAPACITY 128u
#define TEST_CONSOLE_CAPACITY 32u

typedef struct {
    int event_index;
    uint16_t type;
    uint16_t code;
    int32_t value;
} test_event_t;

static uint8_t g_allocation[TEST_ALLOCATION_BYTES];
static int g_allocation_used;
static input_device_description_t g_descriptions[EDGE_INPUT_DEVICE_MAX];
static const void *g_input_owners[EDGE_INPUT_DEVICE_MAX];
static test_event_t g_events[TEST_EVENT_CAPACITY];
static uint32_t g_event_count;
static uint8_t g_console[TEST_CONSOLE_CAPACITY];
static uint32_t g_console_count;
static int g_mouse_calls;
static int g_mouse_dx;
static int g_mouse_dy;
static int g_mouse_wheel;
static uint8_t g_mouse_buttons;
static int g_open_calls;
static int g_close_calls;

struct malloc_type M_DEVBUF[1];

static int
test_fail(const char *expression, int line)
{
    printf("bsd_bridge_evdev_unit: FAIL line %d: %s\n", line, expression);
    return (1);
}

#define CHECK(expression) do { \
    if (!(expression)) \
        return (test_fail(#expression, __LINE__)); \
} while (0)

void *
bsd_memset(void *destination, int value, size_t length)
{
    uint8_t *bytes = destination;

    for (size_t index = 0; index < length; ++index)
        bytes[index] = (uint8_t)value;
    return (destination);
}

void *
bsd_memcpy(void *destination, const void *source, size_t length)
{
    uint8_t *output = destination;
    const uint8_t *input = source;

    for (size_t index = 0; index < length; ++index)
        output[index] = input[index];
    return (destination);
}

size_t
bsd_strlcpy(char *destination, const char *source, size_t capacity)
{
    size_t length = 0;

    while (source[length] != '\0')
        ++length;
    if (capacity != 0) {
        size_t copied = length < capacity - 1u ? length : capacity - 1u;
        (void)bsd_memcpy(destination, source, copied);
        destination[copied] = '\0';
    }
    return (length);
}

void *
bsd_malloc(size_t size, struct malloc_type *type, int flags)
{
    (void)type;
    (void)flags;
    if (g_allocation_used || size > sizeof(g_allocation))
        return (NULL);
    g_allocation_used = 1;
    (void)bsd_memset(g_allocation, 0, sizeof(g_allocation));
    return (g_allocation);
}

void
bsd_free(void *allocation, struct malloc_type *type)
{
    (void)type;
    if (allocation == g_allocation)
        g_allocation_used = 0;
}

int
bsd_mutex_init(bsd_mutex_t *mutex, const char *name, uint32_t flags)
{
    (void)bsd_memset(mutex, 0, sizeof(*mutex));
    mutex->name = name;
    mutex->flags = flags;
    mutex->initialized = 1;
    return (0);
}

int
bsd_mutex_destroy(bsd_mutex_t *mutex)
{
    if (mutex == NULL || !mutex->initialized || mutex->owner != 0)
        return (-1);
    mutex->initialized = 0;
    return (0);
}

void
bsd_mutex_lock(bsd_mutex_t *mutex)
{
    if (mutex->owner != 0 && (mutex->flags & BSD_MUTEX_RECURSE) != 0) {
        ++mutex->recursion;
        return;
    }
    mutex->owner = 1;
}

int
bsd_mutex_trylock(bsd_mutex_t *mutex)
{
    if (mutex->owner != 0)
        return (0);
    bsd_mutex_lock(mutex);
    return (1);
}

void
bsd_mutex_unlock(bsd_mutex_t *mutex)
{
    if (mutex->recursion != 0) {
        --mutex->recursion;
        return;
    }
    mutex->owner = 0;
}

int
bsd_mutex_owned(const bsd_mutex_t *mutex)
{
    return (mutex != NULL && mutex->owner != 0);
}

int
bsd_mutex_recursed(const bsd_mutex_t *mutex)
{
    return (mutex != NULL && mutex->recursion != 0);
}

int
bsd_mutex_assert(const bsd_mutex_t *mutex, int assertion)
{
    (void)assertion;
    return (mutex != NULL ? 0 : -1);
}

int
input_device_register(uint32_t event_index,
    const input_device_description_t *description, const void *owner)
{
    if (event_index >= EDGE_INPUT_DEVICE_MAX || description == NULL ||
        owner == NULL)
        return (-22);
    if (g_input_owners[event_index] != NULL &&
        g_input_owners[event_index] != owner)
        return (-16);
    g_descriptions[event_index] = *description;
    g_input_owners[event_index] = owner;
    return (0);
}

int
input_device_register_available(uint32_t preferred_event_index,
    const input_device_description_t *description, const void *owner,
    uint32_t *event_index_out)
{
    int error;

    if (description == NULL || owner == NULL || event_index_out == NULL)
        return (-22);
    if (preferred_event_index < EDGE_INPUT_DEVICE_MAX) {
        error = input_device_register(
            preferred_event_index, description, owner);
        if (error == 0) {
            *event_index_out = preferred_event_index;
            return (0);
        }
        if (error != -16)
            return (error);
    }
    for (uint32_t event_index = 0;
         event_index < EDGE_INPUT_DEVICE_MAX; ++event_index) {
        if (event_index == preferred_event_index ||
            g_input_owners[event_index] != NULL)
            continue;
        error = input_device_register(event_index, description, owner);
        if (error == 0) {
            *event_index_out = event_index;
            return (0);
        }
        if (error != -16)
            return (error);
    }
    return (-28);
}

int
input_device_unregister(uint32_t event_index, const void *owner)
{
    if (event_index >= EDGE_INPUT_DEVICE_MAX ||
        g_input_owners[event_index] != owner)
        return (-19);
    g_input_owners[event_index] = NULL;
    (void)bsd_memset(&g_descriptions[event_index], 0,
        sizeof(g_descriptions[event_index]));
    return (0);
}

void
keyboard_emit_linux_input_event(int event_id, uint16_t type, uint16_t code,
    int32_t value)
{
    if (g_event_count >= TEST_EVENT_CAPACITY)
        return;
    g_events[g_event_count].event_index = event_id;
    g_events[g_event_count].type = type;
    g_events[g_event_count].code = code;
    g_events[g_event_count].value = value;
    ++g_event_count;
}

void
keyboard_emit_scancode_console_only(uint8_t scancode)
{
    if (g_console_count < TEST_CONSOLE_CAPACITY)
        g_console[g_console_count++] = scancode;
}

void
keyboard_mouse_emit_compat_packet_ex(int dx, int dy, int wheel,
    uint8_t buttons, int wheel_present)
{
    (void)wheel_present;
    ++g_mouse_calls;
    g_mouse_dx = dx;
    g_mouse_dy = dy;
    g_mouse_wheel = wheel;
    g_mouse_buttons = buttons;
}

static int
test_open(struct evdev_dev *evdev)
{
    (void)evdev;
    ++g_open_calls;
    return (0);
}

static int
test_close(struct evdev_dev *evdev)
{
    (void)evdev;
    ++g_close_calls;
    return (0);
}

static int
test_keyboard(void)
{
    static const struct evdev_methods methods = {
        .ev_open = test_open,
        .ev_close = test_close,
    };
    struct evdev_dev *evdev = evdev_alloc();

    CHECK(evdev != NULL);
    evdev_set_name(evdev, "FreeBSD USB keyboard");
    evdev_set_phys(evdev, "usb-test/input0");
    evdev_set_id(evdev, BUS_USB, 0x1234, 0x5678, 0x0100);
    evdev_set_methods(evdev, NULL, &methods);
    evdev_support_event(evdev, EV_SYN);
    evdev_support_event(evdev, EV_REP);
    evdev_support_key(evdev, KEY_A);
    evdev_support_led(evdev, LED_CAPSL);
    CHECK(evdev_register(evdev) == 0);
    CHECK(g_open_calls == 1);
    CHECK(g_input_owners[EDGE_INPUT_KEYBOARD] == evdev);
    CHECK(g_descriptions[EDGE_INPUT_KEYBOARD].role ==
        EDGE_INPUT_ROLE_KEYBOARD);
    CHECK(g_descriptions[EDGE_INPUT_KEYBOARD].vendor == 0x1234);
    CHECK((g_descriptions[EDGE_INPUT_KEYBOARD]
        .key_bits[KEY_A >> 3] & (1u << (KEY_A & 7u))) != 0);
    CHECK(evdev_push_key(evdev, KEY_A, 1) == 0);
    CHECK(evdev_sync(evdev) == 0);
    CHECK(evdev_push_key(evdev, KEY_A, 0) == 0);
    CHECK(g_event_count == 3);
    CHECK(g_events[0].event_index == (int)EDGE_INPUT_KEYBOARD);
    CHECK(g_events[0].type == EV_KEY && g_events[0].code == KEY_A &&
        g_events[0].value == 1);
    CHECK(g_console_count == 2);
    CHECK(g_console[0] == 0x1e && g_console[1] == 0x9e);
    CHECK(evdev_hid2key(4) == KEY_A);
    evdev_free(evdev);
    CHECK(g_close_calls == 1);
    CHECK(g_input_owners[EDGE_INPUT_KEYBOARD] == NULL);
    return (0);
}

static int
test_pointer(void)
{
    struct evdev_dev *evdev = evdev_alloc();
    uint32_t first_event = g_event_count;

    CHECK(evdev != NULL);
    evdev_set_name(evdev, "FreeBSD USB mouse");
    evdev_set_phys(evdev, "usb-test/input1");
    evdev_set_id(evdev, BUS_USB, 0x1111, 0x2222, 0x0100);
    evdev_support_event(evdev, EV_SYN);
    evdev_support_key(evdev, BTN_LEFT);
    evdev_support_rel(evdev, REL_X);
    evdev_support_rel(evdev, REL_Y);
    evdev_support_rel(evdev, REL_WHEEL);
    CHECK(evdev_register(evdev) == 0);
    CHECK(g_input_owners[EDGE_INPUT_POINTER] == evdev);
    CHECK(g_descriptions[EDGE_INPUT_POINTER].role ==
        EDGE_INPUT_ROLE_POINTER);
    CHECK(evdev_push_rel(evdev, REL_X, 7) == 0);
    CHECK(evdev_push_rel(evdev, REL_Y, -3) == 0);
    CHECK(evdev_push_rel(evdev, REL_WHEEL, 1) == 0);
    CHECK(evdev_push_key(evdev, BTN_LEFT, 1) == 0);
    CHECK(evdev_sync(evdev) == 0);
    CHECK(g_mouse_calls == 1);
    CHECK(g_mouse_dx == 7 && g_mouse_dy == 3 && g_mouse_wheel == 1);
    CHECK(g_mouse_buttons == 1);
    CHECK(g_event_count == first_event + 5u);
    CHECK(g_events[first_event].event_index == (int)EDGE_INPUT_POINTER);
    CHECK(evdev_sync(evdev) == 0);
    CHECK(g_mouse_calls == 1);
    evdev_free(evdev);
    CHECK(g_input_owners[EDGE_INPUT_POINTER] == NULL);
    return (0);
}

static int
test_shared_keyboard_slot(void)
{
    static int native_keyboard;
    static int native_pointer;
    struct evdev_dev *evdev;
    uint32_t first_event = g_event_count;

    g_input_owners[EDGE_INPUT_KEYBOARD] = &native_keyboard;
    g_input_owners[EDGE_INPUT_POINTER] = &native_pointer;
    evdev = evdev_alloc();
    CHECK(evdev != NULL);
    evdev_set_name(evdev, "FreeBSD ACPI power button");
    evdev_set_phys(evdev, "acpi/button0");
    evdev_support_event(evdev, EV_SYN);
    evdev_support_key(evdev, KEY_POWER);
    CHECK(evdev_register(evdev) == 0);
    CHECK(g_input_owners[2] == evdev);
    CHECK(g_descriptions[2].role == EDGE_INPUT_ROLE_KEYBOARD);
    CHECK(evdev_push_key(evdev, KEY_POWER, 1) == 0);
    CHECK(evdev_sync(evdev) == 0);
    CHECK(g_event_count == first_event + 2u);
    CHECK(g_events[first_event].event_index == 2);
    evdev_free(evdev);
    CHECK(g_input_owners[2] == NULL);
    g_input_owners[EDGE_INPUT_KEYBOARD] = NULL;
    g_input_owners[EDGE_INPUT_POINTER] = NULL;
    return (0);
}

int
main(void)
{
    if (test_keyboard() != 0)
        return (1);
    if (test_pointer() != 0)
        return (1);
    if (test_shared_keyboard_slot() != 0)
        return (1);
    printf("bsd_bridge_evdev_unit: PASS\n");
    return (0);
}
