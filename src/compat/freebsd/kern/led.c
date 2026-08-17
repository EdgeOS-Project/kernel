/* SPDX-License-Identifier: MPL-2.0 */
/* Lightweight LED lifecycle and state control for imported BSD drivers. */

#include <dev/led/led.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/systm.h"

#define BSD_LED_ENOENT 2
#define BSD_LED_EINVAL 22
#define BSD_LED_NAME_MAX 32

typedef struct bsd_led_device bsd_led_device_t;

struct bsd_led_device {
    bsd_led_device_t *next;
    led_t *function;
    void *context;
    int state;
    char name[BSD_LED_NAME_MAX];
};

static volatile uint32_t g_led_guard;
static bsd_led_device_t *g_led_devices;

static void
led_lock(void)
{
    bsd_critical_enter();
    while (__atomic_test_and_set(&g_led_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(_M_ARM64)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
led_unlock(void)
{
    __atomic_clear(&g_led_guard, __ATOMIC_RELEASE);
    bsd_critical_exit();
}

struct cdev *
led_create_state(led_t *function, void *context, const char *name, int state)
{
    bsd_led_device_t *device;

    if (!function || !name || name[0] == '\0')
        return 0;
    device = bsd_kmalloc(
        sizeof(*device), BSD_M_WAITOK | BSD_M_ZERO);
    if (!device)
        return 0;
    device->function = function;
    device->context = context;
    device->state = state != 0;
    (void)bsd_strlcpy(device->name, name, sizeof(device->name));
    led_lock();
    device->next = g_led_devices;
    g_led_devices = device;
    led_unlock();
    if (state != -1)
        function(context, device->state);
    return (struct cdev *)device;
}

struct cdev *
led_create(led_t *function, void *context, const char *name)
{
    return led_create_state(function, context, name, 0);
}

void
led_destroy(struct cdev *public_device)
{
    bsd_led_device_t *device = (bsd_led_device_t *)public_device;
    bsd_led_device_t **position;
    int found = 0;

    if (!device)
        return;
    led_lock();
    position = &g_led_devices;
    while (*position && *position != device)
        position = &(*position)->next;
    if (*position == device) {
        *position = device->next;
        found = 1;
    }
    led_unlock();
    if (found)
        bsd_kfree(device);
}

int
led_set(const char *name, const char *command)
{
    bsd_led_device_t *device;
    led_t *function;
    void *context;
    int state;

    if (!name || !command)
        return BSD_LED_EINVAL;
    if (bsd_strcmp(command, "0") == 0 ||
        bsd_strcmp(command, "off") == 0)
        state = 0;
    else if (bsd_strcmp(command, "1") == 0 ||
        bsd_strcmp(command, "on") == 0)
        state = 1;
    else
        return BSD_LED_EINVAL;
    led_lock();
    for (device = g_led_devices; device; device = device->next) {
        if (bsd_strcmp(device->name, name) == 0)
            break;
    }
    if (!device) {
        led_unlock();
        return BSD_LED_ENOENT;
    }
    device->state = state;
    function = device->function;
    context = device->context;
    led_unlock();
    function(context, state);
    return 0;
}
