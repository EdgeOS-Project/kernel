/* SPDX-License-Identifier: MPL-2.0 */
/* ACPI ioctl registry used by complete imported ACPI drivers. */

#include <stddef.h>
#include <stdint.h>
#include <sys/param.h>

#define BSD_ACPI_IOCTL_MAX 32
#define BSD_ACPI_EBUSY 16
#define BSD_ACPI_EINVAL 22
#define BSD_ACPI_ENOENT 2
#define BSD_ACPI_ENOMEM 12

typedef int (*bsd_acpi_ioctl_handler_t)(u_long, caddr_t, void *);

typedef struct bsd_acpi_ioctl_entry {
    u_long command;
    bsd_acpi_ioctl_handler_t handler;
    void *argument;
} bsd_acpi_ioctl_entry_t;

static bsd_acpi_ioctl_entry_t g_acpi_ioctls[BSD_ACPI_IOCTL_MAX];
static volatile unsigned int g_acpi_ioctl_guard;

static void
acpi_ioctl_lock(void)
{
    while (__atomic_test_and_set(&g_acpi_ioctl_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
acpi_ioctl_unlock(void)
{
    __atomic_clear(&g_acpi_ioctl_guard, __ATOMIC_RELEASE);
}

int
acpi_register_ioctl(u_long command, bsd_acpi_ioctl_handler_t handler,
    void *argument)
{
    size_t empty = BSD_ACPI_IOCTL_MAX;

    if (!handler)
        return BSD_ACPI_EINVAL;
    acpi_ioctl_lock();
    for (size_t index = 0; index < BSD_ACPI_IOCTL_MAX; ++index) {
        if (!g_acpi_ioctls[index].handler) {
            if (empty == BSD_ACPI_IOCTL_MAX)
                empty = index;
            continue;
        }
        if (g_acpi_ioctls[index].command != command)
            continue;
        if (g_acpi_ioctls[index].handler == handler &&
            g_acpi_ioctls[index].argument == argument) {
            acpi_ioctl_unlock();
            return 0;
        }
        acpi_ioctl_unlock();
        return BSD_ACPI_EBUSY;
    }
    if (empty == BSD_ACPI_IOCTL_MAX) {
        acpi_ioctl_unlock();
        return BSD_ACPI_ENOMEM;
    }
    g_acpi_ioctls[empty].command = command;
    g_acpi_ioctls[empty].handler = handler;
    g_acpi_ioctls[empty].argument = argument;
    acpi_ioctl_unlock();
    return 0;
}

void
acpi_deregister_ioctl(u_long command, bsd_acpi_ioctl_handler_t handler)
{
    if (!handler)
        return;
    acpi_ioctl_lock();
    for (size_t index = 0; index < BSD_ACPI_IOCTL_MAX; ++index) {
        if (g_acpi_ioctls[index].command != command ||
            g_acpi_ioctls[index].handler != handler)
            continue;
        g_acpi_ioctls[index] = (bsd_acpi_ioctl_entry_t){0};
    }
    acpi_ioctl_unlock();
}

void
acpi_deregister_ioctls(bsd_acpi_ioctl_handler_t handler)
{
    if (!handler)
        return;
    acpi_ioctl_lock();
    for (size_t index = 0; index < BSD_ACPI_IOCTL_MAX; ++index) {
        if (g_acpi_ioctls[index].handler != handler)
            continue;
        g_acpi_ioctls[index] = (bsd_acpi_ioctl_entry_t){0};
    }
    acpi_ioctl_unlock();
}

int
bsd_acpi_ioctl_dispatch(u_long command, caddr_t data)
{
    bsd_acpi_ioctl_entry_t selected = {0};

    acpi_ioctl_lock();
    for (size_t index = 0; index < BSD_ACPI_IOCTL_MAX; ++index) {
        if (g_acpi_ioctls[index].handler &&
            g_acpi_ioctls[index].command == command) {
            selected = g_acpi_ioctls[index];
            break;
        }
    }
    acpi_ioctl_unlock();
    if (!selected.handler)
        return BSD_ACPI_ENOENT;
    return selected.handler(command, data, selected.argument);
}
