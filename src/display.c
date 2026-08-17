/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent display backend registry. */

#include <stddef.h>

#include "display.h"
#include "sys/spinlock.h"

#if __STDC_HOSTED__
static volatile unsigned int g_display_guard;
#else
static spinlock_t g_display_guard;
#endif
static display_backend_t g_display_backend;
static uint64_t g_display_generation;
static int g_display_registered;

static uint64_t
display_lock(void)
{
#if __STDC_HOSTED__
    while (__atomic_test_and_set(&g_display_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
    return 0;
#else
    return spin_lock_irqsave(&g_display_guard);
#endif
}

static void
display_unlock(uint64_t flags)
{
#if __STDC_HOSTED__
    (void)flags;
    __atomic_clear(&g_display_guard, __ATOMIC_RELEASE);
#else
    spin_unlock_irqrestore(&g_display_guard, flags);
#endif
}

static int
display_backend_valid(const display_backend_t *backend)
{
    if (!backend || !backend->name || backend->name[0] == '\0' ||
        !backend->owner)
        return 0;
    if ((backend->flags & DISPLAY_BACKEND_EXPLICIT_PRESENT) != 0 &&
        !backend->operations.present_rect)
        return 0;
    if ((backend->flags & DISPLAY_BACKEND_DYNAMIC_MODE) != 0 &&
        (!backend->operations.get_mode || !backend->operations.set_mode))
        return 0;
    return 1;
}

int
display_backend_register(const display_backend_t *backend)
{
    uint64_t flags;

    if (!display_backend_valid(backend))
        return -1;
    flags = display_lock();
    g_display_backend = *backend;
    g_display_registered = 1;
    g_display_generation++;
    display_unlock(flags);
    return 0;
}

void
display_backend_unregister(const void *owner)
{
    uint64_t flags;

    if (!owner)
        return;
    flags = display_lock();
    if (g_display_registered && g_display_backend.owner == owner) {
        g_display_backend = (display_backend_t){0};
        g_display_registered = 0;
        g_display_generation++;
    }
    display_unlock(flags);
}

void
display_backend_reset(void)
{
    uint64_t flags = display_lock();
    if (g_display_registered) {
        g_display_backend = (display_backend_t){0};
        g_display_registered = 0;
        g_display_generation++;
    }
    display_unlock(flags);
}

int
display_backend_snapshot(display_backend_t *backend, uint64_t *generation)
{
    int registered;
    uint64_t flags;

    flags = display_lock();
    registered = g_display_registered;
    if (backend)
        *backend = registered ? g_display_backend : (display_backend_t){0};
    if (generation)
        *generation = g_display_generation;
    display_unlock(flags);
    return registered;
}

int
display_backend_is_owner(const void *owner)
{
    int result;
    uint64_t flags;

    if (!owner)
        return 0;
    flags = display_lock();
    result = g_display_registered && g_display_backend.owner == owner;
    display_unlock(flags);
    return result;
}

int
display_backend_requires_present(void)
{
    int result;
    uint64_t flags;

    flags = display_lock();
    result = g_display_registered &&
        (g_display_backend.flags & DISPLAY_BACKEND_EXPLICIT_PRESENT) != 0;
    display_unlock(flags);
    return result;
}

void
display_backend_present_rect(uint32_t x, uint32_t y, uint32_t width,
                             uint32_t height)
{
    display_backend_t backend;

    if (!width || !height || !display_backend_snapshot(&backend, 0) ||
        !backend.operations.present_rect)
        return;
    backend.operations.present_rect(backend.context, x, y, width, height);
}

void
display_backend_present_rects(const display_rect_t *rects, uint32_t count)
{
    display_backend_t backend;

    if (!rects || !count || !display_backend_snapshot(&backend, 0))
        return;
    if (backend.operations.present_rects) {
        backend.operations.present_rects(backend.context, rects, count);
        return;
    }
    if (!backend.operations.present_rect)
        return;
    for (uint32_t index = 0; index < count; ++index) {
        if (!rects[index].width || !rects[index].height)
            continue;
        backend.operations.present_rect(
            backend.context, rects[index].x, rects[index].y,
            rects[index].width, rects[index].height);
    }
}

int
display_backend_get_mode(display_mode_t *mode)
{
    display_backend_t backend;

    if (!mode || !display_backend_snapshot(&backend, 0) ||
        !backend.operations.get_mode)
        return -1;
    return backend.operations.get_mode(backend.context, mode);
}

int
display_backend_set_mode(const display_mode_t *mode)
{
    display_backend_t backend;
    int result;

    if (!mode || !mode->width || !mode->height ||
        !display_backend_snapshot(&backend, 0) ||
        !backend.operations.set_mode)
        return -1;
    result = backend.operations.set_mode(backend.context, mode);
    if (result == 0)
        display_backend_notify_mode_change();
    return result;
}

int
display_backend_poll(void)
{
    display_backend_t backend;

    if (!display_backend_snapshot(&backend, 0) ||
        !backend.operations.poll)
        return 0;
    return backend.operations.poll(backend.context);
}

void
display_backend_notify_mode_change(void)
{
    uint64_t flags = display_lock();
    if (g_display_registered)
        g_display_generation++;
    display_unlock(flags);
}

uint64_t
display_backend_generation(void)
{
    uint64_t generation;
    uint64_t flags;

    flags = display_lock();
    generation = g_display_generation;
    display_unlock(flags);
    return generation;
}
