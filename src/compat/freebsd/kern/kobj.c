/* SPDX-License-Identifier: MPL-2.0 */
/* Shared FreeBSD kobj-compatible method dispatcher for EdgeOS drivers. */

#include <stddef.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/kobj.h"

#define BSD_KOBJ_ENXIO 6

static volatile unsigned int g_kobj_guard;
static unsigned int g_kobj_next_id = 1;
static const struct kobj_method g_kobj_null_method;

static void
kobj_guard_lock(void)
{
    while (__atomic_test_and_set(&g_kobj_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
kobj_guard_unlock(void)
{
    __atomic_clear(&g_kobj_guard, __ATOMIC_RELEASE);
}

static void
kobj_prepare_ops(kobj_class_t class_object, kobj_ops_t ops)
{
    kobj_method_t *method;

    for (method = class_object->methods; method && method->desc; ++method) {
        if (method->desc->id == 0)
            method->desc->id = g_kobj_next_id++;
    }
    for (unsigned int index = 0; index < KOBJ_CACHE_SIZE; ++index)
        ops->cache[index] = &g_kobj_null_method;
    ops->cls = class_object;
}

int
kobj_error_method(void)
{
    return BSD_KOBJ_ENXIO;
}

void
kobj_class_compile(kobj_class_t class_object)
{
    kobj_ops_t candidate;

    if (!class_object ||
        __atomic_load_n(&class_object->ops, __ATOMIC_ACQUIRE))
        return;
    candidate = bsd_malloc(sizeof(*candidate), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!candidate)
        bsd_bridge_panic_stop();

    kobj_guard_lock();
    if (!class_object->ops) {
        kobj_prepare_ops(class_object, candidate);
        __atomic_store_n(&class_object->ops, candidate, __ATOMIC_RELEASE);
        candidate = 0;
    }
    kobj_guard_unlock();
    if (candidate)
        bsd_free(candidate, M_DEVBUF);
}

void
kobj_class_compile_static(kobj_class_t class_object, kobj_ops_t ops)
{
    if (!class_object || !ops)
        bsd_bridge_panic_stop();
    kobj_guard_lock();
    if (!class_object->ops) {
        kobj_prepare_ops(class_object, ops);
        class_object->refs++;
        __atomic_store_n(&class_object->ops, ops, __ATOMIC_RELEASE);
    }
    kobj_guard_unlock();
}

void
kobj_class_retain(kobj_class_t class_object)
{
    if (!class_object)
        bsd_bridge_panic_stop();
    kobj_class_compile(class_object);
    kobj_guard_lock();
    if (!class_object->ops) {
        kobj_guard_unlock();
        bsd_bridge_panic_stop();
    }
    class_object->refs++;
    kobj_guard_unlock();
}

void
kobj_class_release(kobj_class_t class_object)
{
    int release_class;

    if (!class_object)
        bsd_bridge_panic_stop();
    kobj_guard_lock();
    if (class_object->refs == 0) {
        kobj_guard_unlock();
        bsd_bridge_panic_stop();
    }
    class_object->refs--;
    release_class = class_object->refs == 0;
    kobj_guard_unlock();
    if (release_class)
        kobj_class_free(class_object);
}

void
kobj_class_free(kobj_class_t class_object)
{
    kobj_ops_t ops = 0;

    if (!class_object)
        return;
    kobj_guard_lock();
    if (class_object->refs == 0) {
        ops = class_object->ops;
        class_object->ops = 0;
    }
    kobj_guard_unlock();
    if (ops)
        bsd_free(ops, M_DEVBUF);
}

static int
kobj_init_internal(kobj_t object, kobj_class_t class_object)
{
    if (!object || !class_object)
        return -1;
    for (;;) {
        kobj_class_compile(class_object);
        kobj_guard_lock();
        if (class_object->ops) {
            object->ops = class_object->ops;
            class_object->refs++;
            kobj_guard_unlock();
            return 0;
        }
        kobj_guard_unlock();
    }
}

kobj_t
kobj_create(kobj_class_t class_object, struct malloc_type *type, int flags)
{
    kobj_t object;

    if (!class_object || class_object->size < sizeof(*object))
        return 0;
    object = bsd_malloc(class_object->size, type, flags | M_ZERO);
    if (!object)
        return 0;
    if (kobj_init_internal(object, class_object) != 0) {
        bsd_free(object, type);
        return 0;
    }
    return object;
}

void
kobj_init(kobj_t object, kobj_class_t class_object)
{
    if (kobj_init_internal(object, class_object) != 0)
        bsd_bridge_panic_stop();
}

void
kobj_init_static(kobj_t object, kobj_class_t class_object)
{
    kobj_guard_lock();
    if (!object || !class_object || !class_object->ops) {
        kobj_guard_unlock();
        bsd_bridge_panic_stop();
    }
    object->ops = class_object->ops;
    class_object->refs++;
    kobj_guard_unlock();
}

void
kobj_delete(kobj_t object, struct malloc_type *type)
{
    kobj_class_t class_object;
    int release_class;

    if (!object || !object->ops)
        return;
    kobj_guard_lock();
    class_object = object->ops->cls;
    if (!class_object || class_object->refs == 0) {
        kobj_guard_unlock();
        bsd_bridge_panic_stop();
    }
    object->ops = 0;
    class_object->refs--;
    release_class = class_object->refs == 0;
    kobj_guard_unlock();

    if (release_class)
        kobj_class_free(class_object);
    if (type)
        bsd_free(object, type);
}

static kobj_method_t *
kobj_find_method(kobj_class_t class_object, kobjop_desc_t descriptor)
{
    kobj_method_t *method;

    for (method = class_object->methods; method && method->desc; ++method) {
        if (method->desc == descriptor)
            return method;
    }
    if (class_object->baseclasses) {
        for (kobj_class_t *base = class_object->baseclasses; *base; ++base) {
            method = kobj_find_method(*base, descriptor);
            if (method)
                return method;
        }
    }
    return 0;
}

kobj_method_t *
kobj_lookup_method(kobj_class_t class_object, kobj_method_t **cache_entry,
    kobjop_desc_t descriptor)
{
    kobj_method_t *method;

    if (!class_object || !descriptor)
        return 0;
    method = kobj_find_method(class_object, descriptor);
    if (!method)
        method = &descriptor->deflt;
    if (cache_entry)
        __atomic_store_n(cache_entry, method, __ATOMIC_RELEASE);
    return method;
}
