/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS system-controller register framework.
 *
 * The public provider contract is the unmodified FreeBSD interface. EdgeOS
 * supplies the shared registry, provider lifecycle, serialized register
 * access, and a Device Tree backed register-space provider.
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "compat/freebsd/dev/ofw/ofw_bus.h"
#include "compat/freebsd/dev/ofw/openfirm.h"
#include <sys/queue.h>
#include <dev/syscon/syscon.h>
#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/machine/bus.h"
#include "compat/freebsd/sys/kobj.h"
#include "syscon_if.h"

#define BSD_SYSCON_ENOENT 2
#define BSD_SYSCON_ENXIO 6
#define BSD_SYSCON_ENOMEM 12
#define BSD_SYSCON_EBUSY 16
#define BSD_SYSCON_ENODEV 19
#define BSD_SYSCON_EINVAL 22

MALLOC_DEFINE(M_SYSCON, "syscon", "EdgeOS system-controller framework");

typedef TAILQ_HEAD(edgeos_syscon_list, syscon) edgeos_syscon_list_t;

typedef struct edgeos_syscon_map {
    bus_space_tag_t tag;
    bus_space_handle_t handle;
    bus_size_t size;
    volatile unsigned char guard;
    bool mapped;
} edgeos_syscon_map_t;

static edgeos_syscon_list_t g_syscons =
    TAILQ_HEAD_INITIALIZER(g_syscons);
static volatile unsigned char g_syscon_registry_guard;
static volatile unsigned char g_syscon_lazy_guard;

static void
syscon_spin_lock(volatile unsigned char *guard)
{
    while (__atomic_test_and_set(guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
syscon_spin_unlock(volatile unsigned char *guard)
{
    __atomic_clear(guard, __ATOMIC_RELEASE);
}

static int
syscon_default_init(struct syscon *controller)
{
    (void)controller;
    return 0;
}

static int
syscon_default_uninit(struct syscon *controller)
{
    (void)controller;
    return 0;
}

static uint32_t
syscon_default_read_4(struct syscon *controller, bus_size_t offset)
{
    uint32_t value;

    if (!controller || !controller->pdev)
        return 0;
    SYSCON_DEVICE_LOCK(controller->pdev);
    value = SYSCON_UNLOCKED_READ_4(controller, offset);
    SYSCON_DEVICE_UNLOCK(controller->pdev);
    return value;
}

static int
syscon_default_write_4(struct syscon *controller, bus_size_t offset,
    uint32_t value)
{
    int error;

    if (!controller || !controller->pdev)
        return BSD_SYSCON_ENODEV;
    SYSCON_DEVICE_LOCK(controller->pdev);
    error = SYSCON_UNLOCKED_WRITE_4(controller, offset, value);
    SYSCON_DEVICE_UNLOCK(controller->pdev);
    return error;
}

static int
syscon_default_modify_4(struct syscon *controller, bus_size_t offset,
    uint32_t clear_bits, uint32_t set_bits)
{
    int error;

    if (!controller || !controller->pdev)
        return BSD_SYSCON_ENODEV;
    SYSCON_DEVICE_LOCK(controller->pdev);
    error = SYSCON_UNLOCKED_MODIFY_4(
        controller, offset, clear_bits, set_bits);
    SYSCON_DEVICE_UNLOCK(controller->pdev);
    return error;
}

static syscon_method_t syscon_methods[] = {
    SYSCONMETHOD(syscon_init, syscon_default_init),
    SYSCONMETHOD(syscon_uninit, syscon_default_uninit),
    SYSCONMETHOD(syscon_read_4, syscon_default_read_4),
    SYSCONMETHOD(syscon_write_4, syscon_default_write_4),
    SYSCONMETHOD(syscon_modify_4, syscon_default_modify_4),
    SYSCONMETHOD_END
};

DEFINE_CLASS_0(syscon, syscon_class, syscon_methods, 0);

static bool
edgeos_syscon_offset_valid(
    const edgeos_syscon_map_t *map, bus_size_t offset)
{
    return map && map->mapped && offset <= map->size &&
        map->size - offset >= sizeof(uint32_t);
}

static int
edgeos_syscon_map_init(struct syscon *controller)
{
    edgeos_syscon_map_t *map;
    uint64_t address;
    uint64_t size;
    int error;

    if (!controller || controller->ofw_node == 0 ||
        controller->ofw_node == (phandle_t)-1)
        return BSD_SYSCON_EINVAL;
    map = syscon_get_softc(controller);
    if (!map)
        return BSD_SYSCON_ENOMEM;
    error = bsd_ofw_fdt_get_reg(
        controller->ofw_node, 0, &address, &size);
    if (error != 0 || size < sizeof(uint32_t))
        return BSD_SYSCON_ENXIO;
    if ((bus_addr_t)address != address || (bus_size_t)size != size)
        return BSD_SYSCON_EINVAL;
    map->tag = bsd_bus_space_memory_tag();
    if (!map->tag)
        return BSD_SYSCON_ENXIO;
    error = bus_space_map(map->tag, (bus_addr_t)address,
        (bus_size_t)size, 0, &map->handle);
    if (error != 0) {
        map->tag = 0;
        return error;
    }
    map->size = (bus_size_t)size;
    map->mapped = true;
    return 0;
}

static int
edgeos_syscon_map_uninit(struct syscon *controller)
{
    edgeos_syscon_map_t *map =
        controller ? syscon_get_softc(controller) : 0;

    if (!map)
        return BSD_SYSCON_EINVAL;
    syscon_spin_lock(&map->guard);
    if (map->mapped)
        bus_space_unmap(map->tag, map->handle, map->size);
    map->mapped = false;
    map->tag = 0;
    map->handle = 0;
    map->size = 0;
    syscon_spin_unlock(&map->guard);
    return 0;
}

static uint32_t
edgeos_syscon_map_read_4(struct syscon *controller, bus_size_t offset)
{
    edgeos_syscon_map_t *map =
        controller ? syscon_get_softc(controller) : 0;
    uint32_t value = 0;

    if (!map)
        return 0;
    syscon_spin_lock(&map->guard);
    if (edgeos_syscon_offset_valid(map, offset))
        value = bus_space_read_4(map->tag, map->handle, offset);
    syscon_spin_unlock(&map->guard);
    return value;
}

static int
edgeos_syscon_map_write_4(struct syscon *controller, bus_size_t offset,
    uint32_t value)
{
    edgeos_syscon_map_t *map =
        controller ? syscon_get_softc(controller) : 0;
    int error = 0;

    if (!map)
        return BSD_SYSCON_EINVAL;
    syscon_spin_lock(&map->guard);
    if (!edgeos_syscon_offset_valid(map, offset))
        error = BSD_SYSCON_EINVAL;
    else {
        bus_space_write_4(map->tag, map->handle, offset, value);
        bus_space_barrier(map->tag, map->handle, offset,
            sizeof(value), BUS_SPACE_BARRIER_WRITE);
    }
    syscon_spin_unlock(&map->guard);
    return error;
}

static int
edgeos_syscon_map_modify_4(struct syscon *controller, bus_size_t offset,
    uint32_t clear_bits, uint32_t set_bits)
{
    edgeos_syscon_map_t *map =
        controller ? syscon_get_softc(controller) : 0;
    uint32_t value;
    int error = 0;

    if (!map)
        return BSD_SYSCON_EINVAL;
    syscon_spin_lock(&map->guard);
    if (!edgeos_syscon_offset_valid(map, offset))
        error = BSD_SYSCON_EINVAL;
    else {
        value = bus_space_read_4(map->tag, map->handle, offset);
        value &= ~clear_bits;
        value |= set_bits;
        bus_space_write_4(map->tag, map->handle, offset, value);
        bus_space_barrier(map->tag, map->handle, offset,
            sizeof(value), BUS_SPACE_BARRIER_WRITE);
    }
    syscon_spin_unlock(&map->guard);
    return error;
}

static uint32_t
edgeos_syscon_map_unlocked_read_4(
    struct syscon *controller, bus_size_t offset)
{
    edgeos_syscon_map_t *map =
        controller ? syscon_get_softc(controller) : 0;

    if (!edgeos_syscon_offset_valid(map, offset))
        return 0;
    return bus_space_read_4(map->tag, map->handle, offset);
}

static int
edgeos_syscon_map_unlocked_write_4(struct syscon *controller,
    bus_size_t offset, uint32_t value)
{
    edgeos_syscon_map_t *map =
        controller ? syscon_get_softc(controller) : 0;

    if (!edgeos_syscon_offset_valid(map, offset))
        return BSD_SYSCON_EINVAL;
    bus_space_write_4(map->tag, map->handle, offset, value);
    bus_space_barrier(map->tag, map->handle, offset,
        sizeof(value), BUS_SPACE_BARRIER_WRITE);
    return 0;
}

static int
edgeos_syscon_map_unlocked_modify_4(struct syscon *controller,
    bus_size_t offset, uint32_t clear_bits, uint32_t set_bits)
{
    edgeos_syscon_map_t *map =
        controller ? syscon_get_softc(controller) : 0;
    uint32_t value;

    if (!edgeos_syscon_offset_valid(map, offset))
        return BSD_SYSCON_EINVAL;
    value = bus_space_read_4(map->tag, map->handle, offset);
    value &= ~clear_bits;
    value |= set_bits;
    bus_space_write_4(map->tag, map->handle, offset, value);
    bus_space_barrier(map->tag, map->handle, offset,
        sizeof(value), BUS_SPACE_BARRIER_WRITE);
    return 0;
}

static syscon_method_t edgeos_syscon_map_methods[] = {
    SYSCONMETHOD(syscon_init, edgeos_syscon_map_init),
    SYSCONMETHOD(syscon_uninit, edgeos_syscon_map_uninit),
    SYSCONMETHOD(syscon_read_4, edgeos_syscon_map_read_4),
    SYSCONMETHOD(syscon_write_4, edgeos_syscon_map_write_4),
    SYSCONMETHOD(syscon_modify_4, edgeos_syscon_map_modify_4),
    SYSCONMETHOD(syscon_unlocked_read_4,
        edgeos_syscon_map_unlocked_read_4),
    SYSCONMETHOD(syscon_unlocked_write_4,
        edgeos_syscon_map_unlocked_write_4),
    SYSCONMETHOD(syscon_unlocked_modify_4,
        edgeos_syscon_map_unlocked_modify_4),
    SYSCONMETHOD_END
};

DEFINE_CLASS_1(edgeos_syscon_map, edgeos_syscon_map_class,
    edgeos_syscon_map_methods, sizeof(edgeos_syscon_map_t),
    syscon_class);

static struct syscon *
syscon_find_by_ofw_node_locked(phandle_t node)
{
    struct syscon *entry;

    TAILQ_FOREACH(entry, &g_syscons, syscon_link) {
        if (entry->ofw_node == node)
            return entry;
    }
    return 0;
}

static struct syscon *
syscon_find_by_ofw_node(phandle_t node)
{
    struct syscon *entry;

    syscon_spin_lock(&g_syscon_registry_guard);
    entry = syscon_find_by_ofw_node_locked(node);
    syscon_spin_unlock(&g_syscon_registry_guard);
    return entry;
}

static void
syscon_destroy_unregistered(struct syscon *controller)
{
    if (!controller)
        return;
    if (controller->softc)
        bsd_free(controller->softc, M_SYSCON);
    kobj_delete((kobj_t)controller, 0);
    bsd_free(controller, M_SYSCON);
}

void *
syscon_get_softc(struct syscon *controller)
{
    return controller ? controller->softc : 0;
}

struct syscon *
syscon_create(device_t provider, syscon_class_t class_object)
{
    struct syscon *controller;

    if (!class_object)
        return 0;
    controller = bsd_malloc(
        sizeof(*controller), M_SYSCON, M_WAITOK | M_ZERO);
    if (!controller)
        return 0;
    kobj_init((kobj_t)controller, (kobj_class_t)class_object);
    if (class_object->size != 0) {
        controller->softc = bsd_malloc(
            class_object->size, M_SYSCON, M_WAITOK | M_ZERO);
        if (!controller->softc) {
            kobj_delete((kobj_t)controller, 0);
            bsd_free(controller, M_SYSCON);
            return 0;
        }
    }
    controller->pdev = provider;
    return controller;
}

struct syscon *
syscon_register(struct syscon *controller)
{
    int error;

    if (!controller)
        return 0;
#ifdef FDT
    if (controller->ofw_node == 0 && controller->pdev)
        controller->ofw_node = ofw_bus_get_node(controller->pdev);
    if (controller->ofw_node == 0 ||
        controller->ofw_node == (phandle_t)-1)
        return 0;
#endif
    error = SYSCON_INIT(controller);
    if (error != 0)
        return 0;
    syscon_spin_lock(&g_syscon_registry_guard);
#ifdef FDT
    if (syscon_find_by_ofw_node_locked(controller->ofw_node)) {
        syscon_spin_unlock(&g_syscon_registry_guard);
        (void)SYSCON_UNINIT(controller);
        return 0;
    }
#endif
    TAILQ_INSERT_TAIL(&g_syscons, controller, syscon_link);
    syscon_spin_unlock(&g_syscon_registry_guard);
#ifdef FDT
    if (controller->pdev)
        (void)OF_device_register_xref(
            OF_xref_from_node(controller->ofw_node), controller->pdev);
#endif
    return controller;
}

int
syscon_unregister(struct syscon *controller)
{
    struct syscon *entry;
    bool found = false;

    if (!controller)
        return BSD_SYSCON_EINVAL;
    syscon_spin_lock(&g_syscon_registry_guard);
    TAILQ_FOREACH(entry, &g_syscons, syscon_link) {
        if (entry != controller)
            continue;
        TAILQ_REMOVE(&g_syscons, controller, syscon_link);
        found = true;
        break;
    }
    syscon_spin_unlock(&g_syscon_registry_guard);
    if (!found)
        return BSD_SYSCON_ENOENT;
#ifdef FDT
    if (controller->pdev)
        OF_device_unregister_xref(
            OF_xref_from_node(controller->ofw_node), controller->pdev);
#endif
    return SYSCON_UNINIT(controller);
}

#ifdef FDT
struct syscon *
syscon_create_ofw_node(device_t provider, syscon_class_t class_object,
    phandle_t node)
{
    struct syscon *controller =
        syscon_create(provider, class_object);

    if (!controller)
        return 0;
    controller->ofw_node = node;
    if (!syscon_register(controller)) {
        syscon_destroy_unregistered(controller);
        return 0;
    }
    return controller;
}

phandle_t
syscon_get_ofw_node(struct syscon *controller)
{
    return controller ? controller->ofw_node : 0;
}

static struct syscon *
syscon_create_fdt_map(phandle_t node)
{
    return syscon_create_ofw_node(
        0, &edgeos_syscon_map_class, node);
}

int
syscon_get_by_ofw_node(device_t consumer, phandle_t node,
    struct syscon **result)
{
    struct syscon *controller;

    (void)consumer;
    if (result)
        *result = 0;
    if (!result || node == 0 || node == (phandle_t)-1)
        return BSD_SYSCON_EINVAL;
    syscon_spin_lock(&g_syscon_lazy_guard);
    controller = syscon_find_by_ofw_node(node);
    if (!controller)
        controller = syscon_create_fdt_map(node);
    syscon_spin_unlock(&g_syscon_lazy_guard);
    if (!controller)
        return BSD_SYSCON_ENODEV;
    *result = controller;
    return 0;
}

int
syscon_get_by_ofw_property(device_t consumer, phandle_t node, char *name,
    struct syscon **result)
{
    pcell_t xref;
    ssize_t length;

    if (result)
        *result = 0;
    if (!result || !name || name[0] == '\0')
        return BSD_SYSCON_EINVAL;
    if (node == 0 && consumer)
        node = ofw_bus_get_node(consumer);
    if (node == 0 || node == (phandle_t)-1)
        return BSD_SYSCON_ENXIO;
    length = OF_getencprop(node, name, &xref, sizeof(xref));
    if (length < (ssize_t)sizeof(xref))
        return BSD_SYSCON_ENOENT;
    return syscon_get_by_ofw_node(
        consumer, OF_node_from_xref(xref), result);
}
#endif
