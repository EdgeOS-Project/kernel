/* SPDX-License-Identifier: MPL-2.0 */
/* Shared FreeBSD newbus-compatible device runtime for EdgeOS drivers. */

#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#ifdef BSD_BRIDGE_HOST_TEST
#include <stdio.h>
#else
void printf(const char *format, ...);
#endif

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/driver_hooks.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/resource.h"
#include "compat/freebsd/edgeos/sysctl.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/module.h"
#include "compat/freebsd/sys/mutex.h"

#define BSD_NEWBUS_ENOENT 2
#define BSD_NEWBUS_ENXIO 6
#define BSD_NEWBUS_ENOMEM 12
#define BSD_NEWBUS_EBUSY 16
#define BSD_NEWBUS_EEXIST 17
#define BSD_NEWBUS_EINVAL 22
#define BSD_NEWBUS_RESET_DETACH 0x0000001u

#define BSD_NEWBUS_DEVICE_ENABLED 0x01u
#define BSD_NEWBUS_DEVICE_FIXED_CLASS 0x02u
#define BSD_NEWBUS_DEVICE_QUIET 0x10u
#define BSD_NEWBUS_DEVICE_QUIET_CHILDREN 0x400u
#define BSD_NEWBUS_DEVICE_SUSPENDED 0x100u
#define BSD_NEWBUS_DEVICE_FIRMWARE_OWNED 0x200u
#define BSD_NEWBUS_DEVICE_EXTERNAL_SOFTC 0x40u
#define BSD_NEWBUS_DEVICE_IVARS_OWNED 0x80u
#define BSD_NEWBUS_DEVICE_DESC_OWNED 0x80000000u
#define BSD_DRIVER_ATTACH_HOOK_CAPACITY 32u
#define BSD_DRIVER_ATTACH_NAME_CAPACITY 32u

typedef struct bsd_driver_link bsd_driver_link_t;
typedef struct bsd_driver_attach_hook bsd_driver_attach_hook_t;
typedef struct bsd_driver_attach_state bsd_driver_attach_state_t;
typedef struct bsd_device_property bsd_device_property_t;
typedef void (*bsd_device_prop_destructor_t)(device_t device,
    const char *name, void *value, void *context);

struct bsd_driver_link {
    driver_t *driver;
    int pass;
    bsd_driver_link_t *next;
};

struct bsd_driver_attach_hook {
    char driver_name[BSD_DRIVER_ATTACH_NAME_CAPACITY];
    bsd_driver_attach_begin_t begin;
    bsd_driver_attach_end_t end;
    void *context;
};

struct bsd_driver_attach_state {
    bsd_driver_attach_end_t end;
    void *context;
    uintptr_t cookie;
    uint8_t active;
};

struct bsd_device_property {
    bsd_device_property_t *next;
    bsd_device_prop_destructor_t destructor;
    void *value;
    void *destructor_context;
    char name[];
};

struct devclass {
    struct devclass *next;
    devclass_t parent;
    bsd_driver_link_t *drivers;
    char *name;
    int next_unit;
};

struct _device {
    KOBJ_FIELDS;
    device_t parent;
    device_t child_head;
    device_t child_tail;
    device_t sibling_next;
    device_t global_next;
    driver_t *driver;
    devclass_t devclass;
    int unit;
    char *nameunit;
    const char *description;
    void *ivars;
    void *firmware_metadata;
    void *softc;
    bsd_device_property_t *properties;
    bus_dma_tag_t dma_tag;
    void *sysctl_state;
    device_state_t state;
    uint32_t devflags;
    uint32_t flags;
    unsigned int order;
    unsigned int busy;
};

device_t root_bus;
devclass_t root_devclass;

static volatile unsigned int g_newbus_guard;
static volatile unsigned int g_driver_attach_hook_guard;
static devclass_t g_devclasses;
static device_t g_devices;
static bsd_driver_attach_hook_t
    g_driver_attach_hooks[BSD_DRIVER_ATTACH_HOOK_CAPACITY];
static size_t g_driver_attach_hook_count;

extern struct kobjop_desc device_probe_desc;
extern struct kobjop_desc device_identify_desc;
__attribute__((weak)) struct kobjop_desc device_identify_desc = {
    0, { &device_identify_desc, (kobjop_t)kobj_error_method }
};
extern struct kobjop_desc device_attach_desc;
extern struct kobjop_desc device_detach_desc;
extern struct kobjop_desc device_shutdown_desc;
extern struct kobjop_desc device_suspend_desc;
extern struct kobjop_desc device_resume_desc;

typedef int bsd_device_method_t(device_t);

static void device_release_description(device_t device);

typedef void bsd_device_identify_method_t(
    driver_t *driver, device_t parent);

static void
driver_attach_hook_guard_lock(void)
{
    while (__atomic_test_and_set(&g_driver_attach_hook_guard,
        __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
driver_attach_hook_guard_unlock(void)
{
    __atomic_clear(&g_driver_attach_hook_guard, __ATOMIC_RELEASE);
}

int
bsd_driver_attach_hook_register(const char *driver_name,
    bsd_driver_attach_begin_t begin, bsd_driver_attach_end_t end,
    void *context)
{
    bsd_driver_attach_hook_t *hook;
    size_t length;

    if (!driver_name || driver_name[0] == '\0' || (!begin && !end))
        return BSD_NEWBUS_EINVAL;
    length = bsd_strlen(driver_name);
    if (length >= BSD_DRIVER_ATTACH_NAME_CAPACITY)
        return BSD_NEWBUS_EINVAL;

    driver_attach_hook_guard_lock();
    for (size_t index = 0; index < g_driver_attach_hook_count; ++index) {
        hook = &g_driver_attach_hooks[index];
        if (bsd_strcmp(hook->driver_name, driver_name) != 0)
            continue;
        if (hook->begin == begin && hook->end == end &&
            hook->context == context) {
            driver_attach_hook_guard_unlock();
            return 0;
        }
        driver_attach_hook_guard_unlock();
        return BSD_NEWBUS_EEXIST;
    }
    if (g_driver_attach_hook_count >= BSD_DRIVER_ATTACH_HOOK_CAPACITY) {
        driver_attach_hook_guard_unlock();
        return BSD_NEWBUS_ENOMEM;
    }
    hook = &g_driver_attach_hooks[g_driver_attach_hook_count++];
    bsd_memcpy(hook->driver_name, driver_name, length + 1u);
    hook->begin = begin;
    hook->end = end;
    hook->context = context;
    driver_attach_hook_guard_unlock();
    return 0;
}

static int
driver_attach_hook_begin(device_t device,
    bsd_driver_attach_state_t *state)
{
    bsd_driver_attach_begin_t begin = 0;
    bsd_driver_attach_end_t end = 0;
    void *context = 0;
    driver_t *driver;
    int error;

    bsd_memset(state, 0, sizeof(*state));
    driver = device_get_driver(device);
    if (!driver || !driver->name)
        return 0;
    driver_attach_hook_guard_lock();
    for (size_t index = 0; index < g_driver_attach_hook_count; ++index) {
        bsd_driver_attach_hook_t *hook = &g_driver_attach_hooks[index];

        if (bsd_strcmp(hook->driver_name, driver->name) == 0) {
            begin = hook->begin;
            end = hook->end;
            context = hook->context;
            break;
        }
    }
    driver_attach_hook_guard_unlock();
    if (begin) {
        error = begin(device, &state->cookie, context);
        if (error)
            return error;
    }
    if (begin || end) {
        state->end = end;
        state->context = context;
        state->active = 1;
    }
    return 0;
}

static void
driver_attach_hook_end(device_t device,
    bsd_driver_attach_state_t *state, int result)
{
    if (!state->active)
        return;
    state->active = 0;
    if (state->end) {
        state->end(device, state->cookie, result, state->context);
    }
}

static void
newbus_guard_lock(void)
{
    while (__atomic_test_and_set(&g_newbus_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
newbus_guard_unlock(void)
{
    __atomic_clear(&g_newbus_guard, __ATOMIC_RELEASE);
}

static void
device_property_release(device_t device, bsd_device_property_t *property)
{
    if (property->destructor)
        property->destructor(device, property->name, property->value,
            property->destructor_context);
    bsd_free(property, M_DEVBUF);
}

static void
device_properties_release(device_t device)
{
    bsd_device_property_t *property;

    for (;;) {
        newbus_guard_lock();
        property = device->properties;
        if (property)
            device->properties = property->next;
        newbus_guard_unlock();
        if (!property)
            return;
        device_property_release(device, property);
    }
}

int
device_set_prop(device_t device, const char *name, void *value,
    bsd_device_prop_destructor_t destructor, void *destructor_context)
{
    bsd_device_property_t **cursor;
    bsd_device_property_t *old_property = 0;
    bsd_device_property_t *property;
    size_t name_length;

    if (!device || !name || name[0] == '\0')
        return BSD_NEWBUS_EINVAL;
    name_length = bsd_strlen(name) + 1u;
    if (name_length == 0 ||
        name_length > SIZE_MAX - sizeof(*property))
        return BSD_NEWBUS_EINVAL;
    property = bsd_malloc(sizeof(*property) + name_length, M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!property)
        return BSD_NEWBUS_ENOMEM;
    property->destructor = destructor;
    property->value = value;
    property->destructor_context = destructor_context;
    bsd_memcpy(property->name, name, name_length);

    newbus_guard_lock();
    for (cursor = &device->properties; *cursor;
        cursor = &(*cursor)->next) {
        if (bsd_strcmp((*cursor)->name, name) != 0)
            continue;
        old_property = *cursor;
        *cursor = old_property->next;
        break;
    }
    property->next = device->properties;
    device->properties = property;
    newbus_guard_unlock();
    if (old_property)
        device_property_release(device, old_property);
    return 0;
}

int
device_get_prop(device_t device, const char *name, void **value)
{
    bsd_device_property_t *property;

    if (!device || !name || !value)
        return BSD_NEWBUS_EINVAL;
    newbus_guard_lock();
    for (property = device->properties; property;
        property = property->next) {
        if (bsd_strcmp(property->name, name) != 0)
            continue;
        *value = property->value;
        newbus_guard_unlock();
        return 0;
    }
    newbus_guard_unlock();
    return BSD_NEWBUS_ENOENT;
}

int
device_clear_prop(device_t device, const char *name)
{
    bsd_device_property_t **cursor;
    bsd_device_property_t *property = 0;

    if (!device || !name)
        return BSD_NEWBUS_EINVAL;
    newbus_guard_lock();
    for (cursor = &device->properties; *cursor;
        cursor = &(*cursor)->next) {
        if (bsd_strcmp((*cursor)->name, name) != 0)
            continue;
        property = *cursor;
        *cursor = property->next;
        break;
    }
    newbus_guard_unlock();
    if (!property)
        return BSD_NEWBUS_ENOENT;
    device_property_release(device, property);
    return 0;
}

void
device_clear_prop_alldev(const char *name)
{
    bsd_device_property_t **cursor;
    bsd_device_property_t *property;
    device_t device;

    if (!name)
        return;
    for (;;) {
        property = 0;
        device = 0;
        newbus_guard_lock();
        for (device_t candidate = g_devices; candidate;
            candidate = candidate->global_next) {
            for (cursor = &candidate->properties; *cursor;
                cursor = &(*cursor)->next) {
                if (bsd_strcmp((*cursor)->name, name) != 0)
                    continue;
                property = *cursor;
                *cursor = property->next;
                device = candidate;
                break;
            }
            if (property)
                break;
        }
        newbus_guard_unlock();
        if (!property)
            return;
        device_property_release(device, property);
    }
}

#ifdef BSD_BRIDGE_HOST_TEST
/*
 * Hosted newbus tests are single-threaded and intentionally do not start the
 * kernel synchronization runtime. Track nesting so topology assertions remain
 * meaningful without adding a second synchronization setup to every test.
 */
static struct mtx g_host_bus_topology_mutex;
static unsigned int g_host_bus_topology_depth;

struct mtx *
bus_topo_mtx(void)
{
    return &g_host_bus_topology_mutex;
}

void
bus_topo_lock(void)
{
    g_host_bus_topology_depth++;
}

void
bus_topo_unlock(void)
{
    if (g_host_bus_topology_depth == 0)
        __builtin_trap();
    g_host_bus_topology_depth--;
}

void
bus_topo_assert(void)
{
    if (g_host_bus_topology_depth == 0)
        __builtin_trap();
}
#else
struct mtx *
bus_topo_mtx(void)
{
    return &Giant;
}

void
bus_topo_lock(void)
{
    mtx_lock(bus_topo_mtx());
}

void
bus_topo_unlock(void)
{
    mtx_unlock(bus_topo_mtx());
}

void
bus_topo_assert(void)
{
    mtx_assert(bus_topo_mtx(), MA_OWNED);
}
#endif

static char *
newbus_string_duplicate(const char *text)
{
    size_t length;
    char *copy;

    if (!text)
        return 0;
    length = bsd_strlen(text) + 1;
    copy = bsd_malloc(length, M_DEVBUF, M_WAITOK);
    if (copy)
        bsd_memcpy(copy, text, length);
    return copy;
}

static void
device_release_nameunit(device_t device)
{
    if (device->nameunit) {
        bsd_free(device->nameunit, M_DEVBUF);
        device->nameunit = 0;
    }
}

static int
device_refresh_nameunit(device_t device)
{
    const char *name;
    size_t capacity;
    char *nameunit;

    device_release_nameunit(device);
    name = device_get_name(device);
    if (!name)
        return 0;
    capacity = bsd_strlen(name) + 24;
    nameunit = bsd_malloc(capacity, M_DEVBUF, M_WAITOK);
    if (!nameunit)
        return BSD_NEWBUS_ENOMEM;
    bsd_snprintf(nameunit, capacity, "%s%d", name, device->unit);
    device->nameunit = nameunit;
    return 0;
}

devclass_t
devclass_find(const char *class_name)
{
    devclass_t current;

    if (!class_name)
        return 0;
    newbus_guard_lock();
    for (current = g_devclasses; current; current = current->next) {
        if (bsd_strcmp(current->name, class_name) == 0)
            break;
    }
    newbus_guard_unlock();
    return current;
}

devclass_t
devclass_create(const char *class_name)
{
    devclass_t candidate;
    devclass_t existing;

    if (!class_name || class_name[0] == '\0')
        return 0;
    existing = devclass_find(class_name);
    if (existing)
        return existing;

    candidate = bsd_malloc(sizeof(*candidate), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!candidate)
        return 0;
    candidate->name = newbus_string_duplicate(class_name);
    if (!candidate->name) {
        bsd_free(candidate, M_DEVBUF);
        return 0;
    }

    newbus_guard_lock();
    for (existing = g_devclasses; existing; existing = existing->next) {
        if (bsd_strcmp(existing->name, class_name) == 0)
            break;
    }
    if (!existing) {
        candidate->next = g_devclasses;
        g_devclasses = candidate;
        existing = candidate;
        candidate = 0;
    }
    newbus_guard_unlock();

    if (candidate) {
        bsd_free(candidate->name, M_DEVBUF);
        bsd_free(candidate, M_DEVBUF);
    }
    return existing;
}

const char *
devclass_get_name(devclass_t device_class)
{
    return device_class ? device_class->name : 0;
}

int
devclass_add_driver(devclass_t device_class, driver_t *driver, int pass,
    devclass_t *result)
{
    bsd_driver_link_t *link;
    bsd_driver_link_t *tail;
    devclass_t driver_class;
    devclass_t parent_class = 0;

    if (!device_class || !driver)
        return BSD_NEWBUS_EINVAL;
    driver_class = devclass_create(driver->name);
    if (!driver_class)
        return BSD_NEWBUS_ENOMEM;
    if (driver->baseclasses && driver->baseclasses[0] &&
        driver->baseclasses[0]->name &&
        bsd_strcmp(driver->baseclasses[0]->name, driver->name) != 0) {
        parent_class = devclass_create(driver->baseclasses[0]->name);
        if (!parent_class)
            return BSD_NEWBUS_ENOMEM;
    }
    link = bsd_malloc(sizeof(*link), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!link)
        return BSD_NEWBUS_ENOMEM;
    link->driver = driver;
    link->pass = pass;
    kobj_class_retain(driver);

    newbus_guard_lock();
    tail = device_class->drivers;
    if (!tail) {
        device_class->drivers = link;
    } else {
        for (;;) {
            if (tail->driver == driver) {
                newbus_guard_unlock();
                kobj_class_release(driver);
                bsd_free(link, M_DEVBUF);
                return BSD_NEWBUS_EEXIST;
            }
            if (!tail->next)
                break;
            tail = tail->next;
        }
        tail->next = link;
    }
    newbus_guard_unlock();
    if (parent_class && !devclass_get_parent(driver_class))
        devclass_set_parent(driver_class, parent_class);
    if (result)
        *result = driver_class;
    return 0;
}

int
devclass_delete_driver(devclass_t device_class, driver_t *driver)
{
    bsd_driver_link_t **cursor;
    bsd_driver_link_t *removed = 0;
    device_t device;

    if (!device_class || !driver)
        return BSD_NEWBUS_EINVAL;
    newbus_guard_lock();
    for (device = g_devices; device; device = device->global_next) {
        if (device->driver == driver && device_is_attached(device)) {
            newbus_guard_unlock();
            return BSD_NEWBUS_EBUSY;
        }
    }
    for (cursor = &device_class->drivers; *cursor;
        cursor = &(*cursor)->next) {
        if ((*cursor)->driver == driver) {
            removed = *cursor;
            *cursor = removed->next;
            break;
        }
    }
    newbus_guard_unlock();
    if (!removed)
        return BSD_NEWBUS_ENOENT;
    kobj_class_release(driver);
    bsd_free(removed, M_DEVBUF);
    return 0;
}

static kobjop_t
driver_explicit_method(driver_t *driver, struct kobjop_desc *descriptor)
{
    if (!driver || !descriptor)
        return 0;
    for (kobj_method_t *method = driver->methods;
        method && method->desc; ++method) {
        if (method->desc == descriptor)
            return method->func;
    }
    if (driver->baseclasses) {
        for (kobj_class_t *base = driver->baseclasses;
            *base; ++base) {
            kobjop_t method =
                driver_explicit_method(*base, descriptor);

            if (method)
                return method;
        }
    }
    return 0;
}

void
bsd_device_identify_children(device_t device)
{
    bsd_driver_link_t *link;
    driver_t **drivers;
    size_t count = 0;
    size_t index = 0;

    if (!device || !device->devclass)
        return;
    newbus_guard_lock();
    for (link = device->devclass->drivers; link; link = link->next)
        count++;
    newbus_guard_unlock();
    if (count == 0)
        return;

    drivers = bsd_malloc(
        count * sizeof(*drivers), M_TEMP, M_WAITOK | M_ZERO);
    if (!drivers)
        return;
    newbus_guard_lock();
    for (link = device->devclass->drivers;
        link && index < count; link = link->next)
        drivers[index++] = link->driver;
    newbus_guard_unlock();

    for (size_t driver_index = 0;
        driver_index < index; ++driver_index) {
        driver_t *driver = drivers[driver_index];
        kobjop_t method = driver_explicit_method(
            driver, &device_identify_desc);

        if (method) {
            ((bsd_device_identify_method_t *)method)(
                driver, device);
        }
    }
    bsd_free(drivers, M_TEMP);
}

int
driver_module_handler(struct module *module, int event, void *argument)
{
    bsd_driver_module_data_t *module_data = argument;
    devclass_t bus_class;
    int error = 0;

    if (!module_data || !module_data->bus_name || !module_data->driver)
        return BSD_NEWBUS_EINVAL;
    bus_class = devclass_find(module_data->bus_name);
    if (!bus_class && event == MOD_LOAD)
        bus_class = devclass_create(module_data->bus_name);
    if (!bus_class)
        return BSD_NEWBUS_ENOENT;

    if (event == MOD_LOAD) {
        if (module_data->chain_event) {
            error = module_data->chain_event(module, event,
                module_data->chain_argument);
            if (error)
                return error;
        }
        error = devclass_add_driver(bus_class, module_data->driver,
            module_data->pass, module_data->driver_class);
        if (error && module_data->chain_event) {
            (void)module_data->chain_event(module, MOD_UNLOAD,
                module_data->chain_argument);
        }
        return error;
    }
    if (event == MOD_QUIESCE) {
        newbus_guard_lock();
        for (device_t device = g_devices; device;
            device = device->global_next) {
            if (device->driver == module_data->driver &&
                device_is_attached(device)) {
                newbus_guard_unlock();
                return BSD_NEWBUS_EBUSY;
            }
        }
        newbus_guard_unlock();
        return module_data->chain_event ?
            module_data->chain_event(module, event,
                module_data->chain_argument) : 0;
    }
    if (event == MOD_UNLOAD) {
        error = devclass_delete_driver(bus_class, module_data->driver);
        if (!error && module_data->chain_event) {
            error = module_data->chain_event(module, event,
                module_data->chain_argument);
        }
        return error;
    }
    if (event == MOD_SHUTDOWN) {
        return module_data->chain_event ?
            module_data->chain_event(module, event,
                module_data->chain_argument) : 0;
    }
    return BSD_NEWBUS_EINVAL;
}

static int
devclass_allocate_unit(devclass_t device_class, int requested)
{
    int unit = requested;
    int used;

    newbus_guard_lock();
    if (unit == DEVICE_UNIT_ANY)
        unit = device_class->next_unit;
    do {
        device_t device;

        used = 0;
        for (device = g_devices; device; device = device->global_next) {
            if (device->devclass == device_class && device->unit == unit) {
                used = 1;
                unit++;
                break;
            }
        }
    } while (used && requested == DEVICE_UNIT_ANY);
    if (used) {
        newbus_guard_unlock();
        return -1;
    }
    if (unit >= device_class->next_unit)
        device_class->next_unit = unit + 1;
    newbus_guard_unlock();
    return unit;
}

static void
device_insert_global(device_t device)
{
    newbus_guard_lock();
    device->global_next = g_devices;
    g_devices = device;
    newbus_guard_unlock();
}

static void
device_remove_global(device_t device)
{
    device_t *cursor;

    newbus_guard_lock();
    for (cursor = &g_devices; *cursor; cursor = &(*cursor)->global_next) {
        if (*cursor == device) {
            *cursor = device->global_next;
            break;
        }
    }
    newbus_guard_unlock();
}

bool
bsd_device_is_registered(device_t device)
{
    device_t entry;
    bool registered = false;

    if (!device)
        return false;
    newbus_guard_lock();
    for (entry = g_devices; entry; entry = entry->global_next) {
        if (entry == device) {
            registered = true;
            break;
        }
    }
    newbus_guard_unlock();
    return registered;
}

int
device_set_devclass(device_t device, const char *class_name)
{
    devclass_t device_class;
    int unit;

    if (!device || !class_name)
        return BSD_NEWBUS_EINVAL;
    device_class = devclass_create(class_name);
    if (!device_class)
        return BSD_NEWBUS_ENOMEM;
    if (device->devclass == device_class)
        return 0;
    unit = devclass_allocate_unit(device_class, device->unit);
    if (unit < 0)
        return BSD_NEWBUS_EEXIST;
    device->devclass = device_class;
    device->unit = unit;
    return device_refresh_nameunit(device);
}

int
device_set_devclass_fixed(device_t device, const char *class_name)
{
    int error;

    error = device_set_devclass(device, class_name);
    if (error != 0)
        return error;
    device->flags |= BSD_NEWBUS_DEVICE_FIXED_CLASS;
    return 0;
}

bool
device_is_devclass_fixed(device_t device)
{
    return device &&
        (device->flags & BSD_NEWBUS_DEVICE_FIXED_CLASS) != 0;
}

static device_t
device_allocate(const char *name, int unit, unsigned int order)
{
    device_t device;

    device = bsd_malloc(sizeof(*device), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!device)
        return 0;
    device->unit = unit;
    device->order = order;
    device->state = DS_NOTPRESENT;
    device->flags = BSD_NEWBUS_DEVICE_ENABLED;
    if (name && device_set_devclass_fixed(device, name) != 0) {
        bsd_free(device, M_DEVBUF);
        return 0;
    }
    device_insert_global(device);
    return device;
}

device_t
device_add_child_ordered(device_t parent, unsigned int order,
    const char *name, int unit)
{
    device_t device;
    device_t *cursor;

    if (!parent)
        return 0;
    device = device_allocate(name, unit, order);
    if (!device)
        return 0;
    device->parent = parent;
    if (device_has_quiet_children(parent)) {
        device->flags |= BSD_NEWBUS_DEVICE_QUIET |
            BSD_NEWBUS_DEVICE_QUIET_CHILDREN;
    }

    newbus_guard_lock();
    cursor = &parent->child_head;
    while (*cursor && (*cursor)->order <= order)
        cursor = &(*cursor)->sibling_next;
    device->sibling_next = *cursor;
    *cursor = device;
    if (!device->sibling_next)
        parent->child_tail = device;
    if (!parent->child_tail)
        parent->child_tail = device;
    newbus_guard_unlock();
    return device;
}

device_t
device_add_child(device_t parent, const char *name, int unit)
{
    return device_add_child_ordered(parent, 0, name, unit);
}

device_t
bus_generic_add_child(device_t parent, unsigned int order,
    const char *name, int unit)
{
    return device_add_child_ordered(parent, order, name, unit);
}

device_t
bsd_newbus_create_root(const char *name, int unit, driver_t *driver)
{
    device_t device;

    if (root_bus)
        return root_bus;
    device = device_allocate(name, unit, 0);
    if (!device)
        return 0;
    if (driver && device_set_driver(device, driver) != 0) {
        device_remove_global(device);
        device_release_nameunit(device);
        bsd_free(device, M_DEVBUF);
        return 0;
    }
    device->state = driver ? DS_ALIVE : DS_NOTPRESENT;
    root_bus = device;
    root_devclass = device->devclass;
    return device;
}

int
bsd_newbus_attach_synthetic(device_t parent, const char *name, int unit,
    driver_t *driver, device_t *result)
{
    device_t device;
    int error;

    if (result)
        *result = 0;
    if (!parent || !name || !driver)
        return BSD_NEWBUS_EINVAL;
    device = device_add_child(parent, name, unit);
    if (!device)
        return BSD_NEWBUS_ENOMEM;
    error = device_set_driver(device, driver);
    if (error != 0)
        goto fail;
    device->state = DS_ALIVE;
    error = device_attach(device);
    if (error != 0)
        goto fail;
    if (result)
        *result = device;
    return 0;

fail:
    (void)device_delete_child(parent, device);
    return error;
}

static int
device_call(device_t device, struct kobjop_desc *descriptor)
{
    kobj_method_t **cache_entry;
    kobj_method_t *method;

    if (!device || !device->ops || !descriptor)
        return BSD_NEWBUS_ENXIO;
    cache_entry =
        &device->ops->cache[descriptor->id & (KOBJ_CACHE_SIZE - 1)];
    method = *cache_entry;
    if (method->desc != descriptor)
        method = kobj_lookup_method(device->ops->cls, cache_entry,
            descriptor);
    return ((bsd_device_method_t *)method->func)(device);
}

static void
device_free_owned_softc(device_t device)
{
    if (device->softc &&
        (device->flags & BSD_NEWBUS_DEVICE_EXTERNAL_SOFTC) == 0)
        bsd_free(device->softc, M_DEVBUF);
    device->softc = 0;
    device->flags &= ~BSD_NEWBUS_DEVICE_EXTERNAL_SOFTC;
}

static void
device_unbind_driver(device_t device)
{
    if (device->ops)
        kobj_delete((kobj_t)device, 0);
    device_free_owned_softc(device);
    device->driver = 0;
}

static int
device_bind_driver(device_t device, driver_t *driver, int assign_class)
{
    void *softc = 0;

    if (!device)
        return BSD_NEWBUS_EINVAL;
    if (device->state == DS_ATTACHED || device->state == DS_ATTACHING)
        return BSD_NEWBUS_EBUSY;
    if (device->driver == driver)
        return 0;
    device_unbind_driver(device);
    if (!driver)
        return 0;
    if (driver->size != 0) {
        softc = bsd_malloc(driver->size, M_DEVBUF, M_WAITOK | M_ZERO);
        if (!softc) {
            device_printf(device,
                "unable to allocate %zu-byte softc for %s\n",
                driver->size, driver->name ? driver->name : "driver");
            return BSD_NEWBUS_ENOMEM;
        }
    }
    kobj_init((kobj_t)device, driver);
    device->driver = driver;
    device->softc = softc;
    if (assign_class && !device->devclass &&
        device_set_devclass(device, driver->name) != 0) {
        device_unbind_driver(device);
        return BSD_NEWBUS_ENOMEM;
    }
    return 0;
}

int
device_set_driver(device_t device, driver_t *driver)
{
    return device_bind_driver(device, driver, 1);
}

int
device_probe_child(device_t parent, device_t child)
{
    devclass_t bus_class;
    driver_t *selected = 0;
    int selected_result = INT_MIN;

    if (!parent || !child || !parent->devclass || !device_is_enabled(child))
        return BSD_NEWBUS_ENXIO;
    for (bus_class = parent->devclass; bus_class;
        bus_class = bus_class->parent) {
        bsd_driver_link_t *link;

        for (link = bus_class->drivers; link; link = link->next) {
            int result;
            const char *class_name;

            class_name = child->devclass ?
                devclass_get_name(child->devclass) : 0;
            if (class_name &&
                bsd_strcmp(class_name, link->driver->name) != 0)
                continue;

            device_release_description(child);
            if (device_bind_driver(child, link->driver, 0) != 0)
                continue;
            result = device_call(child, &device_probe_desc);
            if (result <= 0 && result > selected_result) {
                selected = link->driver;
                selected_result = result;
            }
            device_unbind_driver(child);
            if (result == BUS_PROBE_SPECIFIC)
                break;
        }
        if (selected_result == BUS_PROBE_SPECIFIC)
            break;
    }
    if (!selected)
        return BSD_NEWBUS_ENXIO;
    device_release_description(child);
    if (device_bind_driver(child, selected, 1) != 0)
        return BSD_NEWBUS_ENOMEM;
    selected_result = device_call(child, &device_probe_desc);
    if (selected_result > 0) {
        device_unbind_driver(child);
        return selected_result;
    }
    child->state = DS_ALIVE;
    return 0;
}

int
device_probe(device_t device)
{
    int result;

    if (!device)
        return BSD_NEWBUS_EINVAL;
    if (!device->driver)
        return device->parent ?
            device_probe_child(device->parent, device) :
            BSD_NEWBUS_ENXIO;
    result = device_call(device, &device_probe_desc);
    if (result <= 0) {
        device->state = DS_ALIVE;
        return 0;
    }
    device->state = DS_NOTPRESENT;
    return result;
}

int
device_attach(device_t device)
{
    bsd_driver_attach_state_t attach_state;
    int result;

    if (!device || !device->driver)
        return BSD_NEWBUS_EINVAL;
    if (device->state == DS_ATTACHED)
        return 0;
    if (device->state != DS_ALIVE)
        return BSD_NEWBUS_ENXIO;
    device->state = DS_ATTACHING;
    result = driver_attach_hook_begin(device, &attach_state);
    if (result == 0) {
        result = device_call(device, &device_attach_desc);
        driver_attach_hook_end(device, &attach_state, result);
    }
    if (result != 0)
        device_printf(device, "attach failed: error=%d\n", result);
    device->state = result == 0 ? DS_ATTACHED : DS_NOTPRESENT;
    return result;
}

int
device_probe_and_attach(device_t device)
{
    int result;

    result = device_probe(device);
    return result == 0 ? device_attach(device) : result;
}

int
device_detach(device_t device)
{
    int result;

    if (!device)
        return BSD_NEWBUS_EINVAL;
    if (device->state != DS_ATTACHED)
        return 0;
    result = device_call(device, &device_detach_desc);
    if (result == 0) {
        device->state = DS_NOTPRESENT;
        device_unbind_driver(device);
    }
    return result;
}

int
device_shutdown(device_t device)
{
    if (!device || device->state != DS_ATTACHED)
        return 0;
    return device_call(device, &device_shutdown_desc);
}

int
device_suspend(device_t device)
{
    int result;

    if (!device || device->state != DS_ATTACHED)
        return BSD_NEWBUS_EINVAL;
    result = device_call(device, &device_suspend_desc);
    if (result == 0)
        device->flags |= BSD_NEWBUS_DEVICE_SUSPENDED;
    return result;
}

int
device_resume(device_t device)
{
    int result;

    if (!device || device->state != DS_ATTACHED)
        return BSD_NEWBUS_EINVAL;
    if ((device->flags & BSD_NEWBUS_DEVICE_SUSPENDED) == 0)
        return 0;
    result = device_call(device, &device_resume_desc);
    if (result == 0)
        device->flags &= ~BSD_NEWBUS_DEVICE_SUSPENDED;
    return result;
}

int
bus_detach_children(device_t device)
{
    device_t *children;
    int count;
    int result;

    if (!device)
        return BSD_NEWBUS_EINVAL;
    result = device_get_children(device, &children, &count);
    if (result != 0)
        return result;
    for (int index = count - 1; index >= 0; --index) {
        result = device_detach(children[index]);
        if (result != 0)
            break;
    }
    if (children)
        bsd_free(children, M_TEMP);
    return result;
}

int
bus_generic_detach(device_t device)
{
    int result = bus_detach_children(device);

    return result == 0 ? device_delete_children(device) : result;
}

int
bus_generic_shutdown(device_t device)
{
    device_t *children;
    int count;
    int result;

    if (!device)
        return BSD_NEWBUS_EINVAL;
    result = device_get_children(device, &children, &count);
    if (result != 0)
        return result;
    for (int index = count - 1; index >= 0; --index)
        (void)device_shutdown(children[index]);
    if (children)
        bsd_free(children, M_TEMP);
    return 0;
}

int
bus_generic_suspend_child(device_t bus, device_t child)
{
    (void)bus;
    return device_suspend(child);
}

int
bus_generic_resume_child(device_t bus, device_t child)
{
    (void)bus;
    return device_resume(child);
}

int
bus_generic_suspend(device_t device)
{
    device_t *children;
    int count;
    int result;
    int index;

    if (!device)
        return BSD_NEWBUS_EINVAL;
    result = device_get_children(device, &children, &count);
    if (result != 0)
        return result;
    for (index = count - 1; index >= 0; --index) {
        result = bus_generic_suspend_child(device, children[index]);
        if (result != 0)
            break;
    }
    if (result != 0) {
        for (int rollback = index + 1; rollback < count; ++rollback)
            (void)bus_generic_resume_child(device, children[rollback]);
    }
    if (children)
        bsd_free(children, M_TEMP);
    return result;
}

int
bus_generic_resume(device_t device)
{
    device_t *children;
    int count;
    int result;

    if (!device)
        return BSD_NEWBUS_EINVAL;
    result = device_get_children(device, &children, &count);
    if (result != 0)
        return result;
    for (int index = 0; index < count; ++index)
        (void)bus_generic_resume_child(device, children[index]);
    if (children)
        bsd_free(children, M_TEMP);
    return 0;
}

static int
bus_reset_suspend_child(device_t bus, device_t child)
{
#ifdef BSD_BRIDGE_HOST_TEST
    return bus_generic_suspend_child(bus, child);
#else
    return BUS_SUSPEND_CHILD(bus, child);
#endif
}

static int
bus_reset_resume_child(device_t bus, device_t child)
{
#ifdef BSD_BRIDGE_HOST_TEST
    return bus_generic_resume_child(bus, child);
#else
    return BUS_RESUME_CHILD(bus, child);
#endif
}

static int
bus_reset_prepare_child(device_t bus, device_t child)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)bus;
    (void)child;
    return 0;
#else
    return BUS_RESET_PREPARE(bus, child);
#endif
}

static void
bus_reset_post_child(device_t bus, device_t child)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)bus;
    (void)child;
#else
    (void)BUS_RESET_POST(bus, child);
#endif
}

static void
bus_helper_reset_rollback(device_t bus, device_t *children,
    int first, int count, int flags)
{
    for (int index = first; index < count; ++index) {
        bus_reset_post_child(bus, children[index]);
        if ((flags & BSD_NEWBUS_RESET_DETACH) != 0)
            (void)device_probe_and_attach(children[index]);
        else
            (void)bus_reset_resume_child(bus, children[index]);
    }
}

int
bus_helper_reset_prepare(device_t bus, int flags)
{
    device_t *children;
    int count;
    int error;

    if (!bus || device_get_state(bus) != DS_ATTACHED)
        return BSD_NEWBUS_EBUSY;
    error = device_get_children(bus, &children, &count);
    if (error != 0)
        return error;
    for (int index = count - 1; index >= 0; --index) {
        device_t child = children[index];

        if ((flags & BSD_NEWBUS_RESET_DETACH) != 0) {
            error = device_get_state(child) == DS_ATTACHED ?
                device_detach(child) : 0;
        } else {
            error = bus_reset_suspend_child(bus, child);
        }
        if (error == 0) {
            error = bus_reset_prepare_child(bus, child);
            if (error != 0) {
                if ((flags & BSD_NEWBUS_RESET_DETACH) != 0)
                    (void)device_probe_and_attach(child);
                else
                    (void)bus_reset_resume_child(bus, child);
            }
        }
        if (error != 0) {
            bus_helper_reset_rollback(
                bus, children, index + 1, count, flags);
            if (children)
                bsd_free(children, M_TEMP);
            return error;
        }
    }
    if (children)
        bsd_free(children, M_TEMP);
    return 0;
}

int
bus_helper_reset_post(device_t bus, int flags)
{
    device_t *children;
    int count;
    int first_error = 0;
    int error;

    if (!bus)
        return BSD_NEWBUS_EINVAL;
    error = device_get_children(bus, &children, &count);
    if (error != 0)
        return error;
    for (int index = 0; index < count; ++index) {
        bus_reset_post_child(bus, children[index]);
        error = (flags & BSD_NEWBUS_RESET_DETACH) != 0 ?
            device_probe_and_attach(children[index]) :
            bus_reset_resume_child(bus, children[index]);
        if (first_error == 0 && error != 0)
            first_error = error;
    }
    if (children)
        bsd_free(children, M_TEMP);
    return first_error;
}

int
device_delete_child(device_t parent, device_t child)
{
    device_t *cursor;

    if (!parent || !child || child->parent != parent)
        return BSD_NEWBUS_EINVAL;
    if (child->child_head ||
        __atomic_load_n(&child->busy, __ATOMIC_ACQUIRE) != 0)
        return BSD_NEWBUS_EBUSY;
    if (child->state == DS_ATTACHED && device_detach(child) != 0)
        return BSD_NEWBUS_EBUSY;

    newbus_guard_lock();
    for (cursor = &parent->child_head; *cursor;
        cursor = &(*cursor)->sibling_next) {
        if (*cursor == child) {
            *cursor = child->sibling_next;
            break;
        }
    }
    parent->child_tail = parent->child_head;
    while (parent->child_tail && parent->child_tail->sibling_next)
        parent->child_tail = parent->child_tail->sibling_next;
    newbus_guard_unlock();

    device_unbind_driver(child);
    bsd_resource_release_device(child);
    bsd_sysctl_device_destroy(&child->sysctl_state);
    device_properties_release(child);
    if ((child->flags & BSD_NEWBUS_DEVICE_IVARS_OWNED) != 0)
        bsd_free(child->ivars, M_DEVBUF);
    if ((child->flags & BSD_NEWBUS_DEVICE_FIRMWARE_OWNED) != 0)
        bsd_free(child->firmware_metadata, M_DEVBUF);
    device_remove_global(child);
    device_release_nameunit(child);
    if ((child->flags & BSD_NEWBUS_DEVICE_DESC_OWNED) != 0)
        bsd_free((void *)child->description, M_DEVBUF);
    bsd_free(child, M_DEVBUF);
    return 0;
}

void
device_busy(device_t device)
{
    unsigned int previous;

    if (!device)
        bsd_bridge_panic_stop();
    previous = __atomic_fetch_add(
        &device->busy, 1u, __ATOMIC_ACQ_REL);
    if (previous == UINT_MAX)
        bsd_bridge_panic_stop();
    if (previous == 0 && device->parent)
        device_busy(device->parent);
}

void
device_unbusy(device_t device)
{
    unsigned int current;

    if (!device)
        bsd_bridge_panic_stop();
    current = __atomic_load_n(&device->busy, __ATOMIC_ACQUIRE);
    for (;;) {
        if (current == 0)
            bsd_bridge_panic_stop();
        if (__atomic_compare_exchange_n(
            &device->busy, &current, current - 1u, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
    if (current == 1 && device->parent)
        device_unbusy(device->parent);
}

int
device_delete_children(device_t parent)
{
    if (!parent)
        return BSD_NEWBUS_EINVAL;
    while (parent->child_head) {
        device_t child = parent->child_head;
        int result = device_delete_children(child);

        if (result != 0)
            return result;
        result = device_delete_child(parent, child);
        if (result != 0)
            return result;
    }
    return 0;
}

int
device_get_children(device_t device, device_t **children, int *count)
{
    device_t *array;
    device_t child;
    int child_count = 0;
    int index = 0;

    if (!device || !children || !count)
        return BSD_NEWBUS_EINVAL;
    for (child = device->child_head; child; child = child->sibling_next)
        child_count++;
    if (child_count == 0) {
        *children = 0;
        *count = 0;
        return 0;
    }
    array = bsd_malloc((size_t)child_count * sizeof(*array), M_TEMP,
        M_WAITOK);
    if (!array)
        return BSD_NEWBUS_ENOMEM;
    for (child = device->child_head; child; child = child->sibling_next)
        array[index++] = child;
    *children = array;
    *count = child_count;
    return 0;
}

device_t
device_find_child(device_t parent, const char *class_name, int unit)
{
    device_t child;

    if (!parent || !class_name)
        return 0;
    for (child = parent->child_head; child; child = child->sibling_next) {
        const char *name = device_get_name(child);

        if (name && bsd_strcmp(name, class_name) == 0 &&
            (unit == DEVICE_UNIT_ANY || unit == child->unit))
            return child;
    }
    return 0;
}

device_t
devclass_get_device(devclass_t device_class, int unit)
{
    device_t device;

    for (device = g_devices; device; device = device->global_next) {
        if (device->devclass == device_class && device->unit == unit)
            return device;
    }
    return 0;
}

void *
devclass_get_softc(devclass_t device_class, int unit)
{
    return device_get_softc(devclass_get_device(device_class, unit));
}

int
devclass_get_devices(devclass_t device_class, device_t **devices,
    int *count)
{
    device_t *array;
    size_t capacity;

    if (!devices || !count)
        return BSD_NEWBUS_EINVAL;
    *devices = 0;
    *count = 0;
    if (!device_class)
        return BSD_NEWBUS_EINVAL;
    for (;;) {
        device_t device;
        size_t actual = 0;

        newbus_guard_lock();
        for (device = g_devices; device; device = device->global_next) {
            if (device->devclass == device_class)
                actual++;
        }
        newbus_guard_unlock();
        capacity = actual;
        array = bsd_malloc((capacity != 0 ? capacity : 1u) *
            sizeof(*array), M_TEMP, M_WAITOK | M_ZERO);
        if (!array)
            return BSD_NEWBUS_ENOMEM;

        newbus_guard_lock();
        actual = 0;
        for (device = g_devices; device; device = device->global_next) {
            if (device->devclass == device_class)
                actual++;
        }
        if (actual <= capacity) {
            size_t index = 0;

            for (device = g_devices; device; device = device->global_next) {
                if (device->devclass == device_class)
                    array[index++] = device;
            }
            newbus_guard_unlock();
            *devices = array;
            *count = (int)actual;
            return 0;
        }
        newbus_guard_unlock();
        bsd_free(array, M_TEMP);
    }
}

int
devclass_get_drivers(devclass_t device_class, driver_t ***drivers,
    int *count)
{
    driver_t **array;
    size_t capacity;

    if (!device_class || !drivers || !count)
        return BSD_NEWBUS_EINVAL;
    for (;;) {
        bsd_driver_link_t *link;
        size_t actual = 0;

        newbus_guard_lock();
        for (link = device_class->drivers; link; link = link->next)
            actual++;
        newbus_guard_unlock();
        capacity = actual;
        array = bsd_malloc((capacity != 0 ? capacity : 1u) *
            sizeof(*array), M_TEMP, M_NOWAIT | M_ZERO);
        if (!array)
            return BSD_NEWBUS_ENOMEM;

        newbus_guard_lock();
        actual = 0;
        for (link = device_class->drivers; link; link = link->next)
            actual++;
        if (actual <= capacity) {
            size_t index = 0;

            for (link = device_class->drivers; link; link = link->next)
                array[index++] = link->driver;
            newbus_guard_unlock();
            *drivers = array;
            *count = (int)actual;
            return 0;
        }
        newbus_guard_unlock();
        bsd_free(array, M_TEMP);
    }
}

int
devclass_get_count(devclass_t device_class)
{
    device_t device;
    int count = 0;

    for (device = g_devices; device; device = device->global_next) {
        if (device->devclass == device_class)
            count++;
    }
    return count;
}

int
devclass_get_maxunit(devclass_t device_class)
{
    return device_class ? device_class->next_unit : 0;
}

int
devclass_find_free_unit(devclass_t device_class, int unit)
{
    if (!device_class)
        return unit;
    if (unit < 0)
        unit = 0;
    while (unit < INT_MAX && devclass_get_device(device_class, unit))
        ++unit;
    return unit;
}

void
devclass_set_parent(devclass_t device_class, devclass_t parent)
{
    if (device_class)
        device_class->parent = parent;
}

devclass_t
devclass_get_parent(devclass_t device_class)
{
    return device_class ? device_class->parent : 0;
}

const char *
device_get_name(device_t device)
{
    if (!device)
        return 0;
    if (device->devclass)
        return device->devclass->name;
    return device->driver ? device->driver->name : 0;
}

const char *
device_get_nameunit(device_t device)
{
    return device ? device->nameunit : 0;
}

const char *
device_get_desc(device_t device)
{
    return device ? device->description : 0;
}

device_t
device_get_parent(device_t device)
{
    return device ? device->parent : 0;
}

driver_t *
device_get_driver(device_t device)
{
    return device ? device->driver : 0;
}

devclass_t
device_get_devclass(device_t device)
{
    return device ? device->devclass : 0;
}

void *
device_get_softc(device_t device)
{
    return device ? device->softc : 0;
}

void *
device_get_ivars(device_t device)
{
    return device ? device->ivars : 0;
}

void *
bsd_device_get_firmware_metadata(device_t device)
{
    return device ? device->firmware_metadata : 0;
}

int
device_get_unit(device_t device)
{
    return device ? device->unit : -1;
}

device_state_t
device_get_state(device_t device)
{
    return device ? device->state : DS_NOTPRESENT;
}

uint32_t
device_get_flags(device_t device)
{
    return device ? device->devflags : 0;
}

int
device_is_alive(device_t device)
{
    return device && device->state >= DS_ALIVE;
}

int
device_is_attached(device_t device)
{
    return device && device->state == DS_ATTACHED;
}

int
device_is_enabled(device_t device)
{
    return device &&
        (device->flags & BSD_NEWBUS_DEVICE_ENABLED) != 0;
}

int
device_is_suspended(device_t device)
{
    return device &&
        (device->flags & BSD_NEWBUS_DEVICE_SUSPENDED) != 0;
}

int
device_is_quiet(device_t device)
{
    return device && (device->flags & BSD_NEWBUS_DEVICE_QUIET) != 0;
}

int
device_has_quiet_children(device_t device)
{
    return device &&
        (device->flags & BSD_NEWBUS_DEVICE_QUIET_CHILDREN) != 0;
}

bool
device_has_children(device_t device)
{
    return device && device->child_head;
}

int
device_set_unit(device_t device, int unit)
{
    if (!device || unit < 0 || device->state == DS_ATTACHED)
        return BSD_NEWBUS_EINVAL;
    if (device->devclass) {
        device_t conflict = devclass_get_device(device->devclass, unit);

        if (conflict && conflict != device)
            return BSD_NEWBUS_EEXIST;
    }
    device->unit = unit;
    return device_refresh_nameunit(device);
}

void
device_set_softc(device_t device, void *softc)
{
    if (!device)
        return;
    device_free_owned_softc(device);
    device->softc = softc;
    if (softc)
        device->flags |= BSD_NEWBUS_DEVICE_EXTERNAL_SOFTC;
}

void
device_claim_softc(device_t device)
{
    if (!device)
        return;
    if (device->softc)
        device->flags |= BSD_NEWBUS_DEVICE_EXTERNAL_SOFTC;
    else
        device->flags &= ~BSD_NEWBUS_DEVICE_EXTERNAL_SOFTC;
}

void
device_free_softc(void *softc)
{
    if (softc)
        bsd_free(softc, M_DEVBUF);
}

void
device_set_ivars(device_t device, void *ivars)
{
    if (!device)
        return;
    if ((device->flags & BSD_NEWBUS_DEVICE_IVARS_OWNED) != 0)
        bsd_free(device->ivars, M_DEVBUF);
    device->ivars = ivars;
    device->flags &= ~BSD_NEWBUS_DEVICE_IVARS_OWNED;
}

void
bsd_device_set_ivars_owned(device_t device, void *ivars)
{
    if (!device)
        return;
    device_set_ivars(device, ivars);
    if (ivars)
        device->flags |= BSD_NEWBUS_DEVICE_IVARS_OWNED;
}

void
bsd_device_set_firmware_metadata_owned(device_t device, void *metadata)
{
    if (!device)
        return;
    if ((device->flags & BSD_NEWBUS_DEVICE_FIRMWARE_OWNED) != 0)
        bsd_free(device->firmware_metadata, M_DEVBUF);
    device->firmware_metadata = metadata;
    device->flags &= ~BSD_NEWBUS_DEVICE_FIRMWARE_OWNED;
    if (metadata)
        device->flags |= BSD_NEWBUS_DEVICE_FIRMWARE_OWNED;
}

void
device_set_flags(device_t device, uint32_t flags)
{
    if (device)
        device->devflags = flags;
}

static void
device_release_description(device_t device)
{
    if ((device->flags & BSD_NEWBUS_DEVICE_DESC_OWNED) != 0)
        bsd_free((void *)device->description, M_DEVBUF);
    device->description = 0;
    device->flags &= ~BSD_NEWBUS_DEVICE_DESC_OWNED;
}

void
device_set_desc(device_t device, const char *description)
{
    if (!device)
        return;
    device_release_description(device);
    device->description = description;
}

void
device_set_desc_copy(device_t device, const char *description)
{
    char *copy;

    if (!device)
        return;
    copy = newbus_string_duplicate(description ? description : "");
    if (!copy)
        return;
    device_release_description(device);
    device->description = copy;
    device->flags |= BSD_NEWBUS_DEVICE_DESC_OWNED;
}

void
device_set_descf(device_t device, const char *format, ...)
{
    char buffer[256];
    va_list arguments;

    if (!device || !format)
        return;
    va_start(arguments, format);
    (void)bsd_vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    device_set_desc_copy(device, buffer);
}

void
device_enable(device_t device)
{
    if (device)
        device->flags |= BSD_NEWBUS_DEVICE_ENABLED;
}

void
device_disable(device_t device)
{
    if (device)
        device->flags &= ~BSD_NEWBUS_DEVICE_ENABLED;
}

void
device_quiet(device_t device)
{
    if (device)
        device->flags |= BSD_NEWBUS_DEVICE_QUIET;
}

void
device_quiet_children(device_t device)
{
    if (device)
        device->flags |= BSD_NEWBUS_DEVICE_QUIET_CHILDREN;
}

void
device_verbose(device_t device)
{
    if (device)
        device->flags &= ~BSD_NEWBUS_DEVICE_QUIET;
}

int
device_print_prettyname(device_t device)
{
    const char *name = device_get_name(device);

    if (!name)
        return bsd_printf("unknown: ");
    return bsd_printf("%s%d: ", name, device_get_unit(device));
}

int
device_printf(device_t device, const char *format, ...)
{
    char buffer[512];
    va_list arguments;
    int result;

    if (!format)
        return 0;
    va_start(arguments, format);
    result = bsd_vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    printf("%s: %s", device_get_nameunit(device), buffer);
    return result;
}

int
device_log(device_t device, int priority, const char *format, ...)
{
    char buffer[512];
    va_list arguments;
    int result;

    if (!format)
        return 0;
    va_start(arguments, format);
    result = bsd_vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    bsd_log(priority, "%s: %s", device_get_nameunit(device), buffer);
    return result;
}

void
bsd_device_set_dma_tag(device_t device, bus_dma_tag_t tag)
{
    if (device)
        device->dma_tag = tag;
}

bus_dma_tag_t
bus_get_dma_tag(device_t device)
{
    while (device) {
        if (device->dma_tag)
            return device->dma_tag;
        device = device->parent;
    }
    return 0;
}

int
bus_get_domain(device_t device, int *domain)
{
    if (!device || !domain)
        return BSD_NEWBUS_EINVAL;
    *domain = 0;
    return 0;
}

int
bus_child_present(device_t child)
{
    return device_is_alive(child) ? -1 : 0;
}

struct sysctl_ctx_list *
device_get_sysctl_ctx(device_t device)
{
    if (!device)
        return 0;
    return bsd_sysctl_device_context(&device->sysctl_state,
        device_get_nameunit(device));
}

struct sysctl_oid *
device_get_sysctl_tree(device_t device)
{
    if (!device)
        return 0;
    return bsd_sysctl_device_tree(&device->sysctl_state,
        device_get_nameunit(device));
}
