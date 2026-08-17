/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared EdgeOS BSD bridge newbus lifecycle. */

#include <stddef.h>
#include <stdint.h>

#include <sys/bus.h>
#include <sys/cpuset.h>
#include <sys/kernel.h>
#include <sys/rman.h>
#include <sys/smp.h>
#include <machine/resource.h>

#include <bus_if.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/driver_hooks.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/systm.h"

#define TEST_ARENA_SIZE (8u * 1024u * 1024u)
#define TEST_PAGE_SIZE 4096u
#define assert(condition) do {                                          \
    if (!(condition))                                                    \
        __builtin_trap();                                                \
} while (0)

struct kobjop_desc device_probe_desc = {
    0, { &device_probe_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_attach_desc = {
    0, { &device_attach_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_detach_desc = {
    0, { &device_detach_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_shutdown_desc = {
    0, { &device_shutdown_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_suspend_desc = {
    0, { &device_suspend_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_resume_desc = {
    0, { &device_resume_desc, (kobjop_t)kobj_error_method }
};
struct kobjop_desc device_identify_desc = {
    0, { &device_identify_desc, (kobjop_t)kobj_error_method }
};

int
bus_generic_suspend_intr(device_t bus, device_t child,
    struct resource *resource)
{
    (void)bus;
    (void)child;
    (void)resource;
    return 0;
}

int
bus_generic_resume_intr(device_t bus, device_t child,
    struct resource *resource)
{
    (void)bus;
    (void)child;
    (void)resource;
    return 0;
}

typedef struct {
    int probe_count;
    int attach_count;
    int detach_count;
    int suspend_count;
    int resume_count;
    int value;
} test_softc_t;

static int wrong_probe_count;
static int lifecycle_log[16];
static int lifecycle_log_count;
static int suspend_failure_unit = -1;
static int interrupt_bind_count;
static int interrupt_bind_cpu = -1;
static char interrupt_description[64];
static int attach_hook_active;
static int attach_hook_begin_count;
static int attach_hook_end_count;
static int attach_hook_last_result;
static int identify_count;
static int property_destructor_count;
static void *property_last_value;
static void *property_last_context;
static _Alignas(TEST_PAGE_SIZE) uint8_t g_test_arena[TEST_ARENA_SIZE];
static size_t g_test_arena_offset;

static void
test_property_destructor(device_t device, const char *name, void *value,
    void *context)
{
    assert(device != 0);
    assert(name != 0);
    property_destructor_count++;
    property_last_value = value;
    property_last_context = context;
}

int
kernel_boot_option_get(const char *name, char *value, size_t capacity)
{
    (void)name;
    (void)value;
    (void)capacity;
    return 0;
}

void
config_intrhook_oneshot(ich_func_t function, void *argument)
{
    function(argument);
}

int
bus_setup_intr(device_t device, struct resource *resource, int flags,
    driver_filter_t *filter, driver_intr_t *handler, void *argument,
    void **cookie)
{
    (void)device;
    (void)resource;
    (void)flags;
    (void)filter;
    (void)handler;
    (void)argument;
    (void)cookie;
    return 45;
}

static int
test_bus_bind_intr(device_t bus, device_t child,
    struct resource *resource, int cpu)
{
    assert(bus != 0);
    assert(child != 0);
    assert(resource != 0);
    interrupt_bind_count++;
    interrupt_bind_cpu = cpu;
    return 0;
}

static int
test_bus_describe_intr(device_t bus, device_t child,
    struct resource *resource, void *cookie, const char *description)
{
    assert(bus != 0);
    assert(child != 0);
    assert(resource != 0);
    assert(cookie == (void *)(uintptr_t)0x30);
    (void)bsd_strlcpy(interrupt_description, description,
        sizeof(interrupt_description));
    return 0;
}

static int
test_bus_get_cpus(device_t bus, device_t child,
    enum cpu_sets operation, size_t set_size, struct _cpuset *set)
{
    assert(bus != 0);
    assert(child != 0);
    assert(set_size >= sizeof(*set));
    if (operation != LOCAL_CPUS)
        return 22;
    CPU_ZERO(set);
    CPU_SET(1, set);
    return 0;
}

static void
record_lifecycle(device_t device, int operation)
{
    lifecycle_log[lifecycle_log_count++] =
        operation * 10 + device_get_unit(device);
}

static int
wrong_probe(device_t device)
{
    test_softc_t *softc = device_get_softc(device);

    wrong_probe_count++;
    softc->probe_count++;
    device_set_desc(device, "lower priority driver");
    return BUS_PROBE_GENERIC;
}

static int
test_probe(device_t device)
{
    test_softc_t *softc = device_get_softc(device);

    softc->probe_count++;
    device_set_desc(device, "test driver");
    return BUS_PROBE_DEFAULT;
}

static void
test_identify(driver_t *driver, device_t parent)
{
    assert(driver != 0);
    assert(parent != 0);
    identify_count++;
}

static int
test_attach(device_t device)
{
    test_softc_t *softc = device_get_softc(device);

    assert(attach_hook_active == 1);
    softc->attach_count++;
    if (device_get_unit(device) == 2)
        return 5;
    softc->value = 42;
    return 0;
}

static int
test_attach_hook_begin(device_t device, uintptr_t *cookie, void *context)
{
    assert(device != 0);
    assert(device_get_state(device) == DS_ATTACHING);
    assert(context == (void *)(uintptr_t)0x1234);
    assert(attach_hook_active == 0);
    attach_hook_active = 1;
    attach_hook_begin_count++;
    *cookie = (uintptr_t)(device_get_unit(device) + 10);
    return 0;
}

static void
test_attach_hook_end(device_t device, uintptr_t cookie, int result,
    void *context)
{
    assert(device != 0);
    assert(cookie == (uintptr_t)(device_get_unit(device) + 10));
    assert(context == (void *)(uintptr_t)0x1234);
    assert(attach_hook_active == 1);
    attach_hook_active = 0;
    attach_hook_end_count++;
    attach_hook_last_result = result;
}

static int
test_detach(device_t device)
{
    test_softc_t *softc = device_get_softc(device);

    softc->detach_count++;
    record_lifecycle(device, 4);
    return 0;
}

static int
test_shutdown(device_t device)
{
    record_lifecycle(device, 3);
    return 0;
}

static int
test_suspend(device_t device)
{
    test_softc_t *softc = device_get_softc(device);

    softc->suspend_count++;
    record_lifecycle(device, 1);
    if (device_get_unit(device) == suspend_failure_unit)
        return 16;
    return 0;
}

static int
test_resume(device_t device)
{
    test_softc_t *softc = device_get_softc(device);

    softc->resume_count++;
    record_lifecycle(device, 2);
    return 0;
}

static const struct kobj_method test_methods[] = {
    { &device_identify_desc, (kobjop_t)test_identify },
    { &device_probe_desc, (kobjop_t)test_probe },
    { &device_attach_desc, (kobjop_t)test_attach },
    { &device_detach_desc, (kobjop_t)test_detach },
    { &device_shutdown_desc, (kobjop_t)test_shutdown },
    { &device_suspend_desc, (kobjop_t)test_suspend },
    { &device_resume_desc, (kobjop_t)test_resume },
    KOBJMETHOD_END,
};

static const struct kobj_method wrong_methods[] = {
    { &device_probe_desc, (kobjop_t)wrong_probe },
    KOBJMETHOD_END,
};

static const struct kobj_method root_methods[] = {
    { &bus_bind_intr_desc, (kobjop_t)test_bus_bind_intr },
    { &bus_describe_intr_desc, (kobjop_t)test_bus_describe_intr },
    { &bus_get_cpus_desc, (kobjop_t)test_bus_get_cpus },
    KOBJMETHOD_END,
};

static struct kobj_class root_driver = {
    "testbus", root_methods, 0, 0, 0, 0
};

static struct kobj_class wrong_driver = {
    "wrongdev", wrong_methods, sizeof(test_softc_t), 0, 0, 0
};

static struct kobj_class test_driver = {
    "testdev", test_methods, sizeof(test_softc_t), 0, 0, 0
};

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    size_t bytes;
    void *memory;

    (void)context;
    if (page_count > SIZE_MAX / TEST_PAGE_SIZE)
        return 0;
    bytes = (size_t)page_count * TEST_PAGE_SIZE;
    if (bytes > TEST_ARENA_SIZE - g_test_arena_offset)
        return 0;
    memory = g_test_arena + g_test_arena_offset;
    g_test_arena_offset += bytes;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)base;
    (void)page_count;
    (void)context;
}

int
main(void)
{
    bsd_allocator_ops_t allocator_ops = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    device_t root;
    device_t child;
    device_t second_child;
    device_t generic_child;
    device_t failed_child;
    device_t *children;
    device_t *class_devices;
    driver_t **class_drivers;
    devclass_t root_class;
    devclass_t test_class;
    test_softc_t *softc;
    int child_count;
    int class_count;
    int driver_count;
    int dma_marker;
    int interrupt_marker;
    int property_first;
    int property_second;
    void *property_value;
    cpuset_t cpus;
    struct resource_list resources;
    struct resource *listed_resource;

    assert(bsd_allocator_initialize(&allocator_ops) == 0);
    assert(bsd_driver_attach_hook_register("testdev",
        test_attach_hook_begin, test_attach_hook_end,
        (void *)(uintptr_t)0x1234) == 0);
    assert(bsd_driver_attach_hook_register("testdev",
        test_attach_hook_begin, test_attach_hook_end,
        (void *)(uintptr_t)0x1234) == 0);
    root = bsd_newbus_create_root("testbus", 0, &root_driver);
    assert(root != 0);
    root_class = device_get_devclass(root);
    assert(root_class != 0);
    assert(device_is_devclass_fixed(root));
    assert(devclass_add_driver(root_class, &wrong_driver, 0, 0) == 0);
    assert(devclass_add_driver(root_class, &test_driver, 0, 0) == 0);
    test_class = devclass_find("testdev");
    assert(test_class != 0);
    class_devices = (device_t *)(uintptr_t)1;
    class_count = -1;
    assert(devclass_get_devices(test_class, &class_devices,
        &class_count) == 0);
    assert(class_devices != 0);
    assert(class_count == 0);
    bsd_free(class_devices, M_TEMP);
    class_devices = (device_t *)(uintptr_t)1;
    class_count = -1;
    assert(devclass_get_devices(0, &class_devices, &class_count) == 22);
    assert(class_devices == 0);
    assert(class_count == 0);
    assert(wrong_driver.ops != 0);
    assert(wrong_driver.refs == 1);
    assert(test_driver.ops != 0);
    assert(test_driver.refs == 1);
    class_drivers = 0;
    driver_count = -1;
    assert(devclass_get_drivers(root_class, &class_drivers,
        &driver_count) == 0);
    assert(driver_count == 2);
    assert(class_drivers[0] == &wrong_driver);
    assert(class_drivers[1] == &test_driver);
    bsd_free(class_drivers, M_TEMP);
    bus_identify_children(root);
    assert(identify_count == 1);

    child = device_add_child(root, 0, DEVICE_UNIT_ANY);
    assert(child != 0);
    assert(!device_is_devclass_fixed(child));
    assert(device_probe_and_attach(child) == 0);
    assert(device_is_attached(child));
    assert(device_get_driver(child) == &test_driver);
    assert(bsd_strcmp(device_get_name(child), "testdev") == 0);
    assert(device_get_unit(child) == 0);
    assert(device_get_nameunit(child) != 0);
    assert(device_print_prettyname(child) == 10);
    assert(device_get_desc(child) != 0);
    softc = device_get_softc(child);
    assert(softc != 0);
    assert(softc->probe_count == 1);
    assert(wrong_probe_count == 1);
    assert(softc->attach_count == 1);
    assert(softc->value == 42);
    device_busy(child);
    assert(device_delete_child(root, child) == 16);
    device_unbusy(child);
    assert(device_is_attached(child));

    resource_list_init(&resources);
    assert(resource_list_add_next(
        &resources, SYS_RES_IRQ, 5, 5, 1) == 0);
    listed_resource = resource_list_alloc(&resources, root, child,
        SYS_RES_IRQ, 0, 0, RM_MAX_END, 1, 0);
    assert(listed_resource != 0);
    assert(resource_list_busy(&resources, SYS_RES_IRQ, 0));
    assert(resource_list_release(
        &resources, root, child, listed_resource) == 0);
    assert(!resource_list_busy(&resources, SYS_RES_IRQ, 0));
    resource_list_free(&resources);

    bsd_device_set_dma_tag(root, (bus_dma_tag_t)&dma_marker);
    assert(bus_get_dma_tag(child) == (bus_dma_tag_t)&dma_marker);
    assert(device_get_children(root, &children, &child_count) == 0);
    assert(child_count == 1);
    assert(children[0] == child);
    bsd_free(children, M_TEMP);

    assert(bus_bind_intr(child,
        (struct resource *)&interrupt_marker, 1) == 0);
    assert(interrupt_bind_count == 1);
    assert(interrupt_bind_cpu == 1);
    assert(bus_describe_intr(child,
        (struct resource *)&interrupt_marker,
        (void *)(uintptr_t)0x30, "%s-%d", "queue", 2) == 0);
    assert(bsd_strcmp(interrupt_description, "queue-2") == 0);
    CPU_ZERO(&cpus);
    assert(bus_get_cpus(child, LOCAL_CPUS, sizeof(cpus), &cpus) == 0);
    assert(bsd_cpuset_low64(&cpus) == UINT64_C(2));
    CPU_ZERO(&all_cpus);
    CPU_SET(0, &all_cpus);
    CPU_SET(1, &all_cpus);
    CPU_ZERO(&cpus);
    assert(bus_get_cpus(child, INTR_CPUS, sizeof(cpus), &cpus) == 0);
    assert(bsd_cpuset_low64(&cpus) == UINT64_C(3));

    assert(device_suspend(child) == 0);
    assert(device_is_suspended(child));
    assert(device_resume(child) == 0);
    assert(!device_is_suspended(child));
    assert(softc->suspend_count == 1);
    assert(softc->resume_count == 1);

    second_child = device_add_child(root, 0, DEVICE_UNIT_ANY);
    assert(second_child != 0);
    assert(device_probe_and_attach(second_child) == 0);
    class_devices = 0;
    class_count = -1;
    assert(devclass_get_devices(test_class, &class_devices,
        &class_count) == 0);
    assert(class_count == 2);
    assert(class_devices[0] == child ||
        class_devices[1] == child);
    assert(class_devices[0] == second_child ||
        class_devices[1] == second_child);
    bsd_free(class_devices, M_TEMP);

    generic_child = bus_generic_add_child(
        root, 25, "fixeddev", DEVICE_UNIT_ANY);
    assert(generic_child != 0);
    assert(device_get_parent(generic_child) == root);
    assert(device_is_devclass_fixed(generic_child));
    assert(bsd_strcmp(device_get_name(generic_child), "fixeddev") == 0);
    property_value = 0;
    assert(device_get_prop(generic_child, "iommu-unit",
        &property_value) == 2);
    assert(device_set_prop(generic_child, "iommu-unit", &property_first,
        test_property_destructor, (void *)(uintptr_t)1) == 0);
    assert(device_get_prop(generic_child, "iommu-unit",
        &property_value) == 0);
    assert(property_value == &property_first);
    assert(device_set_prop(generic_child, "iommu-unit", &property_second,
        test_property_destructor, (void *)(uintptr_t)2) == 0);
    assert(property_destructor_count == 1);
    assert(property_last_value == &property_first);
    assert(property_last_context == (void *)(uintptr_t)1);
    assert(device_set_prop(child, "global-property", &property_first,
        test_property_destructor, (void *)(uintptr_t)3) == 0);
    assert(device_set_prop(generic_child, "global-property",
        &property_second, test_property_destructor,
        (void *)(uintptr_t)4) == 0);
    device_clear_prop_alldev("global-property");
    assert(property_destructor_count == 3);
    assert(device_get_prop(child, "global-property", &property_value) == 2);
    assert(device_get_prop(generic_child, "global-property",
        &property_value) == 2);
    assert(device_delete_child(root, generic_child) == 0);
    assert(property_destructor_count == 4);
    assert(property_last_value == &property_second);
    assert(property_last_context == (void *)(uintptr_t)2);

    device_quiet_children(root);
    assert(device_has_quiet_children(root));
    failed_child = device_add_child(root, "fixeddev", DEVICE_UNIT_ANY);
    assert(failed_child != 0);
    assert(device_is_devclass_fixed(failed_child));
    assert(device_is_quiet(failed_child));
    assert(device_has_quiet_children(failed_child));
    assert(device_delete_child(root, failed_child) == 0);

    lifecycle_log_count = 0;
    assert(bus_generic_shutdown(root) == 0);
    assert(lifecycle_log_count == 2);
    assert(lifecycle_log[0] == 31);
    assert(lifecycle_log[1] == 30);

    lifecycle_log_count = 0;
    suspend_failure_unit = 0;
    assert(bus_generic_suspend(root) == 16);
    assert(lifecycle_log_count == 3);
    assert(lifecycle_log[0] == 11);
    assert(lifecycle_log[1] == 10);
    assert(lifecycle_log[2] == 21);
    assert(!device_is_suspended(second_child));
    suspend_failure_unit = -1;

    lifecycle_log_count = 0;
    assert(bus_generic_suspend(root) == 0);
    assert(lifecycle_log[0] == 11);
    assert(lifecycle_log[1] == 10);
    assert(bus_generic_resume(root) == 0);
    assert(lifecycle_log[2] == 20);
    assert(lifecycle_log[3] == 21);

    failed_child = device_add_child(root, 0, DEVICE_UNIT_ANY);
    assert(failed_child != 0);
    assert(device_probe_and_attach(failed_child) == 5);
    assert(device_get_state(failed_child) == DS_NOTPRESENT);
    assert(attach_hook_begin_count == 3);
    assert(attach_hook_end_count == 3);
    assert(attach_hook_last_result == 5);
    assert(attach_hook_active == 0);

    wrong_probe_count = 3;
    generic_child = device_add_child(root, "testdev", DEVICE_UNIT_ANY);
    assert(generic_child != 0);
    assert(device_is_devclass_fixed(generic_child));
    assert(device_probe_and_attach(generic_child) == 0);
    assert(device_get_driver(generic_child) == &test_driver);
    assert(wrong_probe_count == 3);
    assert(attach_hook_begin_count == 4);
    assert(attach_hook_end_count == 4);
    assert(device_delete_child(root, generic_child) == 0);

    lifecycle_log_count = 0;
    assert(bus_generic_detach(root) == 0);
    assert(lifecycle_log_count == 2);
    assert(lifecycle_log[0] == 41);
    assert(lifecycle_log[1] == 40);
    assert(!device_has_children(root));
    assert(devclass_delete_driver(root_class, &test_driver) == 0);
    assert(devclass_delete_driver(root_class, &wrong_driver) == 0);
    assert(test_driver.refs == 0);
    assert(test_driver.ops == 0);
    assert(wrong_driver.refs == 0);
    assert(wrong_driver.ops == 0);
    return 0;
}
