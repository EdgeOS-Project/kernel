/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for BSD bridge static startup and module lifecycle. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/module.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/package.h"
#include "compat/freebsd/sys/module.h"
#include "bsd_module_linker_test_adapter.h"

bsd_driver_package_record_t bsd_driver_package_registry[] = {
    {
        .descriptor = {
            .id = "freebsd-module-test",
            .provider = "freebsd",
            .upstream_commit = "0123456789abcdef0123456789abcdef01234567",
            .source_count = 2,
            .builtin_module_count = 2,
            .loadable_module_count = 0,
            .disabled_module_count = 0,
        },
        .state = BSD_DRIVER_PACKAGE_REGISTERED,
    },
};

const size_t bsd_driver_package_registry_count =
    sizeof(bsd_driver_package_registry) /
    sizeof(bsd_driver_package_registry[0]);

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

static int lifecycle_log[32];
static size_t lifecycle_count;
static int driver_chain_loads;
static int driver_chain_quiesces;
static int driver_chain_unloads;
static int dynamic_module_loads;
static int dynamic_module_unloads;
static int dynamic_sysuninit_calls;

static void
record_lifecycle(int value)
{
    assert(lifecycle_count < sizeof(lifecycle_log) /
        sizeof(lifecycle_log[0]));
    lifecycle_log[lifecycle_count++] = value;
}

static void
early_startup(const void *argument)
{
    record_lifecycle((int)(uintptr_t)argument);
}

static void
late_startup(const void *argument)
{
    record_lifecycle((int)(uintptr_t)argument);
}

static void
early_shutdown(const void *argument)
{
    record_lifecycle((int)(uintptr_t)argument);
}

static void
late_shutdown(const void *argument)
{
    record_lifecycle((int)(uintptr_t)argument);
}

C_SYSINIT(test_early_startup, SI_SUB_LOCK, SI_ORDER_FIRST,
    early_startup, (const void *)(uintptr_t)1);
C_SYSINIT(test_late_startup, SI_SUB_CONFIGURE, SI_ORDER_ANY,
    late_startup, (const void *)(uintptr_t)4);
C_SYSUNINIT(test_early_shutdown, SI_SUB_LOCK, SI_ORDER_FIRST,
    early_shutdown, (const void *)(uintptr_t)6);
C_SYSUNINIT(test_late_shutdown, SI_SUB_CONFIGURE, SI_ORDER_ANY,
    late_shutdown, (const void *)(uintptr_t)5);

static int
base_module_event(module_t module, int event, void *argument)
{
    (void)argument;
    assert(module != 0);
    assert(module_getname(module) != 0);
    if (event == MOD_LOAD) {
        record_lifecycle(2);
        return 0;
    }
    if (event == MOD_QUIESCE)
        return 45;
    if (event == MOD_UNLOAD) {
        record_lifecycle(8);
        return 0;
    }
    if (event == MOD_SHUTDOWN)
        return 0;
    return 45;
}

static moduledata_t base_module_data = {
    "bridge_base",
    base_module_event,
    0,
};

DECLARE_MODULE(bridge_base, base_module_data, SI_SUB_DRIVERS,
    SI_ORDER_FIRST);
MODULE_VERSION(bridge_base, 3);

static int
dynamic_module_event(module_t module, int event, void *argument)
{
    (void)argument;
    assert(module != 0);
    if (event == MOD_LOAD) {
        dynamic_module_loads++;
        return 0;
    }
    if (event == MOD_UNLOAD) {
        dynamic_module_unloads++;
        return 0;
    }
    if (event == MOD_QUIESCE || event == MOD_SHUTDOWN)
        return 0;
    return 45;
}

static moduledata_t dynamic_module_data = {
    "dynamic_driver",
    dynamic_module_event,
    0,
};

static const struct bsd_module_static_record dynamic_declaration = {
    BSD_MODULE_DECLARATION, "dynamic_driver", 0, &dynamic_module_data,
    0, 0, 0, MDT_MODULE,
};

static const struct bsd_module_static_record dynamic_dependency = {
    BSD_MODULE_DEPENDENCY, "dynamic_driver", "bridge_base", 0,
    3, 3, 3, MDT_DEPEND,
};

static const struct bsd_module_static_record dynamic_version = {
    BSD_MODULE_VERSION, "dynamic_driver", "dynamic_driver", 0,
    7, 7, 7, MDT_VERSION,
};

static const struct mod_pnp_match_info dynamic_pnp = {
    "dynamic test", "testbus", 0, 0, 0,
};

static const struct bsd_module_static_record dynamic_pnp_record = {
    BSD_MODULE_PNP, "dynamic_driver", "testbus", &dynamic_pnp,
    0, 0, 0, MDT_PNP_INFO,
};

static const struct sysinit dynamic_sysinit = {
    SI_SUB_DRIVERS, SI_ORDER_ANY,
    (sysinit_cfunc_t)(sysinit_nfunc_t)module_register_init,
    &dynamic_module_data, "dynamic_driver",
};

static void
dynamic_sysuninit_callback(const void *argument)
{
    (void)argument;
    dynamic_sysuninit_calls++;
}

static const struct sysinit dynamic_sysuninit = {
    SI_SUB_DRIVERS, SI_ORDER_ANY, dynamic_sysuninit_callback,
    0, "dynamic_driver",
};

static const void *const dynamic_sysinit_records[] = {
    &dynamic_sysinit,
};

static const void *const dynamic_sysuninit_records[] = {
    &dynamic_sysuninit,
};

static const void *const dynamic_metadata_records[] = {
    &dynamic_declaration,
    &dynamic_dependency,
    &dynamic_version,
    &dynamic_pnp_record,
};

static int
test_probe(device_t device)
{
    device_set_desc(device, "module-managed test device");
    return BUS_PROBE_DEFAULT;
}

static int
test_attach(device_t device)
{
    int *value = device_get_softc(device);

    *value = 42;
    return 0;
}

static int
test_detach(device_t device)
{
    int *value = device_get_softc(device);

    *value = 0;
    return 0;
}

static const struct kobj_method test_driver_methods[] = {
    { &device_probe_desc, (kobjop_t)test_probe },
    { &device_attach_desc, (kobjop_t)test_attach },
    { &device_detach_desc, (kobjop_t)test_detach },
    KOBJMETHOD_END,
};

static struct kobj_class test_driver = {
    "moduledev", test_driver_methods, sizeof(int), 0, 0, 0
};

static int
driver_chain_event(struct module *module, int event, void *argument)
{
    (void)module;
    (void)argument;
    if (event == MOD_LOAD) {
        driver_chain_loads++;
        record_lifecycle(3);
        return 0;
    }
    if (event == MOD_QUIESCE) {
        driver_chain_quiesces++;
        return 0;
    }
    if (event == MOD_UNLOAD) {
        driver_chain_unloads++;
        record_lifecycle(7);
        return 0;
    }
    if (event == MOD_SHUTDOWN)
        return 0;
    return 45;
}

static bsd_driver_module_data_t test_driver_module_data = {
    .chain_event = driver_chain_event,
    .chain_argument = 0,
    .bus_name = "testbus",
    .driver = &test_driver,
    .driver_class = 0,
    .pass = 0x7fffffff,
};

static moduledata_t test_driver_module = {
    "testbus/testdriver",
    driver_module_handler,
    &test_driver_module_data,
};

DECLARE_MODULE(testdriver_testbus, test_driver_module, SI_SUB_DRIVERS,
    SI_ORDER_MIDDLE);
MODULE_VERSION(testdriver, 1);
MODULE_DEPEND(testdriver, bridge_base, 3, 3, 3);
MODULE_DEPEND(testdriver, geom_flashmap, 0, 0, 0);
MODULE_DEPEND(testdriver, wlan_amrr, 1, 1, 1);

struct test_pnp_entry {
    uint32_t identifier;
};

static const struct test_pnp_entry test_pnp_table[] = {
    { 0x10203040u },
};

MODULE_PNP_INFO("U32:identifier;", testbus, testdriver, test_pnp_table, 1);

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U,
            (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

int
main(void)
{
    bsd_allocator_ops_t allocator_ops = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    const struct mod_pnp_match_info *pnp;
    module_t base_module;
    module_t driver_module;
    struct linker_file *dynamic_file;
    bsd_linker_record_set_t dynamic_records = {
        .sysinit_begin = dynamic_sysinit_records,
        .sysinit_end = dynamic_sysinit_records + 1,
        .sysuninit_begin = dynamic_sysuninit_records,
        .sysuninit_end = dynamic_sysuninit_records + 1,
        .metadata_begin = dynamic_metadata_records,
        .metadata_end = dynamic_metadata_records + 4,
    };
    bsd_linker_image_t *dynamic_image;
    device_t root;
    device_t child;

    assert(bsd_allocator_initialize(&allocator_ops) == 0);
    assert(bsd_module_validate_dependencies() == 0);
    assert(!bsd_sysinit_is_complete());
    assert(bsd_sysinit_run_through(SI_SUB_DRIVERS) == 0);
    assert(!bsd_sysinit_is_complete());
    assert(lifecycle_count == 3);
    assert(lifecycle_log[0] == 1);
    assert(lifecycle_log[1] == 2);
    assert(lifecycle_log[2] == 3);
    assert(bsd_sysinit_run_remaining() == 0);
    assert(bsd_sysinit_is_complete());
    assert(bsd_sysinit_run_all() == 0);
    assert(bsd_driver_package_find("freebsd-module-test",
        &(bsd_driver_package_status_t){ 0 }) == 0);
    assert(bsd_driver_package_registry[0].state ==
        BSD_DRIVER_PACKAGE_ACTIVE);
    assert(lifecycle_count == 4);
    assert(lifecycle_log[0] == 1);
    assert(lifecycle_log[1] == 2);
    assert(lifecycle_log[2] == 3);
    assert(lifecycle_log[3] == 4);
    assert(driver_chain_loads == 1);

    assert(bsd_module_linked_file_count() == 0);
    dynamic_image = bsd_test_linker_image_create(&dynamic_records);
    assert(dynamic_image != 0);
    assert(bsd_module_activate_image(dynamic_image, "dynamic_driver.ko",
        &dynamic_file) == 0);
    assert(dynamic_file != 0);
    assert(bsd_module_linked_file_count() == 1);
    assert(dynamic_module_loads == 1);
    assert(module_lookupbyname("dynamic_driver") != 0);
    assert(module_file(module_lookupbyname("dynamic_driver")) ==
        dynamic_file);
    assert(bsd_module_pnp_count() == 2);

    dynamic_image = bsd_test_linker_image_create(&dynamic_records);
    assert(dynamic_image != 0);
    assert(bsd_module_activate_image(dynamic_image, "dynamic_driver.ko",
        0) == 17);
    assert(bsd_test_linker_image_release_count() == 1);
    assert(bsd_module_deactivate_file(dynamic_file) == 0);
    assert(bsd_module_linked_file_count() == 0);
    assert(dynamic_module_unloads == 1);
    assert(dynamic_sysuninit_calls == 1);
    assert(module_lookupbyname("dynamic_driver") == 0);
    assert(bsd_module_pnp_count() == 1);
    assert(bsd_test_linker_image_release_count() == 2);

    base_module = module_lookupbyname("bridge_base");
    driver_module = module_lookupbyname("testbus/testdriver");
    assert(base_module != 0);
    assert(driver_module != 0);
    assert(module_lookupbyid(module_getid(base_module)) == base_module);
    assert(module_unload(base_module) == 16);

    assert(bsd_module_pnp_count() == 1);
    pnp = bsd_module_pnp_get(0);
    assert(pnp != 0);
    assert(pnp->entry_len == (int)sizeof(test_pnp_table[0]));
    assert(pnp->num_entry == 1);
    assert(bsd_module_pnp_get(1) == 0);

    root = bsd_newbus_create_root("testbus", 0, 0);
    assert(root != 0);
    child = device_add_child(root, 0, DEVICE_UNIT_ANY);
    assert(child != 0);
    assert(device_probe_and_attach(child) == 0);
    assert(device_get_driver(child) == &test_driver);
    assert(*(int *)device_get_softc(child) == 42);
    assert(module_quiesce(driver_module) == 16);
    assert(device_detach(child) == 0);
    assert(device_delete_child(root, child) == 0);

    assert(bsd_sysuninit_run_all() == 0);
    assert(bsd_sysuninit_run_all() == 0);
    assert(bsd_driver_package_registry[0].state ==
        BSD_DRIVER_PACKAGE_STOPPED);
    assert(driver_chain_quiesces == 1);
    assert(driver_chain_unloads == 1);
    assert(lifecycle_count == 8);
    assert(lifecycle_log[4] == 5);
    assert(lifecycle_log[5] == 6);
    assert(lifecycle_log[6] == 7);
    assert(lifecycle_log[7] == 8);
    return 0;
}
