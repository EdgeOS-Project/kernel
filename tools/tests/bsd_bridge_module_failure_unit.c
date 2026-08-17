/* SPDX-License-Identifier: MPL-2.0 */
/* Negative-path tests for BSD bridge module dependency and rollback rules. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/module.h"
#include "compat/freebsd/sys/module.h"

static int load_count;
static int unload_count;

#if !defined(BSD_MODULE_DEPENDENCY_ROLLBACK) && \
    !defined(BSD_MODULE_DEPENDENCY_CYCLE)
static int
failure_module_event(module_t module, int event, void *argument)
{
    (void)module;
    (void)argument;
    if (event == MOD_LOAD) {
        load_count++;
#if defined(BSD_MODULE_UNAVAILABLE)
        return 6;
#elif defined(BSD_MODULE_CALLBACK_FAILURE)
        return 5;
#else
        return 0;
#endif
    }
    if (event == MOD_UNLOAD) {
        unload_count++;
        return 0;
    }
    return 0;
}

static moduledata_t failure_module_data = {
    "failure_test",
    failure_module_event,
    0,
};

DECLARE_MODULE(failure_test, failure_module_data, SI_SUB_DRIVERS,
    SI_ORDER_MIDDLE);
MODULE_VERSION(failure_test, 1);
MODULE_DEPEND(failure_test, required_provider, 1, 1, 1);
#elif defined(BSD_MODULE_DEPENDENCY_ROLLBACK)
static int dependency_load_count;
static int dependency_unload_count;
static int parent_load_count;
static int parent_unload_count;

static int
dependency_event(module_t module, int event, void *argument)
{
    (void)module;
    (void)argument;
    if (event == MOD_LOAD)
        dependency_load_count++;
    if (event == MOD_UNLOAD)
        dependency_unload_count++;
    return 0;
}

static int
parent_event(module_t module, int event, void *argument)
{
    (void)module;
    (void)argument;
    if (event == MOD_LOAD) {
        parent_load_count++;
        return 5;
    }
    if (event == MOD_UNLOAD)
        parent_unload_count++;
    return 0;
}

static moduledata_t dependency_module_data = {
    "rollback_dependency",
    dependency_event,
    0,
};

static moduledata_t parent_module_data = {
    "rollback_parent",
    parent_event,
    0,
};

DECLARE_MODULE(rollback_dependency, dependency_module_data,
    SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(rollback_dependency, 1);
DECLARE_MODULE(rollback_parent, parent_module_data,
    SI_SUB_DRIVERS, SI_ORDER_SECOND);
MODULE_VERSION(rollback_parent, 1);
MODULE_DEPEND(rollback_parent, rollback_dependency, 1, 1, 1);
#else
static int cycle_load_count;
static int cycle_unload_count;

static int
cycle_event(module_t module, int event, void *argument)
{
    (void)module;
    (void)argument;
    if (event == MOD_LOAD)
        cycle_load_count++;
    if (event == MOD_UNLOAD)
        cycle_unload_count++;
    return 0;
}

static moduledata_t cycle_a_module_data = {
    "cycle_a",
    cycle_event,
    0,
};

static moduledata_t cycle_b_module_data = {
    "cycle_b",
    cycle_event,
    0,
};

DECLARE_MODULE(cycle_a, cycle_a_module_data, SI_SUB_DRIVERS,
    SI_ORDER_FIRST);
MODULE_VERSION(cycle_a, 1);
MODULE_DEPEND(cycle_a, cycle_b, 1, 1, 1);
DECLARE_MODULE(cycle_b, cycle_b_module_data, SI_SUB_DRIVERS,
    SI_ORDER_SECOND);
MODULE_VERSION(cycle_b, 1);
MODULE_DEPEND(cycle_b, cycle_a, 1, 1, 1);
#endif

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
    int expected_error;

    assert(bsd_allocator_initialize(&allocator_ops) == 0);
#if defined(BSD_MODULE_DEPENDENCY_ROLLBACK)
    module_register_init(&parent_module_data);
    assert(bsd_module_last_error() == 5);
    assert(dependency_load_count == 1);
    assert(dependency_unload_count == 1);
    assert(parent_load_count == 1);
    assert(parent_unload_count == 1);
    assert(module_lookupbyname("rollback_dependency") != 0);
    assert(module_lookupbyname("rollback_parent") != 0);
    return 0;
#elif defined(BSD_MODULE_DEPENDENCY_CYCLE)
    module_register_init(&cycle_a_module_data);
    assert(bsd_module_last_error() == 11);
    assert(cycle_load_count == 0);
    assert(cycle_unload_count == 0);
    return 0;
#elif defined(BSD_MODULE_UNAVAILABLE)
    assert(bsd_module_provide("required_provider", 1) == 0);
    assert(bsd_sysinit_run_all() == 0);
    assert(bsd_module_last_error() == 0);
    assert(bsd_sysinit_is_complete());
    assert(load_count == 1);
    assert(unload_count == 1);
    return 0;
#elif defined(BSD_MODULE_CALLBACK_FAILURE)
    assert(bsd_module_provide("required_provider", 1) == 0);
    expected_error = 5;
#elif defined(BSD_MODULE_VERSION_FAILURE)
    assert(bsd_module_provide("required_provider", 2) == 0);
    expected_error = 45;
#else
    expected_error = 2;
#endif
    assert(bsd_sysinit_run_all() == expected_error);
    assert(bsd_module_last_error() == expected_error);
    assert(!bsd_sysinit_is_complete());
#ifdef BSD_MODULE_CALLBACK_FAILURE
    assert(load_count == 1);
    assert(unload_count == 1);
#else
    assert(load_count == 0);
    assert(unload_count == 0);
#endif
    return 0;
}
