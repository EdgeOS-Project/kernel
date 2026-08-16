/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for source-built BSD driver package lifecycle state. */

#include <assert.h>
#include <stdio.h>

#include "compat/freebsd/edgeos/package.h"

bsd_driver_package_record_t bsd_driver_package_registry[] = {
    {
        .descriptor = {
            .id = "freebsd-active-test",
            .provider = "freebsd",
            .upstream_commit = "0123456789abcdef0123456789abcdef01234567",
            .source_count = 4,
            .builtin_module_count = 2,
            .loadable_module_count = 1,
            .disabled_module_count = 1,
        },
        .state = BSD_DRIVER_PACKAGE_REGISTERED,
    },
    {
        .descriptor = {
            .id = "freebsd-disabled-test",
            .provider = "freebsd",
            .upstream_commit = "0123456789abcdef0123456789abcdef01234567",
            .source_count = 1,
            .builtin_module_count = 0,
            .loadable_module_count = 0,
            .disabled_module_count = 1,
        },
        .state = BSD_DRIVER_PACKAGE_DISABLED,
    },
};

const size_t bsd_driver_package_registry_count =
    sizeof(bsd_driver_package_registry) /
    sizeof(bsd_driver_package_registry[0]);

static void
expect_state(const char *id, bsd_driver_package_state_t state, int error)
{
    bsd_driver_package_status_t status;

    assert(bsd_driver_package_find(id, &status) == 0);
    assert(status.state == state);
    assert(status.error == error);
}

int
main(void)
{
    bsd_driver_package_status_t status;

    assert(bsd_driver_package_count() == 2);
    assert(bsd_driver_package_get(0, &status) == 0);
    assert(status.descriptor.source_count == 4);
    assert(status.descriptor.builtin_module_count == 2);
    assert(status.descriptor.loadable_module_count == 1);
    assert(status.descriptor.disabled_module_count == 1);
    assert(bsd_driver_package_get(2, &status) != 0);
    assert(bsd_driver_package_get(0, 0) != 0);
    assert(bsd_driver_package_find("missing", &status) != 0);

    assert(bsd_driver_packages_prepare() == 0);
    expect_state("freebsd-active-test", BSD_DRIVER_PACKAGE_STARTING, 0);
    expect_state("freebsd-disabled-test", BSD_DRIVER_PACKAGE_DISABLED, 0);
    assert(bsd_driver_packages_activate() == 0);
    expect_state("freebsd-active-test", BSD_DRIVER_PACKAGE_ACTIVE, 0);

    assert(bsd_driver_packages_begin_stop() == 0);
    expect_state("freebsd-active-test", BSD_DRIVER_PACKAGE_STOPPING, 0);
    assert(bsd_driver_packages_finish_stop() == 0);
    expect_state("freebsd-active-test", BSD_DRIVER_PACKAGE_STOPPED, 0);

    bsd_driver_package_registry[0].state = BSD_DRIVER_PACKAGE_REGISTERED;
    assert(bsd_driver_packages_prepare() == 0);
    bsd_driver_packages_fail(5);
    expect_state("freebsd-active-test", BSD_DRIVER_PACKAGE_FAILED, 5);
    expect_state("freebsd-disabled-test", BSD_DRIVER_PACKAGE_DISABLED, 0);

    bsd_driver_package_registry[0].state = BSD_DRIVER_PACKAGE_REGISTERED;
    bsd_driver_package_registry[1].descriptor.id = "freebsd-active-test";
    assert(bsd_driver_packages_prepare() != 0);
    assert(bsd_driver_package_registry[0].state ==
        BSD_DRIVER_PACKAGE_REGISTERED);
    bsd_driver_package_registry[1].descriptor.id = "freebsd-disabled-test";
    bsd_driver_package_registry[0].descriptor.id = ".invalid";
    assert(bsd_driver_packages_prepare() != 0);

    puts("bsd_bridge_package_unit: PASS");
    return 0;
}
