/* SPDX-License-Identifier: MPL-2.0 */
/* Unit coverage for configured BSD driver module path resolution. */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "compat/freebsd/edgeos/driver_loader.h"

static void
expect_path(const char *name, const char *expected)
{
    char path[BSD_DRIVER_MODULE_PATH_MAX];

    assert(bsd_driver_module_resolve_path(
        name, strlen(name), path, sizeof(path)) == 0);
    assert(strcmp(path, expected) == 0);
}

int
main(void)
{
    char path[8];

    expect_path("virtio_gpu", "/opt/edgeos/modules/virtio_gpu.ko");
    expect_path("virtio_blk.ko", "/opt/edgeos/modules/virtio_blk.ko");
    expect_path("network/virtio_net",
        "/opt/edgeos/modules/network/virtio_net.ko");
    expect_path("/custom/driver.ko", "/custom/driver.ko");

    assert(bsd_driver_module_resolve_path(
        0, 0, path, sizeof(path)) == 22);
    assert(bsd_driver_module_resolve_path(
        "", 0, path, sizeof(path)) == 22);
    assert(bsd_driver_module_resolve_path(
        "driver", 6, path, sizeof(path)) == 22);

    puts("bsd_bridge_driver_path_unit: PASS");
    return 0;
}
