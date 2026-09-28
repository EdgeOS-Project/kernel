/* SPDX-License-Identifier: MPL-2.0 */
/* Validate EdgeOS resource discovery against a production Raspberry Pi 5 DTB. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libfdt.h"
#include "arch/arm64/platform.h"
#include "compat/freebsd/edgeos/ofw.h"

static void *
read_file(const char *path, size_t *size_out)
{
    FILE *file = fopen(path, "rb");
    void *buffer;
    long length;

    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    length = ftell(file);
    assert(length > 0);
    assert(fseek(file, 0, SEEK_SET) == 0);
    buffer = malloc((size_t)length);
    assert(buffer != NULL);
    assert(fread(buffer, 1, (size_t)length, file) == (size_t)length);
    assert(fclose(file) == 0);
    *size_out = (size_t)length;
    return buffer;
}

static size_t
count_compatible(const char *compatible)
{
    size_t count = 0;

    while (bsd_ofw_fdt_find_compatible(
        compatible, (unsigned int)count) != 0)
        ++count;
    return count;
}

int
main(int argc, char **argv)
{
    phandle_t root;
    phandle_t serial0_node;
    phandle_t stdout_node;
    phandle_t rp1_gpio;
    uint64_t address;
    uint64_t serial_address;
    uint64_t size;
    int error;
    int serial0_offset;
    void *blob;
    size_t blob_size;

    assert(argc == 2);
    blob = read_file(argv[1], &blob_size);
    serial0_offset = fdt_path_offset(
        blob, "/axi/pcie@1000120000/rp1/serial@30000");
    assert(serial0_offset >= 0);
    assert(fdt_setprop_string(blob, serial0_offset,
        "status", "okay") == 0);
    assert(bsd_ofw_fdt_install(blob, blob_size) == 0);
    root = OF_finddevice("/");
    assert(root != 0 && root != (phandle_t)-1);
    assert(bsd_ofw_fdt_node_is_compatible(
        root, "raspberrypi,5-model-b"));
    assert(bsd_ofw_fdt_node_is_compatible(root, "brcm,bcm2712"));

    stdout_node = bsd_ofw_fdt_stdout_node();
    assert(stdout_node != 0);
    assert(bsd_ofw_fdt_node_is_compatible(stdout_node, "arm,pl011"));
    assert(bsd_ofw_fdt_node_status_okay(stdout_node));
    assert(bsd_ofw_fdt_get_reg(stdout_node, 0, &address, &size) == 0);
    assert(address == UINT64_C(0x107d001000));
    assert(size >= UINT64_C(0x200));
    serial0_node = OF_finddevice("serial0");
    assert(serial0_node != 0 && serial0_node != (phandle_t)-1);
    assert(bsd_ofw_fdt_node_is_compatible(serial0_node, "arm,pl011-axi"));
    assert(bsd_ofw_fdt_node_status_okay(serial0_node));
    assert(bsd_ofw_fdt_get_reg(serial0_node, 0, &serial_address, &size) == 0);
    if (serial_address != UINT64_C(0x1f00030000))
        fprintf(stderr, "RP1 UART0 translated to 0x%llx\n",
            (unsigned long long)serial_address);
    assert(serial_address == UINT64_C(0x1f00030000));
    assert(size >= UINT64_C(0x100));

    assert(count_compatible("arm,cortex-a76") == 4);
    assert(count_compatible("arm,gic-400") == 1);
    assert(count_compatible("brcm,bcm2712-pcie") == 3);
    assert(count_compatible("brcm,bcm2712-sdhci") == 2);
    assert(count_compatible("raspberrypi,rp1-gpio") == 1);
    assert(count_compatible("raspberrypi,rp1-gem") == 1);
    rp1_gpio = bsd_ofw_fdt_find_compatible(
        "raspberrypi,rp1-gpio", 0);
    assert(rp1_gpio != 0);
    error = bsd_ofw_fdt_get_reg(rp1_gpio, 0, &address, &size);
    if (error != 0)
        fprintf(stderr, "RP1 GPIO resource translation failed: %d\n",
            error);
    assert(error == 0);
    assert(address == UINT64_C(0x1f000d0000));
    assert(size >= UINT64_C(0x100));

    assert(edgeos_arm64_platform_configure(NULL) == 0);
    assert(edgeos_arm64_platform_kind() ==
        EDGEOS_ARM64_PLATFORM_RASPBERRY_PI_5);
    assert(edgeos_arm64_platform_serial_base() == serial_address);

    bsd_ofw_fdt_reset();
    free(blob);
    return 0;
}
