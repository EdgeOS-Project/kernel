/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for shared FreeBSD-compatible firmware property access. */

#include <stddef.h>
#include <stdint.h>
#include <sys/bus.h>

#include "compat/freebsd/edgeos/firmware.h"
#include "compat/freebsd/edgeos/systm.h"

#define TEST_FDT_NODE ((phandle_t)7)
#define TEST_FDT_DEVICE ((device_t)(uintptr_t)1)
#define TEST_BUS_DEVICE ((device_t)(uintptr_t)2)
#define TEST_BUS_PARENT ((device_t)(uintptr_t)3)

static unsigned int g_fallback_calls;

static int
test_string_equal(const char *left, const char *right)
{
    while (*left && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

static int
test_copy(void *destination, size_t capacity, const void *source, size_t length)
{
    if (!destination || capacity < length)
        return -1;
    bsd_memcpy(destination, source, length);
    return (int)length;
}

void *
bsd_memcpy(void *destination, const void *source, size_t length)
{
    uint8_t *output = destination;
    const uint8_t *input = source;

    for (size_t index = 0; index < length; ++index)
        output[index] = input[index];
    return destination;
}

phandle_t
bsd_firmware_fdt_node(device_t device)
{
    return device == TEST_FDT_DEVICE ? TEST_FDT_NODE : (phandle_t)-1;
}

device_t
device_get_parent(device_t device)
{
    return device == TEST_BUS_DEVICE ? TEST_BUS_PARENT : 0;
}

ssize_t
bsd_bus_get_property(device_t parent, device_t child, const char *name,
    void *value, size_t size, device_property_type_t type)
{
    uint32_t fallback_value = UINT32_C(0xfeedbeef);

    ++g_fallback_calls;
    if (parent != TEST_BUS_PARENT || child != TEST_BUS_DEVICE ||
        !test_string_equal(name, "fallback") ||
        type != DEVICE_PROP_UINT32)
        return -1;
    return test_copy(value, size, &fallback_value, sizeof(fallback_value));
}

ssize_t
OF_getproplen(phandle_t node, const char *property)
{
    if (node != TEST_FDT_NODE)
        return -1;
    if (test_string_equal(property, "label"))
        return 5;
    if (test_string_equal(property, "clock-frequency"))
        return 4;
    if (test_string_equal(property, "dma-mask"))
        return 8;
    if (test_string_equal(property, "interrupt-parent"))
        return 4;
    if (test_string_equal(property, "dma-coherent"))
        return 0;
    return -1;
}

ssize_t
OF_getprop(phandle_t node, const char *property, void *buffer, size_t size)
{
    static const char label[] = "uart";

    if (node != TEST_FDT_NODE || !test_string_equal(property, "label"))
        return -1;
    return test_copy(buffer, size, label, sizeof(label));
}

ssize_t
OF_getencprop(phandle_t node, const char *property, pcell_t *buffer,
    size_t size)
{
    const uint32_t clock_frequency = UINT32_C(24000000);
    const uint32_t dma_mask[] = {
        UINT32_C(0x12345678),
        UINT32_C(0x9abcdef0),
    };
    const uint32_t interrupt_parent = 1;

    if (node != TEST_FDT_NODE)
        return -1;
    if (test_string_equal(property, "clock-frequency"))
        return test_copy(buffer, size, &clock_frequency,
            sizeof(clock_frequency));
    if (test_string_equal(property, "dma-mask"))
        return test_copy(buffer, size, dma_mask, sizeof(dma_mask));
    if (test_string_equal(property, "interrupt-parent"))
        return test_copy(buffer, size, &interrupt_parent,
            sizeof(interrupt_parent));
    return -1;
}

phandle_t
OF_node_from_xref(phandle_t xref)
{
    return xref == 1 ? (phandle_t)101 : (phandle_t)-1;
}

#define CHECK(expression) do { if (!(expression)) return __LINE__; } while (0)

int
main(void)
{
    char label[5] = {0};
    uint32_t clock_frequency = 0;
    uint32_t fallback = 0;
    uint64_t dma_mask = 0;
    phandle_t parent = 0;

    CHECK(device_get_property(TEST_FDT_DEVICE, "label", 0, 0,
        DEVICE_PROP_BUFFER) == 5);
    CHECK(device_get_property(TEST_FDT_DEVICE, "label", label,
        sizeof(label), DEVICE_PROP_BUFFER) == 5);
    CHECK(label[0] == 'u' && label[3] == 't' && label[4] == '\0');
    CHECK(device_get_property(TEST_FDT_DEVICE, "clock-frequency",
        &clock_frequency, sizeof(clock_frequency),
        DEVICE_PROP_UINT32) == 4);
    CHECK(clock_frequency == UINT32_C(24000000));
    CHECK(device_get_property(TEST_FDT_DEVICE, "dma-mask", &dma_mask,
        sizeof(dma_mask), DEVICE_PROP_UINT64) == 8);
    CHECK(dma_mask == UINT64_C(0x123456789abcdef0));
    CHECK(device_get_property(TEST_FDT_DEVICE, "interrupt-parent",
        &parent, sizeof(parent), DEVICE_PROP_HANDLE) == 4);
    CHECK(parent == (phandle_t)101);
    CHECK(device_has_property(TEST_FDT_DEVICE, "dma-coherent"));
    CHECK(!device_has_property(TEST_FDT_DEVICE, "missing"));
    CHECK(g_fallback_calls == 0);
    CHECK(device_get_property(TEST_FDT_DEVICE, "clock-frequency",
        &clock_frequency, 3, DEVICE_PROP_UINT32) == -1);
    CHECK(device_get_property(TEST_FDT_DEVICE, "dma-mask", &dma_mask,
        4, DEVICE_PROP_UINT64) == -1);
    CHECK(device_get_property(TEST_BUS_DEVICE, "fallback", &fallback,
        sizeof(fallback), DEVICE_PROP_UINT32) == 4);
    CHECK(fallback == UINT32_C(0xfeedbeef));
    CHECK(g_fallback_calls == 1);
    return 0;
}
