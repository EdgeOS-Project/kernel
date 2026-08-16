/* SPDX-License-Identifier: MPL-2.0 */
/* Firmware-described ARM64 platform resource discovery. */

#include <stdint.h>

#include "arch/arm64/platform.h"

#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
#include "compat/freebsd/edgeos/ofw.h"
#define EDGEOS_ARM64_PLATFORM_OFW 1
#endif

#define ARM64_QEMU_VIRT_PL011_BASE UINT64_C(0x09000000)
#define PL011_DR 0x00u
#define PL011_FR 0x18u
#define PL011_FR_RXFE (1u << 4)
#define PL011_FR_TXFF (1u << 5)

#if defined(__aarch64__)
#define ARM64_PLATFORM_SPIN_HINT() __asm__ __volatile__("yield")
#elif defined(__x86_64__)
#define ARM64_PLATFORM_SPIN_HINT() __asm__ __volatile__("pause")
#else
#define ARM64_PLATFORM_SPIN_HINT() ((void)0)
#endif

static volatile uint32_t *g_serial =
    (volatile uint32_t *)(uintptr_t)ARM64_QEMU_VIRT_PL011_BASE;
static edgeos_arm64_platform_kind_t g_platform_kind =
    EDGEOS_ARM64_PLATFORM_GENERIC;
static int g_serial_tx_stalled;

#ifdef EDGEOS_ARM64_PLATFORM_OFW
static int
arm64_platform_is_pl011(phandle_t node)
{
    return node != 0 &&
        (bsd_ofw_fdt_node_is_compatible(node, "arm,pl011") ||
         bsd_ofw_fdt_node_is_compatible(node, "arm,pl011-axi"));
}

static phandle_t
arm64_platform_find_pl011(void)
{
    phandle_t node;

    /*
     * Raspberry Pi firmware keeps its internal debug UART as stdout-path even
     * when uart0_console routes the GPIO header to RP1 UART0.  Linux-facing
     * serial0 is the externally wired console selected by config.txt, so prefer
     * that enabled alias on Pi boards before considering firmware stdout.
     */
    if (g_platform_kind == EDGEOS_ARM64_PLATFORM_RASPBERRY_PI_5 ||
        g_platform_kind == EDGEOS_ARM64_PLATFORM_RASPBERRY_PI_4) {
        node = OF_finddevice("serial0");
        if (arm64_platform_is_pl011(node) &&
            bsd_ofw_fdt_node_status_okay(node))
            return node;
    }

    node = bsd_ofw_fdt_stdout_node();

    if (arm64_platform_is_pl011(node) &&
        bsd_ofw_fdt_node_status_okay(node))
        return node;
    for (unsigned int index = 0;; ++index) {
        node = bsd_ofw_fdt_find_compatible("arm,pl011", index);
        if (node == 0)
            break;
        if (bsd_ofw_fdt_node_status_okay(node))
            return node;
    }
    for (unsigned int index = 0;; ++index) {
        node = bsd_ofw_fdt_find_compatible("arm,pl011-axi", index);
        if (node == 0 || bsd_ofw_fdt_node_status_okay(node))
            return node;
    }
}

static void
arm64_platform_detect_board(void)
{
    phandle_t root = OF_finddevice("/");

    if (root == 0 || root == (phandle_t)-1)
        return;
    if (bsd_ofw_fdt_node_is_compatible(
            root, "raspberrypi,5-model-b") ||
        bsd_ofw_fdt_node_is_compatible(root, "brcm,bcm2712")) {
        g_platform_kind = EDGEOS_ARM64_PLATFORM_RASPBERRY_PI_5;
    } else if (bsd_ofw_fdt_node_is_compatible(
            root, "raspberrypi,4-model-b") ||
        bsd_ofw_fdt_node_is_compatible(root, "brcm,bcm2711")) {
        g_platform_kind = EDGEOS_ARM64_PLATFORM_RASPBERRY_PI_4;
    }
}
#endif

int edgeos_arm64_platform_configure(
    const edgeos_arm64_bootinfo_t *bootinfo) {
    (void)bootinfo;
#ifdef EDGEOS_ARM64_PLATFORM_OFW
    phandle_t node;
    uint64_t address;
    uint64_t size;

    arm64_platform_detect_board();
    node = arm64_platform_find_pl011();
    if (node != 0 &&
        bsd_ofw_fdt_get_reg(node, 0, &address, &size) == 0 &&
        address != 0 && size >= 0x20u) {
        g_serial = (volatile uint32_t *)(uintptr_t)address;
        g_serial_tx_stalled = 0;
        return 0;
    }
#endif
    return -1;
}

edgeos_arm64_platform_kind_t edgeos_arm64_platform_kind(void) {
    return g_platform_kind;
}

uint64_t edgeos_arm64_platform_serial_base(void) {
    return (uint64_t)(uintptr_t)g_serial;
}

void edgeos_arm64_platform_serial_write(char ch) {
    uint32_t spins = 0;

    if (!g_serial || g_serial_tx_stalled) return;
    if (ch == '\n') edgeos_arm64_platform_serial_write('\r');
    while ((g_serial[PL011_FR / 4u] & PL011_FR_TXFF) != 0 &&
           spins++ < 65536u)
        ARM64_PLATFORM_SPIN_HINT();
    if (spins >= 65536u) {
        /* A stale firmware alias must never stall framebuffer or boot output. */
        g_serial_tx_stalled = 1;
        return;
    }
    g_serial[PL011_DR / 4u] = (uint32_t)(uint8_t)ch;
}

int edgeos_arm64_platform_serial_has_input(void) {
    return g_serial &&
        (g_serial[PL011_FR / 4u] & PL011_FR_RXFE) == 0;
}

int edgeos_arm64_platform_serial_read(void) {
    if (!edgeos_arm64_platform_serial_has_input()) return -1;
    return (int)(g_serial[PL011_DR / 4u] & 0xffu);
}
