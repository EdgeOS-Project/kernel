/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for BSD Driver Bridge startup sequencing. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "compat/freebsd/edgeos/audio.h"
#include "compat/freebsd/edgeos/bootstrap.h"

enum test_event {
    TEST_ALLOCATOR = 1,
    TEST_SYNC,
    TEST_KERNEL_WORKERS,
    TEST_CPU,
    TEST_TASKQUEUES,
    TEST_CALLOUTS,
    TEST_BUS_SPACE,
    TEST_BUS_DMA,
    TEST_VM_PAGE,
    TEST_BLOCK,
    TEST_INTERRUPTS,
    TEST_DRIVER_ADAPTERS,
    TEST_KEYBOARD_DRIVERS,
    TEST_PCI_PROVIDER,
    TEST_ETHER_PROVIDER,
    TEST_MEM_PROVIDER,
    TEST_IIC_PROVIDER,
    TEST_RANDOM_PROVIDER,
    TEST_RANDOMDEV_PROVIDER,
    TEST_RANDOM_HARVEST_PROVIDER,
    TEST_EFIRT_PROVIDER,
    TEST_ACPI_PROVIDER,
    TEST_SIMPLEBUS_PROVIDER,
    TEST_OFWBUS_PROVIDER,
    TEST_CAM_PROVIDER,
    TEST_EVDEV_PROVIDER,
    TEST_FIRMWARE_PROVIDER,
    TEST_UPGTFW_PROVIDER,
    TEST_SOUND_PROVIDER,
    TEST_ROOT,
    TEST_MODULES,
    TEST_PCI_INITIALIZE,
    TEST_PCI_ATTACH,
};

static int g_events[33];
static size_t g_event_count;
static int g_allocator_ready;
static int g_sync_ready;
static int g_kernel_workers_ready;
static int g_taskqueues_ready;
static int g_callouts_ready;
static int g_bus_space_ready;
static int g_bus_dma_ready;
static int g_block_ready;
static int g_interrupt_ready;
static int g_pci_ready;
static char g_root_object;
static char g_pci_object;

static void
record_event(enum test_event event)
{
    assert(g_event_count < sizeof(g_events) / sizeof(g_events[0]));
    g_events[g_event_count++] = event;
}

int
bsd_allocator_is_initialized(void)
{
    return g_allocator_ready;
}

int
bsd_allocator_initialize(const bsd_allocator_ops_t *operations)
{
    assert(operations != 0);
    record_event(TEST_ALLOCATOR);
    g_allocator_ready = 1;
    return 0;
}

int
bsd_sync_is_initialized(void)
{
    return g_sync_ready;
}

int
bsd_sync_initialize(const bsd_sync_ops_t *operations)
{
    assert(operations != 0);
    record_event(TEST_SYNC);
    g_sync_ready = 1;
    return 0;
}

int
bsd_kthread_runtime_initialize(void)
{
    record_event(TEST_KERNEL_WORKERS);
    g_kernel_workers_ready = 1;
    return 0;
}

int
bsd_kthread_runtime_is_initialized(void)
{
    return g_kernel_workers_ready;
}

int
bsd_cpu_runtime_initialize(void)
{
    record_event(TEST_CPU);
    return 0;
}

int
bsd_taskqueue_runtime_initialize(void)
{
    record_event(TEST_TASKQUEUES);
    g_taskqueues_ready = 1;
    return 0;
}

int
bsd_taskqueue_runtime_is_initialized(void)
{
    return g_taskqueues_ready;
}

int
bsd_callout_runtime_initialize(void)
{
    record_event(TEST_CALLOUTS);
    g_callouts_ready = 1;
    return 0;
}

int
bsd_callout_runtime_is_initialized(void)
{
    return g_callouts_ready;
}

int
bsd_bus_space_is_initialized(void)
{
    return g_bus_space_ready;
}

int
bsd_bus_space_initialize(const bsd_bus_space_ops_t *memory_operations,
    const bsd_bus_space_ops_t *io_operations)
{
    assert(memory_operations != 0);
    assert(io_operations != 0);
    record_event(TEST_BUS_SPACE);
    g_bus_space_ready = 1;
    return 0;
}

int
bsd_bus_space_ensure_initialized(void)
{
    assert(0 && "explicit bus-space operations must be used");
    return -1;
}

int
bsd_bus_dma_is_initialized(void)
{
    return g_bus_dma_ready;
}

int
bsd_bus_dma_initialize(const bsd_bus_dma_ops_t *operations)
{
    assert(operations != 0);
    record_event(TEST_BUS_DMA);
    g_bus_dma_ready = 1;
    return 0;
}

int
bsd_bus_dma_ensure_initialized(void)
{
    assert(0 && "explicit bus-DMA operations must be used");
    return -1;
}

int
bsd_vm_page_runtime_initialize(void)
{
    record_event(TEST_VM_PAGE);
    return 0;
}

int
bsd_block_is_initialized(void)
{
    return g_block_ready;
}

int
bsd_block_initialize(const bsd_block_backend_ops_t *operations)
{
    assert(operations != 0);
    record_event(TEST_BLOCK);
    g_block_ready = 1;
    return 0;
}

int
bsd_block_ensure_initialized(void)
{
    assert(0 && "explicit block operations must be used");
    return -1;
}

int
bsd_interrupt_is_initialized(void)
{
    return g_interrupt_ready;
}

int
bsd_interrupt_initialize(
    const bsd_interrupt_backend_ops_t *operations)
{
    assert(operations != 0);
    record_event(TEST_INTERRUPTS);
    g_interrupt_ready = 1;
    return 0;
}

int
bsd_interrupt_ensure_initialized(void)
{
    assert(0 && "explicit interrupt operations must be used");
    return -1;
}

int
bsd_driver_adapters_initialize(void)
{
    record_event(TEST_DRIVER_ADAPTERS);
    return 0;
}

void
kbdinit(void)
{
    record_event(TEST_KEYBOARD_DRIVERS);
}

int
bsd_pci_is_initialized(void)
{
    return g_pci_ready;
}

int
bsd_pci_initialize(const bsd_pci_backend_ops_t *operations)
{
    assert(operations != 0);
    record_event(TEST_PCI_INITIALIZE);
    g_pci_ready = 1;
    return 0;
}

int
bsd_pci_ensure_initialized(void)
{
    assert(0 && "explicit PCI operations must be used");
    return -1;
}

int
bsd_module_provide(const char *name, int version)
{
    static const struct {
        const char *name;
        enum test_event event;
    } providers[] = {
        { "pci", TEST_PCI_PROVIDER },
        { "ether", TEST_ETHER_PROVIDER },
        { "mem", TEST_MEM_PROVIDER },
        { "iic", TEST_IIC_PROVIDER },
        { "random_device", TEST_RANDOM_PROVIDER },
        { "randomdev", TEST_RANDOMDEV_PROVIDER },
        { "random_harvestq", TEST_RANDOM_HARVEST_PROVIDER },
        { "efirt", TEST_EFIRT_PROVIDER },
        { "acpi", TEST_ACPI_PROVIDER },
        { "simplebus", TEST_SIMPLEBUS_PROVIDER },
        { "ofwbus", TEST_OFWBUS_PROVIDER },
        { "cam", TEST_CAM_PROVIDER },
        { "evdev", TEST_EVDEV_PROVIDER },
        { "firmware", TEST_FIRMWARE_PROVIDER },
        { "upgtfw_fw", TEST_UPGTFW_PROVIDER },
        { "sound", TEST_SOUND_PROVIDER },
    };

    assert(name != 0);
    for (size_t index = 0;
         index < sizeof(providers) / sizeof(providers[0]); ++index) {
        const char *left = name;
        const char *right = providers[index].name;

        while (*left && *left == *right) {
            left++;
            right++;
        }
        if (*left == *right) {
            assert(version == (providers[index].event == TEST_SOUND_PROVIDER ?
                BSD_AUDIO_MODULE_VERSION : 1));
            record_event(providers[index].event);
            return 0;
        }
    }
    assert(0 && "unexpected built-in module provider");
    return 22;
}

int
bsd_ofw_fdt_available(void)
{
    return 0;
}

int
bsd_fdt_inventory_register(device_t root,
    bsd_fdt_inventory_status_t *status)
{
    (void)root;
    (void)status;
    assert(0 && "Device Tree inventory must not run without firmware");
    return 22;
}

device_t
bsd_newbus_create_root(const char *name, int unit, driver_t *driver)
{
    assert(name != 0 && name[0] == 't');
    assert(unit == 7);
    assert(driver == 0);
    record_event(TEST_ROOT);
    return (device_t)(void *)&g_root_object;
}

int
bsd_sysinit_run_all(void)
{
    record_event(TEST_MODULES);
    return 0;
}

device_t
bsd_pci_attach_bus(device_t parent)
{
    assert(parent == (device_t)(void *)&g_root_object);
    record_event(TEST_PCI_ATTACH);
    return (device_t)(void *)&g_pci_object;
}

int
main(void)
{
    static const int expected[] = {
        TEST_ALLOCATOR,
        TEST_SYNC,
        TEST_KERNEL_WORKERS,
        TEST_CPU,
        TEST_TASKQUEUES,
        TEST_CALLOUTS,
        TEST_BUS_SPACE,
        TEST_BUS_DMA,
        TEST_VM_PAGE,
        TEST_BLOCK,
        TEST_INTERRUPTS,
        TEST_DRIVER_ADAPTERS,
        TEST_KEYBOARD_DRIVERS,
        TEST_PCI_PROVIDER,
        TEST_ETHER_PROVIDER,
        TEST_MEM_PROVIDER,
        TEST_IIC_PROVIDER,
        TEST_RANDOM_PROVIDER,
        TEST_RANDOMDEV_PROVIDER,
        TEST_RANDOM_HARVEST_PROVIDER,
        TEST_EFIRT_PROVIDER,
        TEST_ACPI_PROVIDER,
        TEST_SIMPLEBUS_PROVIDER,
        TEST_OFWBUS_PROVIDER,
        TEST_CAM_PROVIDER,
        TEST_EVDEV_PROVIDER,
        TEST_FIRMWARE_PROVIDER,
        TEST_UPGTFW_PROVIDER,
        TEST_SOUND_PROVIDER,
        TEST_ROOT,
        TEST_MODULES,
        TEST_PCI_INITIALIZE,
        TEST_PCI_ATTACH,
    };
    bsd_allocator_ops_t allocator_operations = { 0 };
    bsd_sync_ops_t sync_operations = { 0 };
    bsd_bus_space_ops_t memory_operations = { 0 };
    bsd_bus_space_ops_t io_operations = { 0 };
    bsd_bus_dma_ops_t bus_dma_operations = { 0 };
    bsd_block_backend_ops_t block_operations = { 0 };
    bsd_interrupt_backend_ops_t interrupt_operations = { 0 };
    bsd_pci_backend_ops_t pci_operations = { 0 };
    bsd_bridge_bootstrap_options_t options = {
        .flags = BSD_BRIDGE_BOOTSTRAP_RUN_MODULES |
            BSD_BRIDGE_BOOTSTRAP_CREATE_ROOT |
            BSD_BRIDGE_BOOTSTRAP_ATTACH_PCI,
        .root_name = "test-root",
        .root_unit = 7,
        .allocator_ops = &allocator_operations,
        .sync_ops = &sync_operations,
        .memory_space_ops = &memory_operations,
        .io_space_ops = &io_operations,
        .bus_dma_ops = &bus_dma_operations,
        .block_ops = &block_operations,
        .interrupt_ops = &interrupt_operations,
        .pci_ops = &pci_operations,
    };
    bsd_bridge_bootstrap_status_t status;

    assert(bsd_bridge_bootstrap(&options) == 0);
    assert(g_event_count == sizeof(expected) / sizeof(expected[0]));
    for (size_t index = 0; index < g_event_count; ++index)
        assert(g_events[index] == expected[index]);

    bsd_bridge_bootstrap_get_status(&status);
    assert(status.state == BSD_BRIDGE_BOOTSTRAP_READY);
    assert(status.stage == BSD_BRIDGE_STAGE_COMPLETE);
    assert(status.error == 0);
    assert(status.flags == options.flags);
    assert(status.root == (device_t)(void *)&g_root_object);
    assert(status.pci_bus == (device_t)(void *)&g_pci_object);

    assert(bsd_bridge_bootstrap(&options) == 0);
    assert(g_event_count == sizeof(expected) / sizeof(expected[0]));
    bsd_bridge_bootstrap_get_status(0);
    puts("bsd_bridge_bootstrap_unit: PASS");
    return 0;
}
