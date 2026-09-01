/* SPDX-License-Identifier: MPL-2.0 */
/* Shared PCI newbus implementation for BSD drivers on EdgeOS. */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/pci.h"
#include "compat/freebsd/edgeos/resource.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/machine/resource.h"
#include "compat/freebsd/sys/kobj.h"

extern int hz;

#if defined(__x86_64__)
int pci_enable_aspm = 1;
#else
int pci_enable_aspm;
#endif

#define BSD_PCI_ENOENT 2
#define BSD_PCI_ENXIO 6
#define BSD_PCI_ENOMEM 12
#define BSD_PCI_EBUSY 16
#define BSD_PCI_EINVAL 22
#define BSD_PCI_CFGMECH_PCIE 3

#define BSD_PCI_VENDOR_INVALID 0xffffu
#define BSD_PCI_COMMAND 0x04
#define BSD_PCI_COMMAND_IO_ENABLE 0x0001u
#define BSD_PCI_COMMAND_MEMORY_ENABLE 0x0002u
#define BSD_PCI_COMMAND_BUSMASTER_ENABLE 0x0004u
#define BSD_PCI_STATUS 0x06
#define BSD_PCI_STATUS_CAPABILITIES 0x0010u
#define BSD_PCI_REVISION 0x08
#define BSD_PCI_PROGIF 0x09
#define BSD_PCI_SUBCLASS 0x0a
#define BSD_PCI_CLASS 0x0b
#define BSD_PCI_CACHE_LINE_SIZE 0x0c
#define BSD_PCI_LATENCY_TIMER 0x0d
#define BSD_PCI_HEADER_TYPE 0x0e
#define BSD_PCI_BAR_FIRST 0x10
#define BSD_PCI_BAR_COUNT 6
#define BSD_PCI_EXPANSION_ROM 0x30
#define BSD_PCI_SUBVENDOR 0x2c
#define BSD_PCI_SUBDEVICE 0x2e
#define BSD_PCI_CAPABILITIES 0x34
#define BSD_PCI_INTERRUPT_LINE 0x3c
#define BSD_PCI_INTERRUPT_PIN 0x3d

#define BSD_PCI_CAP_MSI 0x05
#define BSD_PCI_CAP_MSIX 0x11
#define BSD_PCI_CAP_EXPRESS 0x10
#define BSD_PCI_CAP_HYPERTRANSPORT 0x08
#define BSD_PCI_CAP_POWER_MANAGEMENT 0x01
#define BSD_PCI_POWER_STATUS 0x04
#define BSD_PCI_POWER_STATUS_PME_ENABLE 0x0100u
#define BSD_PCI_POWER_STATUS_PME 0x8000u
#define BSD_PCI_MSI_CONTROL 0x02
#define BSD_PCI_MSI_MMC_MASK 0x000eu
#define BSD_PCI_MSI_MME_MASK 0x0070u
#define BSD_PCI_MSIX_CONTROL 0x02
#define BSD_PCI_MSIX_TABLE 0x04
#define BSD_PCI_MSIX_PBA 0x08
#define BSD_PCI_MSIX_COUNT_MASK 0x07ffu
#define BSD_PCIE_DEVICE_CONTROL 0x08
#define BSD_PCIE_DEVICE_CAPABILITIES 0x04
#define BSD_PCIE_DEVICE_STATUS 0x0a
#define BSD_PCIE_DEVICE_CAPABILITIES_2 0x24
#define BSD_PCIE_DEVICE_CONTROL_2 0x28
#define BSD_PCIE_CAPABILITY_VERSION_MASK 0x000fu
#define BSD_PCIE_CAPABILITY_TYPE_MASK 0x00f0u
#define BSD_PCIE_CAPABILITY_ROOT_PORT 0x0040u
#define BSD_PCIE_CAPABILITY_FLR 0x10000000u
#define BSD_PCIE_CONTROL_INITIATE_FLR 0x8000u
#define BSD_PCIE_STATUS_TRANSACTION_PENDING 0x0020u
#define BSD_PCIE_CAPABILITY_2_COMPLETION_TIMEOUT_RANGES 0x0000000fu
#define BSD_PCIE_CONTROL_2_COMPLETION_TIMEOUT_MASK 0x000fu
#define BSD_PCIE_MAX_READ_REQUEST_MASK 0x7000u
#define BSD_PCIE_LINK_CONTROL 0x10
#define BSD_PCIE_LINK_STATUS 0x12
#define BSD_PCIE_LINK_DISABLE 0x0010u
#define BSD_PCIE_LINK_RETRAIN 0x0020u
#define BSD_PCIE_LINK_TRAINING 0x0800u

#define BSD_PCI_HT_COMMAND 0x02
#define BSD_PCI_HT_CAPABILITY_MASK 0xf800u
#define BSD_PCI_HT_MSI_MAPPING 0xa800u
#define BSD_PCI_HT_MSI_ENABLE 0x0001u
#define BSD_PCI_HT_MSI_FIXED 0x0002u
#define BSD_PCI_HT_MSI_ADDRESS_LOW 0x04
#define BSD_PCI_HT_MSI_ADDRESS_HIGH 0x08
#define BSD_PCI_MSI_ADDRESS_BASE UINT64_C(0xfee00000)

#define BSD_PCI_BAR_IO 0x01u
#define BSD_PCI_BAR_MEMORY_TYPE_MASK 0x06u
#define BSD_PCI_BAR_MEMORY_64 0x04u
#define BSD_PCI_BAR_PREFETCHABLE 0x08u

#define BSD_PCI_IVAR_SUBVENDOR 0
#define BSD_PCI_IVAR_SUBDEVICE 1
#define BSD_PCI_IVAR_VENDOR 2
#define BSD_PCI_IVAR_DEVICE 3
#define BSD_PCI_IVAR_DEVID 4
#define BSD_PCI_IVAR_CLASS 5
#define BSD_PCI_IVAR_SUBCLASS 6
#define BSD_PCI_IVAR_PROGIF 7
#define BSD_PCI_IVAR_REVID 8
#define BSD_PCI_IVAR_INTPIN 9
#define BSD_PCI_IVAR_IRQ 10
#define BSD_PCI_IVAR_DOMAIN 11
#define BSD_PCI_IVAR_BUS 12
#define BSD_PCI_IVAR_SLOT 13
#define BSD_PCI_IVAR_FUNCTION 14
#define BSD_PCI_IVAR_CMDREG 16
#define BSD_PCIB_IVAR_DOMAIN 0
#define BSD_PCIB_IVAR_BUS 1

static const uint32_t g_pci_msi_blacklist[] = {
    UINT32_C(0x00141166),
    UINT32_C(0x00171166),
    UINT32_C(0x25408086),
    UINT32_C(0x254c8086),
    UINT32_C(0x25508086),
    UINT32_C(0x25608086),
    UINT32_C(0x25708086),
    UINT32_C(0x25788086),
    UINT32_C(0x35808086),
    UINT32_C(0x74501022),
};

struct pci_device_table {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint16_t match_flag_vendor:1;
    uint16_t match_flag_device:1;
    uint16_t match_flag_subvendor:1;
    uint16_t match_flag_subdevice:1;
    uint16_t match_flag_class:1;
    uint16_t match_flag_subclass:1;
    uint16_t match_flag_revid:1;
    uint16_t match_flag_unused:9;
#else
    uint16_t match_flag_unused:9;
    uint16_t match_flag_revid:1;
    uint16_t match_flag_subclass:1;
    uint16_t match_flag_class:1;
    uint16_t match_flag_subdevice:1;
    uint16_t match_flag_subvendor:1;
    uint16_t match_flag_device:1;
    uint16_t match_flag_vendor:1;
#endif
    uint16_t vendor;
    uint16_t device;
    uint16_t subvendor;
    uint16_t subdevice;
    uint16_t class_id;
    uint16_t subclass;
    uint16_t revid;
    uint16_t unused;
    uintptr_t driver_data;
    char *descr;
};

typedef enum {
    BSD_PCI_INTERRUPT_NONE,
    BSD_PCI_INTERRUPT_MSI,
    BSD_PCI_INTERRUPT_MSIX,
} bsd_pci_interrupt_mode_t;

struct pci_map {
    uint64_t pm_value;
    uint64_t pm_size;
    uint16_t pm_reg;
    struct {
        struct pci_map *stqe_next;
    } pm_link;
};

typedef struct bsd_pci_function bsd_pci_function_t;

typedef struct {
    bsd_pci_function_t *function;
    unsigned int index;
} bsd_pci_interrupt_source_t;

typedef struct {
    bsd_pci_attach_options_t options;
    bsd_pci_bus_status_t status;
} bsd_pci_bus_context_t;

struct bsd_pci_function {
    device_t device;
    bsd_pci_location_t location;
    uint16_t vendor;
    uint16_t device_id;
    uint16_t subvendor;
    uint16_t subdevice;
    uint16_t command;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t progif;
    uint8_t revision;
    uint8_t interrupt_line;
    uint8_t interrupt_pin;
    uint8_t header_type;
    uint8_t cache_line_size;
    uint8_t latency_timer;
    uint32_t bars[BSD_PCI_BAR_COUNT];
    struct pci_map maps[BSD_PCI_BAR_COUNT];
    uint32_t expansion_rom;
    int msi_capability;
    int msix_capability;
    bsd_pci_interrupt_mode_t interrupt_mode;
    unsigned int vector_count;
    uint32_t vectors[BSD_PCI_MAX_VECTORS];
    bsd_pci_interrupt_source_t sources[BSD_PCI_MAX_VECTORS];
    uint32_t active_vectors;
    uint8_t source_transition;
    volatile unsigned int guard;
};

static bsd_pci_backend_ops_t g_pci_operations;
static volatile unsigned int g_pci_init_guard;
static uint8_t g_pci_initialized;
int cfgmech = BSD_PCI_CFGMECH_PCIE;

extern struct kobjop_desc device_probe_desc;
extern struct kobjop_desc device_attach_desc;
extern struct kobjop_desc device_detach_desc;
extern struct kobjop_desc device_shutdown_desc;
extern struct kobjop_desc device_suspend_desc;
extern struct kobjop_desc device_resume_desc;
extern struct kobjop_desc bus_read_ivar_desc;
extern struct kobjop_desc bus_write_ivar_desc;
extern struct kobjop_desc pci_read_config_desc;
extern struct kobjop_desc pci_write_config_desc;
extern struct kobjop_desc pci_enable_busmaster_desc;
extern struct kobjop_desc pci_disable_busmaster_desc;
extern struct kobjop_desc pci_enable_io_desc;
extern struct kobjop_desc pci_disable_io_desc;
extern struct kobjop_desc pci_find_cap_desc;
extern struct kobjop_desc pci_find_next_cap_desc;
extern struct kobjop_desc pci_find_htcap_desc;
extern struct kobjop_desc pci_find_next_htcap_desc;
extern struct kobjop_desc pci_alloc_msi_desc;
extern struct kobjop_desc pci_alloc_msix_desc;
extern struct kobjop_desc pci_release_msi_desc;
extern struct kobjop_desc pci_msi_count_desc;
extern struct kobjop_desc pci_msix_count_desc;
extern struct kobjop_desc pci_msix_pba_bar_desc;
extern struct kobjop_desc pci_msix_table_bar_desc;

__attribute__((weak))
int
bsd_pci_arch_initialize(void)
{
    return BSD_PCI_ENXIO;
}

static void
pci_pause(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void
pci_spin_lock(volatile unsigned int *guard)
{
    while (__atomic_test_and_set(guard, __ATOMIC_ACQUIRE))
        pci_pause();
}

static void
pci_spin_unlock(volatile unsigned int *guard)
{
    __atomic_clear(guard, __ATOMIC_RELEASE);
}

int
bsd_pci_initialize(const bsd_pci_backend_ops_t *operations)
{
    if (!operations || !operations->read_config ||
        !operations->write_config || !operations->function_count ||
        !operations->function_at)
        return BSD_PCI_EINVAL;
    pci_spin_lock(&g_pci_init_guard);
    if (g_pci_initialized) {
        pci_spin_unlock(&g_pci_init_guard);
        return BSD_PCI_EBUSY;
    }
    g_pci_operations = *operations;
    __atomic_store_n(&g_pci_initialized, 1, __ATOMIC_RELEASE);
    pci_spin_unlock(&g_pci_init_guard);
    return 0;
}

int
bsd_pci_is_initialized(void)
{
    return __atomic_load_n(&g_pci_initialized, __ATOMIC_ACQUIRE) != 0;
}

int
bsd_pci_ensure_initialized(void)
{
    int result;

    if (bsd_pci_is_initialized())
        return 0;
    result = bsd_pci_arch_initialize();
    if (result == BSD_PCI_EBUSY && bsd_pci_is_initialized())
        return 0;
    return bsd_pci_is_initialized() ? 0 : result;
}

int
pci_cfgregopen(void)
{
    return bsd_pci_ensure_initialized() == 0;
}

int
pcie_cfgregopen(uint64_t base, uint16_t domain, uint8_t minbus,
    uint8_t maxbus)
{
    (void)base;
    (void)domain;
    (void)minbus;
    (void)maxbus;
    return pci_cfgregopen();
}

int
bsd_pci_read_config_at(const bsd_pci_location_t *location,
    uint16_t register_offset, unsigned int width, uint32_t *value)
{
    if (!location || !value || (width != 1 && width != 2 && width != 4) ||
        register_offset > 4096u - width ||
        (register_offset & (width - 1u)) != 0)
        return BSD_PCI_EINVAL;
    if (bsd_pci_ensure_initialized() != 0)
        return BSD_PCI_ENXIO;
    *value = g_pci_operations.read_config(g_pci_operations.context,
        location, register_offset, width);
    return 0;
}

int
bsd_pci_write_config_at(const bsd_pci_location_t *location,
    uint16_t register_offset, unsigned int width, uint32_t value)
{
    if (!location || (width != 1 && width != 2 && width != 4) ||
        register_offset > 4096u - width ||
        (register_offset & (width - 1u)) != 0)
        return BSD_PCI_EINVAL;
    if (bsd_pci_ensure_initialized() != 0)
        return BSD_PCI_ENXIO;
    g_pci_operations.write_config(g_pci_operations.context, location,
        register_offset, value, width);
    return 0;
}

uint32_t
pci_cfgregread(int domain, int bus, int slot, int function,
    int register_offset, int width)
{
    bsd_pci_location_t location;
    uint32_t value = UINT32_MAX;

    if (domain < 0 || bus < 0 || bus > UINT8_MAX ||
        slot < 0 || slot > 31 || function < 0 || function > 7 ||
        register_offset < 0 || register_offset > UINT16_MAX)
        return UINT32_MAX;
    location.domain = (uint32_t)domain;
    location.bus = (uint8_t)bus;
    location.slot = (uint8_t)slot;
    location.function = (uint8_t)function;
    if (bsd_pci_read_config_at(&location, (uint16_t)register_offset,
        (unsigned int)width, &value) != 0)
        return UINT32_MAX;
    return value;
}

void
pci_cfgregwrite(int domain, int bus, int slot, int function,
    int register_offset, uint32_t value, int width)
{
    bsd_pci_location_t location;

    if (domain < 0 || bus < 0 || bus > UINT8_MAX ||
        slot < 0 || slot > 31 || function < 0 || function > 7 ||
        register_offset < 0 || register_offset > UINT16_MAX)
        return;
    location.domain = (uint32_t)domain;
    location.bus = (uint8_t)bus;
    location.slot = (uint8_t)slot;
    location.function = (uint8_t)function;
    (void)bsd_pci_write_config_at(&location,
        (uint16_t)register_offset, (unsigned int)width, value);
}

static bsd_pci_function_t *
pci_function(device_t device)
{
    return device ? device_get_ivars(device) : 0;
}

static void pcie_pause_milliseconds(const char *wait_message,
    unsigned int milliseconds);

struct pci_map *
pci_find_bar(device_t device, int register_offset)
{
    bsd_pci_function_t *function = pci_function(device);

    if (!function)
        return 0;
    for (unsigned int index = 0; index < BSD_PCI_BAR_COUNT; ++index) {
        if (function->maps[index].pm_reg == (uint16_t)register_offset &&
            function->maps[index].pm_size != 0)
            return &function->maps[index];
    }
    return 0;
}

struct pci_map *
pci_first_bar(device_t device)
{
    bsd_pci_function_t *function = pci_function(device);

    if (!function)
        return 0;
    for (unsigned int index = 0; index < BSD_PCI_BAR_COUNT; ++index) {
        if (function->maps[index].pm_size != 0)
            return &function->maps[index];
    }
    return 0;
}

struct pci_map *
pci_next_bar(struct pci_map *map)
{
    return map ? map->pm_link.stqe_next : 0;
}

int
pci_power_reset(device_t device)
{
    int capability;
    uint16_t control;
    uint16_t original_state;

    if (bsd_pci_find_capability(device,
        BSD_PCI_CAP_POWER_MANAGEMENT, 0, &capability) != 0)
        return BSD_PCI_ENXIO;
    control = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCI_POWER_STATUS, 2);
    original_state = control & 0x3u;
    if (original_state != 0 && original_state != 3u) {
        bsd_pci_write_config(device,
            capability + BSD_PCI_POWER_STATUS,
            control & (uint16_t)~0x3u, 2);
        pcie_pause_milliseconds("pcipwr0", 10u);
    }
    bsd_pci_write_config(device,
        capability + BSD_PCI_POWER_STATUS,
        (control & (uint16_t)~0x3u) | 3u, 2);
    pcie_pause_milliseconds("pcipwr3", 10u);
    bsd_pci_write_config(device,
        capability + BSD_PCI_POWER_STATUS,
        (control & (uint16_t)~0x3u) | original_state, 2);
    pcie_pause_milliseconds("pcipwrr", 10u);
    return 0;
}

static int
pci_parent_is_bus(device_t parent)
{
    const char *name = device_get_name(parent);

    return name && name[0] == 'p' && name[1] == 'c' &&
        name[2] == 'i' && name[3] == '\0';
}

static device_t
pci_find_device_below(device_t parent, uint16_t vendor,
    uint16_t device_id)
{
    device_t *children = 0;
    device_t found = 0;
    int count = 0;

    if (!parent || device_get_children(parent, &children, &count) != 0)
        return 0;
    for (int index = 0; index < count && !found; ++index) {
        device_t child = children[index];

        if (pci_parent_is_bus(parent)) {
            bsd_pci_function_t *function = pci_function(child);

            if (function && function->vendor == vendor &&
                function->device_id == device_id) {
                found = child;
                break;
            }
        }
        found = pci_find_device_below(child, vendor, device_id);
    }
    if (children)
        bsd_free(children, M_TEMP);
    return found;
}

static device_t
pci_find_location_below(device_t parent, uint32_t domain, uint8_t bus,
    uint8_t slot, uint8_t function_number)
{
    device_t *children = 0;
    device_t found = 0;
    int count = 0;

    if (!parent || device_get_children(parent, &children, &count) != 0)
        return 0;
    for (int index = 0; index < count && !found; ++index) {
        device_t child = children[index];

        if (pci_parent_is_bus(parent)) {
            bsd_pci_function_t *function = pci_function(child);

            if (function &&
                function->location.domain == domain &&
                function->location.bus == bus &&
                function->location.slot == slot &&
                function->location.function == function_number) {
                found = child;
                break;
            }
        }
        found = pci_find_location_below(child, domain, bus, slot,
            function_number);
    }
    if (children)
        bsd_free(children, M_TEMP);
    return found;
}

device_t
pci_find_device(uint16_t vendor, uint16_t device_id)
{
    return pci_find_device_below(root_bus, vendor, device_id);
}

device_t
pci_find_dbsf(uint32_t domain, uint8_t bus, uint8_t slot,
    uint8_t function_number)
{
    if (slot > 31 || function_number > 7)
        return 0;
    return pci_find_location_below(root_bus, domain, bus, slot,
        function_number);
}

device_t
pci_find_bsf(uint8_t bus, uint8_t slot, uint8_t function_number)
{
    return pci_find_dbsf(0, bus, slot, function_number);
}

static uint32_t
pci_backend_read(const bsd_pci_location_t *location, int register_offset,
    int width)
{
    if (!location || register_offset < 0 || register_offset > 4095 ||
        (width != 1 && width != 2 && width != 4) ||
        register_offset > 4096 - width)
        return UINT32_MAX;
    return g_pci_operations.read_config(g_pci_operations.context,
        location, (uint16_t)register_offset, (unsigned int)width);
}

static void
pci_backend_write(const bsd_pci_location_t *location, int register_offset,
    uint32_t value, int width)
{
    if (!location || register_offset < 0 || register_offset > 4095 ||
        (width != 1 && width != 2 && width != 4) ||
        register_offset > 4096 - width)
        return;
    g_pci_operations.write_config(g_pci_operations.context, location,
        (uint16_t)register_offset, value, (unsigned int)width);
}

int
bsd_pci_get_location(device_t device, bsd_pci_location_t *location)
{
    bsd_pci_function_t *function = pci_function(device);

    if (!function || !location)
        return BSD_PCI_EINVAL;
    *location = function->location;
    return 0;
}

uint32_t
bsd_pci_read_config(device_t device, int register_offset, int width)
{
    bsd_pci_function_t *function = pci_function(device);

    return function ? pci_backend_read(&function->location,
        register_offset, width) : UINT32_MAX;
}

const struct pci_device_table *
pci_match_device(device_t child, const struct pci_device_table *entry,
    size_t entry_count)
{
    bsd_pci_function_t *function = pci_function(child);

    if (!function || !entry)
        return NULL;
    while (entry_count-- > 0) {
        bool matches = true;

        if (entry->match_flag_vendor)
            matches = matches && function->vendor == entry->vendor;
        if (entry->match_flag_device)
            matches = matches && function->device_id == entry->device;
        if (entry->match_flag_subvendor)
            matches = matches && function->subvendor == entry->subvendor;
        if (entry->match_flag_subdevice)
            matches = matches && function->subdevice == entry->subdevice;
        if (entry->match_flag_class)
            matches = matches && function->class_code == entry->class_id;
        if (entry->match_flag_subclass)
            matches = matches && function->subclass == entry->subclass;
        if (entry->match_flag_revid)
            matches = matches && function->revision == entry->revid;
        if (matches)
            return entry;
        entry++;
    }
    return NULL;
}

void
bsd_pci_write_config(device_t device, int register_offset, uint32_t value,
    int width)
{
    bsd_pci_function_t *function = pci_function(device);

    if (function)
        pci_backend_write(&function->location, register_offset,
            value, width);
}

static void
pci_capture_config(device_t device, bsd_pci_function_t *function)
{
    function->command = (uint16_t)bsd_pci_read_config(
        device, BSD_PCI_COMMAND, 2);
    function->cache_line_size = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_CACHE_LINE_SIZE, 1);
    function->latency_timer = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_LATENCY_TIMER, 1);
    function->interrupt_line = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_INTERRUPT_LINE, 1);
    function->interrupt_pin = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_INTERRUPT_PIN, 1);
    for (unsigned int index = 0; index < BSD_PCI_BAR_COUNT; ++index) {
        function->bars[index] = bsd_pci_read_config(device,
            BSD_PCI_BAR_FIRST + (int)index * 4, 4);
    }
    function->expansion_rom = bsd_pci_read_config(
        device, BSD_PCI_EXPANSION_ROM, 4);
}

static void
pci_set_native_power_state(device_t device, unsigned int state)
{
    int capability;
    uint16_t control;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_POWER_MANAGEMENT, 0,
        &capability) != 0)
        return;
    control = (uint16_t)bsd_pci_read_config(
        device, capability + BSD_PCI_POWER_STATUS, 2);
    control = (uint16_t)((control & ~UINT16_C(3)) | (state & 3u));
    bsd_pci_write_config(
        device, capability + BSD_PCI_POWER_STATUS, control, 2);
}

struct pci_devinfo;

void
pci_cfg_save(device_t device, struct pci_devinfo *device_info,
    int set_power_state)
{
    bsd_pci_function_t *function = pci_function(device);

    (void)device_info;
    if (!function)
        return;
    pci_capture_config(device, function);
    if (set_power_state)
        pci_set_native_power_state(device, 3);
}

void
pci_cfg_restore(device_t device, struct pci_devinfo *device_info)
{
    bsd_pci_function_t *function = pci_function(device);

    (void)device_info;
    if (!function)
        return;
    pci_set_native_power_state(device, 0);
    bsd_pci_write_config(device, BSD_PCI_INTERRUPT_LINE,
        function->interrupt_line, 1);
    bsd_pci_write_config(device, BSD_PCI_CACHE_LINE_SIZE,
        function->cache_line_size, 1);
    bsd_pci_write_config(device, BSD_PCI_LATENCY_TIMER,
        function->latency_timer, 1);
    for (unsigned int index = 0; index < BSD_PCI_BAR_COUNT; ++index) {
        bsd_pci_write_config(device,
            BSD_PCI_BAR_FIRST + (int)index * 4, function->bars[index], 4);
    }
    bsd_pci_write_config(device, BSD_PCI_EXPANSION_ROM,
        function->expansion_rom, 4);
    bsd_pci_write_config(
        device, BSD_PCI_COMMAND, function->command, 2);
    if (function->interrupt_mode == BSD_PCI_INTERRUPT_MSI &&
        g_pci_operations.enable_msi) {
        (void)g_pci_operations.enable_msi(g_pci_operations.context,
            &function->location, function->vectors,
            function->vector_count);
    } else if (function->interrupt_mode == BSD_PCI_INTERRUPT_MSIX &&
        g_pci_operations.enable_msix) {
        for (unsigned int index = 0;
            index < function->vector_count; ++index) {
            (void)g_pci_operations.enable_msix(g_pci_operations.context,
                &function->location, index, function->vectors[index]);
        }
    }
}

void
pci_save_state(device_t device)
{
    pci_cfg_save(device, NULL, 0);
}

void
pci_restore_state(device_t device)
{
    pci_cfg_restore(device, NULL);
}

int
bsd_pci_find_capability(device_t device, int capability, int start,
    int *capability_register)
{
    int ignored_register;
    uint16_t status;
    uint8_t current;

    if (!pci_function(device) ||
        capability < 0 || capability > UINT8_MAX ||
        start < 0 || start > UINT8_MAX)
        return BSD_PCI_EINVAL;
    if (!capability_register)
        capability_register = &ignored_register;
    status = (uint16_t)bsd_pci_read_config(device, BSD_PCI_STATUS, 2);
    if ((status & BSD_PCI_STATUS_CAPABILITIES) == 0)
        return BSD_PCI_ENOENT;
    current = start == 0 ?
        (uint8_t)bsd_pci_read_config(device, BSD_PCI_CAPABILITIES, 1) :
        (uint8_t)bsd_pci_read_config(device, start + 1, 1);
    current &= 0xfcu;
    for (unsigned int guard = 0; guard < 48 && current >= 0x40;
         ++guard) {
        uint8_t id = (uint8_t)bsd_pci_read_config(device, current, 1);
        uint8_t next = (uint8_t)bsd_pci_read_config(
            device, current + 1, 1) & 0xfcu;

        if (id == (uint8_t)capability) {
            *capability_register = current;
            return 0;
        }
        if (next == current)
            break;
        current = next;
    }
    return BSD_PCI_ENOENT;
}

static int
pci_find_ht_capability(device_t device, int requested_type, int start,
    int *capability_register)
{
    int current = start;

    for (;;) {
        uint16_t command;
        int capability;
        int error;

        error = bsd_pci_find_capability(device,
            BSD_PCI_CAP_HYPERTRANSPORT, current, &capability);
        if (error != 0)
            return error;
        command = (uint16_t)bsd_pci_read_config(device,
            capability + BSD_PCI_HT_COMMAND, 2);
        if ((command & BSD_PCI_HT_CAPABILITY_MASK) ==
            (uint16_t)requested_type) {
            if (capability_register)
                *capability_register = capability;
            return 0;
        }
        current = capability;
    }
}

void
pci_ht_map_msi(device_t device, uint64_t address)
{
    uint64_t mapping_address;
    uint16_t command;
    int capability;

    if (pci_find_ht_capability(device, BSD_PCI_HT_MSI_MAPPING, 0,
        &capability) != 0)
        return;
    command = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCI_HT_COMMAND, 2);
    if ((command & BSD_PCI_HT_MSI_FIXED) != 0) {
        mapping_address = BSD_PCI_MSI_ADDRESS_BASE;
    } else {
        mapping_address = bsd_pci_read_config(device,
            capability + BSD_PCI_HT_MSI_ADDRESS_LOW, 4);
        mapping_address |= (uint64_t)bsd_pci_read_config(device,
            capability + BSD_PCI_HT_MSI_ADDRESS_HIGH, 4) << 32;
    }
    if (address != 0 &&
        (command & BSD_PCI_HT_MSI_ENABLE) == 0 &&
        (mapping_address >> 20) == (address >> 20)) {
        command |= BSD_PCI_HT_MSI_ENABLE;
        bsd_pci_write_config(device,
            capability + BSD_PCI_HT_COMMAND, command, 2);
    } else if (address == 0 &&
        (command & BSD_PCI_HT_MSI_ENABLE) != 0) {
        command &= (uint16_t)~BSD_PCI_HT_MSI_ENABLE;
        bsd_pci_write_config(device,
            capability + BSD_PCI_HT_COMMAND, command, 2);
    }
}

static int
pci_device_id_is_listed(uint32_t device_id,
    const uint32_t *identifiers, size_t count)
{
    for (size_t index = 0; index < count; ++index) {
        if (identifiers[index] == device_id)
            return 1;
    }
    return 0;
}

int
pci_msi_device_blacklisted(device_t device)
{
    bsd_pci_function_t *function = pci_function(device);
    uint32_t device_id;

    if (!function)
        return 0;
    device_id = ((uint32_t)function->device_id << 16) |
        function->vendor;
    return pci_device_id_is_listed(device_id,
        g_pci_msi_blacklist,
        sizeof(g_pci_msi_blacklist) / sizeof(g_pci_msi_blacklist[0]));
}

int
pci_msix_device_blacklisted(device_t device)
{
    return pci_msi_device_blacklisted(device);
}

int
pcie_link_reset(device_t device, int capability)
{
    uint16_t control;
    uint16_t status;
    int short_delay;
    int long_delay;

    if (!pci_function(device) || capability < 0 ||
        capability > UINT8_MAX - BSD_PCIE_LINK_STATUS)
        return BSD_PCI_EINVAL;
    control = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCIE_LINK_CONTROL, 2);
    bsd_pci_write_config(device, capability + BSD_PCIE_LINK_CONTROL,
        control | BSD_PCIE_LINK_DISABLE, 2);
    short_delay = hz / 50;
    if (short_delay < 1)
        short_delay = 1;
    (void)bsd_pause("pcier1", short_delay);
    control &= (uint16_t)~BSD_PCIE_LINK_DISABLE;
    control |= BSD_PCIE_LINK_RETRAIN;
    bsd_pci_write_config(device, capability + BSD_PCIE_LINK_CONTROL,
        control, 2);
    long_delay = hz / 10;
    if (long_delay < 1)
        long_delay = 1;
    (void)bsd_pause("pcier2", long_delay);
    status = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCIE_LINK_STATUS, 2);
    return (status & BSD_PCIE_LINK_TRAINING) != 0 ? 60 : 0;
}

bool
pci_has_pm(device_t device)
{
    return bsd_pci_find_capability(device,
        BSD_PCI_CAP_POWER_MANAGEMENT, 0, 0) == 0;
}

uint32_t
pcie_read_config(device_t device, int register_offset, int width)
{
    int capability;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_EXPRESS, 0,
        &capability) != 0)
        return width == 2 ? UINT16_MAX : UINT32_MAX;
    return bsd_pci_read_config(device,
        capability + register_offset, width);
}

void
pcie_write_config(device_t device, int register_offset, uint32_t value,
    int width)
{
    int capability;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_EXPRESS, 0,
        &capability) != 0)
        return;
    bsd_pci_write_config(device, capability + register_offset, value,
        width);
}

static void
pcie_pause_milliseconds(const char *wait_message, unsigned int milliseconds)
{
    uint64_t ticks;

    ticks = ((uint64_t)milliseconds * (unsigned int)hz + 999u) / 1000u;
    if (ticks == 0)
        ticks = 1;
    if (ticks > INT32_MAX)
        ticks = INT32_MAX;
    (void)bsd_pause(wait_message, (int)ticks);
}

bool
pcie_wait_for_pending_transactions(device_t device, unsigned int max_delay)
{
    int capability;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_EXPRESS, 0,
        &capability) != 0)
        return true;
    while ((bsd_pci_read_config(device,
        capability + BSD_PCIE_DEVICE_STATUS, 2) &
        BSD_PCIE_STATUS_TRANSACTION_PENDING) != 0) {
        unsigned int delay;

        if (max_delay == 0)
            return false;
        delay = max_delay > 100u ? 100u : max_delay;
        pcie_pause_milliseconds("pcietp", delay);
        max_delay -= delay;
    }
    return true;
}

int
pcie_get_max_completion_timeout(device_t device)
{
    uint16_t flags;
    uint16_t control;
    uint32_t capabilities;
    int capability;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_EXPRESS, 0,
        &capability) != 0)
        return 0;
    flags = (uint16_t)bsd_pci_read_config(device, capability + 2, 2);
    capabilities = bsd_pci_read_config(device,
        capability + BSD_PCIE_DEVICE_CAPABILITIES_2, 4);
    if ((flags & BSD_PCIE_CAPABILITY_VERSION_MASK) < 2 ||
        (capabilities &
        BSD_PCIE_CAPABILITY_2_COMPLETION_TIMEOUT_RANGES) == 0)
        return 50 * 1000;
    control = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCIE_DEVICE_CONTROL_2, 2);
    switch (control & BSD_PCIE_CONTROL_2_COMPLETION_TIMEOUT_MASK) {
    case 0x1:
        return 100;
    case 0x2:
        return 10 * 1000;
    case 0x5:
        return 55 * 1000;
    case 0x6:
        return 210 * 1000;
    case 0x9:
        return 900 * 1000;
    case 0xa:
        return 3500 * 1000;
    case 0xd:
        return 13 * 1000 * 1000;
    case 0xe:
        return 64 * 1000 * 1000;
    default:
        return 50 * 1000;
    }
}

bool
pcie_flr(device_t device, unsigned int max_delay, bool force)
{
    uint16_t command;
    uint16_t control;
    int completion_delay = 0;
    int capability;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_EXPRESS, 0,
        &capability) != 0)
        return false;
    if ((bsd_pci_read_config(device,
        capability + BSD_PCIE_DEVICE_CAPABILITIES, 4) &
        BSD_PCIE_CAPABILITY_FLR) == 0)
        return false;

    command = (uint16_t)bsd_pci_read_config(device, BSD_PCI_COMMAND, 2);
    bsd_pci_write_config(device, BSD_PCI_COMMAND,
        command & (uint16_t)~BSD_PCI_COMMAND_BUSMASTER_ENABLE, 2);
    if (!pcie_wait_for_pending_transactions(device, max_delay)) {
        if (!force) {
            bsd_pci_write_config(device, BSD_PCI_COMMAND, command, 2);
            return false;
        }
        completion_delay = pcie_get_max_completion_timeout(device) / 1000;
        if (completion_delay < 10)
            completion_delay = 10;
    }

    control = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCIE_DEVICE_CONTROL, 2);
    bsd_pci_write_config(device, capability + BSD_PCIE_DEVICE_CONTROL,
        control | BSD_PCIE_CONTROL_INITIATE_FLR, 2);
    pcie_pause_milliseconds("pcieflr",
        100u + (unsigned int)completion_delay);
    return true;
}

int
pci_get_max_read_req(device_t device)
{
    int capability;
    uint16_t control;
    unsigned int field;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_EXPRESS, 0,
        &capability) != 0)
        return 0;
    control = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCIE_DEVICE_CONTROL, 2);
    field = (control & BSD_PCIE_MAX_READ_REQUEST_MASK) >> 12;
    return 1 << (field + 7u);
}

int
pci_set_max_read_req(device_t device, int size)
{
    int capability;
    int selected = 128;
    uint16_t control;
    unsigned int field = 0;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_EXPRESS, 0,
        &capability) != 0)
        return 0;
    if (size > 4096)
        size = 4096;
    while (selected < size && selected < 4096) {
        selected <<= 1;
        field++;
    }
    if (selected > size && selected > 128) {
        selected >>= 1;
        field--;
    }
    control = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCIE_DEVICE_CONTROL, 2);
    control &= (uint16_t)~BSD_PCIE_MAX_READ_REQUEST_MASK;
    control |= (uint16_t)(field << 12);
    bsd_pci_write_config(device,
        capability + BSD_PCIE_DEVICE_CONTROL, control, 2);
    return selected;
}

void
pci_enable_pme(device_t device)
{
    int capability;
    uint16_t status;

    if (bsd_pci_find_capability(device,
        BSD_PCI_CAP_POWER_MANAGEMENT, 0, &capability) != 0)
        return;
    status = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCI_POWER_STATUS, 2);
    status |= BSD_PCI_POWER_STATUS_PME |
        BSD_PCI_POWER_STATUS_PME_ENABLE;
    bsd_pci_write_config(device,
        capability + BSD_PCI_POWER_STATUS, status, 2);
}

static unsigned int
pci_msi_supported(device_t device)
{
    int capability;
    uint16_t control;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_MSI, 0,
        &capability) != 0)
        return 0;
    control = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCI_MSI_CONTROL, 2);
    return 1u << ((control & BSD_PCI_MSI_MMC_MASK) >> 1);
}

static unsigned int
pci_msix_supported(device_t device)
{
    int capability;
    uint16_t control;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_MSIX, 0,
        &capability) != 0)
        return 0;
    control = (uint16_t)bsd_pci_read_config(device,
        capability + BSD_PCI_MSIX_CONTROL, 2);
    return (control & BSD_PCI_MSIX_COUNT_MASK) + 1u;
}

int
bsd_pci_msi_count(device_t device)
{
    return (int)pci_msi_supported(device);
}

int
bsd_pci_msix_count(device_t device)
{
    return (int)pci_msix_supported(device);
}

static int
pci_msix_bar(device_t device, int register_offset)
{
    int capability;
    uint32_t value;

    if (bsd_pci_find_capability(device, BSD_PCI_CAP_MSIX, 0,
        &capability) != 0)
        return -1;
    value = bsd_pci_read_config(device,
        capability + register_offset, 4);
    return BSD_PCI_BAR_FIRST + (int)(value & 7u) * 4;
}

int
bsd_pci_msix_table_bar(device_t device)
{
    return pci_msix_bar(device, BSD_PCI_MSIX_TABLE);
}

int
bsd_pci_msix_pba_bar(device_t device)
{
    return pci_msix_bar(device, BSD_PCI_MSIX_PBA);
}

static int
pci_interrupt_source_enable(void *opaque_source)
{
    bsd_pci_interrupt_source_t *source = opaque_source;
    bsd_pci_function_t *function = source->function;
    uint32_t bit = UINT32_C(1) << source->index;
    int result;

    pci_spin_lock(&function->guard);
    if (function->source_transition) {
        pci_spin_unlock(&function->guard);
        return BSD_PCI_EBUSY;
    }
    if (function->active_vectors & bit) {
        pci_spin_unlock(&function->guard);
        return 0;
    }
    function->source_transition = 1;
    pci_spin_unlock(&function->guard);

    if (function->interrupt_mode == BSD_PCI_INTERRUPT_MSI) {
        result = function->active_vectors == 0 &&
            g_pci_operations.enable_msi ?
            g_pci_operations.enable_msi(g_pci_operations.context,
                &function->location, function->vectors,
                function->vector_count) : 0;
    } else if (function->interrupt_mode == BSD_PCI_INTERRUPT_MSIX &&
        g_pci_operations.enable_msix) {
        result = g_pci_operations.enable_msix(
            g_pci_operations.context, &function->location,
            source->index, function->vectors[source->index]);
    } else {
        result = BSD_PCI_ENXIO;
    }

    pci_spin_lock(&function->guard);
    if (result == 0)
        function->active_vectors |= bit;
    function->source_transition = 0;
    pci_spin_unlock(&function->guard);
    return result;
}

static int
pci_interrupt_source_disable(void *opaque_source)
{
    bsd_pci_interrupt_source_t *source = opaque_source;
    bsd_pci_function_t *function = source->function;
    uint32_t bit = UINT32_C(1) << source->index;
    uint32_t remaining;
    int result;

    pci_spin_lock(&function->guard);
    if (function->source_transition) {
        pci_spin_unlock(&function->guard);
        return BSD_PCI_EBUSY;
    }
    if ((function->active_vectors & bit) == 0) {
        pci_spin_unlock(&function->guard);
        return 0;
    }
    remaining = function->active_vectors & ~bit;
    function->source_transition = 1;
    pci_spin_unlock(&function->guard);

    if (function->interrupt_mode == BSD_PCI_INTERRUPT_MSI) {
        result = remaining == 0 && g_pci_operations.disable_msi ?
            g_pci_operations.disable_msi(g_pci_operations.context,
                &function->location) : 0;
    } else if (function->interrupt_mode == BSD_PCI_INTERRUPT_MSIX &&
        g_pci_operations.disable_msix) {
        result = g_pci_operations.disable_msix(
            g_pci_operations.context, &function->location,
            source->index);
    } else {
        result = BSD_PCI_ENXIO;
    }

    pci_spin_lock(&function->guard);
    if (result == 0)
        function->active_vectors = remaining;
    function->source_transition = 0;
    pci_spin_unlock(&function->guard);
    return result;
}

static int
pci_alloc_vectors(device_t device, int *count,
    bsd_pci_interrupt_mode_t mode)
{
    bsd_pci_function_t *function = pci_function(device);
    bsd_resource_interrupt_source_ops_t source_operations;
    unsigned int requested;
    unsigned int supported;
    unsigned int allocated;
    int result;

    if (!function || !count || *count < 1 ||
        *count > BSD_PCI_MAX_VECTORS)
        return BSD_PCI_EINVAL;
    if (!g_pci_operations.allocate_vectors ||
        !g_pci_operations.release_vectors ||
        function->interrupt_mode != BSD_PCI_INTERRUPT_NONE ||
        bsd_resource_is_allocated(device, SYS_RES_IRQ, 0))
        return BSD_PCI_ENXIO;
    requested = (unsigned int)*count;
    supported = mode == BSD_PCI_INTERRUPT_MSI ?
        pci_msi_supported(device) : pci_msix_supported(device);
    if (supported == 0)
        return BSD_PCI_ENOENT;
    if (requested > supported)
        requested = supported;
    if (mode == BSD_PCI_INTERRUPT_MSI &&
        (requested & (requested - 1u)) != 0)
        return BSD_PCI_EINVAL;

    allocated = requested;
    result = g_pci_operations.allocate_vectors(
        g_pci_operations.context, requested,
        mode == BSD_PCI_INTERRUPT_MSI, function->vectors, &allocated);
    if (result != 0)
        return result;
    if (allocated == 0 || allocated > requested ||
        (mode == BSD_PCI_INTERRUPT_MSI &&
         (allocated & (allocated - 1u)) != 0)) {
        g_pci_operations.release_vectors(g_pci_operations.context,
            function->vectors, allocated);
        return BSD_PCI_EINVAL;
    }

    function->interrupt_mode = mode;
    function->vector_count = allocated;
    for (unsigned int index = 0; index < allocated; ++index) {
        function->sources[index].function = function;
        function->sources[index].index = index;
        result = bsd_device_add_resource(device, SYS_RES_IRQ,
            (int)index + 1, function->vectors[index], 1, 0, 0);
        if (result != 0)
            break;
        source_operations.enable = pci_interrupt_source_enable;
        source_operations.disable = pci_interrupt_source_disable;
        source_operations.context = &function->sources[index];
        source_operations.interrupt_flags = 0;
        result = bsd_resource_set_interrupt_source(device,
            (int)index + 1, &source_operations);
        if (result != 0)
            break;
    }
    if (result != 0) {
        for (unsigned int index = 0; index < allocated; ++index)
            bus_delete_resource(device, SYS_RES_IRQ, (int)index + 1);
        g_pci_operations.release_vectors(g_pci_operations.context,
            function->vectors, allocated);
        function->interrupt_mode = BSD_PCI_INTERRUPT_NONE;
        function->vector_count = 0;
        return result;
    }
    if (mode == BSD_PCI_INTERRUPT_MSI) {
        uint16_t control = (uint16_t)bsd_pci_read_config(device,
            function->msi_capability + BSD_PCI_MSI_CONTROL, 2);
        unsigned int encoded = 0;

        while ((1u << encoded) < allocated)
            encoded++;
        control &= ~BSD_PCI_MSI_MME_MASK;
        control |= (uint16_t)(encoded << 4);
        bsd_pci_write_config(device,
            function->msi_capability + BSD_PCI_MSI_CONTROL,
            control, 2);
    }
    *count = (int)allocated;
    return 0;
}

int
bsd_pci_alloc_msi(device_t device, int *count)
{
    return pci_alloc_vectors(device, count, BSD_PCI_INTERRUPT_MSI);
}

int
bsd_pci_alloc_msix(device_t device, int *count)
{
    int table_bar = bsd_pci_msix_table_bar(device);

    if (table_bar < 0 ||
        !bsd_resource_is_allocated(device, SYS_RES_MEMORY, table_bar))
        return BSD_PCI_ENXIO;
    return pci_alloc_vectors(device, count, BSD_PCI_INTERRUPT_MSIX);
}

int
bsd_pci_release_msi(device_t device)
{
    bsd_pci_function_t *function = pci_function(device);
    int result = 0;

    if (!function ||
        function->interrupt_mode == BSD_PCI_INTERRUPT_NONE)
        return BSD_PCI_ENOENT;
    if (function->active_vectors || function->source_transition)
        return BSD_PCI_EBUSY;
    for (unsigned int index = 0; index < function->vector_count; ++index) {
        if (bsd_resource_is_allocated(device, SYS_RES_IRQ,
            (int)index + 1))
            return BSD_PCI_EBUSY;
    }
    if (function->interrupt_mode == BSD_PCI_INTERRUPT_MSI &&
        g_pci_operations.disable_msi) {
        result = g_pci_operations.disable_msi(
            g_pci_operations.context, &function->location);
    } else if (function->interrupt_mode == BSD_PCI_INTERRUPT_MSIX &&
        g_pci_operations.disable_msix_all) {
        result = g_pci_operations.disable_msix_all(
            g_pci_operations.context, &function->location);
    }
    if (result != 0)
        return result;
    for (unsigned int index = 0; index < function->vector_count; ++index)
        bus_delete_resource(device, SYS_RES_IRQ, (int)index + 1);
    g_pci_operations.release_vectors(g_pci_operations.context,
        function->vectors, function->vector_count);
    function->interrupt_mode = BSD_PCI_INTERRUPT_NONE;
    function->vector_count = 0;
    function->active_vectors = 0;
    return 0;
}

bool
is_pci_device(device_t device)
{
    device_t parent;
    devclass_t pci_class;

    if (!device)
        return false;
    parent = device_get_parent(device);
    if (!parent)
        return false;
    pci_class = devclass_find("pci");
    return pci_class && device_get_devclass(parent) == pci_class;
}

device_t
pci_find_pcie_root_port(device_t device)
{
    device_t bridge;
    device_t bus;

    if (!is_pci_device(device))
        return 0;
    for (unsigned int depth = 0; depth < 64u; ++depth) {
        int capability;
        uint16_t flags;

        bus = device_get_parent(device);
        bridge = bus ? device_get_parent(bus) : 0;
        if (!bridge || !is_pci_device(bridge))
            return 0;
        if (bsd_pci_find_capability(bridge, BSD_PCI_CAP_EXPRESS, 0,
            &capability) == 0) {
            flags = (uint16_t)bsd_pci_read_config(bridge,
                capability + 2, 2);
            if ((flags & BSD_PCIE_CAPABILITY_TYPE_MASK) ==
                BSD_PCIE_CAPABILITY_ROOT_PORT)
                return bridge;
        }
        device = bridge;
    }
    return 0;
}

static int
pci_reprogram_function(bsd_pci_function_t *function)
{
    bsd_pci_interrupt_mode_t mode;
    uint32_t active;
    uint32_t vectors[BSD_PCI_MAX_VECTORS];
    unsigned int count;
    int result = 0;

    if (!function)
        return BSD_PCI_EINVAL;
    pci_spin_lock(&function->guard);
    if (function->source_transition) {
        pci_spin_unlock(&function->guard);
        return BSD_PCI_EBUSY;
    }
    mode = function->interrupt_mode;
    count = function->vector_count;
    active = function->active_vectors;
    if (mode == BSD_PCI_INTERRUPT_NONE || active == 0) {
        pci_spin_unlock(&function->guard);
        return 0;
    }
    if (count == 0 || count > BSD_PCI_MAX_VECTORS ||
        (count < BSD_PCI_MAX_VECTORS &&
        (active >> count) != 0)) {
        pci_spin_unlock(&function->guard);
        return BSD_PCI_EINVAL;
    }
    for (unsigned int index = 0; index < count; ++index)
        vectors[index] = function->vectors[index];
    function->source_transition = 1;
    pci_spin_unlock(&function->guard);

    if (mode == BSD_PCI_INTERRUPT_MSI) {
        if (!g_pci_operations.enable_msi)
            result = BSD_PCI_ENXIO;
        else
            result = g_pci_operations.enable_msi(
                g_pci_operations.context, &function->location,
                vectors, count);
    } else if (mode == BSD_PCI_INTERRUPT_MSIX) {
        if (!g_pci_operations.enable_msix) {
            result = BSD_PCI_ENXIO;
        } else {
            for (unsigned int index = 0; index < count; ++index) {
                if ((active & (UINT32_C(1) << index)) == 0)
                    continue;
                result = g_pci_operations.enable_msix(
                    g_pci_operations.context, &function->location,
                    index, vectors[index]);
                if (result != 0)
                    break;
            }
        }
    } else {
        result = BSD_PCI_EINVAL;
    }

    pci_spin_lock(&function->guard);
    function->source_transition = 0;
    pci_spin_unlock(&function->guard);
    return result;
}

static int
pci_reprogram_below(device_t parent)
{
    device_t *children = 0;
    int count = 0;
    int first_error = 0;
    int result;

    if (!parent)
        return BSD_PCI_EINVAL;
    result = device_get_children(parent, &children, &count);
    if (result != 0)
        return result;
    for (int index = 0; index < count; ++index) {
        device_t child = children[index];

        if (is_pci_device(child)) {
            result = pci_reprogram_function(pci_function(child));
            if (result != 0 && first_error == 0) {
                first_error = result;
                device_printf(child,
                    "interrupt reprogramming failed: error=%d\n",
                    result);
            }
        }
        result = pci_reprogram_below(child);
        if (result != 0 && first_error == 0)
            first_error = result;
    }
    if (children)
        bsd_free(children, M_TEMP);
    return first_error;
}

int
bsd_pci_reprogram_interrupts(void)
{
    if (!g_pci_initialized || !root_bus)
        return BSD_PCI_ENXIO;
    return pci_reprogram_below(root_bus);
}

static int
pci_add_bar_resources(device_t device)
{
    bsd_pci_function_t *function = pci_function(device);
    unsigned int bar_count =
        (function->header_type & 0x7fu) == 0 ? 6u : 2u;
    uint16_t command = function->command;
    uint16_t enabled_command = command;

    bsd_pci_write_config(device, BSD_PCI_COMMAND,
        command & ~(BSD_PCI_COMMAND_IO_ENABLE |
                    BSD_PCI_COMMAND_MEMORY_ENABLE), 2);
    for (unsigned int bar = 0; bar < bar_count; ++bar) {
        unsigned int map_index = bar;
        int register_offset = BSD_PCI_BAR_FIRST + (int)bar * 4;
        uint32_t original_low =
            bsd_pci_read_config(device, register_offset, 4);
        uint64_t raw_value = original_low;
        uint64_t base;
        uint64_t mask;
        uint64_t size;
        unsigned int flags = 0;
        int type;

        if (original_low == 0 || original_low == UINT32_MAX)
            continue;
        bsd_pci_write_config(device, register_offset, UINT32_MAX, 4);
        mask = bsd_pci_read_config(device, register_offset, 4);
        bsd_pci_write_config(device, register_offset, original_low, 4);
        if (original_low & BSD_PCI_BAR_IO) {
            type = SYS_RES_IOPORT;
            base = original_low & ~UINT64_C(3);
            mask &= ~UINT64_C(3);
            size = ((~mask) & UINT32_MAX) + 1;
        } else {
            uint32_t original_high = 0;
            uint32_t mask_high = UINT32_MAX;

            type = SYS_RES_MEMORY;
            base = original_low & ~UINT64_C(15);
            mask &= ~UINT64_C(15);
            if (original_low & BSD_PCI_BAR_PREFETCHABLE)
                flags |= RF_PREFETCHABLE;
            if ((original_low & BSD_PCI_BAR_MEMORY_TYPE_MASK) ==
                BSD_PCI_BAR_MEMORY_64 && bar + 1 < bar_count) {
                original_high = bsd_pci_read_config(
                    device, register_offset + 4, 4);
                bsd_pci_write_config(device, register_offset + 4,
                    UINT32_MAX, 4);
                mask_high = bsd_pci_read_config(
                    device, register_offset + 4, 4);
                bsd_pci_write_config(device, register_offset + 4,
                    original_high, 4);
                base |= (uint64_t)original_high << 32;
                raw_value |= (uint64_t)original_high << 32;
                mask |= (uint64_t)mask_high << 32;
                bar++;
                size = ~mask + 1;
            } else {
                size = ((~mask) & UINT32_MAX) + 1;
            }
        }
        if (base != 0 && size != 0 &&
            base <= UINT64_MAX - (size - 1)) {
            uint64_t host_base = base;
            int result = 0;

            if (g_pci_operations.translate_resource)
                result = g_pci_operations.translate_resource(
                    g_pci_operations.context, &function->location,
                    type, base, size, &host_base);
            if (result == 0)
                result = bsd_device_add_resource(device, type,
                    register_offset, host_base, size, flags, 0);
            if (result != 0) {
                bsd_pci_write_config(device, BSD_PCI_COMMAND,
                    command, 2);
                return result;
            }
            enabled_command |= type == SYS_RES_IOPORT ?
                BSD_PCI_COMMAND_IO_ENABLE :
                BSD_PCI_COMMAND_MEMORY_ENABLE;
            function->maps[map_index].pm_value = raw_value;
            function->maps[map_index].pm_size = size;
            function->maps[map_index].pm_reg =
                (uint16_t)register_offset;
        }
    }
    bsd_pci_write_config(
        device, BSD_PCI_COMMAND, enabled_command, 2);
    function->command = enabled_command;
    struct pci_map *previous = 0;
    for (unsigned int index = 0; index < BSD_PCI_BAR_COUNT; ++index) {
        struct pci_map *map = &function->maps[index];

        map->pm_link.stqe_next = 0;
        if (map->pm_size == 0)
            continue;
        if (previous)
            previous->pm_link.stqe_next = map;
        previous = map;
    }
    return 0;
}

static int
pci_add_legacy_interrupt(device_t device)
{
    bsd_pci_function_t *function = pci_function(device);
    uint32_t interrupt;
    uint32_t interrupt_flags = 0;
    int result;

    if (function->interrupt_pin == 0)
        return 0;
    if (g_pci_operations.legacy_interrupt) {
        result = g_pci_operations.legacy_interrupt(
            g_pci_operations.context, &function->location,
            function->interrupt_line, &interrupt, &interrupt_flags);
        if (result != 0)
            return result;
    } else {
        if (function->interrupt_line == 0 ||
            function->interrupt_line == UINT8_MAX)
            return 0;
        interrupt = function->interrupt_line;
    }
    result = bsd_device_add_resource(device, SYS_RES_IRQ, 0,
        interrupt, 1, RF_SHAREABLE, 0);
    if (result == 0 && interrupt_flags != 0)
        result = bsd_resource_set_interrupt_flags(
            device, 0, interrupt_flags);
    return result;
}

static int
pci_populate_function(device_t device, const bsd_pci_location_t *location)
{
    bsd_pci_function_t *function;
    int result;

    function = bsd_malloc(sizeof(*function), M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!function)
        return BSD_PCI_ENOMEM;
    function->device = device;
    function->location = *location;
    bsd_device_set_ivars_owned(device, function);
    function->vendor = (uint16_t)bsd_pci_read_config(device, 0x00, 2);
    function->device_id = (uint16_t)bsd_pci_read_config(device, 0x02, 2);
    function->command = (uint16_t)bsd_pci_read_config(
        device, BSD_PCI_COMMAND, 2);
    function->revision = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_REVISION, 1);
    function->progif = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_PROGIF, 1);
    function->subclass = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_SUBCLASS, 1);
    function->class_code = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_CLASS, 1);
    function->header_type = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_HEADER_TYPE, 1);
    function->subvendor = (uint16_t)bsd_pci_read_config(
        device, BSD_PCI_SUBVENDOR, 2);
    function->subdevice = (uint16_t)bsd_pci_read_config(
        device, BSD_PCI_SUBDEVICE, 2);
    function->interrupt_line = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_INTERRUPT_LINE, 1);
    function->interrupt_pin = (uint8_t)bsd_pci_read_config(
        device, BSD_PCI_INTERRUPT_PIN, 1);
    pci_capture_config(device, function);
    (void)bsd_pci_find_capability(device, BSD_PCI_CAP_MSI, 0,
        &function->msi_capability);
    (void)bsd_pci_find_capability(device, BSD_PCI_CAP_MSIX, 0,
        &function->msix_capability);
    result = pci_add_bar_resources(device);
    if (result == 0)
        result = pci_add_legacy_interrupt(device);
    if (result == 0) {
        device_set_descf(device, "PCI %04x:%04x",
            function->vendor, function->device_id);
    }
    return result;
}

static void
pci_read_identity(const bsd_pci_location_t *location,
    bsd_pci_device_identity_t *identity)
{
    identity->location = *location;
    identity->vendor = (uint16_t)pci_backend_read(location, 0x00, 2);
    identity->device = (uint16_t)pci_backend_read(location, 0x02, 2);
    identity->revision = (uint8_t)pci_backend_read(
        location, BSD_PCI_REVISION, 1);
    identity->progif = (uint8_t)pci_backend_read(
        location, BSD_PCI_PROGIF, 1);
    identity->subclass = (uint8_t)pci_backend_read(
        location, BSD_PCI_SUBCLASS, 1);
    identity->class_code = (uint8_t)pci_backend_read(
        location, BSD_PCI_CLASS, 1);
    identity->subvendor = (uint16_t)pci_backend_read(
        location, BSD_PCI_SUBVENDOR, 2);
    identity->subdevice = (uint16_t)pci_backend_read(
        location, BSD_PCI_SUBDEVICE, 2);
}

static int
pci_bus_probe(device_t device)
{
    (void)device;
    return 0;
}

static int
pci_bus_attach(device_t bus)
{
    bsd_pci_bus_context_t *context = device_get_ivars(bus);
    size_t count = g_pci_operations.function_count(
        g_pci_operations.context);

    if (!context)
        return BSD_PCI_EINVAL;
    for (size_t index = 0; index < count; ++index) {
        bsd_pci_device_identity_t identity;
        bsd_pci_location_t location;
        device_t child;
        int result;

        if (g_pci_operations.function_at(g_pci_operations.context,
            index, &location) != 0)
            continue;
        if (context->options.location_filter_enabled &&
            (location.domain != context->options.domain ||
            location.bus < context->options.first_bus ||
            location.bus > context->options.last_bus))
            continue;
        pci_read_identity(&location, &identity);
        if (identity.vendor == BSD_PCI_VENDOR_INVALID)
            continue;
        context->status.discovered++;
        if (context->options.select_device &&
            !context->options.select_device(context->options.context,
                &identity))
            continue;
        context->status.selected++;
        if (g_pci_operations.prepare_device) {
            result = g_pci_operations.prepare_device(
                g_pci_operations.context, &location);
            if (result != 0)
                return result;
        }
        child = device_add_child(bus, 0, DEVICE_UNIT_ANY);
        if (!child)
            return BSD_PCI_ENOMEM;
        result = pci_populate_function(child, &location);
        if (result != 0) {
            (void)device_delete_child(bus, child);
            return result;
        }
        result = device_probe_and_attach(child);
        if (result == 0)
            context->status.attached++;
        else
            context->status.unclaimed++;
    }
    return 0;
}

typedef int bsd_bus_read_ivar_method_t(device_t bus, device_t child,
    int index, uintptr_t *result);

static int
pci_call_bus_read_ivar(device_t bus, device_t child, int index,
    uintptr_t *result)
{
    kobj_t object = (kobj_t)bus;
    kobj_method_t **cache_entry;
    kobj_method_t *method;

    if (!object || !object->ops || !result)
        return BSD_PCI_ENXIO;
    cache_entry = &object->ops->cache[
        bus_read_ivar_desc.id & (KOBJ_CACHE_SIZE - 1)];
    method = *cache_entry;
    if (!method || method->desc != &bus_read_ivar_desc) {
        method = kobj_lookup_method(object->ops->cls, cache_entry,
            &bus_read_ivar_desc);
    }
    if (!method || !method->func)
        return BSD_PCI_ENXIO;
    return ((bsd_bus_read_ivar_method_t *)method->func)(bus, child,
        index, result);
}

int
pci_attach(device_t bus)
{
    bsd_pci_bus_context_t *context;
    uintptr_t domain;
    uintptr_t bus_number;
    int result;

    if (!bus || bsd_pci_ensure_initialized() != 0)
        return BSD_PCI_ENXIO;
    if (pci_call_bus_read_ivar(device_get_parent(bus), bus,
        BSD_PCIB_IVAR_DOMAIN, &domain) != 0 ||
        pci_call_bus_read_ivar(device_get_parent(bus), bus,
        BSD_PCIB_IVAR_BUS, &bus_number) != 0 ||
        domain > UINT32_MAX || bus_number > UINT8_MAX)
        return BSD_PCI_ENXIO;
    context = bsd_malloc(sizeof(*context), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!context)
        return BSD_PCI_ENOMEM;
    context->options.location_filter_enabled = true;
    context->options.domain = (uint32_t)domain;
    context->options.first_bus = (uint8_t)bus_number;
    context->options.last_bus = (uint8_t)bus_number;
    bsd_device_set_ivars_owned(bus, context);
    result = pci_bus_attach(bus);
    if (result != 0)
        device_set_ivars(bus, 0);
    return result;
}

int
pci_detach(device_t bus)
{
    int result;

    result = bus_generic_detach(bus);
    if (result == 0)
        device_set_ivars(bus, 0);
    return result;
}

static int
pci_bus_read_ivar(device_t bus, device_t child, int which,
    uintptr_t *value)
{
    bsd_pci_function_t *function = pci_function(child);

    (void)bus;
    if (!function || !value)
        return BSD_PCI_EINVAL;
    switch (which) {
    case BSD_PCI_IVAR_SUBVENDOR: *value = function->subvendor; break;
    case BSD_PCI_IVAR_SUBDEVICE: *value = function->subdevice; break;
    case BSD_PCI_IVAR_VENDOR: *value = function->vendor; break;
    case BSD_PCI_IVAR_DEVICE: *value = function->device_id; break;
    case BSD_PCI_IVAR_DEVID:
        *value = ((uint32_t)function->device_id << 16) | function->vendor;
        break;
    case BSD_PCI_IVAR_CLASS: *value = function->class_code; break;
    case BSD_PCI_IVAR_SUBCLASS: *value = function->subclass; break;
    case BSD_PCI_IVAR_PROGIF: *value = function->progif; break;
    case BSD_PCI_IVAR_REVID: *value = function->revision; break;
    case BSD_PCI_IVAR_INTPIN: *value = function->interrupt_pin; break;
    case BSD_PCI_IVAR_IRQ: *value = function->interrupt_line; break;
    case BSD_PCI_IVAR_DOMAIN: *value = function->location.domain; break;
    case BSD_PCI_IVAR_BUS: *value = function->location.bus; break;
    case BSD_PCI_IVAR_SLOT: *value = function->location.slot; break;
    case BSD_PCI_IVAR_FUNCTION: *value = function->location.function; break;
    case BSD_PCI_IVAR_CMDREG:
        *value = bsd_pci_read_config(child, BSD_PCI_COMMAND, 2);
        break;
    default:
        return BSD_PCI_ENOENT;
    }
    return 0;
}

static int
pci_bus_write_ivar(device_t bus, device_t child, int which,
    uintptr_t value)
{
    bsd_pci_function_t *function = pci_function(child);

    (void)bus;
    if (!function)
        return BSD_PCI_EINVAL;
    if (which != BSD_PCI_IVAR_IRQ || value > UINT8_MAX)
        return BSD_PCI_ENOENT;
    function->interrupt_line = (uint8_t)value;
    bsd_pci_write_config(child, BSD_PCI_INTERRUPT_LINE,
        (uint32_t)value, 1);
    return 0;
}

static uint32_t
pci_method_read_config(device_t bus, device_t child, int register_offset,
    int width)
{
    (void)bus;
    return bsd_pci_read_config(child, register_offset, width);
}

static void
pci_method_write_config(device_t bus, device_t child, int register_offset,
    uint32_t value, int width)
{
    (void)bus;
    bsd_pci_write_config(child, register_offset, value, width);
}

static int
pci_set_command(device_t child, uint16_t bits, int enabled)
{
    uint16_t command = (uint16_t)bsd_pci_read_config(
        child, BSD_PCI_COMMAND, 2);

    command = enabled ? command | bits : command & ~bits;
    bsd_pci_write_config(child, BSD_PCI_COMMAND, command, 2);
    return 0;
}

static int
pci_method_enable_busmaster(device_t bus, device_t child)
{
    (void)bus;
    return pci_set_command(child, BSD_PCI_COMMAND_BUSMASTER_ENABLE, 1);
}

static int
pci_method_disable_busmaster(device_t bus, device_t child)
{
    (void)bus;
    return pci_set_command(child, BSD_PCI_COMMAND_BUSMASTER_ENABLE, 0);
}

static int
pci_method_enable_io(device_t bus, device_t child, int type)
{
    (void)bus;
    if (type == SYS_RES_IOPORT)
        return pci_set_command(child, BSD_PCI_COMMAND_IO_ENABLE, 1);
    if (type == SYS_RES_MEMORY)
        return pci_set_command(child, BSD_PCI_COMMAND_MEMORY_ENABLE, 1);
    return BSD_PCI_EINVAL;
}

static int
pci_method_disable_io(device_t bus, device_t child, int type)
{
    (void)bus;
    if (type == SYS_RES_IOPORT)
        return pci_set_command(child, BSD_PCI_COMMAND_IO_ENABLE, 0);
    if (type == SYS_RES_MEMORY)
        return pci_set_command(child, BSD_PCI_COMMAND_MEMORY_ENABLE, 0);
    return BSD_PCI_EINVAL;
}

static int
pci_method_find_cap(device_t bus, device_t child, int capability,
    int *capability_register)
{
    (void)bus;
    return bsd_pci_find_capability(child, capability, 0,
        capability_register);
}

static int
pci_method_find_next_cap(device_t bus, device_t child, int capability,
    int start, int *capability_register)
{
    (void)bus;
    return bsd_pci_find_capability(child, capability, start,
        capability_register);
}

static int
pci_method_find_htcap(device_t bus, device_t child, int capability,
    int *capability_register)
{
    (void)bus;
    return pci_find_ht_capability(child, capability, 0,
        capability_register);
}

static int
pci_method_find_next_htcap(device_t bus, device_t child, int capability,
    int start, int *capability_register)
{
    (void)bus;
    return pci_find_ht_capability(child, capability, start,
        capability_register);
}

static int
pci_method_alloc_msi(device_t bus, device_t child, int *count)
{
    (void)bus;
    return bsd_pci_alloc_msi(child, count);
}

static int
pci_method_alloc_msix(device_t bus, device_t child, int *count)
{
    (void)bus;
    return bsd_pci_alloc_msix(child, count);
}

static int
pci_method_release_msi(device_t bus, device_t child)
{
    (void)bus;
    return bsd_pci_release_msi(child);
}

static int
pci_method_msi_count(device_t bus, device_t child)
{
    (void)bus;
    return bsd_pci_msi_count(child);
}

static int
pci_method_msix_count(device_t bus, device_t child)
{
    (void)bus;
    return bsd_pci_msix_count(child);
}

static int
pci_method_msix_pba_bar(device_t bus, device_t child)
{
    (void)bus;
    return bsd_pci_msix_pba_bar(child);
}

static int
pci_method_msix_table_bar(device_t bus, device_t child)
{
    (void)bus;
    return bsd_pci_msix_table_bar(child);
}

static const struct kobj_method pci_bus_methods[] = {
    { &device_probe_desc, (kobjop_t)pci_bus_probe },
    { &device_attach_desc, (kobjop_t)pci_bus_attach },
    { &device_detach_desc, (kobjop_t)bus_generic_detach },
    { &device_shutdown_desc, (kobjop_t)bus_generic_shutdown },
    { &device_suspend_desc, (kobjop_t)bus_generic_suspend },
    { &device_resume_desc, (kobjop_t)bus_generic_resume },
    { &bus_read_ivar_desc, (kobjop_t)pci_bus_read_ivar },
    { &bus_write_ivar_desc, (kobjop_t)pci_bus_write_ivar },
    { &pci_read_config_desc, (kobjop_t)pci_method_read_config },
    { &pci_write_config_desc, (kobjop_t)pci_method_write_config },
    { &pci_enable_busmaster_desc, (kobjop_t)pci_method_enable_busmaster },
    { &pci_disable_busmaster_desc, (kobjop_t)pci_method_disable_busmaster },
    { &pci_enable_io_desc, (kobjop_t)pci_method_enable_io },
    { &pci_disable_io_desc, (kobjop_t)pci_method_disable_io },
    { &pci_find_cap_desc, (kobjop_t)pci_method_find_cap },
    { &pci_find_next_cap_desc, (kobjop_t)pci_method_find_next_cap },
    { &pci_find_htcap_desc, (kobjop_t)pci_method_find_htcap },
    { &pci_find_next_htcap_desc, (kobjop_t)pci_method_find_next_htcap },
    { &pci_alloc_msi_desc, (kobjop_t)pci_method_alloc_msi },
    { &pci_alloc_msix_desc, (kobjop_t)pci_method_alloc_msix },
    { &pci_release_msi_desc, (kobjop_t)pci_method_release_msi },
    { &pci_msi_count_desc, (kobjop_t)pci_method_msi_count },
    { &pci_msix_count_desc, (kobjop_t)pci_method_msix_count },
    { &pci_msix_pba_bar_desc, (kobjop_t)pci_method_msix_pba_bar },
    { &pci_msix_table_bar_desc, (kobjop_t)pci_method_msix_table_bar },
    KOBJMETHOD_END,
};

struct kobj_class pci_driver = {
    "pci", pci_bus_methods, 0, 0, 0, 0
};

#ifndef BSD_BRIDGE_HOST_TEST
DRIVER_MODULE(pci, pcib, pci_driver, 0, 0);
#endif

device_t
bsd_pci_attach_bus(device_t parent)
{
    return bsd_pci_attach_bus_selected(parent, 0);
}

device_t
bsd_pci_attach_bus_selected(device_t parent,
    const bsd_pci_attach_options_t *options)
{
    bsd_pci_bus_context_t *context;
    device_t bus;

    if (!parent || bsd_pci_ensure_initialized() != 0)
        return 0;
    context = bsd_malloc(sizeof(*context), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!context)
        return 0;
    if (options)
        context->options = *options;
    bus_topo_lock();
    bus = device_add_child(parent, "pci", DEVICE_UNIT_ANY);
    if (!bus) {
        bus_topo_unlock();
        bsd_free(context, M_DEVBUF);
        return 0;
    }
    bsd_device_set_ivars_owned(bus, context);
    if (device_set_driver(bus, &pci_driver) != 0 ||
        device_probe_and_attach(bus) != 0) {
        (void)device_delete_children(bus);
        (void)device_delete_child(parent, bus);
        bus_topo_unlock();
        return 0;
    }
    bus_topo_unlock();
    return bus;
}

int
bsd_pci_bus_get_status(device_t bus, bsd_pci_bus_status_t *status)
{
    bsd_pci_bus_context_t *context;

    if (!bus || !status)
        return BSD_PCI_EINVAL;
    context = device_get_ivars(bus);
    if (!context)
        return BSD_PCI_ENXIO;
    *status = context->status;
    return 0;
}
