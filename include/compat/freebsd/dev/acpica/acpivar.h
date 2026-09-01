/* SPDX-License-Identifier: MPL-2.0 */
/* ACPI attachment helpers backed by the EdgeOS firmware bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_ACPIVAR_H
#define EDGEOS_COMPAT_FREEBSD_ACPIVAR_H

#include <sys/param.h>
#include <sys/cpuset.h>
#ifdef INTRNG
#include <sys/intr.h>
#endif
#ifdef EDGEOS_BSD_FULL_ACPICA
#include <contrib/dev/acpica/include/acpi.h>
#else
#include "../../contrib/dev/acpica/include/acpi.h"
#endif
#ifndef _SYS_BUS_H_
#include "../../edgeos/newbus.h"
#if defined(BSD_BRIDGE_HOST_TEST)
struct resource_list {
    void *stqh_first;
    void **stqh_last;
};
#endif
#endif
#include "acpi_if.h"
#include "../../edgeos/firmware.h"
#include "../../sys/eventhandler.h"
#include "../../sys/module.h"
#include "../../sys/mutex.h"
#include <sys/power.h>
#include "../../sys/sx.h"
#include "../../sys/sysctl.h"

struct sbuf;
struct acpi_battinfo;
struct acpi_bix;
struct acpi_bst;
struct resource;
extern struct mtx acpi_mutex;
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
extern int acpi_override_isa_irq_polarity;
#endif
typedef void acpi_subtable_handler(ACPI_SUBTABLE_HEADER *, void *);

struct acpi_softc {
    device_t acpi_dev;
    enum power_stype acpi_stype;
    int acpi_verbose;
    struct sysctl_ctx_list acpi_sysctl_ctx;
    struct sysctl_oid *acpi_sysctl_tree;
    enum power_stype acpi_power_button_stype;
    enum power_stype acpi_sleep_button_stype;
    enum power_stype acpi_lid_switch_stype;
    int acpi_standby_sx;
    struct resource_list sysres_rl;
};

/* Keep the upstream ACPI child ivar contract for unmodified bus drivers. */
struct acpi_device {
    ACPI_HANDLE ad_handle;
    void *ad_private;
    int ad_flags;
    int ad_cls_class;
    int ad_domain;
    ACPI_BUFFER dsd;
    const ACPI_OBJECT *dsd_pkg;
    struct resource_list ad_rl;
};

#ifdef INTRNG
struct intr_map_data_acpi {
    struct intr_map_data hdr;
    u_int irq;
    u_int pol;
    u_int trig;
};
#endif

#define ACPI_PRW_MAX_POWERRES 8

struct acpi_prw_data {
    ACPI_HANDLE gpe_handle;
    int gpe_bit;
    int lowest_wake;
    ACPI_OBJECT power_res[ACPI_PRW_MAX_POWERRES];
    int power_res_count;
};

#define ACPI_FLAG_WAKE_ENABLED 0x1
#define ACPI_ADR_PCI_SLOT(address) (((address) & 0xffff0000) >> 16)
#define ACPI_ADR_PCI_FUNC(address) ((address) & 0xffff)
#define ACPI_DEV_DOMAIN_UNKNOWN (-1)
#define ACPI_DEV_BASE_ORDER 100
#define ACPI_CAP_PERF_MSRS (1 << 0)
#define ACPI_CAP_C1_IO_HALT (1 << 1)
#define ACPI_CAP_THR_MSRS (1 << 2)
#define ACPI_CAP_SMP_SAME (1 << 3)
#define ACPI_CAP_SMP_SAME_C3 (1 << 4)
#define ACPI_CAP_SMP_DIFF_PX (1 << 5)
#define ACPI_CAP_SMP_DIFF_CX (1 << 6)
#define ACPI_CAP_SMP_DIFF_TX (1 << 7)
#define ACPI_CAP_SMP_C1_NATIVE (1 << 8)
#define ACPI_CAP_SMP_C3_NATIVE (1 << 9)
#define ACPI_CAP_PX_HW_COORD (1 << 11)
#define ACPI_CAP_INTR_CPPC (1 << 12)
#define ACPI_CAP_HW_DUTY_C (1 << 13)
#define ACPI_PKG_VALID(package, minimum) \
    ((package) && (package)->Type == ACPI_TYPE_PACKAGE && \
     (package)->Package.Count >= (minimum))
#define ACPI_PKG_VALID_EQ(package, count) \
    ((package) && (package)->Type == ACPI_TYPE_PACKAGE && \
     (package)->Package.Count == (count))

enum {
    ACPI_IVAR_PRIVATE = 20,
    ACPI_IVAR_DOMAIN,
    ACPI_IVAR_HANDLE = 0x100,
    ACPI_IVAR_FLAGS,
};

#define ACPI_DEVINFO_PRESENT(status, flags) \
    (((status) & (flags)) == (flags))
#define ACPI_DEVICE_PRESENT(status) \
    ACPI_DEVINFO_PRESENT((status), \
        ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_FUNCTIONING)

ACPI_HANDLE acpi_get_handle(device_t device);
void acpi_set_handle(device_t device, ACPI_HANDLE handle);
device_t acpi_get_device(ACPI_HANDLE handle);
void acpi_fake_objhandler(ACPI_HANDLE handle, void *data);
#ifdef EDGEOS_BSD_FULL_ACPICA
static inline ACPI_OBJECT_TYPE
acpi_get_type(device_t device)
{
    ACPI_HANDLE handle;
    ACPI_OBJECT_TYPE type;

    handle = acpi_get_handle(device);
    if (!handle || ACPI_FAILURE(AcpiGetType(handle, &type)))
        return ACPI_TYPE_NOT_FOUND;
    return type;
}
#endif
static inline void *
acpi_get_private(device_t device)
{
    return bsd_firmware_acpi_get_private(device);
}
static inline void
acpi_set_private(device_t device, void *private_data)
{
    (void)bsd_firmware_acpi_set_private(device, private_data);
}
ACPI_STATUS acpi_GetInteger(ACPI_HANDLE handle, char *path,
    UINT32 *number);
ACPI_STATUS acpi_SetInteger(ACPI_HANDLE handle, char *path,
    UINT32 number);
#ifdef EDGEOS_BSD_FULL_ACPICA
ACPI_STATUS acpi_AppendBufferResource(ACPI_BUFFER *buffer,
    ACPI_RESOURCE *resource);
#endif
ACPI_STATUS acpi_ForeachPackageObject(ACPI_OBJECT *object,
    void (*function)(ACPI_OBJECT *component, void *argument),
    void *argument);
ACPI_STATUS acpi_EvaluateDSMTyped(ACPI_HANDLE handle,
    const uint8_t *uuid, int revision, UINT64 function,
    ACPI_OBJECT *package, ACPI_BUFFER *out_buffer,
    ACPI_OBJECT_TYPE type);
ACPI_STATUS acpi_EvaluateDSM(ACPI_HANDLE handle, const uint8_t *uuid,
    int revision, UINT64 function, ACPI_OBJECT *package,
    ACPI_BUFFER *out_buffer);
ACPI_STATUS acpi_EvaluateOSC(ACPI_HANDLE handle, uint8_t *uuid,
    int revision, int count, uint32_t *capabilities_in,
    uint32_t *capabilities_out, bool query);
int acpi_get_acpi_device_path(device_t bus, device_t child,
    const char *locator, struct sbuf *buffer);
uint32_t hpet_get_uid(device_t device);
int acpi_has_hid(ACPI_HANDLE handle);
int acpi_MatchHid(ACPI_HANDLE handle, const char *hardware_id);
#define ACPI_MATCHHID_NOMATCH 0
#define ACPI_MATCHHID_HID 1
#define ACPI_MATCHHID_CID 2
char *acpi_name(ACPI_HANDLE handle);
int acpi_pnpinfo(ACPI_HANDLE handle, struct sbuf *buffer);
int acpi_set_powerstate(device_t child, int state);
int acpi_disabled(const char *name);
uint8_t acpi_BatteryIsPresent(device_t device);
int acpi_PkgInt(ACPI_OBJECT *package, int index, UINT64 *value);
int acpi_PkgInt32(ACPI_OBJECT *package, int index, uint32_t *value);
int acpi_PkgInt16(ACPI_OBJECT *package, int index, uint16_t *value);
int acpi_PkgStr(ACPI_OBJECT *package, int index, void *destination,
    size_t destination_size);
int acpi_PkgGas(device_t device, ACPI_OBJECT *package, int index,
    int *type, int rid, struct resource **resource, u_int flags);
int acpi_PkgFFH_IntelCpu(ACPI_OBJECT *package, int index, int *vendor,
    int *class_id, uint64_t *address, int *access_size);
ACPI_HANDLE acpi_GetReference(ACPI_HANDLE scope, ACPI_OBJECT *object);
void acpi_ec_ecdt_probe(device_t parent);
#ifdef EDGEOS_BSD_FULL_ACPICA
int acpi_bus_alloc_gas(device_t device, int *type, int rid,
    ACPI_GENERIC_ADDRESS *address, struct resource **resource,
    u_int flags);
#endif
int acpi_register_ioctl(u_long command,
    int (*handler)(u_long, caddr_t, void *), void *argument);
void acpi_deregister_ioctl(u_long command,
    int (*handler)(u_long, caddr_t, void *));
void acpi_deregister_ioctls(int (*handler)(u_long, caddr_t, void *));
int bsd_acpi_ioctl_dispatch(u_long command, caddr_t data);
int acpi_battery_register(device_t device);
int acpi_battery_remove(device_t device);
int acpi_battery_get_units(void);
int acpi_battery_get_info_expire(void);
int acpi_battery_bst_valid(struct acpi_bst *status);
int acpi_battery_bix_valid(struct acpi_bix *information);
int acpi_battery_get_battinfo(device_t device,
    struct acpi_battinfo *information);
int acpi_acad_get_acline(int *status);
int bsd_acpi_id_probe(device_t bus, device_t device, char **identifiers,
    char **match);
int acpi_wake_set_enable(device_t device, int enable);
int acpi_parse_prw(ACPI_HANDLE handle, struct acpi_prw_data *prw);
void acpi_UserNotify(const char *subsystem, ACPI_HANDLE handle,
    uint8_t notify);
void acpi_walk_subtables(void *first, void *end,
    acpi_subtable_handler *handler, void *argument);
#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
int acpi_iort_map_pci_msi(u_int segment, u_int requester_id,
    u_int *xref, u_int *device_id);
int acpi_iort_map_pci_smmuv3(u_int segment, u_int requester_id,
    uint64_t *xref, u_int *device_id);
int acpi_iort_its_lookup(u_int its_id, u_int *xref, int *proximity_domain);
int acpi_iort_map_named_msi(const char *device_name, u_int requester_id,
    u_int *xref, u_int *device_id);
int acpi_iort_map_named_smmuv3(const char *device_name,
    u_int requester_id, uint64_t *xref, u_int *device_id);
#endif
void acpi_invoke_sleep_eventhandler(const enum power_stype *stype);
void acpi_invoke_wake_eventhandler(const enum power_stype *stype);
int acpi_ReqSleepState(struct acpi_softc *softc, enum power_stype stype);
ACPI_STATUS acpi_pwr_switch_consumer(ACPI_HANDLE consumer, int state);
int acpi_device_pwr_for_sleep(device_t bus, device_t device, int *dstate);
UINT32 acpi_event_power_button_sleep(struct acpi_softc *softc);
UINT32 acpi_event_power_button_wake(struct acpi_softc *softc);
UINT32 acpi_event_sleep_button_sleep(struct acpi_softc *softc);
UINT32 acpi_event_sleep_button_wake(struct acpi_softc *softc);

#ifdef EDGEOS_BSD_FULL_ACPICA
struct acpi_parse_resource_set {
    void (*set_init)(device_t device, void *argument, void **context);
    void (*set_done)(device_t device, void *context);
    void (*set_ioport)(device_t device, void *context, uint64_t base,
        uint64_t length);
    void (*set_iorange)(device_t device, void *context, uint64_t low,
        uint64_t high, uint64_t length, uint64_t alignment);
    void (*set_memory)(device_t device, void *context, uint64_t base,
        uint64_t length);
    void (*set_memoryrange)(device_t device, void *context, uint64_t low,
        uint64_t high, uint64_t length, uint64_t alignment);
    void (*set_irq)(device_t device, void *context, uint8_t *irq,
        int count, int trigger, int polarity);
    void (*set_ext_irq)(device_t device, void *context, uint32_t *irq,
        int count, int trigger, int polarity);
    void (*set_drq)(device_t device, void *context, uint8_t *drq,
        int count);
    void (*set_start_dependent)(device_t device, void *context,
        int preference);
    void (*set_end_dependent)(device_t device, void *context);
};

extern struct acpi_parse_resource_set acpi_res_parse_set;

void acpi_config_intr(device_t device, ACPI_RESOURCE *resource);
#ifdef INTRNG
int acpi_map_intr(device_t device, u_int irq, ACPI_HANDLE handle);
#endif
ACPI_STATUS acpi_lookup_irq_resource(device_t device, int rid,
    struct resource *resource, ACPI_RESOURCE *acpi_resource);
ACPI_STATUS acpi_parse_resources(device_t device, ACPI_HANDLE handle,
    struct acpi_parse_resource_set *set, void *argument);
#endif

static inline int
acpi_get_flags(device_t device)
{
    return (int)bsd_firmware_acpi_get_flags(device);
}

static inline void
acpi_set_flags(device_t device, int flags)
{
    (void)bsd_firmware_acpi_set_flags(device, (uint32_t)flags);
}

static inline int
acpi_get_domain(device_t device)
{
    return bsd_firmware_acpi_get_domain(device);
}

static inline void
acpi_set_domain(device_t device, int domain)
{
    (void)bsd_firmware_acpi_set_domain(device, domain);
}

static inline int
acpi_map_pxm_to_vm_domainid(int proximity_domain)
{
    (void)proximity_domain;
    return ACPI_DEV_DOMAIN_UNKNOWN;
}

static inline struct acpi_softc *
acpi_device_get_parent_softc(device_t child)
{
    device_t parent = device_get_parent(child);

    return parent ? device_get_softc(parent) : 0;
}

static inline int
acpi_get_verbose(struct acpi_softc *softc)
{
    return softc ? softc->acpi_verbose : 0;
}

#define ACPI_ID_PROBE(bus, device, identifiers, match) \
    bsd_acpi_id_probe((bus), (device), (identifiers), (match))
#define ACPICOMPAT_PNP_INFO(table, bus_name)                             \
    MODULE_PNP_INFO("Z:_HID", bus_name, table##hid, table,              \
        nitems(table) - 1);                                             \
    MODULE_PNP_INFO("Z:_CID", bus_name, table##cid, table,              \
        nitems(table) - 1)
#define ACPI_PNP_INFO(table) ACPICOMPAT_PNP_INFO(table, acpi)
#define ACPI_LOCK(name) mtx_lock(&name##_mutex)
#define ACPI_UNLOCK(name) mtx_unlock(&name##_mutex)
#define ACPI_LOCK_ASSERT(name) mtx_assert(&name##_mutex, MA_OWNED)
#define ACPI_LOCK_DECL(name, description)                              \
    static struct mtx name##_mutex;                                   \
    MTX_SYSINIT(name##_mutex, &name##_mutex, (description), MTX_DEF)
#define ACPI_SERIAL_BEGIN(name) sx_xlock(&name##_sxlock)
#define ACPI_SERIAL_END(name) sx_xunlock(&name##_sxlock)
#define ACPI_SERIAL_ASSERT(name) sx_assert(&name##_sxlock, SX_XLOCKED)
#define ACPI_SERIAL_DECL(name, description)                            \
    static struct sx name##_sxlock;                                   \
    SX_SYSINIT(name##_sxlock, &name##_sxlock, (description))
#define ACPI_VPRINT(device, softc, format, ...) do {                   \
    if (acpi_get_verbose((softc)))                                    \
        device_printf((device), (format), ##__VA_ARGS__);             \
} while (0)

#endif
