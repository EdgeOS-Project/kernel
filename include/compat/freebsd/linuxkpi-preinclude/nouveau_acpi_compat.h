#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_ACPI_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_ACPI_COMPAT_H

#include <linux/pci.h>
#include <linux/acpi.h>
#include <linux/slab.h>
#include <linux/mxm-wmi.h>
#include <linux/vga_switcheroo.h>
#include <drm/drm_edid.h>
#include <acpi/video.h>

#include "nouveau_drv.h"
#include "nouveau_acpi.h"

device_t acpi_get_device(ACPI_HANDLE handle);

static inline int
edgeos_acpi_bus_get_device(acpi_handle handle, struct acpi_device **device)
{
	*device = acpi_get_device(handle);
	return *device != NULL ? 0 : -ENODEV;
}

static inline int
edgeos_acpi_video_get_edid(struct acpi_device *device, int type, int device_id,
    void **edid)
{
	(void)device;
	(void)type;
	(void)device_id;
	(void)edid;
	return -ENODEV;
}

#define acpi_bus_get_device edgeos_acpi_bus_get_device
#define acpi_video_get_edid edgeos_acpi_video_get_edid
#define count Count
#define pointer Pointer
#define type Type
#define integer Integer
#define buffer Buffer
#define value Value
#define length Length

#endif
