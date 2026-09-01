#ifndef _EDGEOS_LINUXKPI_ACPI_H_
#define _EDGEOS_LINUXKPI_ACPI_H_

#include_next <linux/acpi.h>
#include <linux/ioport.h>

#ifndef ACPI_ID_LEN
#define ACPI_ID_LEN 16
#endif

struct acpi_device_id {
	char id[ACPI_ID_LEN];
	kernel_ulong_t driver_data;
};

struct resource_entry {
	struct list_head node;
	struct resource *res;
};

static inline bool
acpi_dev_hid_uid_match(struct acpi_device *adev, const char *hid,
    const char *uid)
{
	(void)adev;
	(void)hid;
	(void)uid;
	return (false);
}

static inline int
acpi_dev_get_memory_resources(struct acpi_device *adev,
    struct list_head *resources)
{
	(void)adev;
	(void)resources;
	return (-ENODEV);
}

static inline void
acpi_dev_free_resource_list(struct list_head *resources)
{
	(void)resources;
}

static inline void *
devm_ioremap_resource(struct device *dev, const struct resource *resource)
{
	(void)dev;
	(void)resource;
	return (ERR_PTR(-ENODEV));
}

#ifndef ACPI_PTR
#define ACPI_PTR(_pointer) (_pointer)
#endif

#endif /* _EDGEOS_LINUXKPI_ACPI_H_ */
