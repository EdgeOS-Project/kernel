#ifndef _EDGEOS_LINUXKPI_EXTCON_H_
#define _EDGEOS_LINUXKPI_EXTCON_H_

#include <linux/err.h>

struct extcon_dev;

#define EXTCON_CHG_USB_SDP 1
#define EXTCON_CHG_USB_CDP 2
#define EXTCON_CHG_USB_ACA 3
#define EXTCON_CHG_USB_DCP 4

static inline struct extcon_dev *
extcon_get_extcon_dev(const char *name)
{
	(void)name;
	return (ERR_PTR(-ENODEV));
}

static inline int
extcon_get_state(struct extcon_dev *device, unsigned int cable)
{
	(void)device;
	(void)cable;
	return (-ENODEV);
}

#endif /* _EDGEOS_LINUXKPI_EXTCON_H_ */
