#ifndef _EDGEOS_LINUXKPI_THUNDERBOLT_H_
#define _EDGEOS_LINUXKPI_THUNDERBOLT_H_

#include <linux/device.h>

static inline int
usb4_usb3_port_match(struct device *dev, const void *fwnode)
{
	(void)dev;
	(void)fwnode;
	return (0);
}

#endif /* _EDGEOS_LINUXKPI_THUNDERBOLT_H_ */
