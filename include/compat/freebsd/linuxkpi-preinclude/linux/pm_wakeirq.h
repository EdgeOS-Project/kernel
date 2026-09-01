#ifndef _EDGEOS_LINUXKPI_PM_WAKEIRQ_H_
#define _EDGEOS_LINUXKPI_PM_WAKEIRQ_H_

#include <linux/device.h>

static inline int
dev_pm_set_wake_irq(struct device *dev, int irq)
{
	(void)dev;
	(void)irq;
	return (0);
}

static inline void
dev_pm_clear_wake_irq(struct device *dev)
{
	(void)dev;
}

#endif /* _EDGEOS_LINUXKPI_PM_WAKEIRQ_H_ */
