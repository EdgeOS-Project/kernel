/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal clock type declaration for the PCI-only ath12k build. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_CLK_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_CLK_H_

#include <linux/device.h>
#include <linux/err.h>

struct clk {
	bool enabled;
};

static inline struct clk *
devm_clk_get(struct device *dev, const char *name)
{
	(void)dev;
	(void)name;
	return (ERR_PTR(-ENOENT));
}

static inline int
clk_prepare_enable(struct clk *clk)
{
	if (IS_ERR_OR_NULL(clk))
		return (clk == NULL ? -EINVAL : PTR_ERR(clk));
	clk->enabled = true;
	return (0);
}

static inline void
clk_disable_unprepare(struct clk *clk)
{
	if (!IS_ERR_OR_NULL(clk))
		clk->enabled = false;
}

#endif
