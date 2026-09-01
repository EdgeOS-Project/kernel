/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS LinuxKPI panic notifier compatibility. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_PANIC_NOTIFIER_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_PANIC_NOTIFIER_H_

#include <linux/notifier.h>

extern struct atomic_notifier_head panic_notifier_list;

#endif
