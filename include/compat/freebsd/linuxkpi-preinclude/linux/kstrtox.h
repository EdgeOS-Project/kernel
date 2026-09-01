/* SPDX-License-Identifier: MPL-2.0 */
/* Keep LinuxKPI string conversion helpers on the BSD bridge runtime. */

#ifndef EDGEOS_LINUXKPI_PREINCLUDE_KSTRTOX_H
#define EDGEOS_LINUXKPI_PREINCLUDE_KSTRTOX_H

char *bsd_strchr(const char *text, int character);

#ifndef strchr
#define strchr(text, character) bsd_strchr((text), (character))
#endif

#include_next <linux/kstrtox.h>

#endif
