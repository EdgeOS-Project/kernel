/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_LINUX_UTSNAME_H
#define EDGEOS_KERNEL_LINUX_UTSNAME_H

#ifndef COMPILE_TIME
#define COMPILE_TIME "unknown build time"
#endif

#define EDGEOS_LINUX_ABI_VERSION "#1 SMP " COMPILE_TIME

typedef struct linux_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
} linux_utsname_t;

void linux_utsname_fill(linux_utsname_t *uts, const char *hostname,
                        const char *release, const char *version,
                        const char *machine);

#endif
