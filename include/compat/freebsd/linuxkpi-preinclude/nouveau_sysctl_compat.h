#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_SYSCTL_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_SYSCTL_COMPAT_H

#include <sys/sysctl.h>

SYSCTL_NODE(_hw, OID_AUTO, nouveau, CTLFLAG_RD, NULL,
    "Nouveau driver parameters");

#undef CONFIG_X86

#endif
