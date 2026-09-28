/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef EDGEOS_LINUXKPI_PREINCLUDE_NETINET_IP_H
#define EDGEOS_LINUXKPI_PREINCLUDE_NETINET_IP_H

/* Keep the BSD IPv4 tag distinct from AMD's firmware discovery tag. */
#define ip bsd_ipv4_header
#include_next <netinet/ip.h>
#undef ip

#endif
