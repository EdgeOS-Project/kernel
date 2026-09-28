/* SPDX-License-Identifier: BSD-3-Clause */
/* Private ifnet view supplied by the shared EdgeOS ifnet runtime. */

#ifndef _NET_IF_PRIVATE_H_
#define _NET_IF_PRIVATE_H_

#include "if_var.h"

#define IF_LLADDR(ifp) if_getlladdr((ifp))

#endif
