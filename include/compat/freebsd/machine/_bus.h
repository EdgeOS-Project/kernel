/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral bus type definitions for BSD drivers on EdgeOS. */

#ifndef _MACHINE__BUS_H_
#define _MACHINE__BUS_H_

#include <stdint.h>

typedef uint64_t bus_addr_t;
typedef uint64_t bus_size_t;

struct bus_space;
typedef struct bus_space *bus_space_tag_t;
typedef uintptr_t bus_space_handle_t;

#endif
