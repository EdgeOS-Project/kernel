/* SPDX-License-Identifier: MPL-2.0 */
/* Memory protection flags used by imported FreeBSD mmap implementations. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_MMAN_H
#define EDGEOS_COMPAT_FREEBSD_SYS_MMAN_H

#define PROT_NONE 0x00
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define PROT_EXEC 0x04

#define MAP_SHARED 0x0001
#define MAP_PRIVATE 0x0002
#define MAP_COPY MAP_PRIVATE

#endif
