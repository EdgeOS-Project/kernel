/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS freestanding types and allocation hooks for SquashFUSE. */

#ifndef EDGEOS_SQFS_PORT_H
#define EDGEOS_SQFS_PORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef EDGEOS_SQFS_HOST_TEST
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include "block/block.h"

#ifndef EDGEOS_SQFS_HOST_TEST
typedef int64_t off_t;
typedef int64_t ssize_t;
typedef uint16_t mode_t;
typedef uint32_t uid_t;
typedef uint64_t dev_t;

#define S_IFMT   0170000u
#define S_IFSOCK 0140000u
#define S_IFLNK  0120000u
#define S_IFREG  0100000u
#define S_IFBLK  0060000u
#define S_IFDIR  0040000u
#define S_IFCHR  0020000u
#define S_IFIFO  0010000u

#define S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#define S_ISLNK(mode)  (((mode) & S_IFMT) == S_IFLNK)
#define S_ISBLK(mode)  (((mode) & S_IFMT) == S_IFBLK)
#define S_ISCHR(mode)  (((mode) & S_IFMT) == S_IFCHR)
#endif

void *edge_sqfs_alloc(size_t size);
void *edge_sqfs_calloc(size_t count, size_t size);
void edge_sqfs_free(void *pointer);

#define malloc(size) edge_sqfs_alloc(size)
#define calloc(count, size) edge_sqfs_calloc((count), (size))
#define free(pointer) edge_sqfs_free(pointer)

#ifndef assert
#define assert(expression) do { \
    if (!(expression)) __builtin_trap(); \
} while (0)
#endif

#endif
