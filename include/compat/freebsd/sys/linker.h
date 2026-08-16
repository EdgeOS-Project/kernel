/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD linker facade backed by the EdgeOS relocatable-object loader. */

#ifndef _SYS_LINKER_H_
#define _SYS_LINKER_H_

#include <stdint.h>
#include <sys/types.h>

#include "../edgeos/linker.h"
#include "module.h"
#include "malloc.h"

struct linker_file {
    bsd_linker_image_t *image;
    const char *filename;
};

typedef struct linker_file *linker_file_t;

#define MODINFO_METADATA 0x8000

extern caddr_t preload_kmdp;
caddr_t preload_search_info(caddr_t metadata, int type);
void *linker_hwpmc_list_objects(void);

#endif
