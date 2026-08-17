#ifndef DEV_DEV_H
#define DEV_DEV_H

#include <stdint.h>

void dev_init(uint32_t magic, void *mb_info);
int dev_register_memory_ramdisk(const char *source, void *base, uint32_t size, uint32_t phys_base);
const char *dev_get_name(int index);
int dev_has_valid_mbr(const char *disk_name);

#endif
