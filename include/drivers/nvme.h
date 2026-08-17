#ifndef DRIVERS_NVME_H
#define DRIVERS_NVME_H

#include <stdint.h>

int nvme_init(void);
int nvme_present(void);
uint32_t nvme_sector_size(void);
uint32_t nvme_sector_count(void);
uint32_t nvme_max_transfer_sectors(void);
int nvme_read(uint32_t lba, uint32_t sector_count, void *buf);
int nvme_write(uint32_t lba, uint32_t sector_count, const void *buf);

#endif
