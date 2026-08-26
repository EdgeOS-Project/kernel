#ifndef DRIVERS_NVME_H
#define DRIVERS_NVME_H

#include <stdint.h>

#define NVME_PASSTHROUGH_MAX_DATA (2u * 1024u * 1024u)
#define NVME_PASSTHROUGH_MAX_METADATA (128u * 1024u)

typedef struct nvme_passthrough_command {
    uint8_t opcode;
    uint8_t flags;
    uint16_t reserved;
    uint32_t namespace_id;
    uint32_t command_dword2;
    uint32_t command_dword3;
    void *data;
    uint32_t data_length;
    void *metadata;
    uint32_t metadata_length;
    uint32_t command_dword10;
    uint32_t command_dword11;
    uint32_t command_dword12;
    uint32_t command_dword13;
    uint32_t command_dword14;
    uint32_t command_dword15;
    uint32_t timeout_milliseconds;
    uint8_t admin;
} nvme_passthrough_command_t;

int nvme_init(void);
int nvme_present(void);
uint32_t nvme_sector_size(void);
uint32_t nvme_sector_count(void);
uint32_t nvme_max_transfer_sectors(void);
uint32_t nvme_namespace_id(void);
int nvme_read(uint32_t lba, uint32_t sector_count, void *buf);
int nvme_write(uint32_t lba, uint32_t sector_count, const void *buf);
int nvme_passthrough(nvme_passthrough_command_t *command,
                     uint64_t *completion_result);

#endif
