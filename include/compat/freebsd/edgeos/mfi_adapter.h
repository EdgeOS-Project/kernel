/* SPDX-License-Identifier: MPL-2.0 */
/* MFI wire-format definitions used by the shared runtime adapter. */

#ifndef EDGEOS_COMPAT_FREEBSD_MFI_ADAPTER_H
#define EDGEOS_COMPAT_FREEBSD_MFI_ADAPTER_H

#include <stdint.h>

#define BSD_MFI_CMD_DCMD 0x05u
#define BSD_MFI_CMD_INIT 0x00u
#define BSD_MFI_DCMD_CTRL_EVENT_GET UINT32_C(0x01040300)
#define BSD_MFI_STAT_OK 0x00u
#define BSD_MFI_STAT_NOT_FOUND 0x23u
#define BSD_MFI_FRAME_DONT_POST 0x0001u
#define BSD_MFI_FRAME_SGL64 0x0002u
#define BSD_MFI_QUEUE_CONTEXT64 0x00000001u

typedef struct __attribute__((packed)) {
    uint8_t cmd;
    uint8_t sense_length;
    uint8_t command_status;
    uint8_t scsi_status;
    uint8_t target_id;
    uint8_t lun_id;
    uint8_t cdb_length;
    uint8_t sg_count;
    uint32_t context;
    uint32_t padding;
    uint16_t flags;
    uint16_t timeout;
    uint32_t data_length;
} bsd_mfi_frame_header_t;

typedef struct __attribute__((packed)) {
    uint32_t address;
    uint32_t length;
} bsd_mfi_sg32_t;

typedef struct __attribute__((packed)) {
    uint64_t address;
    uint32_t length;
} bsd_mfi_sg64_t;

typedef union __attribute__((packed)) {
    bsd_mfi_sg32_t sg32[1];
    bsd_mfi_sg64_t sg64[1];
} bsd_mfi_sgl_t;

typedef struct __attribute__((packed)) {
    bsd_mfi_frame_header_t header;
    uint32_t opcode;
    uint8_t mailbox[12];
    bsd_mfi_sgl_t sgl;
} bsd_mfi_dcmd_frame_t;

typedef struct __attribute__((packed)) {
    bsd_mfi_frame_header_t header;
    uint32_t queue_info_address_low;
    uint32_t queue_info_address_high;
    uint32_t legacy_queue_info_address_low;
    uint32_t legacy_queue_info_address_high;
    uint32_t driver_version_low;
    uint32_t driver_version_high;
    uint32_t reserved[4];
} bsd_mfi_init_frame_t;

typedef struct __attribute__((packed)) {
    uint32_t flags;
    uint32_t reply_queue_entries;
    uint32_t reply_queue_address_low;
    uint32_t reply_queue_address_high;
    uint32_t producer_address_low;
    uint32_t producer_address_high;
    uint32_t consumer_address_low;
    uint32_t consumer_address_high;
} bsd_mfi_init_queue_info_t;

typedef struct __attribute__((packed)) {
    uint32_t count;
    uint32_t reserved;
} bsd_mfi_event_list_header_t;

#endif
