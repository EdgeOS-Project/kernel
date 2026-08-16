/* SPDX-License-Identifier: MPL-2.0 */
/* Shared CAM base types for imported FreeBSD storage drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_CAM_H
#define EDGEOS_COMPAT_FREEBSD_CAM_CAM_H

#include <stdint.h>
#include <limits.h>

typedef unsigned int path_id_t;
typedef unsigned int target_id_t;
typedef uint64_t lun_id_t;

#define CAM_XPT_PATH_ID ((path_id_t)~0u)
#define CAM_BUS_WILDCARD ((path_id_t)~0u)
#define CAM_TARGET_WILDCARD ((target_id_t)~0u)
#define CAM_LUN_WILDCARD ((lun_id_t)~0ull)
#define CAM_MAX_CDBLEN 16
#define CAM_EXTLUN_BYTE_SWIZZLE(lun) ( \
    ((((uint64_t)(lun)) & UINT64_C(0xffff000000000000)) >> 48) | \
    ((((uint64_t)(lun)) & UINT64_C(0x0000ffff00000000)) >> 16) | \
    ((((uint64_t)(lun)) & UINT64_C(0x00000000ffff0000)) << 16) | \
    ((((uint64_t)(lun)) & UINT64_C(0x000000000000ffff)) << 48))

typedef enum cam_status {
    CAM_REQ_INPROG = 0x00,
    CAM_REQ_CMP = 0x01,
    CAM_REQ_ABORTED = 0x02,
    CAM_UA_ABORT = 0x03,
    CAM_REQ_CMP_ERR = 0x04,
    CAM_BUSY = 0x05,
    CAM_REQ_INVALID = 0x06,
    CAM_PATH_INVALID = 0x07,
    CAM_DEV_NOT_THERE = 0x08,
    CAM_UA_TERMIO = 0x09,
    CAM_SEL_TIMEOUT = 0x0a,
    CAM_CMD_TIMEOUT = 0x0b,
    CAM_SCSI_STATUS_ERROR = 0x0c,
    CAM_SCSI_BUS_RESET = 0x0e,
    CAM_UNCOR_PARITY = 0x0f,
    CAM_AUTOSENSE_FAIL = 0x10,
    CAM_NO_HBA = 0x11,
    CAM_DATA_RUN_ERR = 0x12,
    CAM_UNEXP_BUSFREE = 0x13,
    CAM_SEQUENCE_FAIL = 0x14,
    CAM_CCB_LEN_ERR = 0x15,
    CAM_PROVIDE_FAIL = 0x16,
    CAM_BDR_SENT = 0x17,
    CAM_REQ_TERMIO = 0x18,
    CAM_UNREC_HBA_ERROR = 0x19,
    CAM_REQ_TOO_BIG = 0x1a,
    CAM_REQUEUE_REQ = 0x1b,
    CAM_ATA_STATUS_ERROR = 0x1c,
    CAM_SCSI_IT_NEXUS_LOST = 0x1d,
    CAM_SMP_STATUS_ERROR = 0x1e,
    CAM_NVME_STATUS_ERROR = 0x20,
    CAM_RESRC_UNAVAIL = 0x34,
    CAM_MESSAGE_RECV = 0x36,
    CAM_LUN_INVALID = 0x38,
    CAM_TID_INVALID = 0x39,
    CAM_FUNC_NOTAVAIL = 0x3a,
    CAM_CDB_RECVD = 0x3d,
    CAM_SCSI_BUSY = 0x3f,
    CAM_DEV_QFRZN = 0x40,
    CAM_AUTOSNS_VALID = 0x80,
    CAM_RELEASE_SIMQ = 0x100,
    CAM_SIM_QUEUED = 0x200,
    CAM_STATUS_MASK = 0x3f,
    CAM_SENT_SENSE = 0x40000000,
} cam_status;

typedef enum cam_flags {
    CAM_FLAG_NONE = 0x00,
    CAM_EXPECT_INQ_CHANGE = 0x01,
    CAM_RETRY_SELTO = 0x02,
} cam_flags;

#define SF_RETRY_UA 0x01u

typedef struct {
    uint32_t priority;
    uint32_t generation;
    int index;
} cam_pinfo;

#define CAM_PRIORITY_HOST ((0u << 8) + 0x80u)
#define CAM_PRIORITY_BUS ((1u << 8) + 0x80u)
#define CAM_PRIORITY_XPT ((2u << 8) + 0x80u)
#define CAM_PRIORITY_DEV ((3u << 8) + 0x80u)
#define CAM_PRIORITY_NORMAL ((4u << 8) + 0x80u)
#define CAM_PRIORITY_NONE UINT32_MAX
#define CAM_UNQUEUED_INDEX (-1)
#define CAM_ACTIVE_INDEX (-2)
#define CAM_DONEQ_INDEX (-3)

struct cam_path;
struct cam_periph;
struct cam_sim;
union ccb;

void cam_strvis(uint8_t *destination, const uint8_t *source,
    int source_length, int destination_length);

#endif
