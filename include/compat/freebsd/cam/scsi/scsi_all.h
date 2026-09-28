/* SPDX-License-Identifier: MPL-2.0 */
/* SCSI command definitions required by the shared CAM bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_SCSI_SCSI_ALL_H
#define EDGEOS_COMPAT_FREEBSD_CAM_SCSI_SCSI_ALL_H

#include <stdint.h>

struct cam_periph;
union ccb;

#define TEST_UNIT_READY 0x00
#define REQUEST_SENSE 0x03
#define INQUIRY 0x12
#define MODE_SELECT_6 0x15
#define MODE_SENSE_6 0x1a
#define START_STOP_UNIT 0x1b
#define START_STOP START_STOP_UNIT
#define RECEIVE_DIAGNOSTIC 0x1c
#define SEND_DIAGNOSTIC 0x1d
#define PREVENT_ALLOW 0x1e
#define READ_6 0x08
#define WRITE_6 0x0a
#define READ_CAPACITY 0x25
#define READ_10 0x28
#define WRITE_10 0x2a
#define POSITION_TO_ELEMENT 0x2b
#define VERIFY_10 0x2f
#define SYNCHRONIZE_CACHE 0x35
#define WRITE_BUFFER 0x3b
#define READ_BUFFER 0x3c
#define UNMAP 0x42
#define MODE_SELECT_10 0x55
#define MODE_SENSE_10 0x5a
#define VARIABLE_LEN_CDB 0x7f
#define READ_16 0x88
#define WRITE_16 0x8a
#define WRITE_SAME_16 0x93
#define REPORT_LUNS 0xa0
#define READ_12 0xa8
#define WRITE_12 0xaa
#define SERVICE_ACTION_IN 0x9e
#define SAI_READ_CAPACITY_16 0x10

#define T_DIRECT 0x00
#define T_SEQUENTIAL 0x01
#define T_PROCESSOR 0x03
#define T_CDROM 0x05
#define T_NODEVICE 0x1f
#define SCSI_REV_2 2
#define SCSI_REV_SPC 3
#define SCSI_REV_SPC2 4
#define SCSI_REV_SPC3 5
#define SCSI_REV_SPC4 6
#define SCSI_REV_SPC5 7
#define SCSI_STATUS_OK 0x00
#define SCSI_STATUS_CHECK_COND 0x02
#define SCSI_STATUS_COND_MET 0x04
#define SCSI_STATUS_BUSY 0x08
#define SCSI_STATUS_INTERMED 0x10
#define SCSI_STATUS_INTERMED_COND_MET 0x14
#define SCSI_STATUS_RESERV_CONFLICT 0x18
#define SCSI_STATUS_CMD_TERMINATED 0x22
#define SCSI_STATUS_QUEUE_FULL 0x28
#define SI_EVPD 0x01
#define SSS_START 0x01
#define SSS_IMMED 0x01
#define SSS_LOEJ 0x02
#define SSS_PC_MASK 0xf0
#define SSS_PC_START_VALID 0x00
#define SSS_PC_ACTIVE 0x10
#define SSS_PC_IDLE 0x20
#define SSS_PC_STANDBY 0x30
#define SSS_PC_LU_CONTROL 0x70
#define SSS_PC_FORCE_IDLE_0 0xa0
#define SSS_PC_FORCE_STANDBY_0 0xb0
#define SID_CmdQue 0x02
#define SID_Sync 0x10
#define SID_WBus16 0x20
#define SID_SPI_IUS 0x01
#define SID_SPI_QAS 0x02
#define SID_SPI_CLOCK_ST 0x00
#define SID_SPI_CLOCK_DT 0x04
#define SID_SPI_CLOCK_DT_ST 0x0c
#define SID_SPI_MASK 0x0f

#define SMS_DBD 0x08
#define SMS_PAGE_CODE 0x3f
#define SMS_VENDOR_SPECIFIC_PAGE 0x00
#define SMS_CONTROL_MODE_PAGE 0x0a
#define SMS_ALL_PAGES_PAGE 0x3f

#define SRC16_SERVICE_ACTION 0x10

#define SVPD_SUPPORTED_PAGE_LIST 0x00
#define SVPD_SUPPORTED_PAGES_SIZE 251
#define SVPD_UNIT_SERIAL_NUMBER 0x80

#define RPL_LUNDATA_PERIPH_BUS_MASK 0x3f
#define RPL_LUNDATA_FLAT_LUN_MASK 0x3f
#define RPL_LUNDATA_FLAT_LUN_BITS 0x06
#define RPL_LUNDATA_LUN_TARG_MASK 0x3f
#define RPL_LUNDATA_LUN_BUS_MASK 0xe0
#define RPL_LUNDATA_LUN_LUN_MASK 0x1f
#define RPL_LUNDATA_EXT_LEN_MASK 0x30
#define RPL_LUNDATA_EXT_EAM_MASK 0x0f
#define RPL_LUNDATA_EXT_EAM_WK 0x01
#define RPL_LUNDATA_EXT_EAM_NOT_SPEC 0x0f
#define RPL_LUNDATA_ATYP_MASK 0xc0
#define RPL_LUNDATA_ATYP_PERIPH 0x00
#define RPL_LUNDATA_ATYP_FLAT 0x40
#define RPL_LUNDATA_ATYP_LUN 0x80
#define RPL_LUNDATA_ATYP_EXTLUN 0xc0

#define SSD_ERRCODE 0x7f
#define SSD_ERRCODE_VALID 0x80
#define SSD_CURRENT_ERROR 0x70
#define SSD_DEFERRED_ERROR 0x71
#define SSD_DESC_CURRENT_ERROR 0x72
#define SSD_DESC_DEFERRED_ERROR 0x73
#define SSD_KEY 0x0f
#define SSD_KEY_NO_SENSE 0x00
#define SSD_KEY_RECOVERED_ERROR 0x01
#define SSD_KEY_NOT_READY 0x02
#define SSD_KEY_MEDIUM_ERROR 0x03
#define SSD_KEY_HARDWARE_ERROR 0x04
#define SSD_KEY_ILLEGAL_REQUEST 0x05
#define SSD_KEY_UNIT_ATTENTION 0x06
#define SSD_KEY_DATA_PROTECT 0x07
#define SSD_KEY_ABORTED_COMMAND 0x0b
#define SSD_KEY_MISCOMPARE 0x0e
#define SSD_SDAT_OVFL 0x10
#define SSD_ILI 0x20
#define SSD_EOM 0x40
#define SSD_FILEMARK 0x80
#define SSD_FULL_SIZE 252
#define SSD_MIN_SIZE 18
#define SSD_EXTRA_MAX 244

#define SHORT_INQUIRY_LENGTH 36
#define SID_VENDOR_SIZE 8
#define SID_PRODUCT_SIZE 16
#define SID_REVISION_SIZE 4
#define SID_TYPE(inquiry) ((inquiry)->device & 0x1fu)
#define SID_QUAL(inquiry) (((inquiry)->device & 0xe0u) >> 5)
#define SID_QUAL_LU_CONNECTED 0x00
#define SID_QUAL_LU_OFFLINE 0x01
#define SID_QUAL_RSVD 0x02
#define SID_QUAL_BAD_LU 0x03
#define SID_ANSI_REV(inquiry) ((inquiry)->version & 0x07u)

#define SCSI_PROTO_ATA 0x08
#define SPSP_PROTO_ATA SCSI_PROTO_ATA

typedef enum scsi_sense_data_type {
    SSD_TYPE_NONE,
    SSD_TYPE_FIXED,
    SSD_TYPE_DESC,
} scsi_sense_data_type;

typedef enum scsi_sense_elem_type {
    SSD_ELEM_NONE,
    SSD_ELEM_SKIP,
    SSD_ELEM_DESC,
    SSD_ELEM_SKS,
    SSD_ELEM_COMMAND,
    SSD_ELEM_INFO,
    SSD_ELEM_FRU,
    SSD_ELEM_STREAM,
    SSD_ELEM_MAX,
} scsi_sense_elem_type;

struct scsi_generic {
    uint8_t opcode;
    uint8_t bytes[11];
};

struct scsi_test_unit_ready {
    uint8_t opcode;
    uint8_t byte2;
    uint8_t unused[3];
    uint8_t control;
};

struct scsi_sense {
    uint8_t opcode;
    uint8_t byte2;
    uint8_t unused[2];
    uint8_t length;
    uint8_t control;
};

struct scsi_inquiry {
    uint8_t opcode;
    uint8_t byte2;
    uint8_t page_code;
    uint8_t length[2];
    uint8_t control;
};

struct scsi_mode_sense_6 {
    uint8_t opcode;
    uint8_t byte2;
    uint8_t page;
    uint8_t subpage;
    uint8_t length;
    uint8_t control;
};

struct scsi_mode_hdr_6 {
    uint8_t datalen;
    uint8_t medium_type;
    uint8_t dev_specific;
    uint8_t block_descr_len;
};

struct scsi_mode_block_descr {
    uint8_t density_code;
    uint8_t num_blocks[3];
    uint8_t reserved;
    uint8_t block_len[3];
};

struct scsi_control_page {
    uint8_t page_code;
    uint8_t page_length;
    uint8_t rlec;
    uint8_t queue_flags;
    uint8_t eca_and_aen;
    uint8_t flags4;
    uint8_t aen_holdoff_period[2];
    uint8_t busy_timeout_period[2];
    uint8_t extended_selftest_completion_time[2];
};

struct scsi_start_stop_unit {
    uint8_t opcode;
    uint8_t byte2;
    uint8_t reserved[2];
    uint8_t how;
    uint8_t control;
};

struct scsi_sense_data {
    union {
        struct {
            uint8_t error_code;
            uint8_t sense_buf[SSD_FULL_SIZE - 1];
        };
        uint8_t bytes[SSD_FULL_SIZE];
    };
};

struct scsi_sense_data_fixed {
    uint8_t error_code;
    uint8_t segment;
    uint8_t flags;
    uint8_t info[4];
    uint8_t extra_len;
    uint8_t cmd_spec_info[4];
    uint8_t add_sense_code;
    uint8_t add_sense_code_qual;
    uint8_t fru;
    uint8_t sense_key_spec[3];
    uint8_t extra_bytes[14];
};

struct scsi_sense_data_desc {
    uint8_t error_code;
    uint8_t sense_key;
    uint8_t add_sense_code;
    uint8_t add_sense_code_qual;
    uint8_t flags;
    uint8_t reserved[2];
    uint8_t extra_len;
    uint8_t sense_desc[0];
};

struct scsi_inquiry_data {
    uint8_t device;
    uint8_t dev_qual2;
    uint8_t version;
    uint8_t response_format;
    uint8_t additional_length;
    uint8_t spc3_flags;
    uint8_t spc2_flags;
    uint8_t flags;
    char vendor[8];
    char product[16];
    char revision[4];
};

const char *scsi_op_desc(uint16_t opcode,
    struct scsi_inquiry_data *inquiry);

struct scsi_vpd_supported_page_list {
    uint8_t device;
    uint8_t page_code;
    uint8_t reserved;
    uint8_t length;
    uint8_t list[SVPD_SUPPORTED_PAGES_SIZE];
};

struct scsi_vpd_unit_serial_number {
    uint8_t device;
    uint8_t page_code;
    uint8_t reserved;
    uint8_t length;
    uint8_t serial_num[251];
};

struct scsi_read_capacity_data {
    uint8_t addr[4];
    uint8_t length[4];
};

struct scsi_read_capacity_16 {
    uint8_t opcode;
    uint8_t service_action;
    uint8_t addr[8];
    uint8_t alloc_len[4];
    uint8_t reladr;
    uint8_t control;
};

struct scsi_read_capacity_data_long {
    uint8_t addr[8];
    uint8_t length[4];
    uint8_t prot;
    uint8_t prot_lbppbe;
    uint8_t lalba_lbp[2];
    uint8_t reserved[16];
};

#define SRC16_PROT_EN 0x01
#define SRC16_P_TYPE 0x0e
#define SRC16_P_TYPE_SHIFT 1
#define SRC16_PTYPE_1 0x00
#define SRC16_PTYPE_2 0x02
#define SRC16_PTYPE_3 0x04

struct scsi_rw_6 {
    uint8_t opcode;
    uint8_t addr[3];
    uint8_t length;
    uint8_t control;
};

struct scsi_rw_10 {
    uint8_t opcode;
    uint8_t byte2;
    uint8_t addr[4];
    uint8_t reserved;
    uint8_t length[2];
    uint8_t control;
};

struct scsi_rw_12 {
    uint8_t opcode;
    uint8_t byte2;
    uint8_t addr[4];
    uint8_t length[4];
    uint8_t reserved;
    uint8_t control;
};

struct scsi_rw_16 {
    uint8_t opcode;
    uint8_t byte2;
    uint8_t addr[8];
    uint8_t length[4];
    uint8_t reserved;
    uint8_t control;
};

static inline void
scsi_ulto2b(uint32_t value, uint8_t *bytes)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static inline void
scsi_ulto3b(uint32_t value, uint8_t *bytes)
{
    bytes[0] = (uint8_t)(value >> 16);
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)value;
}

static inline void
scsi_ulto4b(uint32_t value, uint8_t *bytes)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static inline void
scsi_u64to8b(uint64_t value, uint8_t *bytes)
{
    bytes[0] = (uint8_t)(value >> 56);
    bytes[1] = (uint8_t)(value >> 48);
    bytes[2] = (uint8_t)(value >> 40);
    bytes[3] = (uint8_t)(value >> 32);
    bytes[4] = (uint8_t)(value >> 24);
    bytes[5] = (uint8_t)(value >> 16);
    bytes[6] = (uint8_t)(value >> 8);
    bytes[7] = (uint8_t)value;
}

static inline uint32_t
scsi_2btoul(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 8) | (uint32_t)bytes[1];
}

static inline uint32_t
scsi_3btoul(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 16) |
        ((uint32_t)bytes[1] << 8) |
        (uint32_t)bytes[2];
}

static inline uint32_t
scsi_4btoul(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
        ((uint32_t)bytes[1] << 16) |
        ((uint32_t)bytes[2] << 8) |
        (uint32_t)bytes[3];
}

static inline uint64_t
scsi_8btou64(const uint8_t *bytes)
{
    return ((uint64_t)bytes[0] << 56) |
        ((uint64_t)bytes[1] << 48) |
        ((uint64_t)bytes[2] << 40) |
        ((uint64_t)bytes[3] << 32) |
        ((uint64_t)bytes[4] << 24) |
        ((uint64_t)bytes[5] << 16) |
        ((uint64_t)bytes[6] << 8) |
        (uint64_t)bytes[7];
}

struct ccb_scsiio;
struct sbuf;

void scsi_command_string(struct ccb_scsiio *request, struct sbuf *buffer);
void scsi_set_sense_data(struct scsi_sense_data *sense_data,
    scsi_sense_data_type sense_format, int current_error, int sense_key,
    int asc, int ascq, ...);
int scsi_get_sense_key(struct scsi_sense_data *sense_data,
    unsigned int sense_len, int show_errors);
void scsi_start_stop(struct ccb_scsiio *request, uint32_t retries,
    void (*completion)(struct cam_periph *, union ccb *),
    uint8_t tag_action, int start, int load_eject, int immediate,
    uint8_t sense_length, uint32_t timeout);
void scsi_start_stop_pc(struct ccb_scsiio *request, uint32_t retries,
    void (*completion)(struct cam_periph *, union ccb *),
    uint8_t tag_action, int start, int load_eject, int immediate,
    uint8_t power_condition, uint8_t sense_length, uint32_t timeout);
void scsi_sense_print(struct ccb_scsiio *request);

#endif
