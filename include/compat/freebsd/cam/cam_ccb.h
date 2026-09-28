/* SPDX-License-Identifier: MPL-2.0 */
/* CAM control blocks used by imported FreeBSD storage drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_CAM_CCB_H
#define EDGEOS_COMPAT_FREEBSD_CAM_CAM_CCB_H

#include <stdint.h>
#include <limits.h>
#include <sys/queue.h>

#include "cam.h"
struct sbuf;
#ifndef __packed
#define __packed __attribute__((__packed__))
#endif
#ifndef __aligned
#define __aligned(value) __attribute__((__aligned__(value)))
#endif
typedef unsigned int u_int;
#include <cam/ata/ata_all.h>
#ifdef BSD_BRIDGE_HOST_TEST
struct nvme_command {
    uint8_t bytes[64];
};
struct nvme_completion {
    uint8_t bytes[16];
};
#else
#include <dev/nvme/nvme.h>
#endif
#include <dev/mmc/mmcreg.h>
#include "scsi/scsi_all.h"

#define IOCDBLEN CAM_MAX_CDBLEN
#define SIM_IDLEN 16
#define HBA_IDLEN 16
#define DEV_IDLEN 16

#define CAM_CDB_POINTER 0x00000001u
#define CAM_DIS_AUTOSENSE 0x00000020u
#define CAM_DIR_BOTH 0x00000000u
#define CAM_DIR_IN 0x00000040u
#define CAM_DIR_OUT 0x00000080u
#define CAM_DIR_NONE 0x000000c0u
#define CAM_DIR_MASK 0x000000c0u
#define CAM_DATA_VADDR 0x00000000u
#define CAM_DATA_PADDR 0x00000010u
#define CAM_DATA_SG 0x00040000u
#define CAM_DATA_SG_PADDR 0x00040010u
#define CAM_DATA_BIO 0x00200000u
#define CAM_DATA_MASK 0x00240010u
#define CAM_DEV_QFRZDIS 0x00000400u
#define CAM_DEV_QFREEZE 0x00000800u
#define CAM_SENSE_PTR 0x00002000u
#define CAM_SENSE_PHYS 0x00004000u
#define CAM_TAG_ACTION_VALID 0x00008000u
#define CAM_DIS_DISCONNECT 0x00020000u
#define CAM_HIGH_POWER 0x00001000u
#define CAM_CDB_PHYS 0x00400000u
#define CAM_SEND_SENSE 0x08000000u
#define CAM_SEND_STATUS 0x40000000u

#define XPT_FC_QUEUED 0x100u
#define XPT_FC_USER_CCB 0x200u
#define XPT_FC_XPT_ONLY 0x400u
#define XPT_FC_DEV_QUEUED (0x800u | XPT_FC_QUEUED)
#define XPT_NOOP 0x00u
#define XPT_SCSI_IO (0x01u | XPT_FC_DEV_QUEUED)
#define XPT_GDEV_TYPE 0x02u
#define XPT_PATH_INQ 0x04u
#define XPT_REL_SIMQ 0x05u
#define XPT_SASYNC_CB 0x06u
#define XPT_SCAN_BUS (0x08u | XPT_FC_QUEUED | XPT_FC_USER_CCB | \
    XPT_FC_XPT_ONLY)
#define XPT_DEV_ADVINFO 0x0eu
#define XPT_ABORT 0x10u
#define XPT_RESET_BUS (0x11u | XPT_FC_XPT_ONLY)
#define XPT_RESET_DEV (0x12u | XPT_FC_DEV_QUEUED)
#define XPT_TERM_IO 0x13u
#define XPT_SCAN_LUN (0x14u | XPT_FC_QUEUED | XPT_FC_USER_CCB)
#define XPT_GET_TRAN_SETTINGS 0x15u
#define XPT_SET_TRAN_SETTINGS 0x16u
#define XPT_CALC_GEOMETRY 0x17u
#define XPT_ATA_IO (0x18u | XPT_FC_DEV_QUEUED)
#define XPT_GET_SIM_KNOB_OLD 0x18u
#define XPT_SET_SIM_KNOB 0x19u
#define XPT_GET_SIM_KNOB 0x1au
#define XPT_SMP_IO (0x1bu | XPT_FC_DEV_QUEUED)
#define XPT_NVME_IO (0x1cu | XPT_FC_DEV_QUEUED)
#define XPT_MMC_IO (0x1du | XPT_FC_DEV_QUEUED)
#define XPT_SCAN_TGT (0x1eu | XPT_FC_QUEUED | XPT_FC_USER_CCB | \
    XPT_FC_XPT_ONLY)
#define XPT_NVME_ADMIN (0x1fu | XPT_FC_DEV_QUEUED)
#define XPT_EN_LUN 0x30u
#define XPT_ACCEPT_TARGET_IO \
    (0x32u | XPT_FC_QUEUED | XPT_FC_USER_CCB)
#define XPT_CONT_TARGET_IO (0x33u | XPT_FC_DEV_QUEUED)
#define XPT_IMMED_NOTIFY \
    (0x34u | XPT_FC_QUEUED | XPT_FC_USER_CCB)
#define XPT_IMMEDIATE_NOTIFY \
    (0x36u | XPT_FC_QUEUED | XPT_FC_USER_CCB)
#define XPT_NOTIFY_ACKNOWLEDGE \
    (0x37u | XPT_FC_QUEUED | XPT_FC_USER_CCB)

typedef uint32_t xpt_opcode;

typedef enum cam_proto {
    PROTO_UNKNOWN,
    PROTO_UNSPECIFIED,
    PROTO_SCSI,
    PROTO_ATA,
    PROTO_ATAPI,
    PROTO_SATAPM,
    PROTO_SEMB,
    PROTO_NVME,
    PROTO_MMCSD,
} cam_proto;

typedef enum cam_xport {
    XPORT_UNKNOWN,
    XPORT_UNSPECIFIED,
    XPORT_SPI,
    XPORT_FC,
    XPORT_SSA,
    XPORT_USB,
    XPORT_PPB,
    XPORT_ATA,
    XPORT_SAS,
    XPORT_SATA,
    XPORT_ISCSI,
    XPORT_SRP,
    XPORT_NVME,
    XPORT_MMCSD,
    XPORT_NVMF,
    XPORT_UFSHCI,
} cam_xport;

#define PROTO_VERSION_UNKNOWN (UINT_MAX - 1u)
#define PROTO_VERSION_UNSPECIFIED UINT_MAX
#define XPORT_VERSION_UNKNOWN (UINT_MAX - 1u)
#define XPORT_VERSION_UNSPECIFIED UINT_MAX

#define PI_TAG_ABLE 0x02u
#define PI_SDTR_ABLE 0x10u
#define PI_SATAPM 0x04u
#define PI_MDP_ABLE 0x80u
#define PIM_ATA_EXT 0x200u
#define PIM_NO_6_BYTE 0x08u
#define PIM_NOBUSRESET 0x10u
#define PIM_SEQSCAN 0x04u
#define PIM_UNMAPPED 0x02u
#define PIM_NOSCAN 0x01u
#define PIM_SCANHILO 0x80u
#define PIM_WLUNS 0x400u
#define PI_WIDE_16 0x20u
#define PIT_PROCESSOR 0x80u
#define PIT_DISCONNECT 0x20u
#define PIT_TERM_IO 0x10u
#define PIM_EXTLUNS 0x100u
#define PIM_NOINITIATOR 0x20u

#define CTS_SCSI_VALID_TQ 0x01u
#define CTS_SCSI_FLAGS_TAG_ENB 0x01u
#define CTS_NVME_VALID_SPEC 0x01u
#define CTS_NVME_VALID_CAPS 0x02u
#define CTS_NVME_VALID_LINK 0x04u

#define CTS_SATA_VALID_MODE 0x01u
#define CTS_SATA_VALID_BYTECOUNT 0x02u
#define CTS_SATA_VALID_REVISION 0x04u
#define CTS_SATA_VALID_PM 0x08u
#define CTS_SATA_VALID_TAGS 0x10u
#define CTS_SATA_VALID_ATAPI 0x20u
#define CTS_SATA_VALID_CAPS 0x40u
#define CTS_SATA_CAPS_H 0x0000ffffu
#define CTS_SATA_CAPS_H_PMREQ 0x00000001u
#define CTS_SATA_CAPS_H_APST 0x00000002u
#define CTS_SATA_CAPS_H_DMAAA 0x00000010u
#define CTS_SATA_CAPS_H_AN 0x00000020u
#define CTS_SATA_CAPS_D 0xffff0000u
#define CTS_SATA_CAPS_D_PMREQ 0x00010000u
#define CTS_SATA_CAPS_D_APST 0x00020000u
#define CTS_SAS_VALID_SPEED 0x1000u

#define AC_INQ_CHANGED 0x400u
#define AC_ADVINFO_CHANGED 0x2000u
#define AC_LOST_DEVICE 0x100u
#define AC_FOUND_DEVICE 0x080u
#define AC_SENT_BDR 0x010u
#define AC_SCSI_AEN 0x008u
#define AC_BUS_RESET 0x001u
#define AC_TRANSFER_NEG 0x200u
#define AC_CONTRACT 0x1000u

#define AC_CONTRACT_DATA_MAX (128u - sizeof(uint64_t))
struct ac_contract {
    uint64_t contract_number;
    uint8_t contract_data[AC_CONTRACT_DATA_MAX];
};

#define AC_CONTRACT_DEV_CHG 1u
struct ac_device_changed {
    uint64_t wwpn;
    uint32_t port;
    target_id_t target;
    uint8_t arrived;
};

#define RELSIM_RELEASE_AFTER_TIMEOUT 0x02u

#define CAM_TIME_DEFAULT 0u
#define CAM_TIME_INFINITY 0xffffffffu
#define CAM_SUCCESS 0
#define CAM_TAG_ACTION_NONE 0u

typedef union ccb_priv_entry {
    void *ptr;
    unsigned long field;
} ccb_priv_entry_t;

typedef struct ccb_priv_area {
    ccb_priv_entry_t entries[2];
} ccb_priv_area_t;

typedef struct ccb_qos_area {
    void *etime;
    uintptr_t sim_data;
    uintptr_t periph_data;
} ccb_qos_area_t;

typedef union camq_entry {
    LIST_ENTRY(ccb_hdr) le;
    SLIST_ENTRY(ccb_hdr) sle;
    TAILQ_ENTRY(ccb_hdr) tqe;
    STAILQ_ENTRY(ccb_hdr) stqe;
} camq_entry_t;

struct ccb_hdr {
    cam_pinfo pinfo;
    camq_entry_t sim_links;
    void (*cbfcnp)(struct cam_periph *, union ccb *);
    xpt_opcode func_code;
    uint32_t status;
    struct cam_path *path;
    path_id_t path_id;
    target_id_t target_id;
    lun_id_t target_lun;
    uint32_t flags;
    uint32_t xflags;
    ccb_priv_area_t periph_priv;
    ccb_priv_area_t sim_priv;
    ccb_qos_area_t qos;
    uint32_t retry_count;
    uint32_t timeout;
    volatile uint32_t bridge_done;
};

#define ppriv_ptr0 periph_priv.entries[0].ptr
#define ppriv_ptr1 periph_priv.entries[1].ptr
#define ppriv_field0 periph_priv.entries[0].field
#define ppriv_field1 periph_priv.entries[1].field

typedef union cdb {
    uint8_t *cdb_ptr;
    uint8_t cdb_bytes[IOCDBLEN];
} cdb_t;

struct ccb_scsiio {
    struct ccb_hdr ccb_h;
    union ccb *next_ccb;
    uint8_t *req_map;
    uint8_t *data_ptr;
    uint32_t dxfer_len;
    struct scsi_sense_data sense_data;
    uint8_t sense_len;
    uint8_t cdb_len;
    uint16_t sglist_cnt;
    uint8_t scsi_status;
    uint8_t sense_resid;
    uint32_t resid;
    cdb_t cdb_io;
    uint8_t *msg_ptr;
    uint16_t msg_len;
    uint8_t tag_action;
    uint8_t priority;
    unsigned int tag_id;
    unsigned int init_id;
};

static inline void
cam_fill_csio(struct ccb_scsiio *request, uint32_t retries,
    void (*completion)(struct cam_periph *, union ccb *), uint32_t flags,
    uint8_t tag_action, uint8_t *data, uint32_t data_length,
    uint8_t sense_length, uint8_t cdb_length, uint32_t timeout)
{
    request->ccb_h.func_code = XPT_SCSI_IO;
    request->ccb_h.flags = flags;
    request->ccb_h.xflags = 0;
    request->ccb_h.retry_count = retries;
    request->ccb_h.cbfcnp = completion;
    request->ccb_h.timeout = timeout;
    request->data_ptr = data;
    request->dxfer_len = data_length;
    request->sense_len = sense_length;
    request->cdb_len = cdb_length;
    request->tag_action = tag_action;
    request->priority = 0;
}

static inline uint8_t *
scsiio_cdb_ptr(struct ccb_scsiio *ccb)
{
    return (ccb->ccb_h.flags & CAM_CDB_POINTER) ?
        ccb->cdb_io.cdb_ptr : ccb->cdb_io.cdb_bytes;
}

struct ccb_getdev {
    struct ccb_hdr ccb_h;
    cam_proto protocol;
    struct scsi_inquiry_data inq_data;
    struct ata_params ident_data;
    uint8_t serial_num[252];
    uint8_t inq_flags;
    uint8_t serial_num_len;
    void *padding[2];
};

#define NVME_DEV_NAME_LEN 52

struct ccb_pathinq_settings_nvme {
    uint32_t nsid;
    uint32_t domain;
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
    uint8_t extra;
    char dev_name[NVME_DEV_NAME_LEN];
};

struct ccb_pathinq_settings_spi {
    uint8_t ppr_options;
};

struct ccb_pathinq_settings_fc {
    uint64_t wwnn;
    uint64_t wwpn;
    uint32_t port;
    uint32_t bitrate;
};

_Static_assert(sizeof(struct ccb_pathinq_settings_nvme) == 64,
    "ccb_pathinq_settings_nvme too big");

struct ccb_pathinq {
    struct ccb_hdr ccb_h;
    uint8_t version_num;
    uint8_t hba_inquiry;
    uint16_t target_sprt;
    uint32_t hba_misc;
    uint16_t hba_eng_cnt;
    uint32_t max_target;
    uint32_t max_lun;
    uint32_t async_flags;
    target_id_t initiator_id;
    char sim_vid[SIM_IDLEN];
    char hba_vid[HBA_IDLEN];
    char dev_name[DEV_IDLEN];
    uint32_t unit_number;
    uint32_t bus_id;
    uint32_t base_transfer_speed;
    cam_proto protocol;
    unsigned int protocol_version;
    cam_xport transport;
    unsigned int transport_version;
    union {
        struct ccb_pathinq_settings_spi spi;
        struct ccb_pathinq_settings_nvme nvme;
        struct ccb_pathinq_settings_fc fc;
        uint8_t opaque[128];
    } xport_specific;
    unsigned int maxio;
    uint16_t hba_vendor;
    uint16_t hba_device;
    uint16_t hba_subvendor;
    uint16_t hba_subdevice;
};

struct ccb_setasync {
    struct ccb_hdr ccb_h;
    uint32_t event_enable;
    void (*callback)(void *, uint32_t, struct cam_path *, void *);
    void *callback_arg;
};

typedef enum ccb_smp_pass_flags {
    SMP_FLAG_NONE = 0x00,
    SMP_FLAG_REQ_SG = 0x01,
    SMP_FLAG_RSP_SG = 0x02,
} ccb_smp_pass_flags;

struct ccb_smpio {
    struct ccb_hdr ccb_h;
    uint8_t *smp_request;
    int smp_request_len;
    uint16_t smp_request_sglist_cnt;
    uint8_t *smp_response;
    int smp_response_len;
    uint16_t smp_response_sglist_cnt;
    ccb_smp_pass_flags flags;
};

#define CDAI_FLAG_NONE 0x0u
#define CDAI_FLAG_STORE 0x1u
#define CDAI_TYPE_SCSI_DEVID 1u
#define CDAI_TYPE_SERIAL_NUM 2u
#define CDAI_TYPE_PHYS_PATH 3u
#define CDAI_TYPE_RCAPLONG 4u
#define CDAI_TYPE_EXT_INQ 5u

struct ccb_dev_advinfo {
    struct ccb_hdr ccb_h;
    uint32_t flags;
    uint32_t buftype;
    int64_t bufsiz;
    int64_t provsiz;
    uint8_t *buf;
};

struct ccb_abort {
    struct ccb_hdr ccb_h;
    union ccb *abort_ccb;
};

struct ccb_relsim {
    struct ccb_hdr ccb_h;
    uint32_t release_flags;
    uint32_t openings;
    uint32_t release_timeout;
    uint32_t qfrozen_cnt;
};

#define RELSIM_ADJUST_OPENINGS 0x01u

struct ccb_resetdev {
    struct ccb_hdr ccb_h;
};

struct ccb_nvmeio {
    struct ccb_hdr ccb_h;
    union ccb *next_ccb;
    struct nvme_command cmd;
    struct nvme_completion cpl;
    uint8_t *data_ptr;
    uint32_t dxfer_len;
    uint16_t sglist_cnt;
    uint16_t unused;
};

struct ccb_ataio {
    struct ccb_hdr ccb_h;
    union ccb *next_ccb;
    struct ata_cmd cmd;
    struct ata_res res;
    uint8_t *data_ptr;
    uint32_t dxfer_len;
    uint32_t resid;
    uint8_t ata_flags;
#define ATA_FLAG_AUX 0x01u
#define ATA_FLAG_ICC 0x02u
    uint8_t icc;
    uint32_t aux;
    uint32_t unused;
};

struct ccb_mmcio {
    struct ccb_hdr ccb_h;
    union ccb *next_ccb;
    struct mmc_command cmd;
    struct mmc_command stop;
};

static inline void
cam_fill_mmcio(struct ccb_mmcio *request, uint32_t retries,
    void (*completion)(struct cam_periph *, union ccb *), uint32_t flags,
    uint32_t opcode, uint32_t argument, uint32_t command_flags,
    struct mmc_data *data, uint32_t timeout)
{
    request->ccb_h.func_code = XPT_MMC_IO;
    request->ccb_h.flags = flags;
    request->ccb_h.retry_count = retries;
    request->ccb_h.cbfcnp = completion;
    request->ccb_h.timeout = timeout;
    request->cmd.opcode = opcode;
    request->cmd.arg = argument;
    request->cmd.flags = command_flags;
    request->cmd.error = 0;
    request->cmd.data = data;
    request->cmd.resp[0] = 0;
    request->cmd.resp[1] = 0;
    request->cmd.resp[2] = 0;
    request->cmd.resp[3] = 0;
    request->stop.opcode = 0;
    request->stop.arg = 0;
    request->stop.flags = 0;
}

typedef enum cts_type {
    CTS_TYPE_CURRENT_SETTINGS,
    CTS_TYPE_USER_SETTINGS,
} cts_type;

struct ccb_trans_settings_scsi {
    unsigned int valid;
    unsigned int flags;
};

struct ccb_trans_settings_spi {
    unsigned int valid;
    unsigned int flags;
    unsigned int sync_period;
    unsigned int sync_offset;
    unsigned int bus_width;
    unsigned int ppr_options;
};

#define CTS_SPI_VALID_SYNC_RATE 0x01u
#define CTS_SPI_VALID_SYNC_OFFSET 0x02u
#define CTS_SPI_VALID_BUS_WIDTH 0x04u
#define CTS_SPI_VALID_DISC 0x08u
#define CTS_SPI_VALID_PPR_OPTIONS 0x10u
#define CTS_SPI_FLAGS_DISC_ENB 0x01u

struct ccb_trans_settings_fc {
    unsigned int valid;
    uint64_t wwnn;
    uint64_t wwpn;
    uint32_t port;
    uint32_t bitrate;
};

#define CTS_FC_VALID_SPEED 0x1000u
#define CTS_FC_VALID_PORT 0x2000u
#define CTS_FC_VALID_WWPN 0x4000u
#define CTS_FC_VALID_WWNN 0x8000u

struct ccb_trans_settings_ata {
    unsigned int valid;
    unsigned int flags;
};

struct ccb_trans_settings_pata {
    unsigned int valid;
    int mode;
    unsigned int bytecount;
    unsigned int atapi;
    unsigned int caps;
};

#define CTS_ATA_VALID_MODE 0x01u
#define CTS_ATA_VALID_BYTECOUNT 0x02u
#define CTS_ATA_VALID_ATAPI 0x20u
#define CTS_ATA_VALID_CAPS 0x40u
#define CTS_ATA_CAPS_H 0x0000ffffu
#define CTS_ATA_CAPS_H_DMA48 0x00000001u
#define CTS_ATA_CAPS_D 0xffff0000u

struct ccb_trans_settings_sata {
    unsigned int valid;
    int mode;
    unsigned int bytecount;
    int revision;
    unsigned int pm_present;
    unsigned int tags;
    unsigned int atapi;
    unsigned int caps;
};

struct ccb_trans_settings_sas {
    unsigned int valid;
    uint32_t bitrate;
};

struct ccb_trans_settings_nvme {
    unsigned int valid;
    uint32_t spec;
    uint32_t max_xfer;
    uint32_t caps;
    uint8_t lanes;
    uint8_t speed;
    uint8_t max_lanes;
    uint8_t max_speed;
};

struct ccb_trans_settings_ufshci {
    unsigned int valid;
    uint32_t speed;
    uint8_t hs_gear;
    uint8_t tx_lanes;
    uint8_t rx_lanes;
    uint8_t max_hs_gear;
    uint8_t max_tx_lanes;
    uint8_t max_rx_lanes;
};

#define CTS_UFSHCI_VALID_LINK 0x01u

struct ccb_trans_settings {
    struct ccb_hdr ccb_h;
    cts_type type;
    cam_proto protocol;
    unsigned int protocol_version;
    cam_xport transport;
    unsigned int transport_version;
    union {
        unsigned int valid;
        struct ccb_trans_settings_ata ata;
        struct ccb_trans_settings_scsi scsi;
        struct ccb_trans_settings_nvme nvme;
    } proto_specific;
    union {
        unsigned int valid;
        struct ccb_trans_settings_spi spi;
        struct ccb_trans_settings_fc fc;
        struct ccb_trans_settings_sas sas;
        struct ccb_trans_settings_pata ata;
        struct ccb_trans_settings_sata sata;
        struct ccb_trans_settings_nvme nvme;
        struct ccb_trans_settings_ufshci ufshci;
    } xport_specific;
};

struct ccb_calc_geometry {
    struct ccb_hdr ccb_h;
    uint32_t block_size;
    uint64_t volume_size;
    uint32_t cylinders;
    uint8_t heads;
    uint8_t secs_per_track;
};

#define KNOB_VALID_ADDRESS 0x01u
#define KNOB_VALID_ROLE 0x02u
#define KNOB_ROLE_NONE 0x00u
#define KNOB_ROLE_INITIATOR 0x01u
#define KNOB_ROLE_TARGET 0x02u
#define KNOB_ROLE_BOTH 0x03u

struct ccb_sim_knob_settings_spi {
    unsigned int valid;
    unsigned int initiator_id;
    unsigned int role;
};

struct ccb_sim_knob_settings_fc {
    unsigned int valid;
    uint64_t wwnn;
    uint64_t wwpn;
    unsigned int role;
};

struct ccb_sim_knob_settings_sas {
    unsigned int valid;
    uint64_t wwnn;
    unsigned int role;
};

struct ccb_sim_knob {
    struct ccb_hdr ccb_h;
    union {
        unsigned int valid;
        struct ccb_sim_knob_settings_spi spi;
        struct ccb_sim_knob_settings_fc fc;
        struct ccb_sim_knob_settings_sas sas;
        uint8_t pad[128];
    } xport_specific;
};

struct ccb_en_lun {
    struct ccb_hdr ccb_h;
    uint16_t grp6_len;
    uint16_t grp7_len;
    uint8_t enable;
};

struct ccb_rescan {
    struct ccb_hdr ccb_h;
    cam_flags flags;
};

struct ccb_immediate_notify {
    struct ccb_hdr ccb_h;
    unsigned int tag_id;
    unsigned int seq_id;
    unsigned int initiator_id;
    unsigned int arg;
};

struct ccb_notify_acknowledge {
    struct ccb_hdr ccb_h;
    unsigned int tag_id;
    unsigned int seq_id;
    unsigned int initiator_id;
    unsigned int arg;
};

struct ccb_accept_tio {
    struct ccb_hdr ccb_h;
    cdb_t cdb_io;
    uint8_t cdb_len;
    uint8_t tag_action;
    uint8_t sense_len;
    uint8_t priority;
    unsigned int tag_id;
    unsigned int init_id;
    struct scsi_sense_data sense_data;
};

union ccb {
    struct ccb_hdr ccb_h;
    struct ccb_scsiio csio;
    struct ccb_getdev cgd;
    struct ccb_pathinq cpi;
    struct ccb_setasync csa;
    struct ccb_smpio smpio;
    struct ccb_dev_advinfo cdai;
    struct ccb_abort cab;
    struct ccb_relsim crs;
    struct ccb_resetdev crd;
    struct ccb_ataio ataio;
    struct ccb_mmcio mmcio;
    struct ccb_nvmeio nvmeio;
    struct ccb_trans_settings cts;
    struct ccb_calc_geometry ccg;
    struct ccb_sim_knob knob;
    struct ccb_accept_tio atio;
    struct ccb_scsiio ctio;
    struct ccb_en_lun cel;
    struct ccb_rescan crcn;
    struct ccb_immediate_notify cin1;
    struct ccb_notify_acknowledge cna2;
};

#endif
