/* SPDX-License-Identifier: MPL-2.0 */
/* Pulse-per-second interface implemented by the EdgeOS FreeBSD bridge. */

#ifndef _SYS_TIMEPPS_H_
#define _SYS_TIMEPPS_H_

#include <stdint.h>
#include <sys/ioccom.h>
#include <sys/time.h>

#define PPS_API_VERS_1 1

typedef unsigned int pps_seq_t;

typedef struct {
    unsigned int integral;
    unsigned int fractional;
} pps_ntp_fp_t;

typedef union {
    struct timespec tspec;
    pps_ntp_fp_t ntpfp;
    unsigned long longpad[3];
} pps_timeu_t;

typedef struct {
    pps_seq_t assert_sequence;
    pps_seq_t clear_sequence;
    pps_timeu_t assert_tu;
    pps_timeu_t clear_tu;
    int current_mode;
} pps_info_t;

typedef struct {
    int api_version;
    int mode;
    pps_timeu_t assert_off_tu;
    pps_timeu_t clear_off_tu;
} pps_params_t;

#define assert_timestamp assert_tu.tspec
#define clear_timestamp clear_tu.tspec
#define assert_offset assert_off_tu.tspec
#define clear_offset clear_off_tu.tspec

#define PPS_CAPTUREASSERT 0x01
#define PPS_CAPTURECLEAR 0x02
#define PPS_CAPTUREBOTH 0x03
#define PPS_OFFSETASSERT 0x10
#define PPS_OFFSETCLEAR 0x20
#define PPS_ECHOASSERT 0x40
#define PPS_ECHOCLEAR 0x80
#define PPS_CANWAIT 0x100
#define PPS_CANPOLL 0x200
#define PPS_TSFMT_TSPEC 0x1000
#define PPS_TSFMT_NTPFP 0x2000

struct pps_fetch_args {
    int tsformat;
    pps_info_t pps_info_buf;
    struct timespec timeout;
};

struct pps_kcbind_args {
    int kernel_consumer;
    int edge;
    int tsformat;
};

#define PPS_IOC_CREATE _IO('1', 1)
#define PPS_IOC_DESTROY _IO('1', 2)
#define PPS_IOC_SETPARAMS _IOW('1', 3, pps_params_t)
#define PPS_IOC_GETPARAMS _IOR('1', 4, pps_params_t)
#define PPS_IOC_GETCAP _IOR('1', 5, int)
#define PPS_IOC_FETCH _IOWR('1', 6, struct pps_fetch_args)
#define PPS_IOC_KCBIND _IOW('1', 7, struct pps_kcbind_args)
#define PPS_IOC_FETCH_FFCOUNTER _IO('1', 8)

struct mtx;

#define KCMODE_EDGEMASK 0x03
#define KCMODE_ABIFLAG 0x80000000
#define PPS_ABI_VERSION 1
#define PPSFLAG_MTX_SPIN 0x01

struct pps_state {
    unsigned int capgen;
    unsigned int capcount;
    pps_params_t ppsparam;
    pps_info_t ppsinfo;
    int kcmode;
    int ppscap;
    unsigned int ppscount[3];
    uint16_t driver_abi;
    uint16_t kernel_abi;
    struct mtx *driver_mtx;
    uint32_t flags;
};

void pps_capture(struct pps_state *);
void pps_event(struct pps_state *, int);
void pps_init(struct pps_state *);
void pps_init_abi(struct pps_state *);
int pps_ioctl(unsigned long, caddr_t, struct pps_state *);

#endif
