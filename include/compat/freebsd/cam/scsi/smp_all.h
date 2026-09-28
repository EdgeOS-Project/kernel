/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Serial Management Protocol response definitions used by the shared CAM
 * gateway. Imported MPS/MPR drivers submit complete request and response
 * frames; the transport evaluates the standard result byte.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_SCSI_SMP_ALL_H
#define EDGEOS_COMPAT_FREEBSD_CAM_SCSI_SMP_ALL_H

#define SMP_FRAME_TYPE_REQUEST 0x40
#define SMP_FRAME_TYPE_RESPONSE 0x41
#define SMP_FR_ACCEPTED 0x00

#endif
