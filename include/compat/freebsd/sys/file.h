/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal kernel file handle used by imported device declarations. */

#ifndef _SYS_FILE_H_
#define _SYS_FILE_H_

struct file {
    void *f_data;
    int f_flag;
};

#endif
