/* SPDX-License-Identifier: MPL-2.0 */
/* Local-domain socket address layout used by imported BSD drivers. */

#ifndef _SYS_UN_H_
#define _SYS_UN_H_

#include <sys/socket.h>

#define SUNPATHLEN 104

struct sockaddr_un {
    uint8_t sun_len;
    sa_family_t sun_family;
    char sun_path[SUNPATHLEN];
};

#endif
