/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _SYS_SOCKET_H_
#define _SYS_SOCKET_H_

#include <stdint.h>

typedef uint8_t sa_family_t;

struct sockaddr {
    uint8_t sa_len;
    sa_family_t sa_family;
    char sa_data[14];
};

struct sockaddr_storage {
    uint8_t ss_len;
    sa_family_t ss_family;
    char padding[126];
};

#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_LOCAL AF_UNIX
#define AF_INET 2
#define AF_INET6 28
#define AF_LINK 18
#define AF_IEEE80211 37
#define AF_HYPERV 43

#define SOCK_STREAM 1

#define SO_ACCEPTCONN 0x0002

#define MSG_PEEK 0x00000002
#define MSG_EOR 0x00000008
#define MSG_WAITALL 0x00000040
#define MSG_DONTWAIT 0x00000080
#define MSG_NBIO 0x00004000

enum shutdown_how {
    SHUT_RD = 0,
    SHUT_WR = 1,
    SHUT_RDWR = 2,
};

#endif
