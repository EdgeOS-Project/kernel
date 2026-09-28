/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NET_IF_DL_H_
#define _NET_IF_DL_H_

#include <stdint.h>

struct sockaddr_dl {
    uint8_t sdl_len;
    uint8_t sdl_family;
    uint16_t sdl_index;
    uint8_t sdl_type;
    uint8_t sdl_nlen;
    uint8_t sdl_alen;
    uint8_t sdl_slen;
    char sdl_data[46];
};

#define LLADDR(address) (&(address)->sdl_data[(address)->sdl_nlen])

#endif
