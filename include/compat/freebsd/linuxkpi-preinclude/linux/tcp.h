/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef _EDGEOS_LINUXKPI_LINUX_TCP_H_
#define _EDGEOS_LINUXKPI_LINUX_TCP_H_

#include <netinet/tcp.h>
#include <linux/skbuff.h>

static inline struct tcphdr *
tcp_hdr(struct sk_buff *socket_buffer)
{
    return (struct tcphdr *)skb_transport_header(socket_buffer);
}

static inline uint32_t
tcp_hdrlen(struct sk_buff *socket_buffer)
{
    struct tcphdr *header;

    header = tcp_hdr(socket_buffer);
    return 4U * header->doff;
}

#endif
