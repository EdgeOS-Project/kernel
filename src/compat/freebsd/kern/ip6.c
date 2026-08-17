/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * IPv6 extension-header walking for imported FreeBSD network drivers.
 *
 * This implementation follows FreeBSD sys/netinet6/ip6_input.c and keeps the
 * same offsets, first-fragment rule, and terminal-protocol behavior.
 */

#include "compat/freebsd/netinet/in.h"
#include "compat/freebsd/netinet/ip6.h"
#include "compat/freebsd/netinet6/ip6_var.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/mbuf.h"

int
ip6_nexthdr(const struct mbuf *mbuf, int offset, int protocol,
    int *next_protocol)
{
    struct ip6_hdr ip6;
    struct ip6_ext extension;
    struct ip6_frag fragment;

    if (!mbuf) {
        bsd_printf("[bsd-bridge] panic: ip6_nexthdr: mbuf is null");
        bsd_bridge_panic_stop();
        return -1;
    }
    if ((mbuf->m_flags & M_PKTHDR) == 0 || mbuf->m_pkthdr.len < offset)
        return -1;

    switch (protocol) {
    case IPPROTO_IPV6:
        if (mbuf->m_pkthdr.len < offset + (int)sizeof(ip6))
            return -1;
        m_copydata(mbuf, offset, (int)sizeof(ip6), (char *)&ip6);
        if (next_protocol)
            *next_protocol = ip6.ip6_nxt;
        return offset + (int)sizeof(ip6);

    case IPPROTO_FRAGMENT:
        if (mbuf->m_pkthdr.len < offset + (int)sizeof(fragment))
            return -1;
        m_copydata(mbuf, offset, (int)sizeof(fragment),
            (char *)&fragment);
        if ((fragment.ip6f_offlg & IP6F_OFF_MASK) != 0)
            return -1;
        if (next_protocol)
            *next_protocol = fragment.ip6f_nxt;
        return offset + (int)sizeof(fragment);

    case IPPROTO_AH:
        if (mbuf->m_pkthdr.len < offset + (int)sizeof(extension))
            return -1;
        m_copydata(mbuf, offset, (int)sizeof(extension),
            (char *)&extension);
        if (next_protocol)
            *next_protocol = extension.ip6e_nxt;
        return offset + ((extension.ip6e_len + 2) << 2);

    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_DSTOPTS:
        if (mbuf->m_pkthdr.len < offset + (int)sizeof(extension))
            return -1;
        m_copydata(mbuf, offset, (int)sizeof(extension),
            (char *)&extension);
        if (next_protocol)
            *next_protocol = extension.ip6e_nxt;
        return offset + ((extension.ip6e_len + 1) << 3);

    case IPPROTO_NONE:
    case IPPROTO_ESP:
    case IPPROTO_IPCOMP:
    default:
        return -1;
    }
}

int
ip6_lasthdr(const struct mbuf *mbuf, int offset, int protocol,
    int *next_protocol)
{
    int local_next = -1;

    if (!next_protocol)
        next_protocol = &local_next;
    for (;;) {
        int new_offset =
            ip6_nexthdr(mbuf, offset, protocol, next_protocol);

        if (new_offset < 0)
            return offset;
        if (new_offset < offset)
            return -1;
        if (new_offset == offset)
            return new_offset;
        offset = new_offset;
        protocol = *next_protocol;
    }
}
