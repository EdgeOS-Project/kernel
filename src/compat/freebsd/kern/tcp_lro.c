/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Driver-facing TCP large receive offload support derived from the FreeBSD
 * tcp_lro interface. EdgeOS retains the FreeBSD queue contract while
 * delivering completed aggregates through the shared ifnet gateway.
 */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/net/ethernet.h"
#include "compat/freebsd/net/if_var.h"
#include "compat/freebsd/netinet/in.h"
#include "compat/freebsd/netinet/ip.h"
#include "compat/freebsd/netinet/ip6.h"
#include "compat/freebsd/netinet/tcp.h"
#include "compat/freebsd/netinet/tcp_lro.h"
#include "compat/freebsd/sys/mbuf.h"

#define EDGE_LRO_EINVAL 22
#define EDGE_LRO_ENOMEM 12
#define EDGE_LRO_TCP_OPTION_EOL 0
#define EDGE_LRO_TCP_OPTION_NOP 1
#define EDGE_LRO_TCP_OPTION_TIMESTAMP 8
#define EDGE_LRO_TCP_OPTION_TIMESTAMP_LENGTH 10

struct edge_lro_ipv4_wire {
    uint8_t version_header_length;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t source[4];
    uint8_t destination[4];
} __attribute__((packed));

struct edge_lro_ipv6_wire {
    uint32_t flow;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source[16];
    uint8_t destination[16];
} __attribute__((packed));

struct edge_lro_tcp_wire {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed));

struct edge_lro_packet {
    union lro_address address;
    struct edge_lro_ipv4_wire *ip4;
    struct edge_lro_ipv6_wire *ip6;
    struct edge_lro_tcp_wire *tcp;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint32_t payload_length;
    uint16_t frame_length;
    uint16_t ip_length;
    uint16_t tcp_length;
    uint16_t l3_offset;
    uint16_t l4_offset;
    uint16_t payload_offset;
    uint16_t window;
    uint16_t flags;
    uint8_t ip_version;
};

static uint16_t
edge_lro_load_network_word(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] << 8) | bytes[1];
}

static uint32_t
edge_lro_checksum_bytes(uint32_t sum, const uint8_t *bytes, size_t length,
    uint8_t *odd_byte, int *has_odd_byte)
{
    size_t offset = 0;

    if (*has_odd_byte && length != 0) {
        sum += ((uint16_t)*odd_byte << 8) | bytes[0];
        *has_odd_byte = 0;
        offset = 1;
    }
    while (offset + 1 < length) {
        sum += edge_lro_load_network_word(bytes + offset);
        offset += 2;
    }
    if (offset < length) {
        *odd_byte = bytes[offset];
        *has_odd_byte = 1;
    }
    return sum;
}

static uint16_t
edge_lro_checksum_finish(uint32_t sum, uint8_t odd_byte, int has_odd_byte)
{
    if (has_odd_byte)
        sum += (uint16_t)odd_byte << 8;
    while (sum >> 16)
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t
edge_lro_pseudo_sum(const struct edge_lro_packet *packet,
    uint32_t tcp_length)
{
    uint32_t sum = 0;

    if (packet->ip_version == 4) {
        const uint8_t *source = packet->ip4->source;
        const uint8_t *destination = packet->ip4->destination;

        sum += edge_lro_load_network_word(source);
        sum += edge_lro_load_network_word(source + 2);
        sum += edge_lro_load_network_word(destination);
        sum += edge_lro_load_network_word(destination + 2);
        sum += IPPROTO_TCP;
        sum += tcp_length;
    } else {
        const uint8_t *source = packet->ip6->source;
        const uint8_t *destination = packet->ip6->destination;

        for (unsigned int offset = 0; offset < 16; offset += 2) {
            sum += edge_lro_load_network_word(source + offset);
            sum += edge_lro_load_network_word(destination + offset);
        }
        sum += tcp_length >> 16;
        sum += tcp_length & UINT32_C(0xffff);
        sum += IPPROTO_TCP;
    }
    return sum;
}

static uint16_t
edge_lro_mbuf_checksum(struct mbuf *mbuf, uint32_t offset, uint32_t length,
    uint32_t initial_sum)
{
    uint8_t bytes[256];
    uint8_t odd_byte = 0;
    int has_odd_byte = 0;
    uint32_t sum = initial_sum;

    while (length != 0) {
        uint32_t chunk = length > sizeof(bytes) ?
            (uint32_t)sizeof(bytes) : length;

        m_copydata(mbuf, (int)offset, (int)chunk, (char *)bytes);
        sum = edge_lro_checksum_bytes(
            sum, bytes, chunk, &odd_byte, &has_odd_byte);
        offset += chunk;
        length -= chunk;
    }
    return edge_lro_checksum_finish(sum, odd_byte, has_odd_byte);
}

static void
edge_lro_update_ipv4_checksum(struct edge_lro_ipv4_wire *header)
{
    uint8_t odd_byte = 0;
    int has_odd_byte = 0;
    uint32_t sum;
    uint16_t checksum;

    header->checksum = 0;
    sum = edge_lro_checksum_bytes(0, (const uint8_t *)header,
        (size_t)(header->version_header_length & 0x0fu) * 4u,
        &odd_byte, &has_odd_byte);
    checksum = edge_lro_checksum_finish(sum, odd_byte, has_odd_byte);
    header->checksum = htons(checksum);
}

static int
edge_lro_parse_packet(struct mbuf *mbuf, struct edge_lro_packet *packet)
{
    uint8_t *frame;
    uint32_t available;
    uint32_t expected_frame_length;
    uint16_t ether_type;
    uint16_t l3_offset = ETHER_HDR_LEN;

    if (!mbuf || !packet || (mbuf->m_flags & M_PKTHDR) == 0 ||
        !mbuf->m_data)
        return TCP_LRO_CANNOT;
    available = m_length(mbuf, 0);
    if (available < ETHER_HDR_LEN || mbuf->m_len < ETHER_HDR_LEN)
        return TCP_LRO_CANNOT;
    frame = (uint8_t *)mbuf->m_data;
    ether_type = edge_lro_load_network_word(frame + 12);
    bsd_memset(packet, 0, sizeof(*packet));

    if (ether_type == ETHERTYPE_VLAN) {
        if (available < ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN ||
            mbuf->m_len < ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN)
            return TCP_LRO_CANNOT;
        packet->address.vlan_id =
            edge_lro_load_network_word(frame + 14) & EVL_VLID_MASK;
        ether_type = edge_lro_load_network_word(frame + 16);
        l3_offset += ETHER_VLAN_ENCAP_LEN;
    } else if ((mbuf->m_flags & M_VLANTAG) != 0) {
        packet->address.vlan_id =
            mbuf->m_pkthdr.ether_vtag & EVL_VLID_MASK;
    }

    packet->l3_offset = l3_offset;
    if (ether_type == ETHERTYPE_IP) {
        uint16_t fragment;

        if (available < l3_offset + sizeof(struct edge_lro_ipv4_wire) ||
            (uint32_t)mbuf->m_len <
            (uint32_t)l3_offset + sizeof(struct edge_lro_ipv4_wire))
            return TCP_LRO_CANNOT;
        packet->ip4 =
            (struct edge_lro_ipv4_wire *)(frame + l3_offset);
        if ((packet->ip4->version_header_length >> 4) != IPVERSION ||
            (packet->ip4->version_header_length & 0x0fu) < 5 ||
            packet->ip4->protocol != IPPROTO_TCP)
            return TCP_LRO_NOT_SUPPORTED;
        packet->ip_length = ntohs(packet->ip4->total_length);
        packet->l4_offset =
            l3_offset +
            (uint16_t)(packet->ip4->version_header_length & 0x0fu) * 4u;
        fragment = ntohs(packet->ip4->fragment_offset);
        if ((fragment & (IP_MF | IP_OFFMASK)) != 0 ||
            packet->ip_length <
            (uint16_t)(packet->ip4->version_header_length & 0x0fu) * 4u)
            return TCP_LRO_NOT_SUPPORTED;
        packet->ip_version = 4;
        packet->address.lro_type = LRO_TYPE_IPV4_TCP;
        bsd_memcpy(&packet->address.s_addr.v4.s_addr,
            packet->ip4->source, sizeof(packet->ip4->source));
        bsd_memcpy(&packet->address.d_addr.v4.s_addr,
            packet->ip4->destination, sizeof(packet->ip4->destination));
        expected_frame_length = l3_offset + packet->ip_length;
    } else if (ether_type == ETHERTYPE_IPV6) {
        if (available < l3_offset + sizeof(struct edge_lro_ipv6_wire) ||
            (uint32_t)mbuf->m_len <
            (uint32_t)l3_offset + sizeof(struct edge_lro_ipv6_wire))
            return TCP_LRO_CANNOT;
        packet->ip6 =
            (struct edge_lro_ipv6_wire *)(frame + l3_offset);
        if ((frame[l3_offset] >> 4) != 6 ||
            packet->ip6->next_header != IPPROTO_TCP)
            return TCP_LRO_NOT_SUPPORTED;
        packet->ip_length =
            (uint16_t)(sizeof(struct edge_lro_ipv6_wire) +
            ntohs(packet->ip6->payload_length));
        packet->l4_offset =
            l3_offset + sizeof(struct edge_lro_ipv6_wire);
        packet->ip_version = 6;
        packet->address.lro_type = LRO_TYPE_IPV6_TCP;
        bsd_memcpy(packet->address.s_addr.v6.s6_addr,
            packet->ip6->source, sizeof(packet->ip6->source));
        bsd_memcpy(packet->address.d_addr.v6.s6_addr,
            packet->ip6->destination, sizeof(packet->ip6->destination));
        expected_frame_length = l3_offset + packet->ip_length;
    } else {
        return TCP_LRO_NOT_SUPPORTED;
    }

    if (expected_frame_length > available ||
        packet->l4_offset + sizeof(struct edge_lro_tcp_wire) >
        expected_frame_length ||
        packet->l4_offset + sizeof(struct edge_lro_tcp_wire) >
        (uint32_t)mbuf->m_len)
        return TCP_LRO_CANNOT;
    if (available > expected_frame_length) {
        m_adj(mbuf, -(int)(available - expected_frame_length));
        available = expected_frame_length;
    }

    packet->tcp =
        (struct edge_lro_tcp_wire *)(frame + packet->l4_offset);
    packet->tcp_length =
        (uint16_t)(packet->tcp->data_offset_reserved >> 4) * 4u;
    if (packet->tcp_length < sizeof(struct edge_lro_tcp_wire) ||
        packet->l4_offset + packet->tcp_length > available ||
        packet->l4_offset + packet->tcp_length > (uint32_t)mbuf->m_len)
        return TCP_LRO_CANNOT;
    packet->payload_offset = packet->l4_offset + packet->tcp_length;
    packet->payload_length = available - packet->payload_offset;
    packet->frame_length = (uint16_t)available;
    packet->sequence = ntohl(packet->tcp->sequence);
    packet->acknowledgment = ntohl(packet->tcp->acknowledgment);
    packet->window = ntohs(packet->tcp->window);
    packet->flags =
        ((uint16_t)(packet->tcp->data_offset_reserved & 0x0fu) << 8) |
        packet->tcp->flags;
    packet->address.s_port = packet->tcp->source_port;
    packet->address.d_port = packet->tcp->destination_port;

    if (packet->payload_length == 0 ||
        (packet->flags & TH_ACK) == 0 ||
        (packet->flags & (TH_SYN | TH_FIN | TH_RST | TH_URG)) != 0)
        return TCP_LRO_NOT_SUPPORTED;
    return 0;
}

static int
edge_lro_options_compatible(const struct edge_lro_packet *left,
    const struct edge_lro_packet *right)
{
    const uint8_t *left_options;
    const uint8_t *right_options;
    uint16_t offset = sizeof(struct edge_lro_tcp_wire);

    if (left->tcp_length != right->tcp_length)
        return 0;
    left_options = (const uint8_t *)left->tcp;
    right_options = (const uint8_t *)right->tcp;
    while (offset < left->tcp_length) {
        uint8_t kind = left_options[offset];
        uint8_t right_kind = right_options[offset];
        uint8_t length;

        if (kind != right_kind)
            return 0;
        if (kind == EDGE_LRO_TCP_OPTION_EOL)
            return 1;
        if (kind == EDGE_LRO_TCP_OPTION_NOP) {
            ++offset;
            continue;
        }
        if (offset + 1 >= left->tcp_length)
            return 0;
        length = left_options[offset + 1];
        if (length < 2 || offset + length > left->tcp_length ||
            right_options[offset + 1] != length)
            return 0;
        if (kind != EDGE_LRO_TCP_OPTION_TIMESTAMP ||
            length != EDGE_LRO_TCP_OPTION_TIMESTAMP_LENGTH) {
            if (bsd_memcmp(left_options + offset,
                right_options + offset, length) != 0)
                return 0;
        }
        offset += length;
    }
    return 1;
}

static int
edge_lro_address_equal(const union lro_address *left,
    const union lro_address *right)
{
    return bsd_memcmp(left, right, sizeof(*left)) == 0;
}

static struct lro_entry *
edge_lro_find_entry(struct lro_ctrl *control,
    const struct edge_lro_packet *packet)
{
    struct lro_entry *entry;

    LIST_FOREACH(entry, &control->lro_active, next) {
        if (edge_lro_address_equal(
            &entry->outer.data, &packet->address))
            return entry;
    }
    return 0;
}

static struct mbuf *
edge_lro_last_mbuf(struct mbuf *mbuf)
{
    if (!mbuf)
        return 0;
    while (mbuf->m_next)
        mbuf = mbuf->m_next;
    return mbuf;
}

static void
edge_lro_recompute_checksums(struct lro_entry *entry)
{
    struct edge_lro_packet packet;
    uint32_t tcp_length;
    uint16_t checksum;

    bsd_memset(&packet, 0, sizeof(packet));
    packet.ip_version = entry->outer.data.lro_type == LRO_TYPE_IPV4_TCP ?
        4 : 6;
    packet.ip4 = (struct edge_lro_ipv4_wire *)entry->outer.ip4;
    packet.ip6 = (struct edge_lro_ipv6_wire *)entry->outer.ip6;
    packet.tcp = (struct edge_lro_tcp_wire *)entry->outer.tcp;
    packet.l4_offset = (uint16_t)((uint8_t *)packet.tcp -
        (uint8_t *)entry->m_head->m_data);
    tcp_length = entry->m_head->m_pkthdr.len - packet.l4_offset;
    packet.tcp->checksum = 0;
    checksum = edge_lro_mbuf_checksum(entry->m_head,
        packet.l4_offset, tcp_length,
        edge_lro_pseudo_sum(&packet, tcp_length));
    packet.tcp->checksum = htons(checksum);
    if (packet.ip_version == 4)
        edge_lro_update_ipv4_checksum(packet.ip4);
}

static void
edge_lro_flush_entry(struct lro_ctrl *control, struct lro_entry *entry)
{
    struct ifnet *interface;

    if (!entry || !entry->m_head)
        return;
    LIST_REMOVE(entry, next);
    edge_lro_recompute_checksums(entry);
    entry->m_head->m_pkthdr.lro_nsegs =
        (uint16_t)(entry->compressed + 1u);
    entry->m_head->m_pkthdr.csum_flags |=
        CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
    entry->m_head->m_pkthdr.csum_data = UINT16_MAX;
    interface = control->ifp ?
        control->ifp : entry->m_head->m_pkthdr.rcvif;
    control->lro_flushed++;
    if_input(interface, entry->m_head);
    bsd_memset(entry, 0, sizeof(*entry));
    LIST_INSERT_HEAD(&control->lro_free, entry, next);
}

static struct lro_entry *
edge_lro_allocate_entry(struct lro_ctrl *control)
{
    struct lro_entry *entry = LIST_FIRST(&control->lro_free);

    if (!entry) {
        entry = LIST_FIRST(&control->lro_active);
        if (entry)
            edge_lro_flush_entry(control, entry);
        entry = LIST_FIRST(&control->lro_free);
    }
    if (entry)
        LIST_REMOVE(entry, next);
    return entry;
}

static int
edge_lro_begin_entry(struct lro_ctrl *control, struct mbuf *mbuf,
    const struct edge_lro_packet *packet)
{
    struct lro_entry *entry = edge_lro_allocate_entry(control);

    if (!entry)
        return TCP_LRO_NO_ENTRIES;
    bsd_memset(entry, 0, sizeof(*entry));
    entry->m_head = mbuf;
    entry->m_tail = edge_lro_last_mbuf(mbuf);
    entry->m_last_mbuf = entry->m_tail;
    entry->outer.data = packet->address;
    entry->outer.ip4 = (struct ip *)packet->ip4;
    entry->outer.tcp = (struct tcphdr *)packet->tcp;
    entry->outer.total_hdr_len = packet->payload_offset;
    entry->next_seq = packet->sequence + packet->payload_length;
    entry->ack_seq = packet->acknowledgment;
    entry->window = packet->window;
    entry->flags = packet->flags;
    entry->uncompressed = 1;
    LIST_INSERT_HEAD(&control->lro_active, entry, next);
    control->lro_queued++;
    return 0;
}

static int
edge_lro_append(struct lro_ctrl *control, struct lro_entry *entry,
    struct mbuf *mbuf, const struct edge_lro_packet *packet)
{
    struct edge_lro_packet current;
    struct edge_lro_ipv4_wire *entry_ip4;
    struct edge_lro_ipv6_wire *entry_ip6;
    struct edge_lro_tcp_wire *entry_tcp;
    uint32_t aggregate_ip_length;
    struct mbuf *last;

    entry_ip4 = (struct edge_lro_ipv4_wire *)entry->outer.ip4;
    entry_ip6 = (struct edge_lro_ipv6_wire *)entry->outer.ip6;
    entry_tcp = (struct edge_lro_tcp_wire *)entry->outer.tcp;
    bsd_memset(&current, 0, sizeof(current));
    current.tcp = entry_tcp;
    current.tcp_length =
        (uint16_t)(entry_tcp->data_offset_reserved >> 4) * 4u;
    if (packet->sequence != entry->next_seq ||
        !edge_lro_options_compatible(&current, packet))
        return TCP_LRO_CANNOT;
    aggregate_ip_length =
        (entry->outer.data.lro_type == LRO_TYPE_IPV4_TCP ?
        ntohs(entry_ip4->total_length) :
        sizeof(struct edge_lro_ipv6_wire) +
        ntohs(entry_ip6->payload_length)) +
        packet->payload_length;
    if (aggregate_ip_length > control->lro_length_lim ||
        entry->compressed >= control->lro_ackcnt_lim)
        return TCP_LRO_CANNOT;

    entry_tcp->acknowledgment = packet->tcp->acknowledgment;
    entry_tcp->window = packet->tcp->window;
    entry_tcp->data_offset_reserved =
        (uint8_t)((entry_tcp->data_offset_reserved & 0xf0u) |
        ((packet->flags >> 8) & 0x0fu));
    entry_tcp->flags = (uint8_t)packet->flags;
    if (packet->tcp_length > sizeof(struct edge_lro_tcp_wire)) {
        bsd_memcpy((uint8_t *)entry_tcp +
            sizeof(struct edge_lro_tcp_wire),
            (const uint8_t *)packet->tcp +
            sizeof(struct edge_lro_tcp_wire),
            packet->tcp_length - sizeof(struct edge_lro_tcp_wire));
    }
    if (entry->outer.data.lro_type == LRO_TYPE_IPV4_TCP) {
        entry_ip4->total_length = htons((uint16_t)aggregate_ip_length);
        entry_ip4->identification = packet->ip4->identification;
    } else {
        entry_ip6->payload_length =
            htons((uint16_t)(aggregate_ip_length -
            sizeof(struct edge_lro_ipv6_wire)));
    }

    m_tag_delete_chain(mbuf, 0);
    m_adj(mbuf, packet->payload_offset);
    mbuf->m_flags &= ~M_PKTHDR;
    mbuf->m_nextpkt = 0;
    last = edge_lro_last_mbuf(mbuf);
    entry->m_tail->m_next = mbuf;
    entry->m_tail = last;
    entry->m_last_mbuf = last;
    entry->m_head->m_pkthdr.len += (int32_t)packet->payload_length;
    entry->next_seq += packet->payload_length;
    entry->ack_seq = packet->acknowledgment;
    entry->window = packet->window;
    entry->flags = packet->flags;
    entry->compressed++;
    control->lro_queued++;
    return 0;
}

int
tcp_lro_init_args(struct lro_ctrl *control, struct ifnet *interface,
    unsigned int entry_count, unsigned int mbuf_queue_depth)
{
    struct lro_entry *entries;

    if (!control)
        return EDGE_LRO_EINVAL;
    if (entry_count == 0)
        entry_count = TCP_LRO_ENTRIES;
    entries = bsd_malloc(
        entry_count * sizeof(*entries), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!entries)
        return EDGE_LRO_ENOMEM;
    bsd_memset(control, 0, sizeof(*control));
    control->ifp = interface;
    control->lro_mbuf_data = (struct lro_mbuf_sort *)entries;
    control->lro_cnt = entry_count;
    control->lro_mbuf_max = mbuf_queue_depth;
    control->lro_ackcnt_lim = TCP_LRO_ACKCNT_MAX;
    control->lro_length_lim = TCP_LRO_LENGTH_MAX;
    LIST_INIT(&control->lro_active);
    LIST_INIT(&control->lro_free);
    for (unsigned int index = 0; index < entry_count; ++index)
        LIST_INSERT_HEAD(&control->lro_free, &entries[index], next);
    return 0;
}

int
tcp_lro_init(struct lro_ctrl *control)
{
    return tcp_lro_init_args(control, 0, TCP_LRO_ENTRIES, 0);
}

void
tcp_lro_flush_all(struct lro_ctrl *control)
{
    if (!control)
        return;
    while (!LIST_EMPTY(&control->lro_active))
        edge_lro_flush_entry(control, LIST_FIRST(&control->lro_active));
}

void
tcp_lro_free(struct lro_ctrl *control)
{
    void *allocation;

    if (!control)
        return;
    tcp_lro_flush_all(control);
    allocation = control->lro_mbuf_data;
    bsd_memset(control, 0, sizeof(*control));
    bsd_free(allocation, M_DEVBUF);
}

int
tcp_lro_rx(struct lro_ctrl *control, struct mbuf *mbuf, uint32_t checksum)
{
    struct edge_lro_packet packet;
    struct lro_entry *entry;
    uint32_t tcp_length;
    int error;

    if (!control || !mbuf || control->lro_cnt == 0)
        return TCP_LRO_CANNOT;
    error = edge_lro_parse_packet(mbuf, &packet);
    if (error != 0)
        return error;
    tcp_length = packet.frame_length - packet.l4_offset;
    if (checksum == 0 &&
        (mbuf->m_pkthdr.csum_flags &
        (CSUM_DATA_VALID | CSUM_PSEUDO_HDR)) !=
        (CSUM_DATA_VALID | CSUM_PSEUDO_HDR) &&
        edge_lro_mbuf_checksum(mbuf, packet.l4_offset, tcp_length,
        edge_lro_pseudo_sum(&packet, tcp_length)) != 0) {
        control->lro_bad_csum++;
        return TCP_LRO_CANNOT;
    }

    entry = edge_lro_find_entry(control, &packet);
    if (entry) {
        error = edge_lro_append(control, entry, mbuf, &packet);
        if (error == 0)
            return 0;
        edge_lro_flush_entry(control, entry);
    }
    return edge_lro_begin_entry(control, mbuf, &packet);
}

void
tcp_lro_queue_mbuf(struct lro_ctrl *control, struct mbuf *mbuf)
{
    struct ifnet *interface;

    if (!mbuf)
        return;
    interface = control && control->ifp ?
        control->ifp : mbuf->m_pkthdr.rcvif;
    if (tcp_lro_rx(control, mbuf, 0) != 0)
        if_input(interface, mbuf);
}
