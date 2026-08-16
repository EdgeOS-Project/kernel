/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NETINET_TCP_LRO_H_
#define _NETINET_TCP_LRO_H_

#include <stdint.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

struct ifnet;
struct mbuf;

#ifdef BSD_BRIDGE_HOST_TEST
struct bintime {
    int64_t sec;
    uint64_t frac;
};
#else
#include <sys/time.h>
#endif

#define TCP_LRO_ENTRIES 8
#define TCP_LRO_LENGTH_MAX (65535 - 255)
#define TCP_LRO_ACKCNT_MAX 65535
#define TCP_LRO_NO_ENTRIES (-2)
#define TCP_LRO_CANNOT (-1)
#define TCP_LRO_NOT_SUPPORTED 1

#define LRO_TYPE_NONE 0
#define LRO_TYPE_IPV4_TCP 1
#define LRO_TYPE_IPV6_TCP 2

union lro_address {
    unsigned long raw[6];
    struct {
        uint8_t lro_type;
        uint8_t lro_flags;
        uint16_t vlan_id;
        uint16_t s_port;
        uint16_t d_port;
        uint32_t vxlan_vni;
        union {
            struct in_addr v4;
            struct in6_addr v6;
        } s_addr;
        union {
            struct in_addr v4;
            struct in6_addr v6;
        } d_addr;
    };
};

struct lro_parser {
    union lro_address data;
    union {
        uint8_t *l3;
        struct ip *ip4;
        struct ip6_hdr *ip6;
    };
    union {
        uint8_t *l4;
        struct tcphdr *tcp;
    };
    uint16_t total_hdr_len;
};

struct lro_entry {
    LIST_ENTRY(lro_entry) next;
    LIST_ENTRY(lro_entry) hash_next;
    struct mbuf *m_head;
    struct mbuf *m_tail;
    struct mbuf *m_last_mbuf;
    struct lro_parser outer;
    struct lro_parser inner;
    uint32_t next_seq;
    uint32_t ack_seq;
    uint32_t tsval;
    uint32_t tsecr;
    uint16_t compressed;
    uint16_t uncompressed;
    uint16_t window;
    uint16_t flags : 12;
    uint16_t timestamp : 1;
    uint16_t needs_merge : 1;
    uint16_t reserved : 2;
    struct bintime alloc_time;
};

LIST_HEAD(lro_head, lro_entry);

struct lro_mbuf_sort {
    uint64_t seq;
    struct mbuf *mb;
};

struct lro_ctrl {
    struct ifnet *ifp;
    struct lro_mbuf_sort *lro_mbuf_data;
    struct bintime lro_last_queue_time;
    uint64_t lro_queued;
    uint64_t lro_flushed;
    uint64_t lro_bad_csum;
    unsigned int lro_cnt;
    unsigned int lro_mbuf_count;
    unsigned int lro_mbuf_max;
    unsigned short lro_ackcnt_lim;
    unsigned short lro_cpu;
    unsigned int lro_length_lim;
    unsigned long lro_hashsz;
    uint32_t lro_last_cpu;
    uint32_t lro_cnt_of_same_cpu;
    struct lro_head *lro_hash;
    struct lro_head lro_active;
    struct lro_head lro_free;
    uint8_t lro_cpu_is_set;
};

int tcp_lro_init(struct lro_ctrl *control);
int tcp_lro_init_args(struct lro_ctrl *control, struct ifnet *ifp,
    unsigned int entry_count, unsigned int mbuf_queue_depth);
void tcp_lro_free(struct lro_ctrl *control);
void tcp_lro_flush_all(struct lro_ctrl *control);
int tcp_lro_rx(struct lro_ctrl *control, struct mbuf *mbuf,
    uint32_t checksum);
void tcp_lro_queue_mbuf(struct lro_ctrl *control, struct mbuf *mbuf);

#endif
