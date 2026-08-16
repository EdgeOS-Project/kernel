/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD-compatible network buffers for imported drivers. */

#ifndef _SYS_MBUF_H_
#define _SYS_MBUF_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

#include "../edgeos/malloc.h"
#include "../machine/param.h"
#include "../vm/uma.h"

struct ifnet;
struct m_tag;

#ifndef MSIZE
#define MSIZE 256
#endif
#ifndef MHLEN
#define MHLEN 192
#endif
#ifndef MINCLSIZE
#define MINCLSIZE (MHLEN + 1)
#endif
#ifndef MCLSHIFT
#define MCLSHIFT 11
#endif
#ifndef MCLBYTES
#define MCLBYTES (1 << MCLSHIFT)
#endif
#ifndef MJUMPAGESIZE
#define MJUMPAGESIZE PAGE_SIZE
#endif
#ifndef MJUM9BYTES
#define MJUM9BYTES (9 * 1024)
#endif
#ifndef MJUM16BYTES
#define MJUM16BYTES (16 * 1024)
#endif

#define MT_DATA 1
#define MT_HEADER MT_DATA
#define M_COPYALL 1000000000

#define M_EXT 0x00000001u
#define M_PKTHDR 0x00000002u
#define M_RDONLY 0x00000008u
#define M_MCAST 0x00000020u
#define M_BCAST 0x00000010u
#define M_VLANTAG 0x00000080u
#define M_PROTO1 0x00002000u
#define M_PROTO2 0x00004000u
#define M_PROTO3 0x00008000u
#define M_PROTO4 0x00010000u
#define M_PROTO5 0x00020000u
#define M_PROTO6 0x00040000u
#define M_PROTO7 0x00080000u
#define M_PROTO8 0x00100000u
#define M_PROTO9 0x00200000u
#define M_PROTO10 0x00400000u
#define M_PROTO11 0x00800000u
#define M_PROTOFLAGS (M_PROTO1 | M_PROTO2 | M_PROTO3 | M_PROTO4 | \
    M_PROTO5 | M_PROTO6 | M_PROTO7 | M_PROTO8 | M_PROTO9 | M_PROTO10 | \
    M_PROTO11)
#define M_COPYFLAGS (M_PKTHDR | M_RDONLY | M_BCAST | M_MCAST | \
    M_VLANTAG | M_PROTOFLAGS)
#define M_FLAG_BITS ""

extern unsigned int max_linkhdr;
void max_linkhdr_grow(unsigned int length);

#define M_HASHTYPE_HASHPROP 0x80
#define M_HASHTYPE_INNER 0x40
#define M_HASHTYPE_HASH(type) (M_HASHTYPE_HASHPROP | (type))
#define M_HASHTYPE_NONE 0
#define M_HASHTYPE_RSS_IPV4 M_HASHTYPE_HASH(1)
#define M_HASHTYPE_RSS_TCP_IPV4 M_HASHTYPE_HASH(2)
#define M_HASHTYPE_RSS_IPV6 M_HASHTYPE_HASH(3)
#define M_HASHTYPE_RSS_TCP_IPV6 M_HASHTYPE_HASH(4)
#define M_HASHTYPE_RSS_IPV6_EX M_HASHTYPE_HASH(5)
#define M_HASHTYPE_RSS_TCP_IPV6_EX M_HASHTYPE_HASH(6)
#define M_HASHTYPE_RSS_UDP_IPV4 M_HASHTYPE_HASH(7)
#define M_HASHTYPE_RSS_UDP_IPV6 M_HASHTYPE_HASH(9)
#define M_HASHTYPE_RSS_UDP_IPV6_EX M_HASHTYPE_HASH(10)
#define M_HASHTYPE_OPAQUE 0x3f
#define M_HASHTYPE_OPAQUE_HASH M_HASHTYPE_HASH(M_HASHTYPE_OPAQUE)
#define M_HASHTYPE_CLEAR(mbuf) ((mbuf)->m_pkthdr.rsstype = 0)
#define M_HASHTYPE_GET(mbuf) \
    ((mbuf)->m_pkthdr.rsstype & ~M_HASHTYPE_INNER)
#define M_HASHTYPE_SET(mbuf, value) ((mbuf)->m_pkthdr.rsstype = (value))
#define M_HASHTYPE_ISHASH(mbuf) \
    (((mbuf)->m_pkthdr.rsstype & M_HASHTYPE_HASHPROP) != 0)

#define CSUM_IP 0x00000001u
#define CSUM_IP_UDP 0x00000002u
#define CSUM_IP_TCP 0x00000004u
#define CSUM_IP_TSO 0x00000010u
#define CSUM_IP6_UDP 0x00000200u
#define CSUM_IP6_TCP 0x00000400u
#define CSUM_IP6_TSO 0x00001000u
#define CSUM_IP_SCTP 0x00000008u
#define CSUM_IP6_SCTP 0x00000800u
#define CSUM_L3_CALC 0x01000000u
#define CSUM_L3_VALID 0x02000000u
#define CSUM_L4_CALC 0x04000000u
#define CSUM_L4_VALID 0x08000000u

#define CSUM_IP_CHECKED CSUM_L3_CALC
#define CSUM_IP_VALID CSUM_L3_VALID
#define CSUM_DATA_VALID CSUM_L4_VALID
#define CSUM_PSEUDO_HDR CSUM_L4_CALC
#define CSUM_SCTP_VALID CSUM_L4_VALID
#define CSUM_DELAY_DATA (CSUM_TCP | CSUM_UDP)
#define CSUM_DELAY_IP CSUM_IP
#define CSUM_DELAY_DATA_IPV6 (CSUM_TCP_IPV6 | CSUM_UDP_IPV6)
#define CSUM_DATA_VALID_IPV6 CSUM_DATA_VALID
#define CSUM_TCP CSUM_IP_TCP
#define CSUM_UDP CSUM_IP_UDP
#define CSUM_TSO (CSUM_IP_TSO | CSUM_IP6_TSO)
#define CSUM_UDP_IPV6 CSUM_IP6_UDP
#define CSUM_TCP_IPV6 CSUM_IP6_TCP
#define CSUM_SCTP CSUM_IP_SCTP
#define CSUM_SCTP_IPV6 CSUM_IP6_SCTP
#define CSUM_L5_CALC 0x10000000u
#define CSUM_L5_VALID 0x20000000u
#define CSUM_COALESCED 0x40000000u
#define CSUM_SND_TAG 0x80000000u
#define CSUM_BITS \
    "\20\1CSUM_IP\2CSUM_IP_UDP\3CSUM_IP_TCP\4CSUM_IP_SCTP\5CSUM_IP_TSO" \
    "\6CSUM_IP_ISCSI\7CSUM_INNER_IP6_UDP\10CSUM_INNER_IP6_TCP" \
    "\11CSUM_INNER_IP6_TSO\12CSUM_IP6_UDP\13CSUM_IP6_TCP" \
    "\14CSUM_IP6_SCTP\15CSUM_IP6_TSO\16CSUM_IP6_ISCSI" \
    "\17CSUM_INNER_IP\20CSUM_INNER_IP_UDP\21CSUM_INNER_IP_TCP" \
    "\22CSUM_INNER_IP_TSO\23CSUM_ENCAP_VXLAN\24CSUM_ENCAP_GENEVE" \
    "\25CSUM_INNER_L3_CALC\26CSUM_INNER_L3_VALID" \
    "\27CSUM_INNER_L4_CALC\30CSUM_INNER_L4_VALID\31CSUM_L3_CALC" \
    "\32CSUM_L3_VALID\33CSUM_L4_CALC\34CSUM_L4_VALID" \
    "\35CSUM_L5_CALC\36CSUM_L5_VALID\37CSUM_COALESCED\40CSUM_SND_TAG"

#define EXT_CLUSTER 1
#define EXT_SFBUF 2
#define EXT_JUMBOP 3
#define EXT_JUMBO9 4
#define EXT_JUMBO16 5
#define EXT_PACKET 6
#define EXT_MBUF 7
#define EXT_RXRING 8
#define EXT_CTL 9
#define EXT_VENDOR1 224
#define EXT_VENDOR2 225
#define EXT_VENDOR3 226
#define EXT_VENDOR4 227
#define EXT_EXP1 244
#define EXT_EXP2 245
#define EXT_EXP3 246
#define EXT_EXP4 247
#define EXT_NET_DRV 252
#define EXT_MOD_TYPE 253
#define EXT_DISPOSABLE 254
#define EXT_EXTREF 255

#define EXT_FLAG_EMBREF 0x000001
#define EXT_FLAG_EXTREF 0x000002
#define EXT_FLAG_NOFREE 0x000010

struct mbuf;
typedef void m_ext_free_t(struct mbuf *);

struct pkthdr {
    struct ifnet *rcvif;
    int32_t len;
    uint32_t flowid;
    uint32_t csum_flags;
    uint8_t rsstype;
    uint8_t reserved[3];
    uint32_t fibnum;
    union {
        uint64_t rcv_tstmp;
        struct {
            uint8_t l2hlen;
            uint8_t l3hlen;
            uint8_t l4hlen;
            uint8_t l5hlen;
            uint8_t inner_l2hlen;
            uint8_t inner_l3hlen;
            uint8_t inner_l4hlen;
            uint8_t inner_l5hlen;
        };
    };
    union {
        uint8_t eight[8];
        uint16_t sixteen[4];
        uint32_t thirtytwo[2];
        uint64_t sixtyfour[1];
        uintptr_t unintptr[1];
        void *ptr;
    } PH_per;
    union {
        uint8_t eight[8];
        uint16_t sixteen[4];
        uint32_t thirtytwo[2];
        uint64_t sixtyfour[1];
        uintptr_t unintptr[1];
        void *ptr;
    } PH_loc;
    struct m_tag *tags;
};

#define ether_vtag PH_per.sixteen[0]
#define tso_segsz PH_per.sixteen[1]
#define csum_data PH_per.thirtytwo[1]
#define lro_nsegs tso_segsz

struct m_ext {
    volatile unsigned int ext_count;
    char *ext_buf;
    uint32_t ext_size;
    uint8_t ext_type;
    uint32_t ext_flags;
    m_ext_free_t *ext_free;
    void *ext_arg1;
    void *ext_arg2;
};

struct mbuf {
    struct mbuf *m_next;
    union {
        struct mbuf *m_nextpkt;
        STAILQ_ENTRY(mbuf) m_stailqpkt;
    };
    char *m_data;
    int32_t m_len;
    uint8_t m_type;
    uint32_t m_flags;
    struct pkthdr m_pkthdr;
    struct m_ext m_ext;
    void *m_bridge_allocation;
    uma_zone_t m_bridge_ext_zone;
    uint32_t m_bridge_capacity;
    uint8_t m_bridge_raw_header;
};

/*
 * EdgeOS keeps the packet storage in a separately allocated contiguous area
 * for every bridge mbuf.  Expose that stable base through the FreeBSD inline
 * packet-data member name so unmodified drivers can restore m_data after a
 * prepend or alignment adjustment.
 */
#define m_pktdat m_ext.ext_buf

struct m_tag {
    struct m_tag *next;
    uint32_t cookie;
    int type;
    uint16_t length;
};

void m_freem(struct mbuf *mbuf);

struct mbufq {
    STAILQ_HEAD(, mbuf) mq_head;
    int mq_len;
    int mq_maxlen;
};

static inline void
mbufq_init(struct mbufq *queue, int maximum_length)
{
    STAILQ_INIT(&queue->mq_head);
    queue->mq_len = 0;
    queue->mq_maxlen = maximum_length;
}

static inline struct mbuf *
mbufq_flush(struct mbufq *queue)
{
    struct mbuf *head = STAILQ_FIRST(&queue->mq_head);

    STAILQ_INIT(&queue->mq_head);
    queue->mq_len = 0;
    return head;
}

static inline void
mbufq_drain(struct mbufq *queue)
{
    struct mbuf *mbuf = mbufq_flush(queue);

    while (mbuf) {
        struct mbuf *next = STAILQ_NEXT(mbuf, m_stailqpkt);

        mbuf->m_nextpkt = 0;
        m_freem(mbuf);
        mbuf = next;
    }
}

static inline struct mbuf *
mbufq_first(const struct mbufq *queue)
{
    return STAILQ_FIRST(&queue->mq_head);
}

static inline struct mbuf *
mbufq_last(const struct mbufq *queue)
{
    return STAILQ_LAST(&queue->mq_head, mbuf, m_stailqpkt);
}

static inline int
mbufq_empty(const struct mbufq *queue)
{
    return queue->mq_len == 0;
}

static inline int
mbufq_full(const struct mbufq *queue)
{
    return queue->mq_maxlen > 0 && queue->mq_len >= queue->mq_maxlen;
}

static inline int
mbufq_len(const struct mbufq *queue)
{
    return queue->mq_len;
}

static inline int
mbufq_enqueue(struct mbufq *queue, struct mbuf *mbuf)
{
    if (mbufq_full(queue))
        return 55;
    STAILQ_INSERT_TAIL(&queue->mq_head, mbuf, m_stailqpkt);
    queue->mq_len++;
    return 0;
}

static inline void
mbufq_remove(struct mbufq *queue, struct mbuf *mbuf)
{
    STAILQ_REMOVE(&queue->mq_head, mbuf, mbuf, m_stailqpkt);
    queue->mq_len--;
}

static inline struct mbuf *
mbufq_dequeue(struct mbufq *queue)
{
    struct mbuf *mbuf = STAILQ_FIRST(&queue->mq_head);

    if (!mbuf)
        return 0;
    STAILQ_REMOVE_HEAD(&queue->mq_head, m_stailqpkt);
    mbuf->m_nextpkt = 0;
    queue->mq_len--;
    return mbuf;
}

static inline void
mbufq_prepend(struct mbufq *queue, struct mbuf *mbuf)
{
    STAILQ_INSERT_HEAD(&queue->mq_head, mbuf, m_stailqpkt);
    queue->mq_len++;
}

static inline void
mbufq_concat(struct mbufq *destination, struct mbufq *source)
{
    destination->mq_len += source->mq_len;
    STAILQ_CONCAT(&destination->mq_head, &source->mq_head);
    source->mq_len = 0;
}

#define mtod(mbuf, type) ((type)((mbuf)->m_data))
#define mtodo(mbuf, offset) \
    ((void *)((mbuf)->m_data + (offset)))
#define M_ASSERTPKTHDR(mbuf) do {                                      \
    if (((mbuf)->m_flags & M_PKTHDR) == 0)                             \
        __builtin_trap();                                              \
} while (0)

struct mbuf *m_getjcl(int how, short type, int flags, int size);
struct mbuf *m_get(int how, short type);
struct mbuf *m_gethdr_raw(int how, short type);
struct mbuf *m_gethdr(int how, short type);
struct mbuf *m_get2(int size, int how, short type, int flags);
struct mbuf *m_get3(int size, int how, short type, int flags);
struct mbuf *m_getm2(struct mbuf *mbuf, int length, int how, short type,
    int flags);
#define m_getm(mbuf, length, how, type) \
    m_getm2((mbuf), (length), (how), (type), M_PKTHDR)
struct mbuf *m_getcl(int how, short type, int flags);
int m_clget(struct mbuf *mbuf, int how);
struct mbuf *m_devget(char *buffer, int total_length, int offset,
    struct ifnet *interface,
    void (*copy)(char *source, char *destination, unsigned int length));
void m_init(struct mbuf *mbuf, int how, short type, int flags);
void m_free_raw(struct mbuf *mbuf);
struct mbuf *m_free(struct mbuf *mbuf);
void m_cljset(struct mbuf *mbuf, void *cluster, int type);
void m_extadd(struct mbuf *mbuf, char *buffer, unsigned int size,
    m_ext_free_t free_callback, void *argument1, void *argument2,
    int flags, int type);
#define MEXTADD(mbuf, buffer, size, free_callback, argument1, argument2, \
    flags, type) \
    m_extadd((mbuf), (char *)(buffer), (size), (free_callback), \
        (argument1), (argument2), (flags), (type))
int m_gettype(int size);
uma_zone_t m_getzone(int size);
void m_adj(struct mbuf *mbuf, int length);
int m_apply(struct mbuf *mbuf, int offset, int length,
    int (*callback)(void *, void *, unsigned int), void *argument);
void m_copydata(const struct mbuf *mbuf, int offset, int length,
    char *destination);
void m_copyback(struct mbuf *mbuf, int offset, int length,
    const void *source);
struct mbuf *m_prepend(struct mbuf *mbuf, int length, int how);
struct mbuf *m_split(struct mbuf *mbuf, int length, int how);
void m_cat(struct mbuf *head, struct mbuf *tail);
void m_catpkt(struct mbuf *head, struct mbuf *tail);
struct mbuf *m_copypacket(const struct mbuf *mbuf, int how);
struct mbuf *m_copym(struct mbuf *mbuf, int offset, int length, int how);
struct mbuf *m_defrag(struct mbuf *mbuf, int how);
struct mbuf *m_collapse(struct mbuf *mbuf, int how, int max_segments);
struct mbuf *m_dup(const struct mbuf *mbuf, int how);
struct mbuf *m_unshare(struct mbuf *mbuf, int how);
struct mbuf *m_pullup(struct mbuf *mbuf, int length);
void m_align(struct mbuf *mbuf, int length);
void m_move_pkthdr(struct mbuf *destination, struct mbuf *source);
int m_dup_pkthdr(struct mbuf *destination, const struct mbuf *source,
    int how);
struct m_tag *m_tag_alloc(uint32_t cookie, int type, int length, int how);
void m_tag_prepend(struct mbuf *mbuf, struct m_tag *tag);
struct m_tag *m_tag_locate(struct mbuf *mbuf, uint32_t cookie, int type,
    struct m_tag *start);
void m_tag_delete(struct mbuf *mbuf, struct m_tag *tag);
void m_tag_delete_chain(struct mbuf *mbuf, struct m_tag *tag);
int m_append(struct mbuf *mbuf, int length, const void *data);
void m_freem(struct mbuf *mbuf);
unsigned int m_length(struct mbuf *mbuf, struct mbuf **last);
struct mbuf *m_getptr(struct mbuf *mbuf, int location, int *offset);

#define m_clrprotoflags(mbuf) ((mbuf)->m_flags &= ~M_PROTOFLAGS)
#define m_rcvif(mbuf) ((mbuf)->m_pkthdr.rcvif)
#define M_SETFIB(mbuf, fib) ((mbuf)->m_pkthdr.fibnum = (uint32_t)(fib))
#define M_PREPEND(mbuf, length, how) \
    ((mbuf) = m_prepend((mbuf), (length), (how)))
#define M_ALIGN(mbuf, length) m_align((mbuf), (length))
#define M_LEADINGSPACE(mbuf) \
    ((int)((mbuf)->m_data && (mbuf)->m_ext.ext_buf ? \
        (mbuf)->m_data - (mbuf)->m_ext.ext_buf : 0))
#define M_TRAILINGROOM(mbuf) \
    ((int)((mbuf)->m_data && (mbuf)->m_ext.ext_buf ? \
        ((mbuf)->m_ext.ext_buf + (mbuf)->m_ext.ext_size) - \
        ((mbuf)->m_data + (mbuf)->m_len) : 0))
#define M_WRITABLE(mbuf) ((mbuf) != 0 &&                              \
    (((mbuf)->m_flags & M_RDONLY) == 0) &&                             \
    (((mbuf)->m_flags & M_EXT) == 0 ||                                \
    (mbuf)->m_ext.ext_count == 1))
#define M_TRAILINGSPACE(mbuf) \
    (M_WRITABLE(mbuf) ? M_TRAILINGROOM(mbuf) : 0)
#define MGETHDR(result, how, type)                                       \
    ((result) = m_getjcl((how), (type), M_PKTHDR, MHLEN))
#define MGET(result, how, type)                                          \
    ((result) = m_get((how), (type)))
#define MCLGET(mbuf, how) m_clget((mbuf), (how))
#define M_MOVE_PKTHDR(destination, source) do {                          \
    (destination)->m_pkthdr = (source)->m_pkthdr;                        \
    (destination)->m_flags |= (source)->m_flags & M_PKTHDR;              \
    (source)->m_flags &= ~M_PKTHDR;                                      \
} while (0)

#endif
