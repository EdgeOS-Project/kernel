/* SPDX-License-Identifier: MPL-2.0 */
/* Shared receive-side scaling interface for BSD network drivers. */

#ifndef _NET_RSS_CONFIG_H_
#define _NET_RSS_CONFIG_H_

#include <stdint.h>

typedef unsigned int u_int;

#define RSS_HASH_NAIVE 0x00000001u
#define RSS_HASH_TOEPLITZ 0x00000002u
#define RSS_HASH_CRC32 0x00000004u
#define RSS_HASH_MASK (RSS_HASH_NAIVE | RSS_HASH_TOEPLITZ)

#define RSS_HASHFIELDS_NONE 0
#define RSS_HASHFIELDS_4TUPLE 1
#define RSS_HASHFIELDS_2TUPLE 2

#define RSS_HASHTYPE_RSS_IPV4 (1u << 1)
#define RSS_HASHTYPE_RSS_TCP_IPV4 (1u << 2)
#define RSS_HASHTYPE_RSS_IPV6 (1u << 3)
#define RSS_HASHTYPE_RSS_TCP_IPV6 (1u << 4)
#define RSS_HASHTYPE_RSS_IPV6_EX (1u << 5)
#define RSS_HASHTYPE_RSS_TCP_IPV6_EX (1u << 6)
#define RSS_HASHTYPE_RSS_UDP_IPV4 (1u << 7)
#define RSS_HASHTYPE_RSS_UDP_IPV6 (1u << 9)
#define RSS_HASHTYPE_RSS_UDP_IPV6_EX (1u << 10)

#define RSS_MAXBITS 7
#define RSS_TABLE_MAXLEN (1u << RSS_MAXBITS)
#define RSS_KEYSIZE 40

#define RSS_HASH_PKT_INGRESS 0
#define RSS_HASH_PKT_EGRESS 1

struct mbuf;

extern int rss_debug;

u_int rss_getbits(void);
u_int rss_getbucket(u_int hash);
u_int rss_get_indirection_to_bucket(u_int index);
u_int rss_getcpu(u_int bucket);
u_int rss_getnumbuckets(void);
u_int rss_getnumcpus(void);
struct mbuf *rss_m2cpuid(struct mbuf *mbuf, uintptr_t source,
    u_int *cpu_id);
u_int rss_hash2cpuid(uint32_t hash_value, uint32_t hash_type);
int rss_hash2bucket(uint32_t hash_value, uint32_t hash_type,
    uint32_t *bucket_id);
int rss_m2bucket(struct mbuf *mbuf, uint32_t *bucket_id);
void rss_getkey(uint8_t *key);
u_int rss_gethashalgo(void);
u_int rss_gethashconfig(void);
uint32_t rss_hash(u_int data_length, const uint8_t *data);

#endif
