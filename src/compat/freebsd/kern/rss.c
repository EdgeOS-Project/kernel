/* SPDX-License-Identifier: MPL-2.0 */
/* Shared receive-side scaling runtime for BSD network drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/net/rss_config.h"
#include "compat/freebsd/sys/mbuf.h"
#include "compat/freebsd/sys/smp.h"

int rss_debug;

/*
 * This is the default key from the RSS specification. Keeping a stable key
 * ensures that software and every attached network device use identical
 * packet-to-queue mappings.
 */
static const uint8_t g_rss_key[RSS_KEYSIZE] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

static u_int
rss_cpu_count(void)
{
    u_int count = mp_ncpus > 0 ? (u_int)mp_ncpus : 1u;

    return count > RSS_TABLE_MAXLEN ? RSS_TABLE_MAXLEN : count;
}

static u_int
rss_bucket_count(void)
{
    u_int cpu_count = rss_cpu_count();
    u_int buckets = 1;

    if (cpu_count == 1)
        return 1;
    while (buckets < cpu_count && buckets < RSS_TABLE_MAXLEN)
        buckets <<= 1;
    return buckets;
}

static int
rss_hash_type_supported(uint32_t hash_type)
{
    switch (hash_type) {
    case M_HASHTYPE_RSS_IPV4:
    case M_HASHTYPE_RSS_TCP_IPV4:
    case M_HASHTYPE_RSS_UDP_IPV4:
    case M_HASHTYPE_RSS_IPV6:
    case M_HASHTYPE_RSS_TCP_IPV6:
    case M_HASHTYPE_RSS_UDP_IPV6:
    case M_HASHTYPE_RSS_IPV6_EX:
    case M_HASHTYPE_RSS_TCP_IPV6_EX:
    case M_HASHTYPE_RSS_UDP_IPV6_EX:
        return 1;
    default:
        return 0;
    }
}

void
rss_getkey(uint8_t *key)
{
    if (!key)
        return;
    for (u_int index = 0; index < RSS_KEYSIZE; ++index)
        key[index] = g_rss_key[index];
}

u_int
rss_gethashalgo(void)
{
    return RSS_HASH_TOEPLITZ;
}

u_int
rss_gethashconfig(void)
{
    return RSS_HASHTYPE_RSS_IPV4 |
        RSS_HASHTYPE_RSS_TCP_IPV4 |
        RSS_HASHTYPE_RSS_IPV6 |
        RSS_HASHTYPE_RSS_TCP_IPV6 |
        RSS_HASHTYPE_RSS_IPV6_EX |
        RSS_HASHTYPE_RSS_TCP_IPV6_EX;
}

u_int
rss_getbits(void)
{
    u_int buckets = rss_bucket_count();
    u_int bits = 0;

    while ((1u << bits) < buckets)
        bits++;
    return bits;
}

u_int
rss_getbucket(u_int hash)
{
    return hash & (rss_bucket_count() - 1u);
}

u_int
rss_get_indirection_to_bucket(u_int index)
{
    return index & (rss_bucket_count() - 1u);
}

u_int
rss_getcpu(u_int bucket)
{
    return bucket % rss_cpu_count();
}

u_int
rss_getnumbuckets(void)
{
    return rss_bucket_count();
}

u_int
rss_getnumcpus(void)
{
    return rss_cpu_count();
}

u_int
rss_hash2cpuid(uint32_t hash_value, uint32_t hash_type)
{
    if (!rss_hash_type_supported(hash_type))
        return UINT32_MAX;
    return rss_getcpu(rss_getbucket(hash_value));
}

int
rss_hash2bucket(uint32_t hash_value, uint32_t hash_type,
    uint32_t *bucket_id)
{
    if (!bucket_id || !rss_hash_type_supported(hash_type))
        return -1;
    *bucket_id = rss_getbucket(hash_value);
    return 0;
}

struct mbuf *
rss_m2cpuid(struct mbuf *mbuf, uintptr_t source, u_int *cpu_id)
{
    (void)source;
    if (!mbuf || !cpu_id)
        return mbuf;
    *cpu_id = rss_hash2cpuid(mbuf->m_pkthdr.flowid,
        M_HASHTYPE_GET(mbuf));
    return mbuf;
}

int
rss_m2bucket(struct mbuf *mbuf, uint32_t *bucket_id)
{
    if (!mbuf)
        return -1;
    return rss_hash2bucket(mbuf->m_pkthdr.flowid,
        M_HASHTYPE_GET(mbuf), bucket_id);
}

uint32_t
rss_hash(u_int data_length, const uint8_t *data)
{
    uint32_t hash = 0;
    uint32_t window;

    if (!data || data_length == 0)
        return 0;
    window = ((uint32_t)g_rss_key[0] << 24) |
        ((uint32_t)g_rss_key[1] << 16) |
        ((uint32_t)g_rss_key[2] << 8) |
        (uint32_t)g_rss_key[3];
    for (u_int index = 0; index < data_length; ++index) {
        for (u_int bit = 0; bit < 8; ++bit) {
            if (data[index] & (1u << (7u - bit)))
                hash ^= window;
            window <<= 1;
            if (index + 4u < RSS_KEYSIZE &&
                (g_rss_key[index + 4u] & (1u << (7u - bit))))
                window |= 1;
        }
    }
    return hash;
}
