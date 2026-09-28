/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared BSD bridge receive-side scaling runtime. */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "compat/freebsd/net/rss_config.h"
#include "compat/freebsd/sys/mbuf.h"

int mp_ncpus = 1;

int
main(void)
{
    static const uint8_t expected_key[RSS_KEYSIZE] = {
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    };
    static const uint8_t ipv4_addresses[] = {
        66, 9, 149, 187, 161, 142, 100, 80,
    };
    struct mbuf packet = {0};
    uint8_t key[RSS_KEYSIZE] = {0};
    uint32_t bucket = UINT32_MAX;
    u_int cpu_id = UINT32_MAX;

    rss_getkey(key);
    assert(memcmp(key, expected_key, sizeof(key)) == 0);
    assert(rss_gethashalgo() == RSS_HASH_TOEPLITZ);
    assert((rss_gethashconfig() & RSS_HASHTYPE_RSS_TCP_IPV4) != 0);
    assert((rss_gethashconfig() & RSS_HASHTYPE_RSS_UDP_IPV4) == 0);
    assert(rss_hash(sizeof(ipv4_addresses), ipv4_addresses) ==
        UINT32_C(0x323e8fc2));

    assert(rss_getnumcpus() == 1);
    assert(rss_getnumbuckets() == 1);
    assert(rss_getbits() == 0);
    assert(rss_getbucket(UINT32_MAX) == 0);
    assert(rss_get_indirection_to_bucket(127) == 0);
    assert(rss_getcpu(0) == 0);

    mp_ncpus = 3;
    assert(rss_getnumcpus() == 3);
    assert(rss_getnumbuckets() == 4);
    assert(rss_getbits() == 2);
    assert(rss_getbucket(7) == 3);
    assert(rss_get_indirection_to_bucket(6) == 2);
    assert(rss_getcpu(3) == 0);
    assert(rss_hash2bucket(7, M_HASHTYPE_RSS_TCP_IPV4,
        &bucket) == 0);
    assert(bucket == 3);
    assert(rss_hash2bucket(7, M_HASHTYPE_NONE, &bucket) == -1);
    assert(rss_hash2bucket(7, M_HASHTYPE_RSS_IPV4, 0) == -1);
    assert(rss_hash2cpuid(7, M_HASHTYPE_RSS_TCP_IPV4) == 0);
    assert(rss_hash2cpuid(7, M_HASHTYPE_NONE) == UINT32_MAX);

    packet.m_pkthdr.flowid = 6;
    M_HASHTYPE_SET(&packet, M_HASHTYPE_RSS_IPV6);
    assert(rss_m2bucket(&packet, &bucket) == 0);
    assert(bucket == 2);
    assert(rss_m2cpuid(&packet, 0, &cpu_id) == &packet);
    assert(cpu_id == 2);
    return 0;
}
