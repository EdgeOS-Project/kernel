/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared FreeBSD network gateway. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/net/bpf.h"
#include "compat/freebsd/net/ethernet.h"
#include "compat/freebsd/net/if_media.h"
#include "compat/freebsd/net/if_types.h"
#include "compat/freebsd/net/if_var.h"
#include "compat/freebsd/net/pfil.h"
#include "compat/freebsd/netinet/in.h"
#include "compat/freebsd/netinet/in_var.h"
#include "compat/freebsd/netinet/sctp.h"
#include "compat/freebsd/netinet/ip6.h"
#include "compat/freebsd/netinet/ip.h"
#include "compat/freebsd/netinet/tcp.h"
#include "compat/freebsd/netinet/tcp_lro.h"
#include "compat/freebsd/netinet6/ip6_var.h"
#include "compat/freebsd/machine/in_cksum.h"
#include "compat/freebsd/sys/counter.h"
#include "compat/freebsd/sys/mbuf.h"
#include "compat/freebsd/sys/sockio.h"
#include "compat/freebsd/vm/uma.h"
#ifdef BSD_BRIDGE_HOST_TEST
typedef unsigned int u_int;
typedef uint64_t u_int64_t;
#define _KERNEL 1
#endif
#include <net/netisr.h>
#include "net/netdev.h"

_Static_assert(M_HASHTYPE_OPAQUE_HASH ==
    (M_HASHTYPE_HASHPROP | M_HASHTYPE_OPAQUE),
    "opaque hash type must preserve FreeBSD receive metadata");
_Static_assert(IFM_SUBTYPE(IFM_ETHER | IFM_2500_T) == IFM_2500_T,
    "extended Ethernet media types must preserve 2.5 GbE");
_Static_assert(IFM_SUBTYPE(IFM_ETHER | IFM_5000_T) == IFM_5000_T,
    "extended Ethernet media types must preserve 5 GbE");
_Static_assert(IFM_SUBTYPE(IFM_ETHER | IFM_10G_KR) == IFM_10G_KR,
    "extended Ethernet media types must preserve 10 GbE backplane");
_Static_assert(IFM_SUBTYPE(IFM_ETHER | IFM_10_FL) == IFM_10_FL,
    "legacy Ethernet media types must preserve 10BaseFL");
_Static_assert(sizeof(struct ifdrv) ==
    IFNAMSIZ + sizeof(unsigned long) + sizeof(size_t) + sizeof(void *),
    "driver-specific interface control layout must match FreeBSD");
_Static_assert(sizeof(struct ifrsskey) == 148,
    "RSS key request layout must match FreeBSD");
_Static_assert(sizeof(struct ifrsshash) == 24,
    "RSS hash request layout must match FreeBSD");
_Static_assert(RSS_KEYLEN == 128,
    "RSS key capacity must match FreeBSD");
_Static_assert(RSS_FUNC_TOEPLITZ == 2,
    "RSS Toeplitz identifier must match FreeBSD");
_Static_assert(sizeof(struct sctphdr) == 12,
    "SCTP packet header must match the wire ABI");
_Static_assert(CSUM_SCTP_IPV6 == CSUM_IP6_SCTP,
    "SCTP IPv6 checksum alias must match FreeBSD");
_Static_assert(CSUM_COALESCED == 0x40000000u,
    "receive coalescing checksum metadata must match FreeBSD");
_Static_assert(CSUM_DELAY_DATA == (CSUM_TCP | CSUM_UDP),
    "deferred IPv4 transport checksums must match FreeBSD");
_Static_assert(CSUM_DELAY_DATA_IPV6 == (CSUM_TCP_IPV6 | CSUM_UDP_IPV6),
    "deferred IPv6 transport checksums must match FreeBSD");
_Static_assert(sizeof(((struct pkthdr *)0)->PH_per) == 8,
    "persistent packet metadata must preserve FreeBSD storage width");
_Static_assert(sizeof(((struct pkthdr *)0)->PH_loc) == 8,
    "local packet metadata must preserve FreeBSD storage width");

#define TEST_PAGE_SIZE 4096u

struct test_ipv4_wire {
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

struct test_tcp_wire {
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

typedef struct test_state {
    int init_count;
    int transmit_count;
    int receive_count;
    int bind_count;
    int unbind_count;
    edge_netdev_handle_t bound_handle;
    uint8_t transmitted[64];
    uint32_t transmitted_length;
    uint8_t received[64];
    uint32_t received_length;
    uint8_t tapped[64];
    uint32_t tapped_length;
    int tap_count;
    int tap_direction;
    int route_notification_count;
    int route_notification_mask;
    int ipv4_configuration_count;
    uint32_t ipv4_address;
    uint32_t ipv4_netmask;
    uint32_t ipv4_gateway;
    int raw_output_count;
    int raw_output_family;
} test_state_t;

static test_state_t g_state;
static int g_external_free_count;
static int g_netisr_handler_count;

static void
test_external_free(struct mbuf *mbuf)
{
    assert(mbuf->m_ext.ext_arg1 == &g_external_free_count);
    assert(mbuf->m_ext.ext_arg2 == (void *)(uintptr_t)7);
    g_external_free_count++;
}

int
lwip_stack_bind_netdev(edge_netdev_handle_t handle)
{
    assert(handle != 0);
    g_state.bound_handle = handle;
    g_state.bind_count++;
    return 0;
}

int
lwip_stack_unbind_netdev(edge_netdev_handle_t handle)
{
    assert(handle == g_state.bound_handle);
    g_state.bound_handle = 0;
    g_state.unbind_count++;
    return 0;
}

edge_netdev_handle_t
lwip_stack_get_netdev(void)
{
    return g_state.bound_handle;
}

int
lwip_stack_configure_ipv4(uint32_t address, uint32_t netmask,
    uint32_t gateway)
{
    g_state.ipv4_configuration_count++;
    g_state.ipv4_address = address;
    g_state.ipv4_netmask = netmask;
    g_state.ipv4_gateway = gateway;
    return 0;
}

void
rt_ifmsg(struct ifnet *interface, int flags_mask)
{
    assert(interface != 0);
    g_state.route_notification_count++;
    g_state.route_notification_mask = flags_mask;
}

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)page_count * TEST_PAGE_SIZE) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static void
test_init(void *context)
{
    if_t ifp = context;

    g_state.init_count++;
    assert(if_setdrvflagbits(ifp, IFF_DRV_RUNNING, 0) == 0);
}

static int
test_transmit(if_t ifp, struct mbuf *mbuf)
{
    unsigned int length = m_length(mbuf, 0);

    assert(ifp != 0);
    assert(length <= sizeof(g_state.transmitted));
    m_copydata(mbuf, 0, (int)length, (char *)g_state.transmitted);
    g_state.transmitted_length = length;
    g_state.transmit_count++;
    m_freem(mbuf);
    return 0;
}

static int
test_raw_output(if_t ifp, struct mbuf *mbuf,
    const struct sockaddr *destination, struct route *route)
{
    unsigned int length = m_length(mbuf, 0);

    (void)route;
    assert(ifp != 0);
    assert(destination != 0);
    assert(length <= sizeof(g_state.transmitted));
    m_copydata(mbuf, 0, (int)length, (char *)g_state.transmitted);
    g_state.transmitted_length = length;
    g_state.raw_output_family = destination->sa_family;
    g_state.raw_output_count++;
    m_freem(mbuf);
    return 0;
}

static void
test_netisr_handler(struct mbuf *mbuf)
{
    assert(mbuf != 0);
    g_netisr_handler_count++;
    m_freem(mbuf);
}

static void
test_receive(const uint8_t *frame, uint32_t length, void *context)
{
    test_state_t *state = context;

    assert(length <= sizeof(state->received));
    memcpy(state->received, frame, length);
    state->received_length = length;
    state->receive_count++;
}

static int
test_media_change(if_t ifp)
{
    return ifp ? 0 : 22;
}

static void
test_media_status(if_t ifp, struct ifmediareq *request)
{
    assert(ifp != 0);
    request->ifm_status = IFM_AVALID | IFM_ACTIVE;
}

static void
test_bpf_receive(void *context, const void *prefix, uint32_t prefix_length,
    const struct mbuf *mbuf, int direction)
{
    test_state_t *state = context;
    const struct mbuf *cursor;
    unsigned int packet_length = 0;

    for (cursor = mbuf; cursor; cursor = cursor->m_next)
        packet_length += (unsigned int)cursor->m_len;

    assert(prefix_length + packet_length <= sizeof(state->tapped));
    if (prefix_length)
        memcpy(state->tapped, prefix, prefix_length);
    m_copydata(mbuf, 0, (int)packet_length,
        (char *)state->tapped + prefix_length);
    state->tapped_length = prefix_length + packet_length;
    state->tap_direction = direction;
    state->tap_count++;
}

static void
test_mbuf(void)
{
    uma_zone_t cluster_zone;
    void *cluster;
    struct mbuf *raw;
    struct mbuf *first;
    struct mbuf *second;
    struct mbuf *flat;
    struct mbuf *copy_mbuf;
    struct mbuf *range_copy;
    struct mbuf *header_copy;
    struct mbuf *appended;
    struct mbuf *vlan;
    struct mbuf *device_packet;
    struct mbuf *external;
    struct mbuf *sized;
    struct mbuf *chain;
    struct ifnet *receive_interface =
        (struct ifnet *)(uintptr_t)0x1234;
    char external_data[16] = "external";
    uint8_t copy[12];

    assert(m_gettype(MCLBYTES) == EXT_CLUSTER);
    assert(m_gettype(MJUMPAGESIZE) == EXT_JUMBOP);
    assert(m_gettype(MJUM9BYTES) == EXT_JUMBO9);
    assert(m_gettype(MJUM16BYTES) == EXT_JUMBO16);
    assert(m_gettype(MJUM16BYTES + 1) == 0);
    sized = m_get2(MCLBYTES + 1, M_NOWAIT, MT_DATA, M_PKTHDR);
    assert(sized != 0);
    assert(sized->m_ext.ext_size == MJUMPAGESIZE);
    m_freem(sized);
    assert(m_get2(MJUMPAGESIZE + 1, M_NOWAIT, MT_DATA, M_PKTHDR) == 0);
    sized = m_get3(MJUMPAGESIZE + 1, M_NOWAIT, MT_DATA, M_PKTHDR);
    assert(sized != 0);
    assert(sized->m_ext.ext_size == MJUM9BYTES);
    m_freem(sized);
    sized = m_get3(MJUM9BYTES + 1, M_NOWAIT, MT_DATA, M_PKTHDR);
    assert(sized != 0);
    assert(sized->m_ext.ext_size == MJUM16BYTES);
    m_freem(sized);
    assert(m_get3(MJUM16BYTES + 1, M_NOWAIT, MT_DATA, M_PKTHDR) == 0);
    chain = m_getm(0, MJUM16BYTES + MCLBYTES, M_NOWAIT, MT_DATA);
    assert(chain != 0);
    assert((chain->m_flags & M_PKTHDR) != 0);
    assert(chain->m_ext.ext_size == MJUM16BYTES);
    assert(chain->m_next != 0);
    assert((chain->m_next->m_flags & M_PKTHDR) == 0);
    assert(chain->m_next->m_ext.ext_size == MCLBYTES);
    m_freem(chain);
    cluster_zone = m_getzone(MCLBYTES);
    assert(cluster_zone != 0);
    cluster = uma_zalloc(cluster_zone, M_NOWAIT);
    raw = m_gethdr_raw(M_NOWAIT, MT_DATA);
    assert(cluster != 0 && raw != 0);
    m_init(raw, M_NOWAIT, MT_DATA, M_PKTHDR);
    m_cljset(raw, cluster, EXT_CLUSTER);
    assert(raw->m_data == cluster);
    assert(raw->m_ext.ext_size == MCLBYTES);
    memcpy(raw->m_data, "raw", 3);
    raw->m_len = 3;
    raw->m_pkthdr.len = 3;
    m_free_raw(raw);

    first = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    second = m_getjcl(M_NOWAIT, MT_DATA, 0, MCLBYTES);
    assert(first != 0 && second != 0);
    memcpy(first->m_data, "abcd", 4);
    memcpy(second->m_data, "efgh", 4);
    first->m_len = 4;
    second->m_len = 4;
    first->m_next = second;
    first->m_pkthdr.len = 8;
    {
        int offset = -1;

        assert(m_getptr(first, 0, &offset) == first && offset == 0);
        assert(m_getptr(first, 3, &offset) == first && offset == 3);
        assert(m_getptr(first, 4, &offset) == second && offset == 0);
        assert(m_getptr(first, 8, &offset) == second && offset == 4);
        assert(m_getptr(first, 9, &offset) == 0);
        assert(m_getptr(first, -1, &offset) == 0);
        assert(m_getptr(first, 0, 0) == 0);
    }
    assert(m_length(first, 0) == 8);
    m_copydata(first, 0, 8, (char *)copy);
    assert(memcmp(copy, "abcdefgh", 8) == 0);
    range_copy = m_copym(first, 2, 5, M_NOWAIT);
    assert(range_copy != 0);
    assert((range_copy->m_flags & M_PKTHDR) == 0);
    assert(m_length(range_copy, 0) == 5);
    memset(copy, 0, sizeof(copy));
    m_copydata(range_copy, 0, 5, (char *)copy);
    assert(memcmp(copy, "cdefg", 5) == 0);
    m_freem(range_copy);
    range_copy = m_copym(first, 0, M_COPYALL, M_NOWAIT);
    assert(range_copy != 0);
    assert((range_copy->m_flags & M_PKTHDR) != 0);
    assert(range_copy->m_pkthdr.len == 8);
    assert(m_length(range_copy, 0) == 8);
    memset(copy, 0, sizeof(copy));
    m_copydata(range_copy, 0, 8, (char *)copy);
    assert(memcmp(copy, "abcdefgh", 8) == 0);
    m_freem(range_copy);
    {
        struct m_tag *source_tag;
        struct m_tag *old_destination_tag;
        struct m_tag *copied_tag;

        first->m_flags |= M_BCAST | M_VLANTAG | M_PROTO3;
        first->m_pkthdr.flowid = 0x12345678u;
        first->m_pkthdr.csum_flags = CSUM_IP_TCP | CSUM_L4_VALID;
        source_tag = m_tag_alloc(0x4567u, 23, 4, M_NOWAIT);
        assert(source_tag != 0);
        memcpy(source_tag + 1, "tag1", 4);
        m_tag_prepend(first, source_tag);

        header_copy = m_getjcl(
            M_NOWAIT, MT_DATA, M_PKTHDR | M_MCAST, MCLBYTES);
        assert(header_copy != 0);
        old_destination_tag = m_tag_alloc(0x1111u, 9, 3, M_NOWAIT);
        assert(old_destination_tag != 0);
        memcpy(old_destination_tag + 1, "old", 3);
        m_tag_prepend(header_copy, old_destination_tag);

        assert(m_dup_pkthdr(header_copy, first, M_NOWAIT) == 1);
        assert((header_copy->m_flags & M_EXT) != 0);
        assert((header_copy->m_flags & M_BCAST) != 0);
        assert((header_copy->m_flags & M_MCAST) == 0);
        assert((header_copy->m_flags & M_VLANTAG) != 0);
        assert((header_copy->m_flags & M_PROTO3) != 0);
        assert(header_copy->m_pkthdr.flowid == 0x12345678u);
        assert(header_copy->m_pkthdr.csum_flags ==
            (CSUM_IP_TCP | CSUM_L4_VALID));
        copied_tag = m_tag_locate(
            header_copy, 0x4567u, 23, 0);
        assert(copied_tag != 0 && copied_tag != source_tag);
        assert(memcmp(copied_tag + 1, "tag1", 4) == 0);
        memcpy(source_tag + 1, "new1", 4);
        assert(memcmp(copied_tag + 1, "tag1", 4) == 0);
        m_freem(header_copy);
    }
    m_adj(first, 2);
    assert(m_length(first, 0) == 6);
    flat = m_defrag(first, M_NOWAIT);
    assert(flat != 0 && flat->m_next == 0 && flat->m_len == 6);
    assert(memcmp(flat->m_data, "cdefgh", 6) == 0);
    copy_mbuf = m_dup(flat, M_NOWAIT);
    assert(copy_mbuf != 0 && copy_mbuf->m_len == 6);
    assert(memcmp(copy_mbuf->m_data, "cdefgh", 6) == 0);
    assert(m_append(copy_mbuf, 4, "ijkl") == 1);
    assert(copy_mbuf->m_pkthdr.len == 10);
    memset(copy, 0, sizeof(copy));
    m_copydata(copy_mbuf, 0, 10, (char *)copy);
    assert(memcmp(copy, "cdefghijkl", 10) == 0);
    m_freem(copy_mbuf);
    m_freem(flat);

    appended = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, 4);
    assert(appended != 0);
    assert(m_append(appended, 8, "12345678") == 1);
    assert(appended->m_next != 0);
    assert(appended->m_pkthdr.len == 8);
    appended = m_pullup(appended, 8);
    assert(appended != 0 && appended->m_next == 0);
    assert(appended->m_len == 8);
    assert(memcmp(appended->m_data, "12345678", 8) == 0);
    m_freem(appended);

    first = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, 32);
    second = m_getjcl(M_NOWAIT, MT_DATA, 0, 32);
    assert(first != 0 && second != 0);
    memcpy(first->m_data, "left", 4);
    memcpy(second->m_data, "right", 5);
    first->m_len = 4;
    second->m_len = 5;
    first->m_pkthdr.len = 4;
    m_cat(first, second);
    assert(first->m_next == 0);
    assert(first->m_len == 9);
    assert(first->m_pkthdr.len == 4);
    assert(memcmp(first->m_data, "leftright", 9) == 0);
    m_freem(first);

    first = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR | M_RDONLY, 32);
    second = m_getjcl(M_NOWAIT, MT_DATA, 0, 32);
    assert(first != 0 && second != 0);
    first->m_len = 1;
    second->m_len = 1;
    m_cat(first, second);
    assert(first->m_next == second);
    m_freem(first);

    first = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    second = m_getjcl(M_NOWAIT, MT_DATA, 0, MCLBYTES);
    assert(first != 0 && second != 0);
    memcpy(first->m_data, "left", 4);
    memcpy(second->m_data, "right", 5);
    first->m_len = 4;
    second->m_len = 5;
    first->m_pkthdr.len = 9;
    first->m_next = second;
    flat = m_collapse(first, M_NOWAIT, 1);
    assert(flat != 0 && flat->m_next == 0);
    assert(flat->m_len == 9);
    assert(memcmp(flat->m_data, "leftright", 9) == 0);
    m_freem(flat);

    vlan = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    assert(vlan != 0);
    memset(vlan->m_data, 0, ETHER_HDR_LEN);
    vlan->m_data[12] = 0x08;
    vlan->m_data[13] = 0x00;
    vlan->m_len = ETHER_HDR_LEN;
    vlan->m_pkthdr.len = ETHER_HDR_LEN;
    vlan = ether_vlanencap(vlan, 7);
    assert(vlan != 0);
    assert(vlan->m_len == ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN);
    assert((uint8_t)vlan->m_data[12] == 0x81);
    assert((uint8_t)vlan->m_data[13] == 0x00);
    assert((uint8_t)vlan->m_data[15] == 7);
    m_freem(vlan);

    device_packet = m_devget("device-data", 11, 2, receive_interface, 0);
    assert(device_packet != 0);
    assert((device_packet->m_flags & M_PKTHDR) != 0);
    assert(device_packet->m_pkthdr.len == 11);
    assert(device_packet->m_pkthdr.rcvif == receive_interface);
    memset(copy, 0, sizeof(copy));
    m_copydata(device_packet, 0, 11, (char *)copy);
    assert(memcmp(copy, "device-data", 11) == 0);
    m_freem(device_packet);

    MGET(external, M_NOWAIT, MT_DATA);
    assert(external != 0);
    assert(external->m_pktdat == external->m_data);
    external->m_data += 8;
    assert(external->m_data != external->m_pktdat);
    external->m_data = external->m_pktdat;
    m_extadd(external, external_data, sizeof(external_data),
        test_external_free, &g_external_free_count,
        (void *)(uintptr_t)7, M_RDONLY, EXT_NET_DRV);
    assert(external->m_data == external_data);
    assert(external->m_ext.ext_buf == external_data);
    assert(external->m_ext.ext_size == sizeof(external_data));
    assert(external->m_ext.ext_type == EXT_NET_DRV);
    assert(!M_WRITABLE(external));
    assert(m_clget(external, M_NOWAIT) == 1);
    assert(g_external_free_count == 1);
    assert(external->m_ext.ext_buf == external->m_data);
    assert(external->m_ext.ext_size == MCLBYTES);
    assert(external->m_ext.ext_type == EXT_CLUSTER);
    assert(external->m_ext.ext_free == 0);
    assert(M_WRITABLE(external));
    m_freem(external);
    assert(g_external_free_count == 1);
    assert(m_clget(0, M_NOWAIT) == 0);

    assert(ether_crc32_le((const uint8_t *)"123456789", 9) ==
        UINT32_C(0x340bc6d9));
}

static void
test_uma(void)
{
    uma_zone_t zone;
    void *first;
    void *second;

    zone = uma_zcreate("test", 32, 0, 0, 0, 0, UMA_ALIGN_PTR,
        UMA_ZONE_ZINIT);
    assert(zone != 0);
    uma_zone_reserve(zone, 1);
    first = uma_zalloc(zone, M_NOWAIT);
    assert(first != 0);
    for (size_t index = 0; index < 32; ++index)
        assert(((uint8_t *)first)[index] == 0);
    second = uma_zalloc(zone, M_NOWAIT);
    assert(second == 0);
    assert(uma_zone_get_cur(zone) == 1);
    uma_zfree(zone, first);
    assert(uma_zone_get_cur(zone) == 0);
    uma_zdestroy(zone);
}

static void
test_counter(void)
{
    counter_u64_t counter = counter_u64_alloc(M_NOWAIT);

    assert(counter != 0);
    assert(counter_u64_fetch(counter) == 0);
    counter_u64_add(counter, 8);
    counter_u64_add(counter, -3);
    counter_enter();
    counter_u64_add_protected(counter, 4);
    counter_exit();
    assert(counter_u64_fetch(counter) == 9);
    counter_u64_add(counter, -4);
    assert(counter_u64_fetch(counter) == 5);
    counter_u64_zero(counter);
    assert(counter_u64_fetch(counter) == 0);
    counter_u64_free(counter);
}

static void
test_buffer_ring(void)
{
    struct buf_ring *ring;
    struct mbuf *packets[4];
    int values[4] = {1, 2, 3, 4};

    assert(buf_ring_alloc(1, M_DEVBUF, M_NOWAIT, 0) == 0);
    assert(buf_ring_alloc(3, M_DEVBUF, M_NOWAIT, 0) == 0);
    ring = buf_ring_alloc(4, M_DEVBUF, M_NOWAIT, 0);
    assert(ring != 0);
    assert(buf_ring_empty(ring));
    assert(buf_ring_count(ring) == 0);
    assert(buf_ring_enqueue(ring, &values[0]) == 0);
    assert(buf_ring_enqueue(ring, &values[1]) == 0);
    assert(buf_ring_enqueue(ring, &values[2]) == 0);
    assert(buf_ring_count(ring) == 3);
    assert(buf_ring_enqueue(ring, &values[3]) == ENOBUFS);
    assert(ring->br_drops == 1);
    assert(buf_ring_peek_clear_sc(ring) == &values[0]);
    buf_ring_putback_sc(ring, &values[3]);
    assert(buf_ring_peek_clear_sc(ring) == &values[3]);
    buf_ring_advance_sc(ring);
    assert(buf_ring_dequeue_sc(ring) == &values[1]);
    assert(buf_ring_dequeue_sc(ring) == &values[2]);
    assert(buf_ring_dequeue_sc(ring) == 0);
    assert(buf_ring_empty(ring));
    buf_ring_free(ring, M_DEVBUF);

    ring = buf_ring_alloc(4, M_DEVBUF, M_NOWAIT, 0);
    assert(ring != 0);
    assert(!drbr_needs_enqueue(0, ring));
    for (size_t index = 0; index < 4; ++index) {
        packets[index] = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR,
            MCLBYTES);
        assert(packets[index] != 0);
    }
    assert(drbr_enqueue(0, ring, packets[0]) == 0);
    assert(drbr_needs_enqueue(0, ring));
    assert(drbr_enqueue(0, ring, packets[1]) == 0);
    assert(drbr_enqueue(0, ring, packets[2]) == 0);
    assert(drbr_inuse(0, ring) == 3);
    assert(drbr_enqueue(0, ring, packets[3]) == ENOBUFS);
    {
        struct mbuf *packet = drbr_dequeue(0, ring);

        assert(packet == packets[0]);
        m_freem(packet);
    }
    {
        struct mbuf *packet = drbr_peek(0, ring);

        assert(packet == packets[1]);
        drbr_putback(0, ring, packet);
        drbr_advance(0, ring);
        m_freem(packet);
    }
    {
        struct mbuf *packet = drbr_dequeue(0, ring);

        assert(packet == packets[2]);
        m_freem(packet);
    }
    assert(drbr_empty(0, ring));
    assert(!drbr_needs_enqueue(0, ring));
    assert(drbr_inuse(0, ring) == 0);
    buf_ring_free(ring, M_DEVBUF);

    ring = buf_ring_alloc(4, M_DEVBUF, M_NOWAIT, 0);
    assert(ring != 0);
    for (size_t index = 0; index < 3; ++index) {
        packets[index] = m_getjcl(
            M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
        assert(packets[index] != 0);
        assert(drbr_enqueue(0, ring, packets[index]) == 0);
    }
    drbr_flush(0, ring);
    assert(drbr_empty(0, ring));
    assert(drbr_inuse(0, ring) == 0);
    drbr_free(ring, M_DEVBUF);

    ring = buf_ring_alloc(4, M_DEVBUF, M_NOWAIT, 0);
    assert(ring != 0);
    packets[0] = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    assert(packets[0] != 0);
    assert(drbr_enqueue(0, ring, packets[0]) == 0);
    drbr_free(ring, M_DEVBUF);
}

static void
test_ipv6_header_walk(void)
{
    struct mbuf *packet;
    struct ip6_hdr *ip6;
    struct ip6_ext *extension;
    struct ip6_frag *fragment;
    int next_protocol;

    packet = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    assert(packet != 0);
    memset(packet->m_data, 0, 64);
    packet->m_len = 40;
    packet->m_pkthdr.len = 40;
    ip6 = (struct ip6_hdr *)packet->m_data;
    ip6->ip6_nxt = IPPROTO_TCP;
    assert(ip6_nexthdr(packet, 0, IPPROTO_IPV6, &next_protocol) == 40);
    assert(next_protocol == IPPROTO_TCP);
    assert(ip6_lasthdr(packet, 0, IPPROTO_IPV6, &next_protocol) == 40);
    assert(next_protocol == IPPROTO_TCP);

    ip6->ip6_nxt = IPPROTO_HOPOPTS;
    extension = (struct ip6_ext *)(packet->m_data + 40);
    extension->ip6e_nxt = IPPROTO_TCP;
    extension->ip6e_len = 0;
    packet->m_len = 48;
    packet->m_pkthdr.len = 48;
    assert(ip6_lasthdr(packet, 0, IPPROTO_IPV6, &next_protocol) == 48);
    assert(next_protocol == IPPROTO_TCP);

    ip6->ip6_nxt = IPPROTO_FRAGMENT;
    fragment = (struct ip6_frag *)(packet->m_data + 40);
    memset(fragment, 0, sizeof(*fragment));
    fragment->ip6f_nxt = IPPROTO_UDP;
    assert(ip6_lasthdr(packet, 0, IPPROTO_IPV6, &next_protocol) == 48);
    assert(next_protocol == IPPROTO_UDP);
    fragment->ip6f_offlg = IP6F_OFF_MASK;
    assert(ip6_nexthdr(packet, 40, IPPROTO_FRAGMENT,
        &next_protocol) == -1);
    assert(ip6_lasthdr(packet, 0, IPPROTO_IPV6, &next_protocol) == 40);

    packet->m_len = 44;
    packet->m_pkthdr.len = 44;
    assert(ip6_nexthdr(packet, 40, IPPROTO_FRAGMENT,
        &next_protocol) == -1);
    m_freem(packet);
}

static struct mbuf *
test_lro_packet(uint32_t sequence, uint32_t acknowledgment,
    const char payload[4], struct ifnet *interface)
{
    struct mbuf *mbuf =
        m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    struct test_ipv4_wire *ip;
    struct test_tcp_wire *tcp;
    uint8_t *frame;

    assert(mbuf != 0);
    frame = (uint8_t *)mbuf->m_data;
    memset(frame, 0, 62);
    frame[12] = 0x08;
    frame[13] = 0x00;
    ip = (struct test_ipv4_wire *)(frame + ETHER_HDR_LEN);
    ip->version_header_length = 0x45;
    ip->total_length = htons(44);
    ip->time_to_live = 64;
    ip->protocol = IPPROTO_TCP;
    ip->source[0] = 10;
    ip->source[3] = 1;
    ip->destination[0] = 10;
    ip->destination[3] = 2;
    tcp = (struct test_tcp_wire *)(frame + ETHER_HDR_LEN + sizeof(*ip));
    tcp->source_port = htons(1234);
    tcp->destination_port = htons(4321);
    tcp->sequence = htonl(sequence);
    tcp->acknowledgment = htonl(acknowledgment);
    tcp->data_offset_reserved = 5u << 4;
    tcp->flags = TH_ACK;
    tcp->window = htons(32768);
    memcpy(frame + ETHER_HDR_LEN + sizeof(*ip) + sizeof(*tcp),
        payload, 4);
    mbuf->m_len = ETHER_HDR_LEN + sizeof(*ip) + sizeof(*tcp) + 4;
    mbuf->m_pkthdr.len = mbuf->m_len;
    mbuf->m_pkthdr.rcvif = interface;
    mbuf->m_pkthdr.csum_flags =
        CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
    mbuf->m_pkthdr.csum_data = UINT16_MAX;
    return mbuf;
}

static void
test_lro(if_t ifp)
{
    struct lro_ctrl control;
    struct mbuf *first;
    struct mbuf *second;
    uint32_t receive_count = (uint32_t)g_state.receive_count;
    const struct test_ipv4_wire *ip;
    const struct test_tcp_wire *tcp;

    assert(tcp_lro_init(&control) == 0);
    control.ifp = ifp;
    first = test_lro_packet(1000, 2000, "abcd", ifp);
    second = test_lro_packet(1004, 2004, "efgh", ifp);
    assert(tcp_lro_rx(&control, first, 0) == 0);
    assert(tcp_lro_rx(&control, second, 0) == 0);
    assert(g_state.receive_count == (int)receive_count);
    assert(control.lro_queued == 2);
    tcp_lro_flush_all(&control);
    assert(g_state.receive_count == (int)receive_count + 1);
    assert(g_state.received_length == 62);
    ip = (const struct test_ipv4_wire *)(
        g_state.received + ETHER_HDR_LEN);
    tcp = (const struct test_tcp_wire *)(
        (const uint8_t *)ip + sizeof(*ip));
    assert(ntohs(ip->total_length) == 48);
    assert(ntohl(tcp->sequence) == 1000);
    assert(ntohl(tcp->acknowledgment) == 2004);
    assert(memcmp((const uint8_t *)tcp + sizeof(*tcp),
        "abcdefgh", 8) == 0);
    assert(control.lro_flushed == 1);
    tcp_lro_free(&control);
}

static void
test_ipv6_pseudo_checksum(void)
{
    struct ip6_hdr header = {0};

    assert(in6_cksum_pseudo(&header, 0, IPPROTO_TCP, 0) == 0x0600);
    assert(in6_cksum_pseudo(&header, 0, IPPROTO_UDP, 0) == 0x1100);
    assert(in6_cksum_pseudo(0, 0, IPPROTO_TCP, 0) == 0);
}

static uint64_t
test_if_counter(if_t ifp, ift_counter counter)
{
    assert(ifp != 0);
    return 1000u + (uint64_t)counter;
}

static void
test_ifnet(void)
{
    if_t ifp;
    device_t first_device = (device_t)(uintptr_t)0x10;
    device_t second_device = (device_t)(uintptr_t)0x20;
    struct mbuf *received;
    struct mbuf *batch[4];
    struct ifmedia media;
    struct ifreq request = {0};
    struct pfil_head_args pfil_arguments = {
        .pa_version = PFIL_VERSION,
        .pa_type = PFIL_TYPE_ETHERNET,
        .pa_headname = "vtnet0",
    };
    pfil_head_t pfil;
    struct mbuf *filtered;
    struct ether_addr generated_address;
    struct ether_addr named_address;
    struct ether_addr repeated_named_address;
    struct bpf_listener *listener;
    struct mbuf *tapped;
    uint8_t mac[ETHER_ADDR_LEN] = {0x52, 0x54, 0, 0x12, 0x34, 0x56};
    uint8_t frame[] = {1, 2, 3, 4, 5, 6};
    uint8_t vlan_frame[] = {
        0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11,
        0x08, 0x00, 0xaa, 0xbb,
    };
    const uint8_t expected_vlan_frame[] = {
        0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11,
        0x81, 0x00, 0x00, 0x07,
        0x08, 0x00, 0xaa, 0xbb,
    };
    int link_up;

    ifp = if_alloc_dev(IFT_ETHER, first_device);
    assert(ifp != 0);
    assert(ifp->if_device == first_device);
    if_setdev(ifp, second_device);
    assert(ifp->if_device == second_device);
    assert(!if_vlantrunkinuse(ifp));
    assert(if_getvlantrunk(ifp) == 0);
    ifp->if_vlantrunk = (struct ifvlantrunk *)(uintptr_t)0x30;
    assert(if_vlantrunkinuse(ifp));
    assert(if_getvlantrunk(ifp) == ifp->if_vlantrunk);
    ifp->if_vlantrunk = 0;
    if_initname(ifp, "vtnet", 0);
    assert(strcmp(if_name(ifp), "vtnet0") == 0);
    assert(if_getdunit(ifp) == 0);
    assert(if_getdunit(NULL) == IF_DUNIT_NONE);
    assert(if_getbaudrate(ifp) == 0);
    assert(if_setbaudrate(ifp, IF_Gbps(10)) == 0);
    assert(if_getbaudrate(ifp) == IF_Gbps(10));
    assert(if_setbaudrate(ifp, IF_Gbps(1)) == IF_Gbps(10));
    assert(if_getbaudrate(ifp) == IF_Gbps(1));
    assert(if_getbaudrate(NULL) == 0);
    assert(if_setsoftc(ifp, ifp) == 0);
    if_setinitfn(ifp, test_init);
    if_settransmitfn(ifp, test_transmit);
    assert(if_setflags(ifp, IFF_BROADCAST | IFF_SIMPLEX |
        IFF_MULTICAST) == 0);
    received = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    assert(received != 0);
    assert(if_sendq_prepend(ifp, received) == 0);
    if_up(ifp);
    assert((if_getflags(ifp) & IFF_UP) != 0);
    assert(g_state.route_notification_count == 1);
    assert(g_state.route_notification_mask == IFF_UP);
    if_down(ifp);
    assert((if_getflags(ifp) & IFF_UP) == 0);
    assert(if_sendq_empty(ifp));
    assert(g_state.route_notification_count == 2);
    assert(g_state.route_notification_mask == IFF_UP);
    assert(if_setcapabilitiesbit(ifp, IFCAP_RXCSUM | IFCAP_LRO |
        IFCAP_JUMBO_MTU | IFCAP_LINKSTATE, 0) == 0);
    assert((if_getcapabilities(ifp) &
        (IFCAP_RXCSUM | IFCAP_LRO)) == 0);
    assert((if_getcapabilities(ifp) &
        (IFCAP_JUMBO_MTU | IFCAP_LINKSTATE)) ==
        (IFCAP_JUMBO_MTU | IFCAP_LINKSTATE));
    assert(if_setcapenable(ifp, IFCAP_JUMBO_MTU | IFCAP_LINKSTATE) == 0);
    assert(if_getcapenable(ifp) ==
        (IFCAP_JUMBO_MTU | IFCAP_LINKSTATE));
    if_inc_counter(ifp, IFCOUNTER_OERRORS, 7);
    if_inc_counter(ifp, IFCOUNTER_OERRORS, -2);
    assert(if_getcounter(ifp, IFCOUNTER_OERRORS) == 5);
    if_setgetcounterfn(ifp, test_if_counter);
    assert(if_getcounter(ifp, IFCOUNTER_OERRORS) ==
        1000u + IFCOUNTER_OERRORS);
    if_setgetcounterfn(ifp, if_get_counter_default);
    IFNET_WLOCK();
    IFNET_WUNLOCK();

    ether_ifattach(ifp, mac);
    assert(ifp->if_attached == 1);
    assert(if_llmaddr_count(ifp) == 0);
    ether_gen_addr(ifp, &generated_address);
    assert((generated_address.octet[0] & 0x01u) == 0);
    assert((generated_address.octet[0] & 0x02u) != 0);
    ether_gen_addr_byname("rge0", &named_address);
    ether_gen_addr_byname("rge0", &repeated_named_address);
    assert(memcmp(&named_address, &repeated_named_address,
        sizeof(named_address)) == 0);
    assert((named_address.octet[0] & 0x01u) == 0);
    assert((named_address.octet[0] & 0x02u) != 0);
    assert(ifmedia_baudrate(IFM_ETHER | IFM_10_FL) == IF_Mbps(10));
    assert(ifmedia_baudrate(IFM_ETHER | IFM_100_T2) == IF_Mbps(100));
    assert(ifmedia_baudrate(IFM_ETHER | IFM_5000_T) ==
        IF_Mbps(5000));
    assert(ifmedia_baudrate(IFM_ETHER | IFM_1000_KX) ==
        IF_Gbps(1));
    assert(ifmedia_baudrate(IFM_ETHER | IFM_10G_TWINAX) ==
        IF_Gbps(10));
    assert(ifmedia_baudrate(IFM_ETHER | IFM_25G_KR) ==
        IF_Gbps(25));
    assert(ifmedia_baudrate(IFM_ETHER | IFM_40G_KR4) ==
        IF_Gbps(40));
    assert(ifmedia_baudrate(IFM_ETHER | IFM_50G_SR2) ==
        IF_Gbps(50));
    assert(ifmedia_baudrate(IFM_ETHER | IFM_100G_SR4) ==
        IF_Gbps(100));
    assert(ifmedia_baudrate(IFM_ETHER | IFM_200G_DR4) ==
        IF_Gbps(200));
    assert(ifp->if_bridge_handle != 0);
    assert(g_state.bound_handle == 0);
    assert(g_state.bind_count == 0);
    assert(edge_netdev_count() == 1);
    assert(edge_netdev_get_info(ifp->if_bridge_handle, 0, 0, 0, 0,
        &link_up, 0) == 0);
    assert(link_up == 1);
    assert(lwip_stack_bind_netdev(ifp->if_bridge_handle) == 0);
    assert(g_state.bound_handle == ifp->if_bridge_handle);
    assert(g_state.bind_count == 1);
    assert(edge_netdev_set_receive_callback(ifp->if_bridge_handle,
        test_receive, &g_state) == 0);
    if_link_state_change(ifp, LINK_STATE_DOWN);
    assert(edge_netdev_transmit(ifp->if_bridge_handle, frame,
        sizeof(frame)) == -2);
    if_link_state_change(ifp, LINK_STATE_UP);
    assert(edge_netdev_set_up(ifp->if_bridge_handle, 1) == 0);
    assert(g_state.init_count == 1);
    assert(edge_netdev_transmit(ifp->if_bridge_handle, frame,
        sizeof(frame)) == 0);
    assert(g_state.transmit_count == 1);
    assert(g_state.transmitted_length == sizeof(frame));
    assert(memcmp(g_state.transmitted, frame, sizeof(frame)) == 0);

    received = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    assert(received != 0);
    memcpy(received->m_data, frame, sizeof(frame));
    received->m_len = sizeof(frame);
    received->m_pkthdr.len = sizeof(frame);
    if_input(ifp, received);
    assert(g_state.receive_count == 1);
    assert(g_state.received_length == sizeof(frame));
    assert(memcmp(g_state.received, frame, sizeof(frame)) == 0);

    for (size_t index = 0; index < sizeof(batch) / sizeof(batch[0]);
        ++index) {
        batch[index] = m_getjcl(
            M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
        assert(batch[index] != 0);
        memcpy(batch[index]->m_data, frame, sizeof(frame));
        batch[index]->m_data[0] = (char)(10u + index);
        batch[index]->m_len = sizeof(frame);
        batch[index]->m_pkthdr.len = sizeof(frame);
        if (index != 0)
            batch[index - 1u]->m_nextpkt = batch[index];
    }
    if_input(ifp, batch[0]);
    assert(g_state.receive_count == 5);
    assert(g_state.received_length == sizeof(frame));
    assert(g_state.received[0] == 13);
    test_lro(ifp);

    bpfattach(ifp, 1, ETHER_HDR_LEN);
    assert(ifp->if_bpf != 0);
    listener = bsd_bpf_listener_attach(
        ifp->if_bpf, test_bpf_receive, &g_state);
    assert(listener != 0);
    tapped = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    assert(tapped != 0);
    memcpy(tapped->m_data, vlan_frame, sizeof(vlan_frame));
    tapped->m_len = sizeof(vlan_frame);
    tapped->m_pkthdr.len = sizeof(vlan_frame);
    tapped->m_pkthdr.ether_vtag = 7;
    tapped->m_flags |= M_VLANTAG;
    ether_bpf_mtap_if(ifp, tapped);
    assert(g_state.tap_count == 1);
    assert(g_state.tap_direction == BPF_D_OUT);
    assert(g_state.tapped_length == sizeof(expected_vlan_frame));
    assert(memcmp(g_state.tapped, expected_vlan_frame,
        sizeof(expected_vlan_frame)) == 0);
    assert(tapped->m_len == sizeof(vlan_frame));
    assert(memcmp(tapped->m_data, vlan_frame, sizeof(vlan_frame)) == 0);
    m_freem(tapped);
    bsd_bpf_listener_detach(listener);
    bpfdetach(ifp);

    ifmedia_init(&media, 0, test_media_change, test_media_status);
    ifmedia_add(&media, IFM_ETHER | IFM_AUTO, 0, 0);
    ifmedia_set(&media, IFM_ETHER | IFM_AUTO);
    request.ifr_media = IFM_ETHER | IFM_AUTO;
    assert(ifmedia_ioctl(ifp, &request, &media, SIOCSIFMEDIA) == 0);
    ifmedia_removeall(&media);

    pfil = pfil_head_register(&pfil_arguments);
    assert(pfil != 0);
    filtered = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    assert(filtered != 0);
    filtered->m_len = 1;
    assert(pfil_mbuf_in(pfil, &filtered, ifp, 0) == 0);
    m_freem(filtered);
    filtered = (struct mbuf *)(uintptr_t)1;
    assert(pfil_mem_in(pfil, frame, sizeof(frame), ifp,
        &filtered) == PFIL_PASS);
    assert(filtered == 0);
    assert(pfil_mem_in(pfil, frame, 0, ifp,
        &filtered) == PFIL_DROPPED);
    pfil_head_unregister(pfil);

    ether_ifdetach(ifp);
    assert(ifp->if_attached == 0);
    assert(g_state.bound_handle == 0);
    assert(g_state.unbind_count == 1);
    assert(edge_netdev_count() == 0);
    if_free(ifp);
}

static void
test_raw_ifnet_and_netisr(void)
{
    static const struct netisr_handler handler = {
        .nh_name = "edgeos-test",
        .nh_handler = test_netisr_handler,
        .nh_proto = NETISR_ROUTE,
        .nh_qlimit = 8,
        .nh_policy = NETISR_POLICY_FLOW,
        .nh_dispatch = NETISR_DISPATCH_DEFERRED,
    };
    if_t ifp;
    struct in_aliasreq alias = {0};
    struct ifreq request = {0};
    struct mbuf *packet;
    uint8_t ethernet_frame[ETHER_HDR_LEN + 20] = {0};
    uint8_t ipv4_packet[20] = {0x45};
    unsigned int queue_limit = 0;
    uint64_t queue_drops = UINT64_MAX;
    char address_buffer[INET6_ADDRSTRLEN];

    ifp = if_alloc(IFT_MBIM);
    assert(ifp != 0);
    if_initname(ifp, "umb", 0);
    if_setoutputfn(ifp, test_raw_output);
    if_attach(ifp);
    assert(ifp->if_attached == 1);
    assert(ifp->if_bridge_handle != 0);
    assert(edge_netdev_set_receive_callback(ifp->if_bridge_handle,
        test_receive, &g_state) == 0);
    assert(edge_netdev_set_up(ifp->if_bridge_handle, 1) == 0);

    ethernet_frame[12] = 0x08;
    ethernet_frame[13] = 0x00;
    memcpy(ethernet_frame + ETHER_HDR_LEN, ipv4_packet,
        sizeof(ipv4_packet));
    assert(edge_netdev_transmit(ifp->if_bridge_handle, ethernet_frame,
        sizeof(ethernet_frame)) == 0);
    assert(g_state.raw_output_count == 1);
    assert(g_state.raw_output_family == AF_INET);
    assert(g_state.transmitted_length == sizeof(ipv4_packet));
    assert(memcmp(g_state.transmitted, ipv4_packet,
        sizeof(ipv4_packet)) == 0);

    packet = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    assert(packet != 0);
    memcpy(packet->m_data, ipv4_packet, sizeof(ipv4_packet));
    packet->m_len = sizeof(ipv4_packet);
    packet->m_pkthdr.len = sizeof(ipv4_packet);
    packet->m_pkthdr.rcvif = ifp;
    assert(netisr_dispatch(NETISR_IP, packet) == 0);
    assert(g_state.received_length == ETHER_HDR_LEN + sizeof(ipv4_packet));
    assert(g_state.received[12] == 0x08 && g_state.received[13] == 0x00);
    assert(memcmp(g_state.received + ETHER_HDR_LEN, ipv4_packet,
        sizeof(ipv4_packet)) == 0);

    alias.ifra_addr.sin_family = AF_INET;
    alias.ifra_addr.sin_addr.s_addr = UINT32_C(0x01020304);
    alias.ifra_mask.sin_addr.s_addr = UINT32_C(0x00ffffff);
    alias.ifra_dstaddr.sin_addr.s_addr = UINT32_C(0x01020301);
    assert(in_control(0, SIOCAIFADDR, (char *)&alias, ifp, 0) == 0);
    assert(g_state.ipv4_configuration_count == 1);
    assert(g_state.ipv4_address == alias.ifra_addr.sin_addr.s_addr);
    assert(g_state.ipv4_netmask == alias.ifra_mask.sin_addr.s_addr);
    assert(g_state.ipv4_gateway == alias.ifra_dstaddr.sin_addr.s_addr);
    assert(in_control(0, SIOCGIFADDR, (char *)&request, ifp, 0) == 0);
    assert(((struct sockaddr_in *)&request.ifr_addr)->sin_addr.s_addr ==
        alias.ifra_addr.sin_addr.s_addr);
    assert(inet_ntop(AF_INET, &alias.ifra_addr.sin_addr,
        address_buffer, sizeof(address_buffer)) == address_buffer);
    assert(strcmp(address_buffer, "4.3.2.1") == 0);

    netisr_register(&handler);
    netisr_getqlimit(&handler, &queue_limit);
    assert(queue_limit == handler.nh_qlimit);
    netisr_getqdrops(&handler, &queue_drops);
    assert(queue_drops == 0);
    assert(netisr_get_cpucount() >= 1);
    assert(netisr_get_cpuid(0) == 0);
    assert(netisr_default_flow2cpu(123) < netisr_get_cpucount());
    packet = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    assert(packet != 0);
    packet->m_len = 1;
    packet->m_pkthdr.len = 1;
    assert(netisr_dispatch(NETISR_ROUTE, packet) == 0);
    assert(g_netisr_handler_count == 1);
    netisr_unregister(&handler);

    assert(in_control(0, SIOCDIFADDR, (char *)&request, ifp, 0) == 0);
    assert(g_state.ipv4_configuration_count == 2);
    assert(g_state.ipv4_address == 0);
    if_detach(ifp);
    if_free(ifp);
}

int
main(void)
{
    bsd_allocator_ops_t allocator_operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };

    assert(bsd_allocator_initialize(&allocator_operations) == 0);
    test_mbuf();
    test_counter();
    test_buffer_ring();
    test_ipv6_header_walk();
    test_ipv6_pseudo_checksum();
    test_uma();
    test_ifnet();
    test_raw_ifnet_and_netisr();
    return 0;
}
