#include "net/lwip_stack.h"

#include "kernel/linux_netlink.h"
#include "kernel/linux_packet.h"
#include "kernel/smp.h"
#include "net/netdev.h"
#include "net/network_core.h"
#ifdef CONFIG_NFSD
#include "fs/nfsd.h"
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/kthread.h"
#endif
#include "sys/boottime.h"
#include "sys/spinlock.h"
#include "string.h"
#include "stdio.h"
#include "vfs/vfs.h"

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/timeouts.h"
#include "lwip/netif.h"
#include "lwip/raw.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/nd6.h"
#include "lwip/priv/nd6_priv.h"
#include "lwip/prot/icmp.h"
#include "lwip/prot/icmp6.h"
#include "lwip/prot/ip6.h"
#include "lwip/dns.h"
#include "lwip/stats.h"
#include "netif/ethernet.h"

#include <stdint.h>

err_t edge_lwip_etharp_add_static_entry(
    struct netif *netif, const ip4_addr_t *ipaddr,
    struct eth_addr *ethaddr);
err_t edge_lwip_etharp_remove_static_entry(
    struct netif *netif, const ip4_addr_t *ipaddr);

typedef struct __attribute__((packed)) {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len_be;
    uint16_t id_be;
    uint16_t frag_be;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum_be;
    uint32_t src_be;
    uint32_t dst_be;
} edge_ipv4_hdr_t;

typedef struct {
    uint8_t used;
    uint16_t id_be;
    uint32_t src_ip_be;
    uint32_t ip_len;
    uint8_t ip_pkt[1600];
} edge_icmp_reply_t;

typedef struct {
    uint8_t used;
    uint16_t id_be;
    uint8_t src_ip6[16];
    uint32_t pkt_len;
    uint8_t pkt[1600];
} edge_icmp6_reply_t;

typedef struct {
    uint8_t used;
    uint32_t len;
    uint8_t data[1600];
} edge_packet_frame_t;

#define EDGE_ICMP_REPLY_Q 16
#define EDGE_ICMP6_REPLY_Q 16
#define EDGE_ICMP_RAW_Q 32
#define EDGE_PACKET_FRAME_Q 32
#define EDGE_LWIP_VIRTUAL_NETIF_MAX 32u
#define EDGE_LWIP_STATIC_NEIGHBOR_MAX 64u
#define EDGE_LWIP_DEFERRED_FRAME_MAX 128u
#define EDGE_LWIP_BRIDGE_AGE_INTERVAL_NS 1000000000ull
#define EDGE_LWIP_BRIDGE_FDB_MAX_AGE_NS 300000000000ull
#define EDGE_LWIP_BRIDGE_MDB_MAX_AGE_NS 260000000000ull

typedef struct edge_lwip_virtual_netif {
    uint8_t used;
    uint8_t ipv4_active;
    int32_t ifindex;
    uint32_t network_namespace;
    uint8_t ipv6_prefix_lengths[LWIP_IPV6_NUM_ADDRESSES];
    ip6_addr_t ipv6_route_gateway;
    struct netif netif;
} edge_lwip_virtual_netif_t;

typedef struct edge_lwip_static_neighbor {
    uint8_t used;
    uint32_t network_namespace;
    int32_t ifindex;
    uint32_t address;
    uint8_t hardware_address[6];
    uint16_t state;
    uint8_t flags;
} edge_lwip_static_neighbor_t;

typedef struct edge_lwip_deferred_frame {
    volatile uint8_t state;
    int32_t ifindex;
    uint32_t network_namespace;
    uint16_t length;
    uint8_t data[1600];
} edge_lwip_deferred_frame_t;

static struct netif g_lwip_netif;
static edge_lwip_virtual_netif_t
    g_lwip_virtual_netifs[EDGE_LWIP_VIRTUAL_NETIF_MAX];
static edge_lwip_static_neighbor_t
    g_lwip_static_neighbors[EDGE_LWIP_STATIC_NEIGHBOR_MAX];
static edge_lwip_deferred_frame_t
    g_lwip_deferred_frames[EDGE_LWIP_DEFERRED_FRAME_MAX];
static struct raw_pcb *g_icmp_raw;
static struct raw_pcb *g_icmp6_raw;
static int g_core_ready;
static int g_ready;
static uint64_t g_rx_packets;
static uint64_t g_rx_bytes;
static volatile uint32_t g_poll_active;
static spinlock_t g_lwip_core_lock;
static volatile uint32_t g_lwip_core_owner = UINT32_MAX;
static uint32_t g_lwip_core_depth[EDGE_SMP_MAX_CPUS];
static uint64_t g_lwip_core_flags[EDGE_SMP_MAX_CPUS];

void lwip_stack_core_enter(void)
{
    uint32_t cpu = edge_smp_current_cpu();
    uint64_t flags;

    if (cpu >= EDGE_SMP_MAX_CPUS) cpu = 0u;
    if (__atomic_load_n(&g_lwip_core_owner, __ATOMIC_ACQUIRE) == cpu) {
        ++g_lwip_core_depth[cpu];
        return;
    }
    flags = spin_lock_irqsave(&g_lwip_core_lock);
    g_lwip_core_flags[cpu] = flags;
    g_lwip_core_depth[cpu] = 1u;
    __atomic_store_n(&g_lwip_core_owner, cpu, __ATOMIC_RELEASE);
}

void lwip_stack_core_exit(void)
{
    uint32_t cpu = edge_smp_current_cpu();
    uint64_t flags;

    if (cpu >= EDGE_SMP_MAX_CPUS) cpu = 0u;
    if (__atomic_load_n(&g_lwip_core_owner, __ATOMIC_ACQUIRE) != cpu ||
        !g_lwip_core_depth[cpu])
        return;
    if (--g_lwip_core_depth[cpu]) return;
    flags = g_lwip_core_flags[cpu];
    __atomic_store_n(&g_lwip_core_owner, UINT32_MAX, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&g_lwip_core_lock, flags);
}
static uint64_t g_bridge_last_age_ns;
static uint32_t g_lwip_ingress_namespace;
static uint8_t g_lwip_ingress_active;
static uint8_t g_lwip_deferred_draining;
static uint64_t g_tx_packets;
static uint64_t g_tx_bytes;
static uint32_t g_tcp_rx_fin_counter;
static uint32_t g_tcp_rx_fin_local_ip_be;
static uint32_t g_tcp_rx_fin_remote_ip_be;
static uint16_t g_tcp_rx_fin_local_port;
static uint16_t g_tcp_rx_fin_remote_port;
static edge_icmp_reply_t g_reply_q[EDGE_ICMP_REPLY_Q];
static edge_icmp_reply_t g_raw_icmp_q[EDGE_ICMP_RAW_Q];
static edge_icmp6_reply_t g_reply6_q[EDGE_ICMP6_REPLY_Q];
static edge_packet_frame_t g_packet_q[EDGE_PACKET_FRAME_Q];
static uint64_t g_packet_frame_readiness_sequence = 1u;
static uint64_t g_icmp_readiness_sequence = 1u;
static uint8_t g_raw_ipv4_frame[1600];
static uint16_t g_raw_ipv4_id;
static char g_hostname[65] = "edgeos";
static edge_netdev_handle_t g_netdev_handle;
static uint8_t g_ipv6_prefix_lengths[LWIP_IPV6_NUM_ADDRESSES];
static uint8_t g_ipv6_disabled;
static uint8_t g_ipv6_forwarding;
static uint8_t g_ipv6_accept_ra = 1;
static uint8_t g_ipv6_autoconf = 1;
static uint8_t g_ipv6_all_disabled;
static uint8_t g_ipv6_all_forwarding;
static uint8_t g_ipv6_all_accept_ra = 1;
static uint8_t g_ipv6_all_autoconf = 1;
static uint8_t g_ipv6_default_disabled;
static uint8_t g_ipv6_default_forwarding;
static uint8_t g_ipv6_default_accept_ra = 1;
static uint8_t g_ipv6_default_autoconf = 1;
static uint8_t g_ipv6_loopback_disabled;
static uint8_t g_ipv6_loopback_forwarding;
static uint8_t g_ipv6_loopback_accept_ra = 1;
static uint8_t g_ipv6_loopback_autoconf = 1;
static ip6_addr_t g_ipv6_route_gateway;

static edge_lwip_virtual_netif_t *edge_lwip_virtual_find(int32_t ifindex);
static void edge_lwip_virtual_remove(edge_lwip_virtual_netif_t *entry);
static void edge_ipv6_provider_synchronize_links(void);
static int edge_lwip_netif_identity(
    const struct netif *netif, uint32_t *network_namespace,
    int32_t *ifindex);
static struct netif *edge_lwip_neighbor_netif(
    uint32_t network_namespace, int32_t ifindex);
static void edge_lwip_static_neighbors_remove_interface(
    uint32_t network_namespace, int32_t ifindex);
static void edge_lwip_deferred_drain(void);

static struct netif *edge_lwip_loopback_netif(void) {
#if LWIP_HAVE_LOOPIF
    struct netif *netif;

    NETIF_FOREACH(netif) {
        if (netif->name[0] == 'l' && netif->name[1] == 'o')
            return netif;
    }
#endif
    return 0;
}

struct netif *lwip_stack_select_socket_route(
    uint32_t network_namespace, uint8_t family,
    const uint8_t source[16], const uint8_t destination[16],
    uint32_t mark, int32_t bound_ifindex,
    uint8_t preferred_source[16], int32_t *selected_ifindex) {
    edge_linux_route_query_t query;
    edge_linux_route_result_t result;
    edge_net_device_snapshot_t snapshot;
    struct netif *netif;
    uint32_t address_length;

    if (!destination ||
        (family != EDGE_LINUX_AF_INET &&
         family != EDGE_LINUX_AF_INET6) ||
        bound_ifindex < 0)
        return 0;
    address_length = family == EDGE_LINUX_AF_INET ? 4u : 16u;
    memset(&query, 0, sizeof(query));
    query.network_namespace = network_namespace;
    query.family = family;
    query.mark = mark;
    query.output_ifindex = bound_ifindex;
    if (source)
        memcpy(query.source, source, address_length);
    memcpy(query.destination, destination, address_length);
    if (edge_linux_route_lookup(&query, &result) < 0 ||
        result.output_ifindex <= 0 ||
        (bound_ifindex > 0 &&
         result.output_ifindex != bound_ifindex))
        return 0;
    netif = edge_lwip_neighbor_netif(
        network_namespace, result.output_ifindex);
    if (!netif) return 0;
    if (preferred_source) {
        memset(preferred_source, 0, 16u);
        memcpy(preferred_source, result.preferred_source,
               address_length);
        if (family == EDGE_LINUX_AF_INET &&
            !preferred_source[0] && !preferred_source[1] &&
            !preferred_source[2] && !preferred_source[3] &&
            edge_net_device_snapshot(
                result.output_ifindex, &snapshot) == EDGE_NET_OK)
            memcpy(preferred_source, &snapshot.ipv4_address, 4u);
    }
    if (selected_ifindex)
        *selected_ifindex = result.output_ifindex;
    return netif;
}

/*
 * Readiness consumers reserve zero for unsupported sources.  A release CAS
 * publishes each completed queue write and preserves that invariant at wrap.
 */
static void edge_readiness_sequence_advance(uint64_t *sequence) {
    uint64_t current;

    current = __atomic_load_n(sequence, __ATOMIC_RELAXED);
    for (;;) {
        uint64_t next = current + 1u;

        if (!next) next = 1u;
        if (__atomic_compare_exchange_n(sequence, &current, next, 0,
                                        __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED))
            return;
    }
}

static int edge_is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int edge_valid_hostname_char(char c) {
    return ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_');
}

static int edge_read_text_file(const char *path, char *buf, int buf_sz) {
    int n;
    if (!path || !buf || buf_sz <= 1) return -1;
    n = vfs_read_file(path, buf, (uint32_t)(buf_sz - 1));
    if (n < 0) return -1;
    if (n >= buf_sz) n = buf_sz - 1;
    buf[n] = 0;
    return n;
}

static int edge_parse_hostname_token(const char *src, char *out, int out_sz) {
    int si = 0;
    int oi = 0;
    if (!src || !out || out_sz <= 1) return -1;
    while (src[si] && edge_is_space(src[si])) si++;
    while (src[si] && !edge_is_space(src[si]) && src[si] != '#') {
        char c = src[si++];
        if (!edge_valid_hostname_char(c)) continue;
        if (oi >= out_sz - 1) return -1;
        out[oi++] = c;
    }
    out[oi] = 0;
    return oi > 0 ? 0 : -1;
}

static void edge_apply_dns_servers_from_text(const char *text) {
#if LWIP_DNS
    ip_addr_t parsed[DNS_MAX_SERVERS];
    int parsed_count = 0;
    int i = 0;
    char line[160];
    int line_len = 0;

    memset(parsed, 0, sizeof(parsed));
    while (text && text[i]) {
        char c = text[i++];
        if (c == '\r') continue;
        if (c == '\n' || line_len >= (int)sizeof(line) - 1) {
            int p = 0;
            char token[80];
            int ti = 0;
            line[line_len] = 0;
            line_len = 0;

            while (line[p] && edge_is_space(line[p])) p++;
            if (line[p] == '#') continue;
            if (strncmp(&line[p], "nameserver", 10) != 0) continue;
            if (line[p + 10] && !edge_is_space(line[p + 10])) continue;
            p += 10;
            while (line[p] && edge_is_space(line[p])) p++;
            while (line[p] && !edge_is_space(line[p]) && line[p] != '#' && ti < (int)sizeof(token) - 1) {
                token[ti++] = line[p++];
            }
            token[ti] = 0;
            if (ti == 0) continue;
            if (parsed_count >= DNS_MAX_SERVERS) continue;
            if (ipaddr_aton(token, &parsed[parsed_count])) parsed_count++;
            continue;
        }
        line[line_len++] = c;
    }
    if (line_len > 0) {
        int p = 0;
        char token[80];
        int ti = 0;
        line[line_len] = 0;
        while (line[p] && edge_is_space(line[p])) p++;
        if (line[p] != '#' &&
            strncmp(&line[p], "nameserver", 10) == 0 &&
            (!line[p + 10] || edge_is_space(line[p + 10]))) {
            p += 10;
            while (line[p] && edge_is_space(line[p])) p++;
            while (line[p] && !edge_is_space(line[p]) && line[p] != '#' && ti < (int)sizeof(token) - 1) {
                token[ti++] = line[p++];
            }
            token[ti] = 0;
            if (ti > 0 && parsed_count < DNS_MAX_SERVERS && ipaddr_aton(token, &parsed[parsed_count])) {
                parsed_count++;
            }
        }
    }

    for (i = 0; i < DNS_MAX_SERVERS; ++i) {
        ip_addr_t zero_ip;
        ip_addr_set_zero(&zero_ip);
        dns_setserver((u8_t)i, i < parsed_count ? &parsed[i] : &zero_ip);
    }
#else
    (void)text;
#endif
}

static void edge_try_reload_dns_from_resolv_conf(void) {
    char buf[2048];
    int n = edge_read_text_file("/etc/resolv.conf", buf, sizeof(buf));
    if (n < 0) return;
    edge_apply_dns_servers_from_text(buf);
}

static void edge_try_reload_hostname_from_file(void) {
    char buf[192];
    char parsed[65];
    if (edge_read_text_file("/etc/hostname", buf, sizeof(buf)) < 0) return;
    if (edge_parse_hostname_token(buf, parsed, sizeof(parsed)) < 0) return;
    (void)lwip_stack_set_hostname(parsed);
}

static void edge_ip6_to_bytes(const ip6_addr_t *a, uint8_t out[16]) {
    if (!a || !out) return;
    for (int i = 0; i < 4; ++i) {
        uint32_t w = lwip_htonl(a->addr[i]);
        out[i * 4 + 0] = (uint8_t)((w >> 24) & 0xFFu);
        out[i * 4 + 1] = (uint8_t)((w >> 16) & 0xFFu);
        out[i * 4 + 2] = (uint8_t)((w >> 8) & 0xFFu);
        out[i * 4 + 3] = (uint8_t)(w & 0xFFu);
    }
}

static void edge_ip6_from_bytes(ip6_addr_t *address,
                                const uint8_t bytes[16]) {
    if (!address || !bytes) return;
    for (int index = 0; index < 4; ++index) {
        uint32_t word = ((uint32_t)bytes[index * 4] << 24) |
                        ((uint32_t)bytes[index * 4 + 1] << 16) |
                        ((uint32_t)bytes[index * 4 + 2] << 8) |
                        (uint32_t)bytes[index * 4 + 3];
        address->addr[index] = lwip_htonl(word);
    }
#if LWIP_IPV6_SCOPES
    address->zone = IP6_NO_ZONE;
#endif
}

static int edge_ipv6_provider_address_at(
    int ordinal, edge_linux_rtnetlink_ipv6_address_t *address) {
    uint8_t bytes[16];
    uint8_t prefix_length;
    uint8_t proc_scope;
    uint8_t flags;

    if (!address || lwip_stack_get_ipv6_addr_at(
            ordinal, bytes, &prefix_length, &proc_scope, &flags) < 0)
        return -1;
    memset(address, 0, sizeof(*address));
    memcpy(address->address, bytes, sizeof(address->address));
    address->prefix_length = prefix_length;
    address->scope = proc_scope == 0x10u ? 254u :
                     proc_scope == 0x20u ? 253u : 0u;
    address->flags = flags;
    for (u8_t index = 0; index < LWIP_IPV6_NUM_ADDRESSES; ++index) {
        const ip6_addr_t *candidate = netif_ip6_addr(&g_lwip_netif, index);
        uint8_t candidate_bytes[16];

        edge_ip6_to_bytes(candidate, candidate_bytes);
        if (memcmp(candidate_bytes, bytes, sizeof(candidate_bytes)) != 0)
            continue;
#if LWIP_IPV6_ADDRESS_LIFETIMES
        address->valid_lifetime = netif_ip6_addr_isstatic(
            &g_lwip_netif, index) ? UINT32_MAX :
            netif_ip6_addr_valid_life(&g_lwip_netif, index);
        address->preferred_lifetime = netif_ip6_addr_isstatic(
            &g_lwip_netif, index) ? UINT32_MAX :
            netif_ip6_addr_pref_life(&g_lwip_netif, index);
#else
        address->valid_lifetime = UINT32_MAX;
        address->preferred_lifetime = UINT32_MAX;
#endif
        break;
    }
    return 0;
}

static int edge_ipv6_provider_configure_address(
    uint32_t network_namespace, int32_t ifindex,
    const uint8_t address[16], uint8_t prefix_length,
    uint32_t flags, uint32_t valid_lifetime,
    uint32_t preferred_lifetime, int active) {
    return lwip_stack_configure_interface_ipv6(
        ifindex, network_namespace, address, prefix_length, flags,
        valid_lifetime, preferred_lifetime, active);
}

static void edge_ipv6_provider_remove_interface(
    uint32_t network_namespace, int32_t ifindex) {
    edge_lwip_virtual_netif_t *entry = edge_lwip_virtual_find(ifindex);

    if (entry && entry->network_namespace == network_namespace)
        edge_lwip_virtual_remove(entry);
}

static int edge_ipv6_provider_router_at(
    int ordinal, edge_linux_rtnetlink_ipv6_router_t *router) {
    if (!router) return -1;
    memset(router, 0, sizeof(*router));
    return lwip_stack_get_ipv6_router(
        ordinal, router->address, &router->lifetime, &router->preference);
}

static int edge_ipv6_provider_configure_router(
    const uint8_t address[16], int active) {
    return lwip_stack_configure_ipv6_default_router(address, active);
}

static int edge_ipv6_provider_neighbor_at(
    int ordinal, edge_linux_rtnetlink_ipv6_neighbor_t *neighbor) {
    if (!neighbor) return -1;
    memset(neighbor, 0, sizeof(*neighbor));
    return lwip_stack_get_ipv6_neighbor(
        ordinal, neighbor->address, neighbor->hardware_address,
        &neighbor->state, &neighbor->is_router);
}

static const edge_linux_rtnetlink_ipv6_provider_t g_ipv6_provider = {
    .address_at = edge_ipv6_provider_address_at,
    .configure_address = edge_ipv6_provider_configure_address,
    .synchronize_links = edge_ipv6_provider_synchronize_links,
    .remove_interface = edge_ipv6_provider_remove_interface,
    .router_at = edge_ipv6_provider_router_at,
    .configure_default_router = edge_ipv6_provider_configure_router,
    .neighbor_at = edge_ipv6_provider_neighbor_at,
};

static int edge_extract_icmp_probe_id(const uint8_t *icmp, uint16_t icmp_len, uint16_t *id_be_out) {
    uint8_t type;
    if (!icmp || icmp_len < 8 || !id_be_out) return 0;
    type = icmp[0];
    if (type == ICMP_ER) {
        memcpy(id_be_out, &icmp[4], sizeof(*id_be_out));
        return 1;
    }
    if (type == 3 || type == 11) {
        const uint8_t *inner_ip = icmp + 8;
        uint16_t inner_len = (uint16_t)(icmp_len - 8);
        uint16_t ihl;
        const uint8_t *inner_icmp;
        if (inner_len < 20) return 0;
        if ((inner_ip[0] >> 4) != 4) return 0;
        ihl = (uint16_t)((inner_ip[0] & 0x0Fu) * 4u);
        if (ihl < 20 || ihl + 8 > inner_len) return 0;
        if (inner_ip[9] != 1) return 0;
        inner_icmp = inner_ip + ihl;
        memcpy(id_be_out, &inner_icmp[4], sizeof(*id_be_out));
        return 1;
    }
    return 0;
}

static int edge_extract_icmp6_probe_id(const uint8_t *icmp6, uint16_t icmp6_len, uint16_t *id_be_out) {
    if (!icmp6 || icmp6_len < 8 || !id_be_out) return 0;

    if (icmp6[0] == ICMP6_TYPE_EREP) {
        memcpy(id_be_out, &icmp6[4], sizeof(*id_be_out));
        return 1;
    }

    if (icmp6[0] == ICMP6_TYPE_DUR || icmp6[0] == ICMP6_TYPE_TE || icmp6[0] == ICMP6_TYPE_PP) {
        const uint8_t *inner_ip6 = icmp6 + 8;
        uint16_t inner_len = (uint16_t)(icmp6_len - 8);
        uint8_t nexth;
        if (inner_len < 48) return 0;
        if ((inner_ip6[0] >> 4) != 6) return 0;
        nexth = inner_ip6[6];
        if (nexth != IP6_NEXTH_ICMP6) return 0;
        memcpy(id_be_out, inner_ip6 + 40 + 4, sizeof(*id_be_out));
        return 1;
    }

    return 0;
}

static uint32_t edge_cksum_accumulate(
    const void *data, uint32_t len, uint32_t accumulator) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t index;

    for (index = 0; index + 1u < len; index += 2u)
        accumulator += ((uint32_t)p[index] << 8u) | p[index + 1u];
    if (len & 1u) accumulator += (uint32_t)p[len - 1u] << 8u;
    return accumulator;
}

static uint16_t edge_cksum_finish(uint32_t accumulator) {
    while (accumulator >> 16u)
        accumulator = (accumulator & 0xffffu) + (accumulator >> 16u);
    return (uint16_t)~accumulator;
}

static uint16_t edge_cksum16(const void *data, uint32_t len) {
    return edge_cksum_finish(edge_cksum_accumulate(data, len, 0u));
}

static void edge_lwip_ipv4_checksums(
    uint8_t *ip, uint16_t available_length, int force_transport) {
    uint8_t pseudo_header[4];
    uint8_t *transport;
    uint16_t header_length;
    uint16_t packet_length;
    uint16_t transport_length;
    uint16_t checksum;
    uint16_t checksum_offset;
    uint32_t accumulator;

    if (!ip || available_length < sizeof(edge_ipv4_hdr_t) ||
        (ip[0] >> 4u) != 4u)
        return;
    header_length = (uint16_t)(ip[0] & 0x0fu) * 4u;
    packet_length = (uint16_t)(((uint16_t)ip[2] << 8u) | ip[3]);
    if (header_length < sizeof(edge_ipv4_hdr_t) ||
        packet_length < header_length ||
        packet_length > available_length)
        return;
    if (force_transport || (ip[10] == 0u && ip[11] == 0u)) {
        ip[10] = 0u;
        ip[11] = 0u;
        checksum = edge_cksum16(ip, header_length);
        ip[10] = (uint8_t)(checksum >> 8u);
        ip[11] = (uint8_t)checksum;
    }
    transport = ip + header_length;
    transport_length = (uint16_t)(packet_length - header_length);
    if ((((uint16_t)ip[6] << 8u) | ip[7]) & 0x1fffu) return;
    if (ip[9] == 1u) {
        if (transport_length < 4u ||
            (!force_transport && (transport[2] || transport[3])))
            return;
        transport[2] = 0u;
        transport[3] = 0u;
        checksum = edge_cksum16(transport, transport_length);
        transport[2] = (uint8_t)(checksum >> 8u);
        transport[3] = (uint8_t)checksum;
        return;
    }
    if (ip[9] == 6u) {
        if (transport_length < 20u ||
            (!force_transport && (transport[16] || transport[17])))
            return;
        checksum_offset = 16u;
    } else if (ip[9] == 17u) {
        if (transport_length < 8u ||
            (!force_transport && (transport[6] || transport[7])))
            return;
        checksum_offset = 6u;
    } else {
        return;
    }
    transport[checksum_offset] = 0u;
    transport[checksum_offset + 1u] = 0u;
    pseudo_header[0] = 0u;
    pseudo_header[1] = ip[9];
    pseudo_header[2] = (uint8_t)(transport_length >> 8u);
    pseudo_header[3] = (uint8_t)transport_length;
    accumulator = edge_cksum_accumulate(ip + 12u, 8u, 0u);
    accumulator = edge_cksum_accumulate(
        pseudo_header, sizeof(pseudo_header), accumulator);
    accumulator = edge_cksum_accumulate(
        transport, transport_length, accumulator);
    checksum = edge_cksum_finish(accumulator);
    if (ip[9] == 17u && checksum == 0u) checksum = 0xffffu;
    transport[checksum_offset] = (uint8_t)(checksum >> 8u);
    transport[checksum_offset + 1u] = (uint8_t)checksum;
}

static void edge_lwip_ipv6_transport_checksum(
    uint8_t *packet, uint16_t packet_length) {
    uint8_t pseudo_header[8];
    uint8_t *transport;
    uint16_t payload_length;
    uint16_t checksum_offset;
    uint16_t checksum;
    uint32_t accumulator;

    if (!packet || packet_length < 40u || (packet[0] >> 4u) != 6u)
        return;
    payload_length = (uint16_t)(((uint16_t)packet[4] << 8u) |
                                packet[5]);
    if (!payload_length)
        payload_length = (uint16_t)(packet_length - 40u);
    if (payload_length > packet_length - 40u) return;
    transport = packet + 40u;
    if (packet[6] == 6u) {
        if (payload_length < 20u) return;
        checksum_offset = 16u;
    } else if (packet[6] == 17u) {
        if (payload_length < 8u) return;
        checksum_offset = 6u;
    } else if (packet[6] == 58u) {
        if (payload_length < 4u) return;
        checksum_offset = 2u;
    } else {
        return;
    }
    transport[checksum_offset] = 0u;
    transport[checksum_offset + 1u] = 0u;
    memset(pseudo_header, 0, sizeof(pseudo_header));
    pseudo_header[2] = (uint8_t)(payload_length >> 8u);
    pseudo_header[3] = (uint8_t)payload_length;
    pseudo_header[7] = packet[6];
    accumulator = edge_cksum_accumulate(packet + 8u, 32u, 0u);
    accumulator = edge_cksum_accumulate(
        pseudo_header, sizeof(pseudo_header), accumulator);
    accumulator = edge_cksum_accumulate(
        transport, payload_length, accumulator);
    checksum = edge_cksum_finish(accumulator);
    if (!checksum) checksum = 0xffffu;
    transport[checksum_offset] = (uint8_t)(checksum >> 8u);
    transport[checksum_offset + 1u] = (uint8_t)checksum;
}

static void edge_lwip_complete_ipv4_checksums(
    uint8_t *frame, uint16_t frame_length) {
    if (!frame || frame_length < 14u + sizeof(edge_ipv4_hdr_t) ||
        frame[12] != 0x08u || frame[13] != 0x00u)
        return;
    edge_lwip_ipv4_checksums(frame + 14u,
                             (uint16_t)(frame_length - 14u), 0);
}

/*
 * Linux IP_HDRINCL still owns fields whose zero values request kernel fill-in.
 * Raw packet generators rely on this for the IPv4 checksum, source address,
 * packet ID, and total length.  Keeping the rule in the network backend makes
 * SOCK_RAW behavior identical for every architecture.
 */
static int edge_prepare_ipv4_hdrincl(uint8_t *packet, uint16_t len) {
    uint16_t header_length;
    uint16_t checksum;

    if (!packet || len < sizeof(edge_ipv4_hdr_t) ||
        (packet[0] >> 4) != 4u)
        return -1;
    header_length = (uint16_t)(packet[0] & 0x0fu) * 4u;
    if (header_length < sizeof(edge_ipv4_hdr_t) || header_length > len)
        return -1;

    packet[2] = (uint8_t)(len >> 8);
    packet[3] = (uint8_t)len;
    if (packet[4] == 0u && packet[5] == 0u) {
        if (++g_raw_ipv4_id == 0u) ++g_raw_ipv4_id;
        packet[4] = (uint8_t)(g_raw_ipv4_id >> 8);
        packet[5] = (uint8_t)g_raw_ipv4_id;
    }
    if (packet[12] == 0u && packet[13] == 0u &&
        packet[14] == 0u && packet[15] == 0u) {
        uint32_t source = packet[16] == 127u ?
            lwip_htonl(IPADDR_LOOPBACK) :
            ip4_addr_get_u32(netif_ip4_addr(&g_lwip_netif));
        memcpy(packet + 12u, &source, sizeof(source));
    }
    packet[10] = 0u;
    packet[11] = 0u;
    checksum = edge_cksum16(packet, header_length);
    packet[10] = (uint8_t)(checksum >> 8);
    packet[11] = (uint8_t)checksum;
    return 0;
}

u32_t sys_now(void) {
    return (u32_t)(boottime_monotonic_us() / 1000ull);
}

static uint16_t edge_get_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t edge_get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           p[3];
}

static int edge_lwip_ipv6_destination_is_local(
    const uint8_t address[16], uint32_t network_namespace) {
#if LWIP_IPV6
    ip6_addr_t destination;

    if (!address || address[0] == 0xffu ||
        (memcmp(address, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1",
                16u) == 0))
        return 1;
    edge_ip6_from_bytes(&destination, address);
    if (network_namespace == 0u) {
        for (u8_t index = 0; index < LWIP_IPV6_NUM_ADDRESSES; ++index) {
            if (ip6_addr_isvalid(
                    netif_ip6_addr_state(&g_lwip_netif, index)) &&
                ip6_addr_zoneless_eq(
                    netif_ip6_addr(&g_lwip_netif, index), &destination))
                return 1;
        }
    }
    for (uint32_t ordinal = 0;
         ordinal < EDGE_LWIP_VIRTUAL_NETIF_MAX; ++ordinal) {
        const edge_lwip_virtual_netif_t *entry =
            &g_lwip_virtual_netifs[ordinal];

        if (!entry->used ||
            entry->network_namespace != network_namespace)
            continue;
        for (u8_t index = 0; index < LWIP_IPV6_NUM_ADDRESSES;
             ++index) {
            if (ip6_addr_isvalid(
                    netif_ip6_addr_state(&entry->netif, index)) &&
                ip6_addr_zoneless_eq(
                    netif_ip6_addr(&entry->netif, index),
                    &destination))
                return 1;
        }
    }
#else
    (void)address;
    (void)network_namespace;
#endif
    return 0;
}

static int edge_lwip_ipv4_forward_input(
    struct pbuf *packet, struct netif *input_interface,
    uint32_t network_namespace, int32_t input_ifindex,
    const uint8_t *header, uint16_t packet_length) {
    edge_linux_netfilter_tuple_t tuple;
    edge_linux_route_query_t query;
    edge_linux_route_result_t route;
    edge_net_device_snapshot_t input_snapshot;
    edge_net_device_snapshot_t output_snapshot;
    struct netif *output_interface;
    struct netif *previous_input_interface;
    struct pbuf *forwarded;
    ip4_addr_t next_hop;
    uint8_t forwarded_packet[1600];
    uint16_t header_length;
    uint16_t transport_offset;
    int destination_translation;
    int source_translation;
    err_t result;

    if (!packet || !input_interface || !header || packet_length < 20u ||
        packet_length > sizeof(forwarded_packet))
        return -1;
    header_length = (uint16_t)(header[0] & 0x0fu) * 4u;
    if ((header[0] >> 4) != 4u || header_length < 20u ||
        header_length > packet_length || header[8] <= 1u)
        return -1;
    if (pbuf_copy_partial(
            packet, forwarded_packet, packet_length, 0) != packet_length)
        return -1;

    memset(&tuple, 0, sizeof(tuple));
    tuple.network_namespace = network_namespace;
    tuple.input_ifindex = input_ifindex;
    tuple.family = EDGE_LINUX_AF_INET;
    tuple.protocol = forwarded_packet[9];
    memcpy(tuple.source_address, forwarded_packet + 12u, 4u);
    memcpy(tuple.destination_address, forwarded_packet + 16u, 4u);
    transport_offset = header_length;
    if ((tuple.protocol == 6u || tuple.protocol == 17u) &&
        packet_length >= transport_offset + 4u) {
        tuple.source_port = edge_get_be16(
            forwarded_packet + transport_offset);
        tuple.destination_port = edge_get_be16(
            forwarded_packet + transport_offset + 2u);
    }
    if (edge_net_device_snapshot(
            input_ifindex, &input_snapshot) == EDGE_NET_OK)
        memcpy(tuple.input_interface, input_snapshot.configuration.name,
               sizeof(tuple.input_interface));
    destination_translation = edge_linux_netfilter_translate_forward(
        &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION);
    if (destination_translation < 0) return -1;
    {
        ip4_addr_t translated_destination;

        memcpy(&translated_destination.addr,
               tuple.destination_address, 4u);
        if (ip4_addr_ismulticast(&translated_destination) ||
            ip4_addr_isbroadcast(
                &translated_destination, input_interface) ||
            ip4_addr_cmp(
                &translated_destination,
                netif_ip4_addr(input_interface)) ||
            edge_linux_rtnetlink_ipv4_is_local_in_namespace(
                network_namespace, translated_destination.addr))
            return 0;
    }

    memset(&query, 0, sizeof(query));
    query.network_namespace = network_namespace;
    query.family = EDGE_LINUX_AF_INET;
    query.input_ifindex = input_ifindex;
    memcpy(query.source, tuple.source_address, 4u);
    memcpy(query.destination, tuple.destination_address, 4u);
    if (edge_linux_route_lookup(&query, &route) < 0 ||
        route.output_ifindex <= 0 ||
        edge_net_device_snapshot(
            route.output_ifindex, &output_snapshot) != EDGE_NET_OK ||
        output_snapshot.configuration.network_namespace !=
            network_namespace)
        return -1;
    tuple.output_ifindex = route.output_ifindex;
    memcpy(tuple.output_interface, output_snapshot.configuration.name,
           sizeof(tuple.output_interface));
    source_translation = edge_linux_netfilter_translate_forward(
        &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE);
    if (source_translation < 0) return -1;
    output_interface = edge_lwip_neighbor_netif(
        network_namespace, route.output_ifindex);
    if (!output_interface) return -1;

    memcpy(forwarded_packet + 12u, tuple.source_address, 4u);
    memcpy(forwarded_packet + 16u, tuple.destination_address, 4u);
    if ((tuple.protocol == 6u || tuple.protocol == 17u) &&
        packet_length >= transport_offset + 4u) {
        forwarded_packet[transport_offset] =
            (uint8_t)(tuple.source_port >> 8u);
        forwarded_packet[transport_offset + 1u] =
            (uint8_t)tuple.source_port;
        forwarded_packet[transport_offset + 2u] =
            (uint8_t)(tuple.destination_port >> 8u);
        forwarded_packet[transport_offset + 3u] =
            (uint8_t)tuple.destination_port;
    }
    --forwarded_packet[8];
    edge_lwip_ipv4_checksums(forwarded_packet, packet_length, 1);

    forwarded = pbuf_alloc(PBUF_LINK, packet_length, PBUF_RAM);
    if (!forwarded) return -1;
    if (pbuf_take(forwarded, forwarded_packet, packet_length) != ERR_OK) {
        pbuf_free(forwarded);
        return -1;
    }
    if (route.gateway[0] || route.gateway[1] ||
        route.gateway[2] || route.gateway[3])
        memcpy(&next_hop.addr, route.gateway, 4u);
    else
        memcpy(&next_hop.addr, tuple.destination_address, 4u);

    previous_input_interface = ip_data.current_input_netif;
    ip_data.current_input_netif = input_interface;
    result = output_interface->output(
        output_interface, forwarded, &next_hop);
    ip_data.current_input_netif = previous_input_interface;
    pbuf_free(forwarded);
    return result == ERR_OK ? 1 : -1;
}

static int edge_lwip_ipv6_forward_input(
    struct pbuf *packet, struct netif *input_interface,
    uint32_t network_namespace, int32_t input_ifindex,
    const uint8_t *header, uint16_t packet_length) {
#if LWIP_IPV6
    edge_linux_netfilter_tuple_t tuple;
    edge_linux_route_query_t query;
    edge_linux_route_result_t route;
    edge_net_device_snapshot_t input_snapshot;
    edge_net_device_snapshot_t output_snapshot;
    struct netif *output_interface;
    struct netif *previous_input_interface;
    struct pbuf *forwarded;
    ip6_addr_t next_hop;
    uint8_t *forwarded_packet;
    uint16_t payload_length;
    int destination_translation;
    int source_translation;
    err_t result;

    if (!packet || !input_interface || !header || packet_length < 40u ||
        packet_length > 1600u ||
        (header[0] >> 4u) != 6u || header[7] <= 1u)
        return -1;
    payload_length = edge_get_be16(header + 4u);
    if (payload_length && payload_length > packet_length - 40u)
        return -1;
    memset(&tuple, 0, sizeof(tuple));
    tuple.network_namespace = network_namespace;
    tuple.input_ifindex = input_ifindex;
    tuple.family = EDGE_LINUX_AF_INET6;
    tuple.protocol = header[6];
    memcpy(tuple.source_address, header + 8u, 16u);
    memcpy(tuple.destination_address, header + 24u, 16u);
    if ((tuple.protocol == 6u || tuple.protocol == 17u) &&
        packet_length >= 44u) {
        tuple.source_port = edge_get_be16(header + 40u);
        tuple.destination_port = edge_get_be16(header + 42u);
    }
    if (edge_net_device_snapshot(
            input_ifindex, &input_snapshot) == EDGE_NET_OK)
        memcpy(tuple.input_interface, input_snapshot.configuration.name,
               sizeof(tuple.input_interface));
    destination_translation = edge_linux_netfilter_translate_forward(
        &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION);
    if (destination_translation < 0) return -1;
    if (edge_lwip_ipv6_destination_is_local(
            tuple.destination_address, network_namespace))
        return 0;

    memset(&query, 0, sizeof(query));
    query.network_namespace = network_namespace;
    query.family = EDGE_LINUX_AF_INET6;
    query.input_ifindex = input_ifindex;
    memcpy(query.source, tuple.source_address, 16u);
    memcpy(query.destination, tuple.destination_address, 16u);
    if (edge_linux_route_lookup(&query, &route) < 0 ||
        route.output_ifindex <= 0 ||
        route.output_ifindex == input_ifindex ||
        edge_net_device_snapshot(
            route.output_ifindex, &output_snapshot) != EDGE_NET_OK ||
        output_snapshot.configuration.network_namespace !=
            network_namespace) {
        IP6_STATS_INC(ip6.rterr);
        IP6_STATS_INC(ip6.drop);
        return -1;
    }
    tuple.output_ifindex = route.output_ifindex;
    memcpy(tuple.output_interface, output_snapshot.configuration.name,
           sizeof(tuple.output_interface));
    source_translation = edge_linux_netfilter_translate_forward(
        &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE);
    if (source_translation < 0) return -1;
    output_interface = edge_lwip_neighbor_netif(
        network_namespace, route.output_ifindex);
    if (!output_interface) return -1;
    if (output_interface->mtu && packet_length > output_interface->mtu) {
        IP6_STATS_INC(ip6.drop);
        return -1;
    }

    forwarded = pbuf_alloc(PBUF_LINK, packet_length, PBUF_RAM);
    if (!forwarded) return -1;
    if (forwarded->len != packet_length ||
        pbuf_copy_partial(
            packet, forwarded->payload, packet_length, 0) != packet_length) {
        pbuf_free(forwarded);
        return -1;
    }
    forwarded_packet = (uint8_t *)forwarded->payload;
    memcpy(forwarded_packet + 8u, tuple.source_address, 16u);
    memcpy(forwarded_packet + 24u, tuple.destination_address, 16u);
    if ((tuple.protocol == 6u || tuple.protocol == 17u) &&
        packet_length >= 44u) {
        forwarded_packet[40] = (uint8_t)(tuple.source_port >> 8u);
        forwarded_packet[41] = (uint8_t)tuple.source_port;
        forwarded_packet[42] = (uint8_t)(tuple.destination_port >> 8u);
        forwarded_packet[43] = (uint8_t)tuple.destination_port;
    }
    if (destination_translation || source_translation)
        edge_lwip_ipv6_transport_checksum(
            forwarded_packet, packet_length);
    --forwarded_packet[7];
    if (memcmp(route.gateway, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
               16u) != 0)
        edge_ip6_from_bytes(&next_hop, route.gateway);
    else
        edge_ip6_from_bytes(&next_hop, tuple.destination_address);
    ip6_addr_assign_zone(&next_hop, IP6_UNICAST, output_interface);

    previous_input_interface = ip_data.current_input_netif;
    ip_data.current_input_netif = input_interface;
    result = output_interface->output_ip6(
        output_interface, forwarded, &next_hop);
    ip_data.current_input_netif = previous_input_interface;
    pbuf_free(forwarded);
    if (result != ERR_OK) {
        IP6_STATS_INC(ip6.drop);
        return -1;
    }
    IP6_STATS_INC(ip6.fw);
    IP6_STATS_INC(ip6.xmit);
    return 1;
#else
    (void)packet;
    (void)input_interface;
    (void)network_namespace;
    (void)input_ifindex;
    (void)header;
    (void)packet_length;
    return -1;
#endif
}

int edge_lwip_packet_input_hook(struct pbuf *packet,
                                struct netif *input_interface) {
    uint8_t frame[1600];
    uint8_t ipv4_header[20];
    uint8_t ipv6_header[44];
    uint16_t packet_length;

    if (!packet || !input_interface) return 0;
    if (packet->tot_len >= sizeof(ipv4_header) &&
        packet->tot_len <= sizeof(frame) &&
        pbuf_copy_partial(packet, ipv4_header, sizeof(ipv4_header), 0) ==
            sizeof(ipv4_header) &&
        (ipv4_header[0] >> 4) == 4u) {
        ip4_addr_t destination;
        uint32_t network_namespace;
        int32_t input_ifindex;
        int forward_result = 0;
        int forwarding = 0;

        memcpy(&destination.addr, ipv4_header + 16u, 4u);
        if (edge_lwip_netif_identity(
                input_interface, &network_namespace, &input_ifindex) == 0) {
            int destination_is_local =
                ip4_addr_ismulticast(&destination) ||
                ip4_addr_isbroadcast(&destination, input_interface) ||
                ip4_addr_cmp(
                    &destination, netif_ip4_addr(input_interface)) ||
                edge_linux_rtnetlink_ipv4_is_local_in_namespace(
                    network_namespace, destination.addr);

            (void)edge_net_namespace_ipv4_forwarding_get(
                network_namespace, &forwarding);
            if (forwarding &&
                (!destination_is_local || ipv4_header[8] > 1u))
                forward_result = edge_lwip_ipv4_forward_input(
                    packet, input_interface, network_namespace,
                    input_ifindex, ipv4_header,
                    (uint16_t)packet->tot_len);
            if (forward_result != 0 || !destination_is_local) {
                pbuf_free(packet);
                return 1;
            }
        }
    }
    if (packet->tot_len >= sizeof(ipv6_header) &&
        packet->tot_len <= sizeof(frame) &&
        pbuf_copy_partial(packet, ipv6_header, sizeof(ipv6_header), 0) ==
            sizeof(ipv6_header) &&
        (ipv6_header[0] >> 4) == 6u) {
        uint32_t network_namespace;
        int32_t input_ifindex;
        int disabled = g_ipv6_disabled;
        int forwarding = g_ipv6_forwarding;
        int accept_ra = g_ipv6_accept_ra;
        int forward_result = 0;
        int destination_is_local;
        int reject;

        if (edge_lwip_netif_identity(
                input_interface, &network_namespace,
                &input_ifindex) < 0)
            return 0;
        (void)edge_net_device_get_ipv6_setting(
            input_ifindex, 0u, &disabled);
        (void)edge_net_device_get_ipv6_setting(
            input_ifindex, 1u, &forwarding);
        (void)edge_net_device_get_ipv6_setting(
            input_ifindex, 2u, &accept_ra);
        reject = disabled;
        destination_is_local =
            edge_lwip_ipv6_destination_is_local(
                ipv6_header + 24u, network_namespace);

        if (!reject && ipv6_header[6] == 58u &&
            ipv6_header[40] == 134u &&
            (accept_ra == 0 ||
             (accept_ra == 1 && forwarding)))
            reject = 1;
        if (!reject && forwarding && !destination_is_local)
            forward_result = edge_lwip_ipv6_forward_input(
                packet, input_interface, network_namespace,
                input_ifindex, ipv6_header,
                (uint16_t)packet->tot_len);
        if (!reject && !forwarding && !destination_is_local)
            reject = 1;
        if (reject || forward_result != 0) {
            pbuf_free(packet);
            return 1;
        }
    }
    if (input_interface->name[0] != 'l' ||
        input_interface->name[1] != 'o')
        return 0;
    if (!packet->tot_len || packet->tot_len > sizeof(frame) - 14u)
        return 0;

    memset(frame, 0, 14u);
    packet_length = (uint16_t)packet->tot_len;
    if (pbuf_copy_partial(packet, frame + 14u, packet_length, 0) !=
        packet_length)
        return 0;

    if ((frame[14] >> 4) == 4u) {
        frame[12] = 0x08u;
        frame[13] = 0x00u;
    } else if ((frame[14] >> 4) == 6u) {
        frame[12] = 0x86u;
        frame[13] = 0xddu;
    } else {
        return 0;
    }
    edge_linux_packet_capture_rx(frame, (uint32_t)packet_length + 14u, 1);
    return 0;
}

int edge_lwip_ipv4_local_address_hook(
    struct netif *interface, const void *address) {
    const ip4_addr_t *ipv4_address = (const ip4_addr_t *)address;
    struct netif *input_interface = ip_current_input_netif();
    uint32_t input_namespace;
    uint32_t network_namespace;
    int32_t input_ifindex;
    int32_t ifindex;

    if (!interface || !ipv4_address)
        return 0;
    if (edge_lwip_netif_identity(
            interface, &network_namespace, &ifindex) < 0)
        return 0;
    if (g_lwip_ingress_active &&
        g_lwip_ingress_namespace != network_namespace)
        return 0;
    if (input_interface &&
        edge_lwip_netif_identity(
            input_interface, &input_namespace, &input_ifindex) == 0 &&
        input_namespace != network_namespace)
        return 0;
    (void)input_ifindex;
    (void)ifindex;
    return ip4_addr1(ipv4_address) == 127u ||
           edge_linux_rtnetlink_ipv4_is_local_in_namespace(
               network_namespace, ip4_addr_get_u32(ipv4_address));
}

int edge_lwip_ipv4_canforward_hook(
    struct pbuf *packet, uint32_t destination) {
    uint32_t network_namespace;
    int32_t input_ifindex;
    int enabled = 0;

    (void)packet;
    (void)destination;
    if (edge_lwip_netif_identity(
            ip_current_input_netif(), &network_namespace,
            &input_ifindex) < 0)
        return 0;
    if (edge_net_namespace_ipv4_forwarding_get(
            network_namespace, &enabled) != EDGE_NET_OK)
        return 0;
    return enabled ? -1 : 0;
}

struct netif *edge_lwip_ipv4_route_hook(const void *destination) {
    const ip4_addr_t *ipv4_destination =
        (const ip4_addr_t *)destination;
    uint32_t index;

    if (!ipv4_destination ||
        (ip4_addr1(ipv4_destination) != 127u &&
         !edge_linux_rtnetlink_ipv4_is_local(
             ip4_addr_get_u32(ipv4_destination))))
        return 0;
    for (index = 0; index < EDGE_LWIP_VIRTUAL_NETIF_MAX; ++index) {
        edge_lwip_virtual_netif_t *entry = &g_lwip_virtual_netifs[index];

        if (entry->used &&
            ip4_addr_eq(netif_ip4_addr(&entry->netif), ipv4_destination))
            return &entry->netif;
    }
    return 0;
}

struct netif *edge_lwip_ipv4_route_source_hook(
    const void *source, const void *destination) {
    const ip4_addr_t *ipv4_source = (const ip4_addr_t *)source;
    const ip4_addr_t *ipv4_destination =
        (const ip4_addr_t *)destination;
    struct netif *input_interface = ip_current_input_netif();
    edge_linux_route_query_t query;
    edge_linux_route_result_t result;
    uint32_t network_namespace;
    int32_t input_ifindex;
    uint32_t index;

    if (!ipv4_source || !ipv4_destination) return 0;
    if (!input_interface) {
        if (ip4_addr_isany(ipv4_source)) return 0;
        if (ip4_addr_eq(netif_ip4_addr(&g_lwip_netif), ipv4_source))
            return &g_lwip_netif;
        for (index = 0; index < EDGE_LWIP_VIRTUAL_NETIF_MAX; ++index) {
            edge_lwip_virtual_netif_t *entry =
                &g_lwip_virtual_netifs[index];

            if (entry->used && ip4_addr_eq(
                    netif_ip4_addr(&entry->netif), ipv4_source))
                return &entry->netif;
        }
        return 0;
    }
    if (edge_lwip_netif_identity(
            input_interface, &network_namespace, &input_ifindex) < 0)
        return 0;
    memset(&query, 0, sizeof(query));
    query.network_namespace = network_namespace;
    query.family = EDGE_LINUX_AF_INET;
    memcpy(query.source, &ipv4_source->addr, 4u);
    memcpy(query.destination, &ipv4_destination->addr, 4u);
    query.input_ifindex = input_ifindex;
    if (edge_linux_route_lookup(&query, &result) < 0 ||
        result.output_ifindex <= 0)
        return 0;
    return edge_lwip_neighbor_netif(
        network_namespace, result.output_ifindex);
}

struct netif *edge_lwip_ipv6_route_hook(
    const void *source, const void *destination) {
#if LWIP_IPV6
    const ip6_addr_t *ipv6_source = (const ip6_addr_t *)source;
    const ip6_addr_t *ipv6_destination =
        (const ip6_addr_t *)destination;
    struct netif *input_interface = ip_current_input_netif();
    edge_linux_route_query_t query;
    edge_linux_route_result_t result;
    uint32_t network_namespace = 0u;
    int32_t input_ifindex = 0;
    uint8_t source_bytes[16];
    uint8_t destination_bytes[16];

    if (!ipv6_source || !ipv6_destination) return 0;
    if (input_interface) {
        if (edge_lwip_netif_identity(
                input_interface, &network_namespace,
                &input_ifindex) < 0)
            return input_interface;
    } else if (!ip6_addr_isany(ipv6_source)) {
        if (network_namespace == 0u) {
            for (u8_t index = 0; index < LWIP_IPV6_NUM_ADDRESSES;
                 ++index) {
                if (ip6_addr_isvalid(
                        netif_ip6_addr_state(&g_lwip_netif, index)) &&
                    ip6_addr_zoneless_eq(
                        netif_ip6_addr(&g_lwip_netif, index),
                        ipv6_source)) {
                    input_ifindex = 2;
                    break;
                }
            }
        }
        for (uint32_t ordinal = 0;
             !input_ifindex && ordinal < EDGE_LWIP_VIRTUAL_NETIF_MAX;
             ++ordinal) {
            edge_lwip_virtual_netif_t *entry =
                &g_lwip_virtual_netifs[ordinal];

            if (!entry->used) continue;
            for (u8_t index = 0; index < LWIP_IPV6_NUM_ADDRESSES;
                 ++index) {
                if (ip6_addr_isvalid(
                        netif_ip6_addr_state(&entry->netif, index)) &&
                    ip6_addr_zoneless_eq(
                        netif_ip6_addr(&entry->netif, index),
                        ipv6_source)) {
                    network_namespace = entry->network_namespace;
                    input_ifindex = entry->ifindex;
                    break;
                }
            }
        }
    }
    edge_ip6_to_bytes(ipv6_source, source_bytes);
    edge_ip6_to_bytes(ipv6_destination, destination_bytes);
    memset(&query, 0, sizeof(query));
    query.network_namespace = network_namespace;
    query.family = EDGE_LINUX_AF_INET6;
    query.input_ifindex = input_ifindex;
    memcpy(query.source, source_bytes, sizeof(source_bytes));
    memcpy(query.destination, destination_bytes,
           sizeof(destination_bytes));
    if (edge_linux_route_lookup(&query, &result) == 0 &&
        result.output_ifindex > 0) {
        struct netif *selected = edge_lwip_neighbor_netif(
            network_namespace, result.output_ifindex);

        if (selected) return selected;
    }
    return input_interface;
#else
    (void)source;
    (void)destination;
    return 0;
#endif
}

const void *edge_lwip_ipv6_gateway_hook(
    struct netif *interface, const void *destination) {
#if LWIP_IPV6
    const ip6_addr_t *ipv6_destination =
        (const ip6_addr_t *)destination;
    edge_lwip_virtual_netif_t *entry = 0;
    edge_linux_route_query_t query;
    edge_linux_route_result_t result;
    ip6_addr_t *gateway;
    uint32_t network_namespace;
    int32_t ifindex;
    uint8_t destination_bytes[16];
    uint8_t index;

    if (!interface || !ipv6_destination ||
        edge_lwip_netif_identity(
            interface, &network_namespace, &ifindex) < 0)
        return 0;
    if (interface == &g_lwip_netif) {
        gateway = &g_ipv6_route_gateway;
    } else {
        entry = edge_lwip_virtual_find(ifindex);
        if (!entry || &entry->netif != interface ||
            entry->network_namespace != network_namespace)
            return 0;
        gateway = &entry->ipv6_route_gateway;
    }
    memset(&query, 0, sizeof(query));
    query.network_namespace = network_namespace;
    query.family = EDGE_LINUX_AF_INET6;
    query.output_ifindex = ifindex;
    edge_ip6_to_bytes(ipv6_destination, destination_bytes);
    memcpy(query.destination, destination_bytes,
           sizeof(destination_bytes));
    for (index = 0; index < LWIP_IPV6_NUM_ADDRESSES; ++index) {
        if (!ip6_addr_isvalid(netif_ip6_addr_state(interface, index)) ||
            ip6_addr_islinklocal(netif_ip6_addr(interface, index)))
            continue;
        edge_ip6_to_bytes(netif_ip6_addr(interface, index), query.source);
        break;
    }
    if (edge_linux_route_lookup(&query, &result) < 0 ||
        result.output_ifindex != ifindex ||
        memcmp(result.gateway,
               "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16u) == 0)
        return 0;
    edge_ip6_from_bytes(gateway, result.gateway);
    ip6_addr_assign_zone(gateway, IP6_UNICAST, interface);
    return gateway;
#else
    (void)interface;
    (void)destination;
    return 0;
#endif
}

static void edge_note_tcp_fin_rx(const uint8_t *frame, uint32_t len) {
    const uint8_t *ip;
    const uint8_t *tcp;
    uint32_t ihl;
    uint32_t total;
    uint32_t thl;
    if (!frame || len < 54) return;
    if (edge_get_be16(frame + 12) != 0x0800u) return;
    ip = frame + 14;
    if ((ip[0] >> 4) != 4 || ip[9] != 6) return;
    ihl = (uint32_t)(ip[0] & 0x0fu) * 4u;
    if (ihl < 20 || len < 14 + ihl + 20) return;
    total = edge_get_be16(ip + 2);
    tcp = ip + ihl;
    thl = (uint32_t)(tcp[12] >> 4) * 4u;
    if (thl < 20 || total < ihl + thl) return;
    if ((tcp[13] & 0x01u) == 0) return;
    g_tcp_rx_fin_counter++;
    if (g_tcp_rx_fin_counter == 0) g_tcp_rx_fin_counter = 1;
    g_tcp_rx_fin_remote_ip_be = edge_get_be32(ip + 12);
    g_tcp_rx_fin_local_ip_be = edge_get_be32(ip + 16);
    g_tcp_rx_fin_remote_port = edge_get_be16(tcp);
    g_tcp_rx_fin_local_port = edge_get_be16(tcp + 2);
}

static void edge_lwip_output_metadata(
    edge_net_packet_metadata_t *metadata, int32_t output_ifindex) {
    edge_net_device_snapshot_t output;
    uint32_t input_namespace;
    int32_t input_ifindex;

    if (!metadata) return;
    metadata->output_ifindex = output_ifindex;
    if (edge_net_device_snapshot(output_ifindex, &output) == EDGE_NET_OK)
        metadata->network_namespace =
            output.configuration.network_namespace;
    if (edge_lwip_netif_identity(
            ip_current_input_netif(), &input_namespace,
            &input_ifindex) == 0 &&
        input_namespace == metadata->network_namespace)
        metadata->input_ifindex = input_ifindex;
}

static int edge_lwip_transmit_frame(
    int32_t ifindex, const uint8_t *frame, uint32_t length) {
    edge_net_packet_segment_t segment;
    edge_net_packet_metadata_t metadata;
    edge_net_packet_t packet;

    if (!frame || !length) return -1;
    segment.data = frame;
    segment.length = length;
    memset(&metadata, 0, sizeof(metadata));
    edge_lwip_output_metadata(&metadata, ifindex);
    metadata.timestamp_ns = boottime_monotonic_us() * 1000u;
    if (edge_net_packet_initialize(
            &packet, &segment, 1u, &metadata, 0, 0) != EDGE_NET_OK)
        return -1;
    return edge_net_device_transmit(ifindex, &packet) == EDGE_NET_OK ?
        0 : -1;
}

static err_t edge_lwip_linkoutput(struct netif *netif, struct pbuf *p) {
    uint8_t frame[1600];
    uint16_t total;
    (void)netif;
    if (!p) return ERR_ARG;
    if (p->tot_len > sizeof(frame)) return ERR_MEM;
    if (pbuf_copy_partial(p, frame, p->tot_len, 0) != p->tot_len) return ERR_VAL;
    total = (uint16_t)p->tot_len;
    edge_lwip_complete_ipv4_checksums(frame, total);
    return g_netdev_handle && edge_lwip_transmit_frame(
        2, frame, total) == 0 ? ERR_OK : ERR_IF;
}

static err_t edge_lwip_netif_init(struct netif *netif) {
    uint8_t mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    uint32_t mtu = 1500;
    int link_up = 1;
    if (!netif) return ERR_ARG;
    netif->name[0] = 'e';
    netif->name[1] = '0';
    netif->output = etharp_output;
#if LWIP_IPV6
    netif->output_ip6 = ethip6_output;
#endif
    netif->linkoutput = edge_lwip_linkoutput;
    if (edge_netdev_get_info(g_netdev_handle, 0, 0, mac, &mtu,
        &link_up, 0) != 0) {
        printf("[net] lwip: selected network device disappeared\n");
        return ERR_IF;
    }
    netif->mtu = (uint16_t)mtu;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP |
                   NETIF_FLAG_IGMP | NETIF_FLAG_UP;
    if (link_up)
        netif->flags |= NETIF_FLAG_LINK_UP;
#if LWIP_IPV6_MLD
    netif->flags |= NETIF_FLAG_MLD6;
#endif
#if LWIP_NETIF_HOSTNAME
    netif_set_hostname(netif, g_hostname);
#endif
    netif->hwaddr_len = 6;
    memcpy(netif->hwaddr, mac, 6);
    return ERR_OK;
}

static err_t edge_lwip_virtual_linkoutput(
    struct netif *netif, struct pbuf *p) {
    edge_lwip_virtual_netif_t *entry;
    uint8_t frame[1600];

    if (!netif || !p) return ERR_ARG;
    entry = (edge_lwip_virtual_netif_t *)netif->state;
    if (!entry || !entry->used) return ERR_IF;
    if (p->tot_len > sizeof(frame)) return ERR_MEM;
    if (pbuf_copy_partial(p, frame, p->tot_len, 0) != p->tot_len)
        return ERR_VAL;
    edge_lwip_complete_ipv4_checksums(frame, (uint16_t)p->tot_len);
    if (edge_lwip_transmit_frame(
            entry->ifindex, frame, p->tot_len) < 0)
        return ERR_IF;
    edge_linux_packet_capture_tx(
        frame, p->tot_len, entry->ifindex);
    return ERR_OK;
}

static err_t edge_lwip_virtual_output_raw(
    struct netif *netif, struct pbuf *p, uint16_t protocol) {
    edge_lwip_virtual_netif_t *entry;
    edge_net_packet_segment_t segment;
    edge_net_packet_metadata_t metadata;
    edge_net_packet_t packet;
    uint8_t payload[1600];

    if (!netif || !p) return ERR_ARG;
    entry = (edge_lwip_virtual_netif_t *)netif->state;
    if (!entry || !entry->used) return ERR_IF;
    if (!p->tot_len || p->tot_len > sizeof(payload)) return ERR_MEM;
    if (pbuf_copy_partial(p, payload, p->tot_len, 0) != p->tot_len)
        return ERR_VAL;
    segment.data = payload;
    segment.length = p->tot_len;
    memset(&metadata, 0, sizeof(metadata));
    metadata.network_namespace = entry->network_namespace;
    edge_lwip_output_metadata(&metadata, entry->ifindex);
    metadata.protocol = protocol;
    metadata.timestamp_ns = boottime_monotonic_us() * 1000u;
    if (edge_net_packet_initialize(
            &packet, &segment, 1u, &metadata, 0, 0) != EDGE_NET_OK)
        return ERR_VAL;
    return edge_net_device_transmit(entry->ifindex, &packet) == EDGE_NET_OK ?
        ERR_OK : ERR_IF;
}

static err_t edge_lwip_virtual_output_ipv4(
    struct netif *netif, struct pbuf *p, const ip4_addr_t *destination) {
    (void)destination;
    return edge_lwip_virtual_output_raw(netif, p, 0x0800u);
}

#if LWIP_IPV6
static err_t edge_lwip_virtual_output_ipv6(
    struct netif *netif, struct pbuf *p, const ip6_addr_t *destination) {
    (void)destination;
    return edge_lwip_virtual_output_raw(netif, p, 0x86ddu);
}
#endif

static int edge_lwip_deferred_enqueue(
    int32_t ifindex, uint32_t network_namespace,
    const uint8_t *frame, uint16_t length) {
    uint32_t index;

    if (!frame || !length || length > 1600u) return -1;
    for (index = 0; index < EDGE_LWIP_DEFERRED_FRAME_MAX; ++index) {
        edge_lwip_deferred_frame_t *slot =
            &g_lwip_deferred_frames[index];
        uint8_t expected = 0u;

        if (!__atomic_compare_exchange_n(
                &slot->state, &expected, 1u, 0,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            continue;
        slot->ifindex = ifindex;
        slot->network_namespace = network_namespace;
        slot->length = length;
        memcpy(slot->data, frame, length);
        __atomic_store_n(&slot->state, 2u, __ATOMIC_RELEASE);
        return 0;
    }
    return -1;
}

static void edge_lwip_virtual_receive_frame(
    int32_t ifindex, uint32_t network_namespace,
    const uint8_t *frame, uint16_t length,
    edge_lwip_virtual_netif_t *entry) {
    struct pbuf *p;
    err_t result;

    if (!entry || !entry->used || entry->ifindex != ifindex ||
        entry->network_namespace != network_namespace || !frame ||
        !length)
        return;
    edge_linux_packet_capture_rx(frame, length, ifindex);
    p = pbuf_alloc(PBUF_RAW, length, PBUF_POOL);
    if (!p) return;
    if (pbuf_take(p, frame, length) != ERR_OK) {
        pbuf_free(p);
        return;
    }
    {
        uint32_t previous_namespace = g_lwip_ingress_namespace;
        uint8_t previous_active = g_lwip_ingress_active;

        g_lwip_ingress_namespace = network_namespace;
        g_lwip_ingress_active = 1u;
        result = entry->netif.input(p, &entry->netif);
        g_lwip_ingress_namespace = previous_namespace;
        g_lwip_ingress_active = previous_active;
    }
    if (result != ERR_OK) pbuf_free(p);
}

static void edge_lwip_virtual_receive(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context) {
    edge_lwip_virtual_netif_t *entry =
        (edge_lwip_virtual_netif_t *)context;
    uint8_t frame[1600];

    if (!entry || !entry->used || entry->ifindex != ifindex ||
        entry->network_namespace != network_namespace || !packet ||
        packet->total_length > sizeof(frame) ||
        edge_net_packet_linearize(packet, frame, sizeof(frame)) < 0)
        return;
    /*
     * Virtual device delivery is synchronous. Queue every frame so a reply
     * cannot re-enter lwIP while the originating TCP output call still owns
     * its unsent segment.
     */
    (void)edge_lwip_deferred_enqueue(
        ifindex, network_namespace, frame,
        (uint16_t)packet->total_length);
}

static void edge_lwip_deferred_drain(void) {
    uint32_t index;

    if (g_lwip_deferred_draining || g_lwip_ingress_active) return;
    g_lwip_deferred_draining = 1u;
    for (;;) {
        int delivered = 0;

        for (index = 0; index < EDGE_LWIP_DEFERRED_FRAME_MAX; ++index) {
            edge_lwip_deferred_frame_t *slot =
                &g_lwip_deferred_frames[index];
            edge_lwip_virtual_netif_t *entry;
            uint8_t expected = 2u;

            if (!__atomic_compare_exchange_n(
                    &slot->state, &expected, 3u, 0,
                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                continue;
            entry = edge_lwip_virtual_find(slot->ifindex);
            if (entry && entry->network_namespace ==
                    slot->network_namespace)
                edge_lwip_virtual_receive_frame(
                    slot->ifindex, slot->network_namespace,
                    slot->data, slot->length, entry);
            __atomic_store_n(&slot->state, 0u, __ATOMIC_RELEASE);
            delivered = 1;
        }
        if (!delivered) break;
    }
    g_lwip_deferred_draining = 0u;
}

static err_t edge_lwip_virtual_netif_init(struct netif *netif) {
    edge_lwip_virtual_netif_t *entry;
    edge_net_device_snapshot_t snapshot;

    if (!netif) return ERR_ARG;
    entry = (edge_lwip_virtual_netif_t *)netif->state;
    if (!entry || !entry->used) return ERR_IF;
    if (edge_net_device_snapshot(
            entry->ifindex, &snapshot) != EDGE_NET_OK ||
        (snapshot.configuration.kind != EDGE_NET_DEVICE_BRIDGE &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_VETH &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_TUN &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_TAP &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_VLAN &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_DUMMY &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_MACVLAN &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_IPVLAN &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_BOND))
        return ERR_IF;
    if (snapshot.configuration.kind == EDGE_NET_DEVICE_BRIDGE)
        netif->name[0] = 'b';
    else if (snapshot.configuration.kind == EDGE_NET_DEVICE_VLAN)
        netif->name[0] = 'l';
    else if (snapshot.configuration.kind == EDGE_NET_DEVICE_DUMMY)
        netif->name[0] = 'd';
    else if (snapshot.configuration.kind == EDGE_NET_DEVICE_MACVLAN)
        netif->name[0] = 'm';
    else if (snapshot.configuration.kind == EDGE_NET_DEVICE_IPVLAN)
        netif->name[0] = 'i';
    else if (snapshot.configuration.kind == EDGE_NET_DEVICE_BOND)
        netif->name[0] = 'n';
    else if (snapshot.configuration.kind == EDGE_NET_DEVICE_TUN)
        netif->name[0] = 't';
    else if (snapshot.configuration.kind == EDGE_NET_DEVICE_TAP)
        netif->name[0] = 'a';
    else
        netif->name[0] = 'v';
    netif->name[1] = (char)('0' + (entry->ifindex % 10));
    if (snapshot.configuration.kind == EDGE_NET_DEVICE_TUN)
        netif->output = edge_lwip_virtual_output_ipv4;
    else
        netif->output = etharp_output;
#if LWIP_IPV6
    if (snapshot.configuration.kind == EDGE_NET_DEVICE_TUN)
        netif->output_ip6 = edge_lwip_virtual_output_ipv6;
    else
        netif->output_ip6 = ethip6_output;
#endif
    if (snapshot.configuration.kind != EDGE_NET_DEVICE_TUN)
        netif->linkoutput = edge_lwip_virtual_linkoutput;
    netif->mtu = (uint16_t)snapshot.configuration.mtu;
    netif->flags = NETIF_FLAG_IGMP | NETIF_FLAG_UP;
    if (snapshot.configuration.kind != EDGE_NET_DEVICE_TUN)
        netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
    if (snapshot.configuration.carrier &&
        (snapshot.configuration.flags & EDGE_NET_DEVICE_FLAG_UP))
        netif->flags |= NETIF_FLAG_LINK_UP;
#if LWIP_IPV6_MLD
    netif->flags |= NETIF_FLAG_MLD6;
#endif
    if (snapshot.configuration.kind == EDGE_NET_DEVICE_TUN) {
        netif->hwaddr_len = 0u;
    } else {
        netif->hwaddr_len = 6u;
        memcpy(netif->hwaddr,
               snapshot.configuration.hardware_address, 6u);
    }
    return ERR_OK;
}

static edge_lwip_virtual_netif_t *edge_lwip_virtual_find(
    int32_t ifindex) {
    uint32_t index;

    for (index = 0; index < EDGE_LWIP_VIRTUAL_NETIF_MAX; ++index) {
        edge_lwip_virtual_netif_t *entry = &g_lwip_virtual_netifs[index];

        if (entry->used && entry->ifindex == ifindex) return entry;
    }
    return 0;
}

static edge_lwip_virtual_netif_t *edge_lwip_virtual_allocate(void) {
    uint32_t index;

    for (index = 0; index < EDGE_LWIP_VIRTUAL_NETIF_MAX; ++index) {
        if (!g_lwip_virtual_netifs[index].used)
            return &g_lwip_virtual_netifs[index];
    }
    return 0;
}

static int edge_lwip_virtual_has_ipv6(
    const edge_lwip_virtual_netif_t *entry) {
#if LWIP_IPV6
    uint8_t index;

    if (!entry || !entry->used) return 0;
    for (index = 0; index < LWIP_IPV6_NUM_ADDRESSES; ++index) {
        if (!ip6_addr_isinvalid(
                netif_ip6_addr_state(&entry->netif, index)) &&
            !ip6_addr_isany(netif_ip6_addr(&entry->netif, index)))
            return 1;
    }
#else
    (void)entry;
#endif
    return 0;
}

static void edge_lwip_virtual_remove(edge_lwip_virtual_netif_t *entry) {
    int32_t ifindex;

    if (!entry || !entry->used) return;
    ifindex = entry->ifindex;
    edge_lwip_static_neighbors_remove_interface(
        entry->network_namespace, ifindex);
    (void)edge_net_device_set_receive_callback(ifindex, 0, 0);
    netif_set_link_down(&entry->netif);
    netif_set_down(&entry->netif);
    netif_remove(&entry->netif);
    memset(entry, 0, sizeof(*entry));
}

static edge_lwip_virtual_netif_t *edge_lwip_virtual_ensure(
    int32_t ifindex, uint32_t network_namespace,
    const edge_net_device_snapshot_t *snapshot) {
    edge_lwip_virtual_netif_t *entry;
    ip4_addr_t zero;

    if (!snapshot) return 0;
    entry = edge_lwip_virtual_find(ifindex);
    if (entry) {
        if (entry->network_namespace != network_namespace) return 0;
        return entry;
    }
    entry = edge_lwip_virtual_allocate();
    if (!entry) return 0;
    memset(entry, 0, sizeof(*entry));
    memset(&zero, 0, sizeof(zero));
    entry->used = 1u;
    entry->ifindex = ifindex;
    entry->network_namespace = network_namespace;
    if (!netif_add(
            &entry->netif, &zero, &zero, &zero, entry,
            edge_lwip_virtual_netif_init,
            snapshot->configuration.kind == EDGE_NET_DEVICE_TUN ?
                ip_input : ethernet_input)) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }
    if (edge_net_device_set_receive_callback(
            ifindex, edge_lwip_virtual_receive, entry) != EDGE_NET_OK) {
        netif_remove(&entry->netif);
        memset(entry, 0, sizeof(*entry));
        return 0;
    }
    return entry;
}

static void edge_lwip_virtual_apply_link_state(
    edge_lwip_virtual_netif_t *entry,
    const edge_net_device_snapshot_t *snapshot) {
    if (!entry || !snapshot) return;
    entry->netif.mtu = (uint16_t)snapshot->configuration.mtu;
    if (snapshot->configuration.flags & EDGE_NET_DEVICE_FLAG_UP)
        netif_set_up(&entry->netif);
    else
        netif_set_down(&entry->netif);
    if (snapshot->configuration.carrier)
        netif_set_link_up(&entry->netif);
    else
        netif_set_link_down(&entry->netif);
}

static void edge_ipv6_provider_synchronize_links(void) {
    uint32_t index;

    for (index = 0; index < EDGE_LWIP_VIRTUAL_NETIF_MAX; ++index) {
        edge_lwip_virtual_netif_t *entry = &g_lwip_virtual_netifs[index];
        edge_net_device_snapshot_t snapshot;

        if (!entry->used || edge_net_device_snapshot(
                entry->ifindex, &snapshot) != EDGE_NET_OK ||
            snapshot.configuration.network_namespace !=
                entry->network_namespace)
            continue;
        edge_lwip_virtual_apply_link_state(entry, &snapshot);
    }
}

int lwip_stack_configure_local_ipv4_alias(
    int32_t ifindex, uint32_t network_namespace,
    uint32_t addr_be, uint8_t prefix_length, int active) {
    edge_lwip_virtual_netif_t *entry;
    edge_net_device_snapshot_t snapshot;
    ip4_addr_t address;
    ip4_addr_t netmask;
    ip4_addr_t gateway;
    uint8_t mask_bytes[4] = {0, 0, 0, 0};
    uint32_t bit;

    if (!g_ready || ifindex <= 2 || prefix_length > 32u)
        return -1;
    entry = edge_lwip_virtual_find(ifindex);
    if (edge_net_device_snapshot(ifindex, &snapshot) != EDGE_NET_OK ||
        snapshot.configuration.network_namespace != network_namespace ||
        (snapshot.configuration.kind != EDGE_NET_DEVICE_BRIDGE &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_VETH &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_TUN &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_TAP &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_VLAN &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_DUMMY &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_MACVLAN &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_IPVLAN &&
         snapshot.configuration.kind != EDGE_NET_DEVICE_BOND))
        return -1;
    if (!active || !addr_be) {
        if (!entry) return 0;
        memset(&address, 0, sizeof(address));
        memset(&netmask, 0, sizeof(netmask));
        memset(&gateway, 0, sizeof(gateway));
        netif_set_addr(&entry->netif, &address, &netmask, &gateway);
        entry->ipv4_active = 0u;
        if (!edge_lwip_virtual_has_ipv6(entry))
            edge_lwip_virtual_remove(entry);
        return 0;
    }
    for (bit = 0; bit < prefix_length; ++bit)
        mask_bytes[bit / 8u] |= (uint8_t)(1u << (7u - bit % 8u));
    address.addr = addr_be;
    memcpy(&netmask.addr, mask_bytes, sizeof(mask_bytes));
    gateway.addr = snapshot.ipv4_gateway;
    entry = edge_lwip_virtual_ensure(
        ifindex, network_namespace, &snapshot);
    if (!entry) return -1;
    netif_set_addr(&entry->netif, &address, &netmask, &gateway);
    entry->ipv4_active = 1u;
    edge_lwip_virtual_apply_link_state(entry, &snapshot);
    return 0;
}

static struct netif *edge_lwip_neighbor_netif(
    uint32_t network_namespace, int32_t ifindex) {
    edge_lwip_virtual_netif_t *entry;

    if (ifindex == 1 && network_namespace == 0u)
        return edge_lwip_loopback_netif();
    if (ifindex == 2 && network_namespace == 0u) return &g_lwip_netif;
    entry = edge_lwip_virtual_find(ifindex);
    if (!entry || entry->network_namespace != network_namespace) return 0;
    return &entry->netif;
}

static int edge_lwip_netif_identity(
    const struct netif *netif, uint32_t *network_namespace,
    int32_t *ifindex) {
    uint32_t index;

    if (!netif || !network_namespace || !ifindex) return -1;
    if (netif == edge_lwip_loopback_netif()) {
        *network_namespace = 0u;
        *ifindex = 1;
        return 0;
    }
    if (netif == &g_lwip_netif) {
        *network_namespace = 0u;
        *ifindex = 2;
        return 0;
    }
    for (index = 0; index < EDGE_LWIP_VIRTUAL_NETIF_MAX; ++index) {
        const edge_lwip_virtual_netif_t *entry =
            &g_lwip_virtual_netifs[index];

        if (!entry->used || &entry->netif != netif) continue;
        *network_namespace = entry->network_namespace;
        *ifindex = entry->ifindex;
        return 0;
    }
    return -1;
}

static int edge_lwip_static_neighbor_matches(
    uint32_t network_namespace, int32_t ifindex, uint32_t address) {
    uint32_t index;

    for (index = 0; index < EDGE_LWIP_STATIC_NEIGHBOR_MAX; ++index) {
        const edge_lwip_static_neighbor_t *entry =
            &g_lwip_static_neighbors[index];

        if (entry->used &&
            entry->network_namespace == network_namespace &&
            entry->ifindex == ifindex && entry->address == address)
            return 1;
    }
    return 0;
}

static int edge_ipv4_provider_neighbor_at(
    uint32_t network_namespace, int ordinal,
    edge_linux_rtnetlink_ipv4_neighbor_t *neighbor) {
    int current = 0;
    uint32_t index;

    if (ordinal < 0 || !neighbor || !g_ready) return -1;
    memset(neighbor, 0, sizeof(*neighbor));
    for (index = 0; index < EDGE_LWIP_STATIC_NEIGHBOR_MAX; ++index) {
        const edge_lwip_static_neighbor_t *entry =
            &g_lwip_static_neighbors[index];

        if (!entry->used ||
            entry->network_namespace != network_namespace ||
            entry->ifindex <= 2)
            continue;
        if (current++ != ordinal) continue;
        neighbor->address = entry->address;
        neighbor->ifindex = entry->ifindex;
        memcpy(neighbor->hardware_address, entry->hardware_address, 6u);
        neighbor->state = entry->state;
        neighbor->flags = entry->flags;
        return 0;
    }
    for (index = 0; index < ARP_TABLE_SIZE; ++index) {
        ip4_addr_t *address;
        struct netif *netif;
        struct eth_addr *ethernet;
        uint32_t owner_namespace;
        int32_t owner_ifindex;

        if (!etharp_get_entry(index, &address, &netif, &ethernet) ||
            edge_lwip_netif_identity(
                netif, &owner_namespace, &owner_ifindex) < 0 ||
            owner_namespace != network_namespace || owner_ifindex <= 2 ||
            edge_lwip_static_neighbor_matches(
                owner_namespace, owner_ifindex, address->addr))
            continue;
        if (current++ != ordinal) continue;
        neighbor->address = address->addr;
        neighbor->ifindex = owner_ifindex;
        memcpy(neighbor->hardware_address, ethernet->addr, 6u);
        neighbor->state = 0x02u;
        return 0;
    }
    return -1;
}

static int edge_ipv4_provider_configure_neighbor(
    uint32_t network_namespace, int32_t ifindex, uint32_t address,
    const uint8_t hardware_address[6], uint16_t state,
    uint8_t flags, int active) {
    edge_lwip_static_neighbor_t *available = 0;
    edge_lwip_static_neighbor_t *selected = 0;
    struct netif *netif;
    ip4_addr_t ipv4;
    uint32_t index;

    if (!g_ready || !address) return -1;
    netif = edge_lwip_neighbor_netif(network_namespace, ifindex);
    if (!netif || (netif->flags & NETIF_FLAG_ETHARP) == 0u) return -1;
    for (index = 0; index < EDGE_LWIP_STATIC_NEIGHBOR_MAX; ++index) {
        edge_lwip_static_neighbor_t *entry =
            &g_lwip_static_neighbors[index];

        if (!entry->used) {
            if (!available) available = entry;
            continue;
        }
        if (entry->network_namespace == network_namespace &&
            entry->ifindex == ifindex && entry->address == address) {
            selected = entry;
            break;
        }
    }
    ipv4.addr = address;
    if (!active) {
        if (!selected) return 0;
        if (edge_lwip_etharp_remove_static_entry(netif, &ipv4) != ERR_OK)
            return -1;
        memset(selected, 0, sizeof(*selected));
        return 0;
    }
    if (!hardware_address || (!selected && !available))
        return -1;
    {
        struct eth_addr ethernet;

        memcpy(ethernet.addr, hardware_address, sizeof(ethernet.addr));
        if (edge_lwip_etharp_add_static_entry(
                netif, &ipv4, &ethernet) != ERR_OK)
            return -1;
    }
    if (!selected) selected = available;
    memset(selected, 0, sizeof(*selected));
    selected->used = 1u;
    selected->network_namespace = network_namespace;
    selected->ifindex = ifindex;
    selected->address = address;
    memcpy(selected->hardware_address, hardware_address, 6u);
    selected->state = state ? state : 0x80u;
    selected->flags = flags;
    return 0;
}

static const edge_linux_rtnetlink_ipv4_provider_t g_ipv4_provider = {
    .neighbor_at = edge_ipv4_provider_neighbor_at,
    .configure_neighbor = edge_ipv4_provider_configure_neighbor,
};

static void edge_lwip_static_neighbors_remove_interface(
    uint32_t network_namespace, int32_t ifindex) {
    uint32_t index;

    for (index = 0; index < EDGE_LWIP_STATIC_NEIGHBOR_MAX; ++index) {
        edge_lwip_static_neighbor_t *entry =
            &g_lwip_static_neighbors[index];
        ip4_addr_t address;

        if (!entry->used ||
            entry->network_namespace != network_namespace ||
            entry->ifindex != ifindex)
            continue;
        address.addr = entry->address;
        {
            struct netif *netif = edge_lwip_neighbor_netif(
                network_namespace, ifindex);

            if (netif)
                (void)edge_lwip_etharp_remove_static_entry(netif, &address);
        }
        memset(entry, 0, sizeof(*entry));
    }
}

static void
edge_lwip_link_state_changed(int link_up, void *context)
{
    (void)context;
    if (link_up)
        netif_set_link_up(&g_lwip_netif);
    else
        netif_set_link_down(&g_lwip_netif);
    (void)edge_net_device_set_link(
        2, link_up ? EDGE_NET_DEVICE_FLAG_RUNNING : 0u,
        EDGE_NET_DEVICE_FLAG_RUNNING, 0u, 0);
    (void)edge_net_device_set_carrier(2, link_up);
}

static void edge_queue_ipv4_icmp_packet(edge_icmp_reply_t *queue, int qlen,
                                        const uint8_t *icmp,
                                        uint16_t icmp_len,
                                        uint32_t src_ip_be, uint16_t id_be) {
    edge_icmp_reply_t *slot = 0;
    edge_ipv4_hdr_t *ip;
    uint32_t ip_len;

    if (!queue || qlen <= 0 || !icmp || icmp_len < 8) return;
    ip_len = (uint32_t)sizeof(edge_ipv4_hdr_t) + icmp_len;
    if (ip_len > sizeof(queue[0].ip_pkt)) return;

    for (int i = 0; i < qlen; ++i) {
        if (!__atomic_load_n(&queue[i].used, __ATOMIC_ACQUIRE)) {
            slot = &queue[i];
            break;
        }
    }
    if (!slot) slot = &queue[0];

    __atomic_store_n(&slot->used, 0u, __ATOMIC_RELEASE);
    slot->id_be = id_be;
    slot->src_ip_be = src_ip_be;
    slot->ip_len = ip_len;
    memset(slot->ip_pkt, 0, sizeof(slot->ip_pkt));

    ip = (edge_ipv4_hdr_t *)slot->ip_pkt;
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->proto = 1;
    ip->total_len_be = (uint16_t)(((slot->ip_len & 0x00FFu) << 8) | ((slot->ip_len & 0xFF00u) >> 8));
    ip->src_be = src_ip_be;
    ip->dst_be = (src_ip_be & 0xffu) == 0x7fu ?
                 src_ip_be : 0x0F02000Au;
    {
        uint16_t checksum;
        ip->csum_be = 0;
        checksum = edge_cksum16(ip, sizeof(*ip));
        slot->ip_pkt[10] = (uint8_t)(checksum >> 8);
        slot->ip_pkt[11] = (uint8_t)checksum;
    }
    memcpy(slot->ip_pkt + sizeof(*ip), icmp, icmp_len);
    __atomic_store_n(&slot->used, 1u, __ATOMIC_RELEASE);
    edge_readiness_sequence_advance(&g_icmp_readiness_sequence);
}

static void edge_queue_icmp_reply(const uint8_t *icmp, uint16_t icmp_len, uint32_t src_ip_be) {
    uint16_t id_be = 0;
    if (!icmp || icmp_len < 8) return;

    edge_queue_ipv4_icmp_packet(g_raw_icmp_q, EDGE_ICMP_RAW_Q, icmp, icmp_len, src_ip_be, 0);
    if (!edge_extract_icmp_probe_id(icmp, icmp_len, &id_be)) return;
    edge_queue_ipv4_icmp_packet(g_reply_q, EDGE_ICMP_REPLY_Q, icmp, icmp_len, src_ip_be, id_be);
}

static void edge_queue_icmp6_reply(const uint8_t *icmp6, uint16_t icmp6_len,
                                   const ip_addr_t *src) {
    edge_icmp6_reply_t *slot = 0;
    uint16_t id_be;
    if (!icmp6 || icmp6_len < 8 || !src || !IP_IS_V6(src)) return;
    if (!edge_extract_icmp6_probe_id(icmp6, icmp6_len, &id_be)) return;
    if (icmp6_len > sizeof(g_reply6_q[0].pkt)) return;

    for (int i = 0; i < EDGE_ICMP6_REPLY_Q; ++i) {
        if (!__atomic_load_n(&g_reply6_q[i].used, __ATOMIC_ACQUIRE)) {
            slot = &g_reply6_q[i];
            break;
        }
    }
    if (!slot) slot = &g_reply6_q[0];

    __atomic_store_n(&slot->used, 0u, __ATOMIC_RELEASE);
    slot->id_be = id_be;
    slot->pkt_len = icmp6_len;
    memset(slot->src_ip6, 0, sizeof(slot->src_ip6));
    memset(slot->pkt, 0, sizeof(slot->pkt));

    edge_ip6_to_bytes(ip_2_ip6(src), slot->src_ip6);
    memcpy(slot->pkt, icmp6, icmp6_len);
    __atomic_store_n(&slot->used, 1u, __ATOMIC_RELEASE);
    edge_readiness_sequence_advance(&g_icmp_readiness_sequence);
}

static u8_t edge_lwip_icmp_recv(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
    uint8_t buf[1536];
    const uint8_t *icmp = 0;
    uint16_t icmp_len = 0;
    uint16_t n;
    (void)arg;
    (void)pcb;
    if (!p || !addr || !IP_IS_V4(addr)) return 0;
    n = p->tot_len > sizeof(buf) ? (uint16_t)sizeof(buf) : (uint16_t)p->tot_len;
    if (n < 8) return 0;
    if (pbuf_copy_partial(p, buf, n, 0) != n) return 0;

    if ((buf[0] >> 4) == 4 && n >= 20) {
        uint16_t ihl = (uint16_t)((buf[0] & 0x0Fu) * 4u);
        if (ihl >= 20 && ihl + 8 <= n) {
            icmp = &buf[ihl];
            icmp_len = (uint16_t)(n - ihl);
        }
    } else {
        icmp = buf;
        icmp_len = n;
    }
    if (!icmp || icmp_len < 8) return 0;
    edge_queue_icmp_reply(icmp, icmp_len, ip4_addr_get_u32(ip_2_ip4(addr)));
    return 0;
}

static u8_t edge_lwip_icmp6_recv(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
    uint8_t buf[1600];
    const uint8_t *icmp6 = 0;
    uint16_t icmp6_len = 0;
    uint16_t n;
    (void)arg;
    (void)pcb;
    if (!p || !addr || !IP_IS_V6(addr)) return 0;
    n = p->tot_len > sizeof(buf) ? (uint16_t)sizeof(buf) : (uint16_t)p->tot_len;
    if (n < 8) return 0;
    if (pbuf_copy_partial(p, buf, n, 0) != n) return 0;

    if ((buf[0] >> 4) == 6 && n >= 48) {
        uint8_t nh = buf[6];
        if (nh == IP6_NEXTH_ICMP6) {
            icmp6 = &buf[40];
            icmp6_len = (uint16_t)(n - 40);
        }
    } else {
        icmp6 = buf;
        icmp6_len = n;
    }

    if (!icmp6 || icmp6_len < 8) return 0;
    edge_queue_icmp6_reply(icmp6, icmp6_len, addr);
    return 0;
}

static void edge_lwip_core_receive(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context) {
    uint8_t frame[1600];
    uint32_t len;
    struct pbuf *p;
    err_t err;

    (void)ifindex;
    (void)context;
    if (!packet || packet->total_length > sizeof(frame)) return;
    len = packet->total_length;
    if (edge_net_packet_linearize(packet, frame, sizeof(frame)) < 0 ||
        !g_ready || !len)
        return;
    g_rx_packets++;
    g_rx_bytes += len;
    edge_note_tcp_fin_rx(frame, len);
    edge_linux_packet_capture_rx(frame, len, 2);
    for (int i = 0; i < EDGE_PACKET_FRAME_Q; ++i) {
        if (!__atomic_load_n(&g_packet_q[i].used, __ATOMIC_ACQUIRE)) {
            g_packet_q[i].len = len;
            memcpy(g_packet_q[i].data, frame, len);
            __atomic_store_n(&g_packet_q[i].used, 1u, __ATOMIC_RELEASE);
            edge_readiness_sequence_advance(
                &g_packet_frame_readiness_sequence);
            break;
        }
    }

    p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) return;
    if (pbuf_take(p, frame, (u16_t)len) != ERR_OK) {
        pbuf_free(p);
        return;
    }
    {
        uint32_t previous_namespace = g_lwip_ingress_namespace;
        uint8_t previous_active = g_lwip_ingress_active;

        g_lwip_ingress_namespace = network_namespace;
        g_lwip_ingress_active = 1u;
        err = g_lwip_netif.input(p, &g_lwip_netif);
        g_lwip_ingress_namespace = previous_namespace;
        g_lwip_ingress_active = previous_active;
    }
    if (err != ERR_OK) {
        printf("[net] lwip: netif->input err=%d\n", (int)err);
        pbuf_free(p);
    }
}

static void edge_lwip_core_transmit(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context) {
    uint8_t frame[1600];
    int length;

    (void)ifindex;
    (void)network_namespace;
    (void)context;
    if (!g_netdev_handle || !packet ||
        packet->total_length > sizeof(frame))
        return;
    length = edge_net_packet_linearize(packet, frame, sizeof(frame));
    if (length < 0 || edge_netdev_transmit(
            g_netdev_handle, frame, (uint32_t)length) < 0)
        return;
    edge_linux_packet_capture_tx(frame, (uint32_t)length, 2);
    ++g_tx_packets;
    g_tx_bytes += (uint32_t)length;
}

static void edge_lwip_rx_frame_cb(const uint8_t *frame, uint32_t len,
                                  void *context) {
    edge_net_packet_segment_t segment;
    edge_net_packet_metadata_t metadata;
    edge_net_packet_t packet;

    (void)context;
    if (!frame || !len) return;
    segment.data = frame;
    segment.length = len;
    memset(&metadata, 0, sizeof(metadata));
    metadata.input_ifindex = 2;
    metadata.timestamp_ns = boottime_monotonic_us() * 1000u;
    if (edge_net_packet_initialize(
            &packet, &segment, 1u, &metadata, 0, 0) != EDGE_NET_OK)
        return;
    (void)edge_net_device_receive(2, &packet);
}

static int edge_lwip_register_physical_device(
    const uint8_t hardware_address[6], uint32_t mtu, int link_up) {
    edge_net_device_configuration_t configuration;
    int result;

    memset(&configuration, 0, sizeof(configuration));
    configuration.ifindex = 2;
    configuration.kind = EDGE_NET_DEVICE_PHYSICAL;
    configuration.flags = EDGE_NET_DEVICE_FLAG_UP |
        EDGE_NET_DEVICE_FLAG_BROADCAST |
        EDGE_NET_DEVICE_FLAG_MULTICAST;
    if (link_up) configuration.flags |= EDGE_NET_DEVICE_FLAG_RUNNING;
    configuration.mtu = mtu;
    configuration.carrier = link_up ? 1u : 0u;
    memcpy(configuration.hardware_address, hardware_address, 6u);
    memcpy(configuration.name, "eth0", 5u);
    configuration.receive = edge_lwip_core_receive;
    configuration.transmit = edge_lwip_core_transmit;
    result = edge_net_device_register(&configuration);
    if (result == EDGE_NET_EXISTS) {
        (void)edge_net_device_unregister(2);
        result = edge_net_device_register(&configuration);
    }
    return result;
}

void lwip_stack_init(void) {
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
    ip4_addr_t gw;

    if (!g_core_ready) {
        lwip_init();
        g_core_ready = 1;
    }
    if (g_ready) return;
    g_netdev_handle = edge_netdev_get_active();
    if (!g_netdev_handle ||
        edge_netdev_set_up(g_netdev_handle, 1) != 0)
        return;
    g_rx_packets = 0;
    g_rx_bytes = 0;
    g_tx_packets = 0;
    g_tx_bytes = 0;
    memset(g_ipv6_prefix_lengths, 0, sizeof(g_ipv6_prefix_lengths));

    /*
     * Keep the QEMU user-net defaults configured inside lwIP until the Linux
     * network configuration ABI is complete enough for DHCP-only operation.
     * The temporary DHCP-only change left the stack unusable when userland's
     * route/address update path missed an edge case, which regressed apk.
     *
     * Red flag: this is a compatibility fallback for the current built-in
     * QEMU/e1000 path, not a rootfs or application special case.  Remove it
     * only after SIOCSIFFLAGS/SIOCSIFADDR/SIOCADDRT, rtnetlink, AF_PACKET,
     * ARP, and route deletion/replacement are validated via serial with
     * Alpine udhcpc and apk.
     */
    IP4_ADDR(&ipaddr, 10, 0, 2, 15);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 10, 0, 2, 2);

    if (!netif_add(&g_lwip_netif, &ipaddr, &netmask, &gw, 0, edge_lwip_netif_init, ethernet_input)) {
        printf("[net] lwip: netif_add failed\n");
        return;
    }
    if (edge_lwip_register_physical_device(
            g_lwip_netif.hwaddr, g_lwip_netif.mtu,
            netif_is_link_up(&g_lwip_netif)) != EDGE_NET_OK) {
        printf("[net] lwip: shared physical device registration failed\n");
        netif_remove(&g_lwip_netif);
        return;
    }
    if (edge_linux_netfilter_enable_datapath() < 0) {
        printf("[net] shared nftables data path registration failed\n");
        netif_remove(&g_lwip_netif);
        return;
    }

#if LWIP_IPV6
#if LWIP_IPV6_AUTOCONFIG
    g_lwip_netif.ip6_autoconfig_enabled =
        g_ipv6_disabled ? 0 : g_ipv6_autoconf;
#endif
    if (!g_ipv6_disabled)
        netif_create_ip6_linklocal_address(&g_lwip_netif, 1);
    g_ipv6_prefix_lengths[0] = 64u;
#if !LWIP_HAVE_LOOPIF
    {
        ip6_addr_t loopback;
        ip6_addr_set_loopback(&loopback);
        netif_ip6_addr_set(&g_lwip_netif, 1, &loopback);
        netif_ip6_addr_set_state(&g_lwip_netif, 1, IP6_ADDR_PREFERRED);
    }
#endif
#endif

    netif_set_default(&g_lwip_netif);
    netif_set_up(&g_lwip_netif);
    netif_set_link_up(&g_lwip_netif);
    edge_linux_netfilter_set_ipv4_masquerade_address(
        ip4_addr_get_u32(netif_ip4_addr(&g_lwip_netif)));
    edge_linux_rtnetlink_set_ipv4_provider(&g_ipv4_provider);
    edge_linux_rtnetlink_set_ipv6_provider(&g_ipv6_provider);

    g_icmp_raw = raw_new(IP_PROTO_ICMP);
    if (!g_icmp_raw) {
        printf("[net] lwip: raw_new(ICMP) failed\n");
        return;
    }
    raw_recv(g_icmp_raw, edge_lwip_icmp_recv, 0);
    raw_bind(g_icmp_raw, IP_ADDR_ANY);

#if LWIP_IPV6
    g_icmp6_raw = raw_new_ip_type(IPADDR_TYPE_V6, IP6_NEXTH_ICMP6);
    if (!g_icmp6_raw) {
        printf("[net] lwip: raw_new(ICMPv6) failed\n");
        return;
    }
    raw_recv(g_icmp6_raw, edge_lwip_icmp6_recv, 0);
    {
        ip_addr_t any6;
        ip_addr_set_any(1, &any6);
        raw_bind(g_icmp6_raw, &any6);
    }
    g_icmp6_raw->chksum_reqd = 1;
    g_icmp6_raw->chksum_offset = 2;
#endif

    if (edge_netdev_set_receive_callback(g_netdev_handle,
        edge_lwip_rx_frame_cb, 0) != 0) {
        (void)edge_netdev_set_up(g_netdev_handle, 0);
        g_netdev_handle = 0;
        return;
    }
    if (edge_netdev_set_link_callback(g_netdev_handle,
        edge_lwip_link_state_changed, 0) != 0) {
        (void)edge_netdev_set_receive_callback(
            g_netdev_handle, 0, 0);
        (void)edge_netdev_set_up(g_netdev_handle, 0);
        g_netdev_handle = 0;
        return;
    }
    g_ready = 1;
    edge_linux_rtnetlink_set_ipv4_update_callback(
        lwip_stack_configure_local_ipv4_alias);
    edge_try_reload_hostname_from_file();
    edge_try_reload_dns_from_resolv_conf();
    printf("[net] lwip: ready ip=10.0.2.15 gw=10.0.2.2\n");
#if LWIP_IPV6
    {
        char ip6buf[48];
        if (ip6addr_ntoa_r(netif_ip6_addr(&g_lwip_netif, 0), ip6buf, sizeof(ip6buf))) {
            printf("[net] lwip: ipv6 ll=%s\n", ip6buf);
        }
    }
#endif
}

void lwip_stack_poll(void) {
    edge_netdev_handle_t handle;
    uint64_t now_ns;
    uint32_t expected = 0u;

    if (!__atomic_compare_exchange_n(
            &g_poll_active, &expected, 1u, 0,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return;
    lwip_stack_core_enter();
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    bsd_kthread_pump();
#endif
    if (!g_ready) {
        handle = edge_netdev_get_active();
        if (handle)
            (void)lwip_stack_bind_netdev(handle);
        if (!g_ready) {
            lwip_stack_core_exit();
            __atomic_store_n(&g_poll_active, 0u, __ATOMIC_RELEASE);
            return;
        }
    }
    if (g_netdev_handle)
        edge_netdev_poll(g_netdev_handle);
    netif_poll_all();
    /* Virtual frames are delivered only at stable protocol-stack boundaries. */
    edge_lwip_deferred_drain();
    sys_check_timeouts();
    edge_lwip_deferred_drain();
    now_ns = boottime_monotonic_us() * 1000u;
    if (now_ns - g_bridge_last_age_ns >=
            EDGE_LWIP_BRIDGE_AGE_INTERVAL_NS) {
        edge_net_bridge_fdb_age(
            now_ns, EDGE_LWIP_BRIDGE_FDB_MAX_AGE_NS);
        edge_net_bridge_mdb_age(
            now_ns, EDGE_LWIP_BRIDGE_MDB_MAX_AGE_NS);
        g_bridge_last_age_ns = now_ns;
    }
#ifdef CONFIG_NFSD
    edge_nfsd_poll();
#endif
    lwip_stack_core_exit();
    __atomic_store_n(&g_poll_active, 0u, __ATOMIC_RELEASE);
}

int lwip_stack_is_ready(void) {
    return g_ready ? 1 : 0;
}

int
lwip_stack_bind_netdev(edge_netdev_handle_t handle)
{
    edge_netdev_handle_t previous = g_netdev_handle;
    uint8_t mac[EDGE_NETDEV_MAC_LENGTH];
    uint32_t mtu;
    int link_up;

    if (!handle ||
        edge_netdev_get_info(handle, 0, 0, mac, &mtu, &link_up, 0) != 0)
        return -1;
    if (!g_ready) {
        if (edge_netdev_set_active(handle) != 0)
            return -1;
        lwip_stack_init();
        return g_ready && g_netdev_handle == handle ? 0 : -1;
    }
    if (previous == handle)
        return 0;
    if (edge_netdev_set_receive_callback(handle,
        edge_lwip_rx_frame_cb, 0) != 0 ||
        edge_netdev_set_up(handle, 1) != 0) {
        (void)edge_netdev_set_receive_callback(handle, 0, 0);
        return -1;
    }
    if (edge_netdev_get_info(handle, 0, 0, mac, &mtu,
        &link_up, 0) != 0) {
        (void)edge_netdev_set_up(handle, 0);
        (void)edge_netdev_set_receive_callback(handle, 0, 0);
        return -1;
    }
    if (edge_netdev_set_link_callback(handle,
        edge_lwip_link_state_changed, 0) != 0) {
        (void)edge_netdev_set_up(handle, 0);
        (void)edge_netdev_set_receive_callback(handle, 0, 0);
        return -1;
    }
    if (edge_netdev_set_active(handle) != 0) {
        (void)edge_netdev_set_link_callback(handle, 0, 0);
        (void)edge_netdev_set_up(handle, 0);
        (void)edge_netdev_set_receive_callback(handle, 0, 0);
        return -1;
    }
    g_netdev_handle = handle;
    memcpy(g_lwip_netif.hwaddr, mac, sizeof(mac));
    g_lwip_netif.mtu = (uint16_t)mtu;
    if (link_up)
        netif_set_link_up(&g_lwip_netif);
    else
        netif_set_link_down(&g_lwip_netif);
    (void)edge_net_device_set_link(
        2, link_up ? EDGE_NET_DEVICE_FLAG_RUNNING : 0u,
        EDGE_NET_DEVICE_FLAG_RUNNING, mtu, 1);
    (void)edge_net_device_set_carrier(2, link_up);
    if (previous) {
        (void)edge_netdev_set_link_callback(previous, 0, 0);
        (void)edge_netdev_set_receive_callback(previous, 0, 0);
        (void)edge_netdev_set_up(previous, 0);
    }
    return 0;
}

int
lwip_stack_unbind_netdev(edge_netdev_handle_t handle)
{
    if (!handle || handle != g_netdev_handle)
        return -1;
    if (edge_netdev_set_link_callback(handle, 0, 0) != 0)
        return -1;
    if (edge_netdev_set_receive_callback(handle, 0, 0) != 0) {
        (void)edge_netdev_set_link_callback(handle,
            edge_lwip_link_state_changed, 0);
        return -1;
    }
    if (edge_netdev_set_up(handle, 0) != 0) {
        (void)edge_netdev_set_receive_callback(handle,
            edge_lwip_rx_frame_cb, 0);
        (void)edge_netdev_set_link_callback(handle,
            edge_lwip_link_state_changed, 0);
        return -1;
    }
    g_netdev_handle = 0;
    if (g_ready) {
        netif_set_link_down(&g_lwip_netif);
        (void)edge_net_device_set_link(
            2, 0u, EDGE_NET_DEVICE_FLAG_RUNNING, 0u, 0);
        (void)edge_net_device_set_carrier(2, 0);
    }
    return 0;
}

edge_netdev_handle_t
lwip_stack_get_netdev(void)
{
    return g_netdev_handle;
}

int lwip_stack_configure_ipv4(uint32_t addr_be, uint32_t netmask_be, uint32_t gw_be) {
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
    if (!g_ready) return -1;
    ipaddr.addr = addr_be;
    netmask.addr = netmask_be;
    gw.addr = gw_be;
    netif_set_addr(&g_lwip_netif, &ipaddr, &netmask, &gw);
    edge_linux_netfilter_set_ipv4_masquerade_address(addr_be);
    return 0;
}

int lwip_stack_get_ipv4(uint32_t *addr_be, uint32_t *netmask_be, uint32_t *gw_be) {
    if (!g_ready) return -1;
    if (addr_be) *addr_be = ip4_addr_get_u32(netif_ip4_addr(&g_lwip_netif));
    if (netmask_be) *netmask_be = ip4_addr_get_u32(netif_ip4_netmask(&g_lwip_netif));
    if (gw_be) *gw_be = ip4_addr_get_u32(netif_ip4_gw(&g_lwip_netif));
    return 0;
}

int lwip_stack_get_ipv4_neighbor(int ordinal, uint32_t *addr_be,
                                 uint8_t mac_out[6], int *ifindex_out) {
    int current = 0;
    if (ordinal < 0 || !addr_be || !mac_out || !ifindex_out || !g_ready)
        return -1;
    for (size_t index = 0; index < ARP_TABLE_SIZE; ++index) {
        ip4_addr_t *address;
        struct netif *netif;
        struct eth_addr *ethernet;
        if (!etharp_get_entry(index, &address, &netif, &ethernet) ||
            netif != &g_lwip_netif)
            continue;
        if (current++ != ordinal) continue;
        *addr_be = address->addr;
        memcpy(mac_out, ethernet->addr, 6u);
        *ifindex_out = 2;
        return 0;
    }
    return -1;
}

int lwip_stack_get_mac(uint8_t mac_out[6]) {
    if (!g_ready || !mac_out || g_lwip_netif.hwaddr_len < 6u) return -1;
    memcpy(mac_out, g_lwip_netif.hwaddr, 6u);
    return 0;
}

int lwip_stack_set_link_state(int up) {
    if (!g_ready) return -1;
    if (up) {
        netif_set_up(&g_lwip_netif);
        netif_set_link_up(&g_lwip_netif);
    } else {
        netif_set_link_down(&g_lwip_netif);
        netif_set_down(&g_lwip_netif);
    }
    (void)edge_net_device_set_link(
        2,
        up ? EDGE_NET_DEVICE_FLAG_UP | EDGE_NET_DEVICE_FLAG_RUNNING : 0u,
        EDGE_NET_DEVICE_FLAG_UP | EDGE_NET_DEVICE_FLAG_RUNNING, 0u, 0);
    (void)edge_net_device_set_carrier(2, up);
    return 0;
}

int lwip_stack_get_link_state(void) {
    return g_ready && netif_is_up(&g_lwip_netif) && netif_is_link_up(&g_lwip_netif);
}

int lwip_stack_set_mtu(uint16_t mtu) {
    if (!g_ready || mtu < 68u) return -1;
    if (edge_net_device_set_link(2, 0u, 0u, mtu, 1) != EDGE_NET_OK)
        return -1;
    g_lwip_netif.mtu = mtu;
    return 0;
}

uint16_t lwip_stack_get_mtu(void) {
    return g_ready ? g_lwip_netif.mtu : 0u;
}

int lwip_stack_send_packet_frame(const void *frame, uint16_t len) {
    edge_net_packet_segment_t segment;
    edge_net_packet_metadata_t metadata;
    edge_net_packet_t packet;

    if (!g_ready || !g_netdev_handle || !frame || len == 0) return -1;
    segment.data = (const uint8_t *)frame;
    segment.length = len;
    memset(&metadata, 0, sizeof(metadata));
    metadata.output_ifindex = 2;
    metadata.timestamp_ns = boottime_monotonic_us() * 1000u;
    if (edge_net_packet_initialize(
            &packet, &segment, 1u, &metadata, 0, 0) != EDGE_NET_OK)
        return -1;
    return edge_net_device_transmit(2, &packet) == EDGE_NET_OK ? 0 : -1;
}

int lwip_stack_recv_packet_frame(uint8_t *frame_out, uint32_t *len_out) {
    if (!g_ready || !len_out) return -1;
    lwip_stack_poll();
    for (int i = 0; i < EDGE_PACKET_FRAME_Q; ++i) {
        edge_packet_frame_t *p = &g_packet_q[i];
        if (!__atomic_load_n(&p->used, __ATOMIC_ACQUIRE)) continue;
        if (!frame_out || *len_out < p->len) {
            *len_out = p->len;
            return -1;
        }
        memcpy(frame_out, p->data, p->len);
        *len_out = p->len;
        __atomic_store_n(&p->used, 0u, __ATOMIC_RELEASE);
        return 1;
    }
    return 0;
}

int lwip_stack_packet_frame_pending(void) {
    if (!g_ready) return 0;
    lwip_stack_poll();
    for (int i = 0; i < EDGE_PACKET_FRAME_Q; ++i)
        if (__atomic_load_n(&g_packet_q[i].used, __ATOMIC_ACQUIRE)) return 1;
    return 0;
}

uint64_t lwip_stack_packet_frame_readiness_sequence(void) {
    return __atomic_load_n(&g_packet_frame_readiness_sequence,
                           __ATOMIC_ACQUIRE);
}

int lwip_stack_send_raw_ipv4(const uint8_t *packet, uint16_t len) {
    struct raw_pcb *pcb;
    struct pbuf *p;
    ip_addr_t destination;
    err_t result;
    if (!g_ready || !packet || len < sizeof(edge_ipv4_hdr_t) ||
        (packet[0] >> 4) != 4) return -1;
    if (((const edge_ipv4_hdr_t *)packet)->dst_be == 0xffffffffu) {
        if ((uint32_t)len + 14u > sizeof(g_raw_ipv4_frame)) return -1;
        memset(g_raw_ipv4_frame, 0xff, 6u);
        if (g_lwip_netif.hwaddr_len < 6u) return -1;
        memcpy(g_raw_ipv4_frame + 6u, g_lwip_netif.hwaddr, 6u);
        g_raw_ipv4_frame[12] = 0x08u;
        g_raw_ipv4_frame[13] = 0x00u;
        memcpy(g_raw_ipv4_frame + 14u, packet, len);
        if (edge_prepare_ipv4_hdrincl(g_raw_ipv4_frame + 14u, len) < 0)
            return -1;
        return lwip_stack_send_packet_frame(
            g_raw_ipv4_frame, (uint16_t)(len + 14u));
    }
    pcb = raw_new(255u);
    if (!pcb) return -1;
#ifdef RAW_FLAGS_HDRINCL
    pcb->flags |= RAW_FLAGS_HDRINCL;
#endif
    p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    if (!p) {
        raw_remove(pcb);
        return -1;
    }
    if (pbuf_take(p, packet, len) != ERR_OK) {
        pbuf_free(p);
        raw_remove(pcb);
        return -1;
    }
    if (p->len < sizeof(edge_ipv4_hdr_t) ||
        edge_prepare_ipv4_hdrincl((uint8_t *)p->payload, len) < 0) {
        pbuf_free(p);
        raw_remove(pcb);
        return -1;
    }
    ip_addr_set_zero(&destination);
    ip_2_ip4(&destination)->addr =
        ((const edge_ipv4_hdr_t *)p->payload)->dst_be;
    result = raw_sendto(pcb, p, &destination);
    pbuf_free(p);
    raw_remove(pcb);
    return result == ERR_OK ? 0 : -1;
}

int lwip_stack_send_icmp_echo(
    uint32_t network_namespace, uint32_t dst_ip_be,
    const uint8_t *icmp_payload, uint16_t icmp_len, uint8_t ttl) {
    struct pbuf *p;
    ip_addr_t dst;
    ip_addr_t source;
    struct netif *output_interface;
    edge_linux_route_query_t query;
    edge_linux_route_result_t route;
    edge_net_device_snapshot_t snapshot;
    uint32_t source_ip_be;
    err_t err;
    uint8_t icmp_buf[1600];

    if (!g_ready || !g_icmp_raw || !icmp_payload || icmp_len < 8) {
        return -1;
    }
    if (icmp_len > sizeof(icmp_buf)) return -1;

    p = pbuf_alloc(PBUF_IP, icmp_len, PBUF_RAM);
    if (!p) return -1;

    memcpy(icmp_buf, icmp_payload, icmp_len);
    icmp_buf[2] = 0;
    icmp_buf[3] = 0;
    {
        uint16_t csum = edge_cksum16(icmp_buf, icmp_len);
        icmp_buf[2] = (uint8_t)(csum >> 8);
        icmp_buf[3] = (uint8_t)(csum & 0xFFu);
    }
    if (pbuf_take(p, icmp_buf, icmp_len) != ERR_OK) {
        pbuf_free(p);
        return -1;
    }

    ip_addr_set_zero(&dst);
    ip_2_ip4(&dst)->addr = dst_ip_be;
    memset(&query, 0, sizeof(query));
    query.network_namespace = network_namespace;
    query.family = EDGE_LINUX_AF_INET;
    memcpy(query.destination, &dst_ip_be, 4u);
    if (edge_linux_route_lookup(&query, &route) < 0 ||
        route.output_ifindex <= 0 ||
        edge_net_device_snapshot(
            route.output_ifindex, &snapshot) != EDGE_NET_OK ||
        snapshot.configuration.network_namespace != network_namespace) {
        pbuf_free(p);
        return -1;
    }
    output_interface = edge_lwip_neighbor_netif(
        network_namespace, route.output_ifindex);
    if (!output_interface) {
        pbuf_free(p);
        return -1;
    }
    memcpy(&source_ip_be, route.preferred_source, 4u);
    if (!source_ip_be) source_ip_be = snapshot.ipv4_address;
    if (!source_ip_be) {
        pbuf_free(p);
        return -1;
    }
    ip_addr_set_zero(&source);
    ip_2_ip4(&source)->addr = source_ip_be;
    if (ttl == 0) ttl = 64;
    g_icmp_raw->ttl = ttl;
    err = raw_sendto_if_src(
        g_icmp_raw, p, &dst, output_interface, &source);
    pbuf_free(p);
    return err == ERR_OK ? 0 : -1;
}

int lwip_stack_send_icmpv6_echo(
    uint32_t network_namespace, const uint8_t dst_ip6[16],
    const uint8_t *icmp_payload, uint16_t icmp_len, uint8_t hop_limit) {
#if LWIP_IPV6
    struct pbuf *p;
    ip_addr_t dst;
    ip_addr_t source;
    struct netif *output_interface;
    edge_linux_route_query_t query;
    edge_linux_route_result_t route;
    edge_net_device_snapshot_t snapshot;
    const ip_addr_t *selected_source;
    uint8_t icmp_buf[1600];
    err_t err;

    if (!g_ready || !g_icmp6_raw || !dst_ip6 || !icmp_payload || icmp_len < 8) return -1;
    if (icmp_len > sizeof(icmp_buf)) return -1;

    p = pbuf_alloc(PBUF_IP, icmp_len, PBUF_RAM);
    if (!p) return -1;

    memcpy(icmp_buf, icmp_payload, icmp_len);
    icmp_buf[2] = 0;
    icmp_buf[3] = 0;
    if (pbuf_take(p, icmp_buf, icmp_len) != ERR_OK) {
        pbuf_free(p);
        return -1;
    }

    ip_addr_set_zero_ip6(&dst);
    edge_ip6_from_bytes(ip_2_ip6(&dst), dst_ip6);
    memset(&query, 0, sizeof(query));
    query.network_namespace = network_namespace;
    query.family = EDGE_LINUX_AF_INET6;
    memcpy(query.destination, dst_ip6, 16u);
    if (edge_linux_route_lookup(&query, &route) < 0 ||
        route.output_ifindex <= 0 ||
        edge_net_device_snapshot(
            route.output_ifindex, &snapshot) != EDGE_NET_OK ||
        snapshot.configuration.network_namespace != network_namespace) {
        pbuf_free(p);
        return -1;
    }
    output_interface = edge_lwip_neighbor_netif(
        network_namespace, route.output_ifindex);
    if (!output_interface) {
        pbuf_free(p);
        return -1;
    }
    selected_source = ip6_select_source_address(
        output_interface, ip_2_ip6(&dst));
    if (!selected_source || !IP_IS_V6(selected_source)) {
        pbuf_free(p);
        return -1;
    }
    ip_addr_copy(source, *selected_source);
    if (hop_limit == 0) hop_limit = 64;
    g_icmp6_raw->ttl = hop_limit;
    err = raw_sendto_if_src(
        g_icmp6_raw, p, &dst, output_interface, &source);
    pbuf_free(p);
    return err == ERR_OK ? 0 : -1;
#else
    (void)network_namespace;
    (void)dst_ip6;
    (void)icmp_payload;
    (void)icmp_len;
    (void)hop_limit;
    return -1;
#endif
}

int lwip_stack_recv_icmp_reply_for_id(uint16_t id_be, uint8_t *ip_packet_out, uint32_t *ip_packet_len, uint32_t *src_ip_be) {
    if (!g_ready || !ip_packet_len) return -1;

    lwip_stack_poll();

    for (int i = 0; i < EDGE_ICMP_REPLY_Q; ++i) {
        edge_icmp_reply_t *r = &g_reply_q[i];
        if (!__atomic_load_n(&r->used, __ATOMIC_ACQUIRE)) continue;
        if (r->id_be != id_be) continue;

        if (ip_packet_out && *ip_packet_len >= r->ip_len) {
            memcpy(ip_packet_out, r->ip_pkt, r->ip_len);
            *ip_packet_len = r->ip_len;
            if (src_ip_be) *src_ip_be = r->src_ip_be;
        } else {
            *ip_packet_len = r->ip_len;
            return -1;
        }

        __atomic_store_n(&r->used, 0u, __ATOMIC_RELEASE);
        return 1;
    }

    return 0;
}

int lwip_stack_icmp_reply_pending_for_id(uint16_t id_be) {
    if (!g_ready) return 0;
    lwip_stack_poll();
    for (int i = 0; i < EDGE_ICMP_REPLY_Q; ++i)
        if (__atomic_load_n(&g_reply_q[i].used, __ATOMIC_ACQUIRE) &&
            g_reply_q[i].id_be == id_be)
            return 1;
    return 0;
}

int lwip_stack_recv_icmp_packet(uint8_t *ip_packet_out, uint32_t *ip_packet_len, uint32_t *src_ip_be) {
    if (!g_ready || !ip_packet_len) return -1;

    lwip_stack_poll();

    for (int i = 0; i < EDGE_ICMP_RAW_Q; ++i) {
        edge_icmp_reply_t *r = &g_raw_icmp_q[i];
        if (!__atomic_load_n(&r->used, __ATOMIC_ACQUIRE)) continue;

        if (ip_packet_out && *ip_packet_len >= r->ip_len) {
            memcpy(ip_packet_out, r->ip_pkt, r->ip_len);
            *ip_packet_len = r->ip_len;
            if (src_ip_be) *src_ip_be = r->src_ip_be;
        } else {
            *ip_packet_len = r->ip_len;
            return -1;
        }

        __atomic_store_n(&r->used, 0u, __ATOMIC_RELEASE);
        return 1;
    }

    return 0;
}

int lwip_stack_icmp_packet_pending(void) {
    if (!g_ready) return 0;
    lwip_stack_poll();
    for (int i = 0; i < EDGE_ICMP_RAW_Q; ++i)
        if (__atomic_load_n(&g_raw_icmp_q[i].used, __ATOMIC_ACQUIRE))
            return 1;
    return 0;
}

uint64_t lwip_stack_icmp_readiness_sequence(void) {
    return __atomic_load_n(&g_icmp_readiness_sequence, __ATOMIC_ACQUIRE);
}

int lwip_stack_recv_icmpv6_reply_for_id(uint16_t id_be, uint8_t *packet_out, uint32_t *packet_len, uint8_t src_ip6_out[16]) {
#if LWIP_IPV6
    if (!g_ready || !packet_len) return -1;

    lwip_stack_poll();

    for (int i = 0; i < EDGE_ICMP6_REPLY_Q; ++i) {
        edge_icmp6_reply_t *r = &g_reply6_q[i];
        if (!__atomic_load_n(&r->used, __ATOMIC_ACQUIRE)) continue;
        if (r->id_be != id_be) continue;

        if (packet_out && *packet_len >= r->pkt_len) {
            memcpy(packet_out, r->pkt, r->pkt_len);
            *packet_len = r->pkt_len;
            if (src_ip6_out) memcpy(src_ip6_out, r->src_ip6, 16);
        } else {
            *packet_len = r->pkt_len;
            return -1;
        }

        __atomic_store_n(&r->used, 0u, __ATOMIC_RELEASE);
        return 1;
    }

    return 0;
#else
    (void)id_be;
    (void)packet_out;
    (void)packet_len;
    (void)src_ip6_out;
    return -1;
#endif
}

int lwip_stack_icmpv6_reply_pending_for_id(uint16_t id_be) {
#if LWIP_IPV6
    if (!g_ready) return 0;
    lwip_stack_poll();
    for (int i = 0; i < EDGE_ICMP6_REPLY_Q; ++i)
        if (__atomic_load_n(&g_reply6_q[i].used, __ATOMIC_ACQUIRE) &&
            g_reply6_q[i].id_be == id_be)
            return 1;
    return 0;
#else
    (void)id_be;
    return 0;
#endif
}

int lwip_stack_get_ipv6_addr(uint8_t out[16], int prefer_global) {
#if LWIP_IPV6
    if (!out || !g_ready) return -1;

    for (u8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; ++i) {
        const ip6_addr_t *a = netif_ip6_addr(&g_lwip_netif, i);
        u8_t st = netif_ip6_addr_state(&g_lwip_netif, i);
        if (!ip6_addr_isvalid(st) || ip6_addr_isany(a)) continue;
        if (prefer_global && ip6_addr_islinklocal(a)) continue;
        edge_ip6_to_bytes(a, out);
        return 0;
    }

    if (prefer_global) return lwip_stack_get_ipv6_addr(out, 0);
    return -1;
#else
    (void)out;
    (void)prefer_global;
    return -1;
#endif
}

int lwip_stack_get_ipv6_addr_at(int ordinal, uint8_t out[16], uint8_t *prefix_len, uint8_t *scope, uint8_t *flags) {
#if LWIP_IPV6
    int n = 0;
    if (!g_ready || ordinal < 0 || !out) return -1;

    for (u8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; ++i) {
        const ip6_addr_t *a = netif_ip6_addr(&g_lwip_netif, i);
        u8_t st = netif_ip6_addr_state(&g_lwip_netif, i);
        if (ip6_addr_isinvalid(st) || ip6_addr_isany(a)) continue;
        if (n++ != ordinal) continue;

        edge_ip6_to_bytes(a, out);
        if (prefix_len) {
            *prefix_len = g_ipv6_prefix_lengths[i] ?
                g_ipv6_prefix_lengths[i] :
                (ip6_addr_isloopback(a) ? 128u : 64u);
        }
        if (scope) {
            if (ip6_addr_isloopback(a)) *scope = 0x10u;
            else if (ip6_addr_islinklocal(a)) *scope = 0x20u;
            else if (ip6_addr_issitelocal(a)) *scope = 0x40u;
            else *scope = 0x00u;
        }
        if (flags) {
            *flags = netif_ip6_addr_isstatic(&g_lwip_netif, i) ? 0x80u : 0u;
            if (ip6_addr_istentative(st)) *flags |= 0x40u;
            if (st == IP6_ADDR_DEPRECATED) *flags |= 0x20u;
            if (st == IP6_ADDR_DUPLICATED) *flags |= 0x08u;
        }
        return 0;
    }
    return -1;
#else
    (void)ordinal;
    (void)out;
    (void)prefix_len;
    (void)scope;
    (void)flags;
    return -1;
#endif
}

int lwip_stack_configure_ipv6(const uint8_t address[16],
                              uint8_t prefix_length, int active) {
    return lwip_stack_configure_interface_ipv6(
        2, 0u, address, prefix_length, 0x02u,
        UINT32_MAX, UINT32_MAX, active);
}

int lwip_stack_configure_interface_ipv6(
    int32_t ifindex, uint32_t network_namespace,
    const uint8_t address[16], uint8_t prefix_length,
    uint32_t flags, uint32_t valid_lifetime,
    uint32_t preferred_lifetime, int active) {
#if LWIP_IPV6
    edge_lwip_virtual_netif_t *entry = 0;
    edge_net_device_snapshot_t snapshot;
    struct netif *netif;
    uint8_t *prefix_lengths;
    ip6_addr_t parsed;
    s8_t index;

    if (!g_ready || !address || prefix_length > 128u) return -1;
    if (ifindex == 2 && network_namespace == 0u) {
        netif = &g_lwip_netif;
        prefix_lengths = g_ipv6_prefix_lengths;
    } else {
        if (ifindex <= 2 ||
            edge_net_device_snapshot(ifindex, &snapshot) != EDGE_NET_OK ||
            snapshot.configuration.network_namespace != network_namespace)
            return -1;
        entry = edge_lwip_virtual_find(ifindex);
        if (!entry && active)
            entry = edge_lwip_virtual_ensure(
                ifindex, network_namespace, &snapshot);
        if (!entry) return active ? -1 : 0;
        netif = &entry->netif;
        prefix_lengths = entry->ipv6_prefix_lengths;
    }
    edge_ip6_from_bytes(&parsed, address);
    index = netif_get_ip6_addr_match(netif, &parsed);
    if (!active) {
        if (index < 0) return 0;
        netif_ip6_addr_set_state(netif, index, IP6_ADDR_INVALID);
        ip_addr_set_zero_ip6(&netif->ip6_addr[index]);
        prefix_lengths[index] = 0u;
        nd6_clear_destination_cache();
        if (entry && !entry->ipv4_active &&
            !edge_lwip_virtual_has_ipv6(entry))
            edge_lwip_virtual_remove(entry);
        return 0;
    }
    if (index < 0 && netif_add_ip6_address(
            netif, &parsed, &index) != ERR_OK)
        return -1;
    if (index < 0) return -1;
    prefix_lengths[index] = prefix_length;
#if LWIP_IPV6_ADDRESS_LIFETIMES
    netif_ip6_addr_set_valid_life(
        netif, index, valid_lifetime == UINT32_MAX ?
            IP6_ADDR_LIFE_STATIC : valid_lifetime);
    netif_ip6_addr_set_pref_life(
        netif, index, preferred_lifetime == UINT32_MAX ?
            IP6_ADDR_LIFE_STATIC : preferred_lifetime);
#endif
    if (flags & 0x02u)
        netif_ip6_addr_set_state(netif, index, IP6_ADDR_PREFERRED);
    if (entry) edge_lwip_virtual_apply_link_state(entry, &snapshot);
    nd6_clear_destination_cache();
    return 0;
#else
    (void)ifindex;
    (void)network_namespace;
    (void)address;
    (void)prefix_length;
    (void)flags;
    (void)valid_lifetime;
    (void)preferred_lifetime;
    (void)active;
    return -1;
#endif
}

int lwip_stack_get_ipv6_router(int ordinal, uint8_t address[16],
                               uint32_t *lifetime, uint8_t *preference) {
#if LWIP_IPV6
    int match = 0;

    if (!g_ready || ordinal < 0 || !address) return -1;
    for (int index = 0; index < LWIP_ND6_NUM_ROUTERS; ++index) {
        const struct nd6_router_list_entry *router =
            &default_router_list[index];

        if (!router->neighbor_entry ||
            router->neighbor_entry->netif != &g_lwip_netif)
            continue;
        if (match++ != ordinal) continue;
        edge_ip6_to_bytes(
            &router->neighbor_entry->next_hop_address, address);
        if (lifetime) {
            *lifetime = router->invalidation_timer == UINT32_MAX ?
                UINT32_MAX : router->invalidation_timer;
        }
        if (preference) *preference = (router->flags >> 3u) & 0x03u;
        return 0;
    }
    return -1;
#else
    (void)ordinal;
    (void)address;
    (void)lifetime;
    (void)preference;
    return -1;
#endif
}

int lwip_stack_configure_ipv6_default_router(const uint8_t address[16],
                                              int active) {
#if LWIP_IPV6
    ip6_addr_t parsed;
    int neighbor_index = -1;
    int router_index = -1;
    int free_neighbor = -1;
    int free_router = -1;

    if (!g_ready || !address) return -1;
    edge_ip6_from_bytes(&parsed, address);
    ip6_addr_assign_zone(&parsed, IP6_UNICAST, &g_lwip_netif);
    if (!ip6_addr_islinklocal(&parsed)) return -1;

    for (int index = 0; index < LWIP_ND6_NUM_NEIGHBORS; ++index) {
        struct nd6_neighbor_cache_entry *neighbor = &neighbor_cache[index];

        if (neighbor->state == ND6_NO_ENTRY) {
            if (free_neighbor < 0) free_neighbor = index;
            continue;
        }
        if (neighbor->netif == &g_lwip_netif &&
            ip6_addr_eq(&neighbor->next_hop_address, &parsed)) {
            neighbor_index = index;
            break;
        }
    }
    if (neighbor_index >= 0) {
        for (int index = 0; index < LWIP_ND6_NUM_ROUTERS; ++index) {
            if (default_router_list[index].neighbor_entry ==
                &neighbor_cache[neighbor_index]) {
                router_index = index;
                break;
            }
        }
    }
    if (!active) {
        if (router_index < 0) return 0;
        default_router_list[router_index].neighbor_entry->isrouter = 0;
        default_router_list[router_index].neighbor_entry = 0;
        default_router_list[router_index].invalidation_timer = 0;
        default_router_list[router_index].flags = 0;
        nd6_clear_destination_cache();
        return 0;
    }
    if (neighbor_index < 0) {
        struct nd6_neighbor_cache_entry *neighbor;

        if (free_neighbor < 0) return -1;
        neighbor_index = free_neighbor;
        neighbor = &neighbor_cache[neighbor_index];
        memset(neighbor, 0, sizeof(*neighbor));
        ip6_addr_set(&neighbor->next_hop_address, &parsed);
        neighbor->netif = &g_lwip_netif;
        neighbor->state = ND6_INCOMPLETE;
    }
    neighbor_cache[neighbor_index].isrouter = 1;
    if (router_index < 0) {
        for (int index = 0; index < LWIP_ND6_NUM_ROUTERS; ++index) {
            if (!default_router_list[index].neighbor_entry) {
                free_router = index;
                break;
            }
        }
        if (free_router < 0) {
            neighbor_cache[neighbor_index].isrouter = 0;
            return -1;
        }
        router_index = free_router;
        default_router_list[router_index].neighbor_entry =
            &neighbor_cache[neighbor_index];
    }
    default_router_list[router_index].invalidation_timer = UINT32_MAX;
    nd6_clear_destination_cache();
    return 0;
#else
    (void)address;
    (void)active;
    return -1;
#endif
}

static uint8_t *edge_ipv6_setting_storage(lwip_ipv6_scope_t scope,
                                          lwip_ipv6_setting_t setting) {
    uint8_t *disabled;
    uint8_t *forwarding;
    uint8_t *accept_ra;
    uint8_t *autoconf;

    if (scope == LWIP_IPV6_SCOPE_ALL) {
        disabled = &g_ipv6_all_disabled;
        forwarding = &g_ipv6_all_forwarding;
        accept_ra = &g_ipv6_all_accept_ra;
        autoconf = &g_ipv6_all_autoconf;
    } else if (scope == LWIP_IPV6_SCOPE_DEFAULT) {
        disabled = &g_ipv6_default_disabled;
        forwarding = &g_ipv6_default_forwarding;
        accept_ra = &g_ipv6_default_accept_ra;
        autoconf = &g_ipv6_default_autoconf;
    } else if (scope == LWIP_IPV6_SCOPE_ETH0 ||
               scope == LWIP_IPV6_SCOPE_FOR_IFINDEX(2)) {
        disabled = &g_ipv6_disabled;
        forwarding = &g_ipv6_forwarding;
        accept_ra = &g_ipv6_accept_ra;
        autoconf = &g_ipv6_autoconf;
    } else if (scope == LWIP_IPV6_SCOPE_FOR_IFINDEX(1)) {
        disabled = &g_ipv6_loopback_disabled;
        forwarding = &g_ipv6_loopback_forwarding;
        accept_ra = &g_ipv6_loopback_accept_ra;
        autoconf = &g_ipv6_loopback_autoconf;
    } else {
        return 0;
    }

    switch (setting) {
        case LWIP_IPV6_SETTING_DISABLE:
            return disabled;
        case LWIP_IPV6_SETTING_FORWARDING:
            return forwarding;
        case LWIP_IPV6_SETTING_ACCEPT_RA:
            return accept_ra;
        case LWIP_IPV6_SETTING_AUTOCONF:
            return autoconf;
        default:
            return 0;
    }
}

static int edge_ipv6_interface_scope_ifindex(lwip_ipv6_scope_t scope) {
    uint32_t value = (uint32_t)scope;

    if (scope == LWIP_IPV6_SCOPE_ETH0) return 2;
    if (value <= (uint32_t)LWIP_IPV6_SCOPE_INTERFACE_BASE)
        return -1;
    value -= (uint32_t)LWIP_IPV6_SCOPE_INTERFACE_BASE;
    return value <= INT32_MAX ? (int)value : -1;
}

static void edge_ipv6_apply_eth0_setting(
    lwip_ipv6_setting_t setting, int value) {
    if (!g_ready) return;
    if (setting == LWIP_IPV6_SETTING_DISABLE) {
        if (value) {
            g_lwip_netif.ip6_autoconfig_enabled = 0;
            nd6_cleanup_netif(&g_lwip_netif);
            for (u8_t index = 0; index < LWIP_IPV6_NUM_ADDRESSES;
                 ++index) {
                netif_ip6_addr_set_state(
                    &g_lwip_netif, index, IP6_ADDR_INVALID);
                g_ipv6_prefix_lengths[index] = 0;
            }
        } else {
            netif_create_ip6_linklocal_address(&g_lwip_netif, 1);
            g_lwip_netif.ip6_autoconfig_enabled = g_ipv6_autoconf;
            nd6_restart_netif(&g_lwip_netif);
        }
    } else if (setting == LWIP_IPV6_SETTING_AUTOCONF &&
               !g_ipv6_disabled) {
        g_lwip_netif.ip6_autoconfig_enabled = (u8_t)value;
        if (value) nd6_restart_netif(&g_lwip_netif);
    }
}

int lwip_stack_ipv6_setting_get_in_namespace(
    uint32_t network_namespace, lwip_ipv6_scope_t scope,
    lwip_ipv6_setting_t setting) {
#if LWIP_IPV6
    int ifindex;
    int interface_value;
    uint8_t *value;

    if (setting < LWIP_IPV6_SETTING_DISABLE ||
        setting > LWIP_IPV6_SETTING_AUTOCONF)
        return -1;
    ifindex = edge_ipv6_interface_scope_ifindex(scope);
    if (ifindex > 0 &&
        (ifindex > 2 || network_namespace != 0u)) {
        return edge_net_device_get_ipv6_setting(
            ifindex, (uint32_t)setting, &interface_value) == EDGE_NET_OK ?
                interface_value : -1;
    }
    if (scope == LWIP_IPV6_SCOPE_ALL ||
        scope == LWIP_IPV6_SCOPE_DEFAULT) {
        return edge_net_namespace_ipv6_setting_get(
            network_namespace, (uint32_t)setting,
            &interface_value) == EDGE_NET_OK ? interface_value : -1;
    }
    if (network_namespace != 0u) return -1;
    value = edge_ipv6_setting_storage(scope, setting);
    return value ? *value : -1;
#else
    (void)network_namespace;
    (void)scope;
    (void)setting;
    return -1;
#endif
}

int lwip_stack_ipv6_setting_get(lwip_ipv6_scope_t scope,
                                lwip_ipv6_setting_t setting) {
    return lwip_stack_ipv6_setting_get_in_namespace(0u, scope, setting);
}

int lwip_stack_ipv6_setting_set_in_namespace(
    uint32_t network_namespace, lwip_ipv6_scope_t scope,
    lwip_ipv6_setting_t setting, int value) {
#if LWIP_IPV6
    edge_net_device_snapshot_t snapshot;
    int ifindex;
    uint8_t *storage;

    if (value < 0 || value >
            (setting == LWIP_IPV6_SETTING_ACCEPT_RA ? 2 : 1) ||
        setting < LWIP_IPV6_SETTING_DISABLE ||
        setting > LWIP_IPV6_SETTING_AUTOCONF)
        return -1;
    ifindex = edge_ipv6_interface_scope_ifindex(scope);
    if (ifindex > 0 &&
        (ifindex > 2 || network_namespace != 0u)) {
        return edge_net_device_set_ipv6_setting(
            ifindex, (uint32_t)setting, value) == EDGE_NET_OK ? 0 : -1;
    }
    if (scope == LWIP_IPV6_SCOPE_DEFAULT)
        return edge_net_namespace_ipv6_setting_set(
            network_namespace, (uint32_t)setting, value) == EDGE_NET_OK ?
                0 : -1;
    if (scope == LWIP_IPV6_SCOPE_ALL) {
        if (edge_net_namespace_ipv6_setting_set(
                network_namespace, (uint32_t)setting,
                value) != EDGE_NET_OK)
            return -1;
        for (uint32_t ordinal = 0;
             edge_net_device_snapshot_at(
                 network_namespace, ordinal, &snapshot) == EDGE_NET_OK;
             ++ordinal) {
            (void)edge_net_device_set_ipv6_setting(
                snapshot.configuration.ifindex,
                (uint32_t)setting, value);
        }
        if (network_namespace != 0u) return 0;
    } else if (network_namespace != 0u) {
        return -1;
    }
    storage = edge_ipv6_setting_storage(scope, setting);
    if (!storage) return -1;
    *storage = (uint8_t)value;
    if (scope == LWIP_IPV6_SCOPE_ALL) {
        storage = edge_ipv6_setting_storage(
            LWIP_IPV6_SCOPE_ETH0, setting);
        if (storage) *storage = (uint8_t)value;
    } else {
        (void)edge_net_device_set_ipv6_setting(
            2, (uint32_t)setting, value);
    }
    edge_ipv6_apply_eth0_setting(setting, value);
    return 0;
#else
    (void)network_namespace;
    (void)scope;
    (void)setting;
    (void)value;
    return -1;
#endif
}

int lwip_stack_ipv6_setting_set(lwip_ipv6_scope_t scope,
                                lwip_ipv6_setting_t setting, int value) {
    return lwip_stack_ipv6_setting_set_in_namespace(
        0u, scope, setting, value);
}

int lwip_stack_get_ipv6_stats(lwip_stack_ipv6_stats_t *stats) {
    if (!stats) return -1;
    memset(stats, 0, sizeof(*stats));
#if LWIP_STATS && IP6_STATS
    stats->in_receives = lwip_stats.ip6.recv;
    stats->in_header_errors = (uint64_t)lwip_stats.ip6.chkerr +
        lwip_stats.ip6.lenerr + lwip_stats.ip6.err;
    stats->in_no_routes = lwip_stats.ip6.rterr;
    stats->in_unknown_protocols = lwip_stats.ip6.proterr;
    stats->in_discards = lwip_stats.ip6.drop;
    stats->in_delivers = lwip_stats.ip6.recv >= lwip_stats.ip6.drop ?
        lwip_stats.ip6.recv - lwip_stats.ip6.drop : 0;
    stats->out_forwards = lwip_stats.ip6.fw;
    stats->out_requests = lwip_stats.ip6.xmit;
    stats->out_no_routes = lwip_stats.ip6.rterr;
#endif
#if LWIP_STATS && IP6_FRAG_STATS
    stats->reassembly_requests = lwip_stats.ip6_frag.recv;
    stats->reassembly_failures = (uint64_t)lwip_stats.ip6_frag.drop +
        lwip_stats.ip6_frag.memerr + lwip_stats.ip6_frag.proterr;
    stats->fragments_created = lwip_stats.ip6_frag.xmit;
#endif
#if LWIP_STATS && ICMP6_STATS
    stats->icmp_in_messages = lwip_stats.icmp6.recv;
    stats->icmp_in_errors = (uint64_t)lwip_stats.icmp6.chkerr +
        lwip_stats.icmp6.lenerr + lwip_stats.icmp6.proterr +
        lwip_stats.icmp6.err;
    stats->icmp_out_messages = lwip_stats.icmp6.xmit;
    stats->icmp_out_errors = (uint64_t)lwip_stats.icmp6.rterr +
        lwip_stats.icmp6.memerr;
#endif
    return 0;
}

int lwip_stack_get_ipv6_neighbor(int ordinal, uint8_t address[16],
                                 uint8_t hardware_address[6],
                                 uint16_t *state, uint8_t *is_router) {
#if LWIP_IPV6
    int match = 0;

    if (!g_ready || ordinal < 0 || !address || !hardware_address) return -1;
    for (int index = 0; index < LWIP_ND6_NUM_NEIGHBORS; ++index) {
        const struct nd6_neighbor_cache_entry *neighbor =
            &neighbor_cache[index];
        uint16_t linux_state;

        if (neighbor->state == ND6_NO_ENTRY ||
            neighbor->netif != &g_lwip_netif)
            continue;
        if (match++ != ordinal) continue;
        switch (neighbor->state) {
        case ND6_INCOMPLETE: linux_state = 0x01u; break;
        case ND6_REACHABLE: linux_state = 0x02u; break;
        case ND6_STALE: linux_state = 0x04u; break;
        case ND6_DELAY: linux_state = 0x08u; break;
        case ND6_PROBE: linux_state = 0x10u; break;
        default: linux_state = 0u; break;
        }
        edge_ip6_to_bytes(&neighbor->next_hop_address, address);
        memcpy(hardware_address, neighbor->lladdr, 6u);
        if (state) *state = linux_state;
        if (is_router) *is_router = neighbor->isrouter;
        return 0;
    }
    return -1;
#else
    (void)ordinal;
    (void)address;
    (void)hardware_address;
    (void)state;
    (void)is_router;
    return -1;
#endif
}

int lwip_stack_set_hostname(const char *name) {
    char sanitized[65];
    int si = 0;
    int oi = 0;

    if (!name || !name[0]) return -1;
    while (name[si] && oi < (int)sizeof(sanitized) - 1) {
        char c = name[si++];
        if (!edge_valid_hostname_char(c)) continue;
        sanitized[oi++] = c;
    }
    if (oi == 0) return -1;
    sanitized[oi] = 0;
    strcpy(g_hostname, sanitized);
#if LWIP_NETIF_HOSTNAME
    if (g_ready) netif_set_hostname(&g_lwip_netif, g_hostname);
#endif
    return 0;
}

const char *lwip_stack_get_hostname(void) {
    return g_hostname;
}

int lwip_stack_reload_system_config(void) {
    edge_try_reload_hostname_from_file();
    edge_try_reload_dns_from_resolv_conf();
    return 0;
}

void lwip_stack_get_link_stats(uint64_t *rx_packets, uint64_t *rx_bytes, uint64_t *tx_packets, uint64_t *tx_bytes) {
    if (rx_packets) *rx_packets = g_rx_packets;
    if (rx_bytes) *rx_bytes = g_rx_bytes;
    if (tx_packets) *tx_packets = g_tx_packets;
    if (tx_bytes) *tx_bytes = g_tx_bytes;
}

int lwip_stack_tcp_rx_fin_seen_v4(uint32_t local_ip_be, uint16_t local_port,
                                  uint32_t remote_ip_be, uint16_t remote_port,
                                  uint32_t *counter_out) {
    if (g_tcp_rx_fin_counter == 0) return 0;
    if (g_tcp_rx_fin_local_ip_be != local_ip_be ||
        g_tcp_rx_fin_remote_ip_be != remote_ip_be ||
        g_tcp_rx_fin_local_port != local_port ||
        g_tcp_rx_fin_remote_port != remote_port) return 0;
    if (counter_out) *counter_out = g_tcp_rx_fin_counter;
    return 1;
}
